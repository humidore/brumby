import argparse
import json
import sys
from pathlib import Path
from typing import Any

import keke
import requests

from . import api
from .config import load_config
from .registry import get_finders


def _load_config(args: argparse.Namespace) -> dict:
    return load_config(Path(args.config) if args.config else None)


def _fmt_vals(vals: frozenset[Any]) -> str:
    if not vals:
        return "(absent)"
    items = sorted(vals, key=str)
    rendered = [str(v) for v in items]
    return rendered[0] if len(rendered) == 1 else "{" + ", ".join(rendered) + "}"


def _fmt_source_set(sources: frozenset[str | None]) -> str:
    if not sources:
        return ""
    items = sorted("(release)" if src is None else str(src) for src in sources)
    return f" [{', '.join(items)}]"


def _fmt_release_ref(ref: api.ReleaseRef) -> str:
    if ref.version is None:
        return "(none)"
    oldest, _newest = ref.upload_bounds
    if oldest is None:
        return f"{ref.version} (base: unknown)"
    return f"{ref.version} (base: {oldest.date().isoformat()})"


def _is_404_http_error(exc: BaseException) -> bool:
    return isinstance(exc, requests.HTTPError) and getattr(exc.response, "status_code", None) == 404


def _add_version_flags(parser: argparse.ArgumentParser) -> None:
    """Add the shared --stable/--new version overrides."""
    parser.add_argument("--stable", default="", help="Older version (auto-detected if omitted)")
    parser.add_argument("--new", default="",
                        help="Newer version (auto-detected if omitted); without --stable, the "
                             "baseline is resolved from this version's upload time rather than "
                             "the current time")


def _inspect_lines(findings, summary: bool = False) -> list[str]:
    kinds = {spec.name: spec.kind for spec in get_finders()}

    def _prefix(name: str) -> str:
        return "  \033[31m[X]\033[0m" if kinds.get(name, "informational") == "sketchy" else "  [i]"

    if not summary:
        return [
            f"{_prefix(f.name)} {f}{f'  [{f.source}]' if f.source else ''}"
            for f in sorted(findings, key=lambda x: (x.name, str(x.value)))
        ]

    grouped: dict[tuple[str, str | None, str], list] = {}
    for finding in findings:
        grouped.setdefault((finding.name, finding.resource, str(finding.value)), []).append(finding)

    lines: list[str] = []
    for (name, resource, _value), items in sorted(grouped.items(), key=lambda kv: (kv[0][0], kv[0][1] or "", kv[0][2])):
        sources = frozenset(item.source for item in items)
        resource_label = resource or "(release)"
        representative = items[0]
        if len(sources) > 3:
            lines.append(f"{_prefix(representative.name)} {representative} @ {resource_label} [*]")
            continue
        for item in sorted(items, key=lambda x: (str(x.value), x.source or "")):
            src = f"  [{item.source}]" if item.source else ""
            lines.append(f"{_prefix(item.name)} {item}{src}")
    return lines


def _default_callback(
    package: str, old_ver: str, new_ver: str,
    name: str, resource: str | None, old_vals: frozenset, new_vals: frozenset,
    old_sources: frozenset[str | None], new_sources: frozenset[str | None],
    kind: str,
) -> None:
    prefix = "  \033[31m[X]\033[0m" if kind == "sketchy" else "  [i]"
    resource_label = resource or "(release)"
    old_text = _fmt_vals(old_vals)
    new_text = _fmt_vals(new_vals)
    added = new_vals - old_vals
    removed = old_vals - new_vals
    if kind == "sketchy":
        parts = []
        if added:
            parts.append(f"new: {_fmt_vals(added)}")
        if removed:
            parts.append(f"gone: {_fmt_vals(removed)}")
        print(
            f"{prefix} {name} @ {resource_label}"
            f"{_fmt_source_set(old_sources | new_sources)}: {', '.join(parts)}"
        )
    else:
        print(
            f"{prefix} {name} @ {resource_label}"
            f"{_fmt_source_set(old_sources | new_sources)}: "
            f"{old_text} → {new_text}"
        )


def cmd_export(args: argparse.Namespace) -> int:
    try:
        result = api.export(
            args.package, args.other or None,
            stable_version=getattr(args, "stable", "") or None,
            new_version=getattr(args, "new", "") or None,
            cutoff_hours=getattr(args, "cutoff", 24),
            last_two=getattr(args, "last_two", False), last=getattr(args, "last", False),
            output=args.output or None, save_dir=getattr(args, "save_artifacts", "") or None,
            config=_load_config(args),
        )
    except ScanSkipped as exc:
        print(f"{args.package}: {exc}")
        return 0
    except requests.HTTPError as exc:
        if _is_404_http_error(exc):
            print(f"error: {args.package} not found (HTTP 404)", file=sys.stderr)
            return 1
        raise
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"Exported to {result.output}")
    print(f"  old:    {result.old.label}  -> old/")
    print(f"  new:    {result.new.label}  -> new/")
    print("  prompt: PROMPT.md")
    return 0


# Kept for callers that used the old CLI helpers; classification now belongs to the API.
ScanSkipped = api.ScanSkipped
_risk_from_diffs = api.classify_diffs
_risk_from_findings = api.classify_findings


def _assess_line(project: str, risk: str) -> str:
    if risk == "did not scan":
        return f"{project:<24} did not scan"
    if risk == "too new":
        return f"{project:<24} \033[33mtoo new to evaluate\033[0m"
    if risk == "high":
        color = "\033[31m"
    else:
        color = "\033[32m"
    return f"{project:<24} {color}{risk} risk\033[0m"


def _assess_emit(project: str, risk: str, as_json: bool) -> None:
    if as_json:
        print(json.dumps({"project": project, "risk": risk}))
    else:
        print(_assess_line(project, risk))


def _assess_error(project: str, message: str, as_json: bool) -> None:
    if as_json:
        print(json.dumps({"project": project, "error": message}), file=sys.stderr)
    else:
        print(f"error: {message}", file=sys.stderr)


def cmd_check(args: argparse.Namespace) -> int:
    try:
        result = api.check(
            args.package, args.other or None,
            stable_version=args.stable or None, new_version=args.new or None,
            cutoff_hours=args.cutoff, last_two=args.last_two, last=args.last,
            list_only=args.list_only, content=not args.fast,
            save_dir=args.save_artifacts or None, config=_load_config(args),
        )
    except ScanSkipped:
        print(f"{args.package}: did not scan")
        return 0
    except requests.HTTPError as exc:
        if _is_404_http_error(exc):
            print(f"error: {args.package} not found (HTTP 404)", file=sys.stderr)
            return 1
        raise
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if result.source == "package":
        print(f"Package: {result.label}")
        print(f"  stable: {_fmt_release_ref(result.old)}")
        print(f"  new:    {_fmt_release_ref(result.new)}")
    else:
        heading = "URL compare" if result.source == "url" else "Local compare"
        print(f"{heading}:")
        print(f"  old: {result.old.label}")
        print(f"  new: {result.new.label}")
    if result.list_only:
        return 0
    for diff in result.diffs:
        _default_callback(
            result.label, result.old.label, result.new.label,
            diff.name, diff.resource, diff.old_values, diff.new_values,
            diff.old_sources, diff.new_sources, diff.kind,
        )
    if result.diffs:
        print(f"\n{result.label}: {len(result.diffs)} difference(s) found")
    else:
        print(f"{result.label}: no differences found")
    print(f"delta: {result.delta:+d} (add={result.added} remove={result.removed})")
    return 2 if result.diffs else 0


def cmd_assess(args: argparse.Namespace) -> int:
    try:
        result = api.assess(
            args.package, stable_version=args.stable or None, new_version=args.new or None,
            cutoff_hours=args.cutoff, content=not args.fast,
            save_dir=args.save_artifacts or None, config=_load_config(args),
        )
    except ScanSkipped:
        project = Path(args.package).name if Path(args.package).is_file() else args.package
        _assess_emit(project, "did not scan", args.json)
        return 0
    except requests.HTTPError as exc:
        if _is_404_http_error(exc):
            _assess_error(args.package, f"{args.package} not found (HTTP 404)", args.json)
            return 1
        raise
    except ValueError as exc:
        _assess_error(args.package, str(exc), args.json)
        return 1
    _assess_emit(result.project, result.risk, args.json)
    return 0


def cmd_inspect(args: argparse.Namespace) -> int:
    try:
        result = api.inspect(
            args.package, args.version or None, finder=args.finder or None,
            content=not args.fast, save_dir=args.save_artifacts or None,
            config=_load_config(args),
        )
    except ScanSkipped:
        print(f"{args.package}: did not scan")
        return 0
    except requests.HTTPError as exc:
        if _is_404_http_error(exc):
            print(f"error: {args.package} not found (HTTP 404)", file=sys.stderr)
            return 0 if args.finder else 1
        raise
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if not result.findings:
        print(f"{result.label}: no findings")
        return 0
    print(f"{result.label}:")
    for line in _inspect_lines(result.findings, summary=args.summary):
        print(line)
    return 1 if args.finder else 0


def cmd_list_finders(args: argparse.Namespace) -> int:
    items = api.finders(config=_load_config(args))
    print(f"{'NAME':<35} {'SCOPE':<12} {'KIND':<14} {'CONTENT':<8} {'ON':<4} DESCRIPTION")
    print("-" * 110)
    for item in items:
        print(
            f"{item.name:<35} {item.scope:<12} {item.kind:<14} "
            f"{'yes' if item.needs_content else 'no':<8} "
            f"{'y' if item.enabled else 'N':<4} {item.description}"
        )
    return 0


def _add_common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--config", default="", metavar="FILE", help="Path to brumby.toml")
    p.add_argument("--fast", action="store_true", help="Skip finders that read file content")
    p.add_argument("--save-artifacts", default="", metavar="DIR",
                   help="Download examined artifacts into DIR and use local files")
    p.add_argument("--trace", default="", metavar="FILE",
                   help="Write a chrome-trace-format profile of downloads/analysis to FILE")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="brumby",
        description="Compare PyPI releases for suspicious changes.",
    )
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    check = sub.add_parser("check", help="Compare two releases (stable vs new by default)")
    check.add_argument("package", help="Package name, local artifact path, or artifact URL")
    check.add_argument("other", nargs="?", default="",
                       help="Optional second local artifact path or URL for a metadata-free artifact-only compare")
    _add_version_flags(check)
    check.add_argument("--cutoff", type=int, default=24, metavar="HOURS",
                       help="Hours threshold for stable classification (default: 24)")
    mode = check.add_mutually_exclusive_group()
    mode.add_argument("--last-two", action="store_true",
                      help="Compare the two most recent releases regardless of age")
    mode.add_argument("--last", action="store_true",
                      help="Compare the newest release vs the newest release at least cutoff hours older; the older version is chosen by upload time and may sort higher than the newest version")
    check.add_argument("--list-only", action="store_true",
                       help="Print detected versions without analyzing")
    _add_common(check)

    assess = sub.add_parser("assess", help="Classify a package as high or average risk")
    assess.add_argument("package", help="Package name or local artifact path")
    _add_version_flags(assess)
    assess.add_argument("--cutoff", type=int, default=24, metavar="HOURS",
                        help="Hours threshold for recent-release classification (default: 24)")
    assess.add_argument("--json", action="store_true",
                        help="Emit result as a JSON object instead of a formatted line")
    _add_common(assess)

    inspect = sub.add_parser("inspect", help="Show findings for one version or local artifact file")
    inspect.add_argument("package")
    inspect.add_argument("version", nargs="?", default="",
                         help="Version to inspect (defaults to latest; ignored for local file paths)")
    inspect.add_argument("--summary", action="store_true",
                         help="Collapse repeated findings with more than 3 values into one row")
    inspect.add_argument("--finder", default="", metavar="NAME",
                         help="Run only one artifact finder; exit 1 if it finds anything")
    _add_common(inspect)

    finders_cmd = sub.add_parser("finders", help="List all registered finders")
    finders_cmd.add_argument("--config", default="", metavar="FILE")

    export = sub.add_parser(
        "export",
        help="Extract two matching artifacts to source trees and write a PROMPT.md for LLM review",
    )
    export.add_argument("package", help="Package name or local artifact path")
    export.add_argument("other", nargs="?", default="",
                        help="Optional second local artifact path for artifact-only compare")
    _add_version_flags(export)
    export.add_argument("--cutoff", type=int, default=24, metavar="HOURS",
                        help="Hours threshold for stable classification (default: 24)")
    export_mode = export.add_mutually_exclusive_group()
    export_mode.add_argument("--last-two", action="store_true",
                             help="Compare the two most recent releases regardless of age")
    export_mode.add_argument("--last", action="store_true",
                             help="Compare the newest release vs the newest release at least cutoff hours older")
    export.add_argument("--output", "-o", default="", metavar="DIR",
                        help="Output directory (default: ./brumby-export-<package>)")
    export.add_argument("--config", default="", metavar="FILE", help="Path to brumby.toml")
    export.add_argument("--save-artifacts", default="", metavar="DIR",
                        help="Also save downloaded artifacts into DIR")
    export.add_argument("--trace", default="", metavar="FILE",
                        help="Write a chrome-trace-format profile of downloads/analysis to FILE")

    args = parser.parse_args()
    trace_file = open(args.trace, "w") if getattr(args, "trace", "") else None
    with keke.TraceOutput(file=trace_file):
        if args.command == "check":
            code = cmd_check(args)
        elif args.command == "assess":
            code = cmd_assess(args)
        elif args.command == "inspect":
            code = cmd_inspect(args)
        elif args.command == "finders":
            code = cmd_list_finders(args)
        elif args.command == "export":
            code = cmd_export(args)
        else:
            parser.print_help()
            code = 1
    sys.exit(code)


if __name__ == "__main__":  # pragma: no cover - exercised by the installed script
    main()
