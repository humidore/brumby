import argparse
import datetime
import json
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path
from typing import Any

import requests

from .analyze import (
    analyze_artifacts,
    analyze_release,
    check_artifacts,
    check_package,
    get_artifacts,
    resolve_versions,
    select_assess_mode,
    ScanSkipped,
)
from .artifact import ArtifactView, make_local_artifact
from .config import get_settings, get_thresholds, is_enabled, load_config
from .pypi import get_latest_version, get_package_info, release_upload_bounds, validate_version
from .registry import get_finders


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


def _fmt_release_version(version: str, bounds: tuple[datetime.datetime | None, datetime.datetime | None]) -> str:
    oldest, _newest = bounds
    if oldest is None:
        return f"{version} (base: unknown)"
    return f"{version} (base: {oldest.date().isoformat()})"


def _is_404_http_error(exc: BaseException) -> bool:
    return isinstance(exc, requests.HTTPError) and getattr(exc.response, "status_code", None) == 404


def _add_version_flags(parser: argparse.ArgumentParser) -> None:
    """Add the shared --stable/--new version overrides."""
    parser.add_argument("--stable", default="", help="Older version (auto-detected if omitted)")
    parser.add_argument("--new", default="",
                        help="Newer version (auto-detected if omitted); without --stable, the "
                             "baseline is resolved from this version's upload time rather than "
                             "the current time")


def _validate_supplied_versions(*versions: str) -> None:
    """Validate any user-supplied version strings, skipping empty (auto-detect) ones."""
    for version in versions:
        if version:
            validate_version(version)


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


def _run_finder_by_name(artifact, config: dict, name: str, content: bool) -> list:
    specs = [s for s in get_finders(scope="artifact") if s.name == name]
    if not specs:
        raise ValueError(f"unknown artifact finder: {name}")
    spec = specs[0]
    if not (content or not spec.needs_content):
        return []
    view = ArtifactView(artifact)
    try:
        return spec.fn(view, get_settings(config, spec.name))
    finally:
        view.close()


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


def _risk_from_diffs(diffs: list[tuple], config: dict) -> str:
    sus_threshold, informational_threshold = get_thresholds(config)
    sketchy_count = sum(1 for diff in diffs if diff[6] == "sketchy")
    informational_count = sum(1 for diff in diffs if diff[6] == "informational")
    high = sketchy_count >= sus_threshold and informational_count >= informational_threshold
    return "high" if high else "average"


def _risk_from_findings(findings, config: dict) -> str:
    sus_threshold, informational_threshold = get_thresholds(config)
    kinds = {spec.name: spec.kind for spec in get_finders()}
    sketchy_count = sum(1 for f in findings if kinds.get(f.name, "informational") == "sketchy")
    informational_count = sum(1 for f in findings if kinds.get(f.name, "informational") == "informational")
    high = sketchy_count >= sus_threshold and informational_count >= informational_threshold
    return "high" if high else "average"


_EXPORT_PROMPT = """\
This directory contains two extracted PyPI release source trees for comparison.

  old/       {old}
  new/       {new}
  diff.txt   unified diff between old/ and new/ (diff -ruN old new)

Review diff.txt together with the full source trees in old/ and new/ for signs of
malicious or suspicious behavior introduced in the new release: exfiltration,
obfuscation, unexpected network/filesystem/process access, credential harvesting,
or other supply-chain tampering.

Output format (exactly):
  - First line: a single integer from 0 to 100 rating how malicious this change
    appears (0 = clearly benign, 100 = clearly malicious).
  - Last line: the literal text DONE
"""


def _pick_export_artifact(artifacts: list) -> Any:
    for artifact in artifacts:
        if artifact.filetype == "sdist":
            return artifact
    return artifacts[0]


def _open_archive(artifact: Any):
    try:
        return artifact.open_local()
    except ValueError:
        pass
    if artifact.filetype == "sdist":
        return artifact.open_sdist_remote()
    return artifact.open_zip_remote()


def _common_top_level(names: list[str]) -> str | None:
    """Return the shared top-level path component if every entry has one, else None."""
    tops = {name.split("/", 1)[0] for name in names if name.strip("/")}
    if len(tops) == 1:
        return next(iter(tops))
    return None


def _safe_member_target(dest: Path, name: str) -> Path:
    dest_resolved = dest.resolve()
    target = (dest / name).resolve()
    if target != dest_resolved and dest_resolved not in target.parents:
        raise ValueError(f"unsafe path in archive member: {name}")
    return target


def _extract_artifact_to(artifact: Any, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    archive = _open_archive(artifact)
    try:
        if isinstance(archive, tarfile.TarFile):
            members = archive.getmembers()
            strip = _common_top_level([m.name for m in members])
            if strip is not None:
                prefix = strip + "/"
                for m in members:
                    m.name = m.name[len(prefix):] if m.name.startswith(prefix) else ""
                members = [m for m in members if m.name]
            archive.extractall(dest, members=members, filter="data")
        else:
            names = archive.namelist()
            strip = _common_top_level(names)
            prefix = (strip + "/") if strip is not None else ""
            for info in archive.infolist():
                relative = info.filename[len(prefix):] if info.filename.startswith(prefix) else info.filename
                if not relative:
                    continue
                target = _safe_member_target(dest, relative)
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info) as src, open(target, "wb") as out:
                    out.write(src.read())
    finally:
        archive.close()


def cmd_export(args: argparse.Namespace) -> int:
    old_path = Path(args.package)
    new_path = Path(args.other) if args.other else None
    output = Path(args.output) if args.output else Path(f"brumby-export-{old_path.stem}")
    try:
        if old_path.is_file() and new_path is not None and new_path.is_file():
            old_artifact = make_local_artifact(old_path)
            new_artifact = make_local_artifact(new_path)
            old_label, new_label = str(old_path), str(new_path)
        else:
            _validate_supplied_versions(args.stable, args.new)
            pkg_info = get_package_info(args.package)
            stable, new = resolve_versions(
                args.package,
                cutoff_hours=args.cutoff,
                stable_version=args.stable or None,
                new_version=args.new or None,
                last_two=args.last_two,
                last=args.last,
                pkg_info=pkg_info,
            )
            if not stable:
                print(f"error: No previous version found for {args.package}", file=sys.stderr)
                return 1
            if not new or stable == new:
                print(f"error: Only one version found for {args.package}", file=sys.stderr)
                return 1
            old_artifacts = get_artifacts(args.package, stable, pkg_info=pkg_info, save_dir=args.save_artifacts or None)
            new_artifacts = get_artifacts(args.package, new, pkg_info=pkg_info, save_dir=args.save_artifacts or None)
            old_artifact = _pick_export_artifact(old_artifacts)
            new_artifact = _pick_export_artifact(new_artifacts)
            old_label, new_label = f"{args.package} {stable}", f"{args.package} {new}"
    except requests.HTTPError as e:
        if _is_404_http_error(e):
            print(f"error: {args.package} not found (HTTP 404)", file=sys.stderr)
            return 1
        raise
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    old_dir = output / "old"
    new_dir = output / "new"
    _extract_artifact_to(old_artifact, old_dir)
    _extract_artifact_to(new_artifact, new_dir)

    diff_result = subprocess.run(
        ["diff", "-ruN", "old", "new"], cwd=output, capture_output=True, text=True,
    )
    (output / "diff.txt").write_text(diff_result.stdout)
    (output / "PROMPT.md").write_text(_EXPORT_PROMPT.format(old=old_label, new=new_label))

    print(f"Exported to {output}")
    print(f"  old:    {old_label}  -> old/")
    print(f"  new:    {new_label}  -> new/")
    print("  diff:   diff.txt")
    print("  prompt: PROMPT.md")
    return 0


def _assess_line(project: str, risk: str) -> str:
    if risk == "did not scan":
        return f"{project:<24} did not scan"
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
    config = load_config(Path(args.config) if args.config else None)
    old_path = Path(args.package)
    new_path = Path(args.other) if args.other else None
    try:
        if old_path.is_file() and new_path is not None and new_path.is_file():
            old_artifact = make_local_artifact(old_path)
            new_artifact = make_local_artifact(new_path)
            package_label = "local compare"
            print("Local compare:")
            print(f"  old: {old_path}")
            print(f"  new: {new_path}")
            _stable_findings, _new_findings, diffs = check_artifacts(
                [old_artifact],
                [new_artifact],
                old_label=str(old_path),
                new_label=str(new_path),
                callback=_default_callback,
                config=config,
                content=not args.fast,
            )
        else:
            _validate_supplied_versions(args.stable, args.new)
            pkg_info = get_package_info(args.package)
            package_label = args.package
            stable, new = resolve_versions(
                args.package,
                cutoff_hours=args.cutoff,
                stable_version=args.stable or None,
                new_version=args.new or None,
                last_two=args.last_two,
                last=args.last,
                pkg_info=pkg_info,
            )

            if args.list_only:
                print(f"Package: {args.package}")
                print(
                    "  stable: "
                    + (
                        _fmt_release_version(stable, release_upload_bounds(pkg_info, stable))
                        if stable
                        else "(none)"
                    )
                )
                print(
                    "  new:    "
                    + (
                        _fmt_release_version(new, release_upload_bounds(pkg_info, new))
                        if new
                        else "(none)"
                    )
                )
                return 0

            if not stable:
                print(f"error: No previous version found for {args.package}", file=sys.stderr)
                return 1
            if not new:
                print(f"error: Only one version found for {args.package}", file=sys.stderr)
                return 1
            if stable == new:
                print(f"error: Only one version found for {args.package}", file=sys.stderr)
                return 1

            print(f"Package: {args.package}")
            print(f"  stable: {_fmt_release_version(stable, release_upload_bounds(pkg_info, stable))}")
            print(f"  new:    {_fmt_release_version(new, release_upload_bounds(pkg_info, new))}")

            _stable_findings, _new_findings, diffs = check_package(
                args.package,
                cutoff_hours=args.cutoff,
                stable_version=stable,
                new_version=new,
                callback=_default_callback,
                config=config,
                content=not args.fast,
                last_two=args.last_two,
                last=args.last,
                pkg_info=pkg_info,
                save_dir=args.save_artifacts or None,
            )
            package_label = args.package
    except ScanSkipped as e:
        print(f"{package_label if 'package_label' in locals() else args.package}: did not scan")
        return 0
    except requests.HTTPError as e:
        if getattr(e.response, "status_code", None) == 404:
            print(f"error: {args.package} not found (HTTP 404)", file=sys.stderr)
            return 1
        raise
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    added = sum(len(new_vals - old_vals) for _, _, old_vals, new_vals, *_ in diffs)
    removed = sum(len(old_vals - new_vals) for _, _, old_vals, new_vals, *_ in diffs)
    delta = added - removed
    if diffs:
        print(f"\n{package_label}: {len(diffs)} difference(s) found")
        print(f"delta: {delta:+d} (add={added} remove={removed})")
        return 2
    print(f"{package_label}: no differences found")
    print(f"delta: {delta:+d} (add={added} remove={removed})")
    return 0


def cmd_assess(args: argparse.Namespace) -> int:
    config = load_config(Path(args.config) if args.config else None)
    local_path = Path(args.package)
    as_json = args.json
    try:
        if local_path.is_file():
            if args.stable or args.new:
                raise ValueError("--stable and --new cannot be used with a local artifact path")
            project = local_path.name
            artifact = make_local_artifact(local_path)
            findings = analyze_artifacts([artifact], config, content=not args.fast)
            risk = _risk_from_findings(findings, config)
        else:
            _validate_supplied_versions(args.stable, args.new)
            pkg_info = get_package_info(args.package)
            project = args.package
            mode, stable, new = select_assess_mode(
                args.package,
                cutoff_hours=args.cutoff,
                pkg_info=pkg_info,
                stable_version=args.stable or None,
                new_version=args.new or None,
            )
            if mode == "first-release":
                risk = "high"
            elif mode == "inspect":
                version = new
                if not version:
                    _assess_error(project, f"Only one version found for {args.package}", as_json)
                    return 1
                artifacts = get_artifacts(args.package, version, pkg_info=pkg_info, save_dir=args.save_artifacts or None)
                findings = analyze_release(artifacts, pkg_info, version, config, content=not args.fast)
                risk = _risk_from_findings(findings, config)
            else:
                if not stable or not new:
                    _assess_error(project, f"Only one version found for {args.package}", as_json)
                    return 1
                _stable_findings, _new_findings, diffs = check_package(
                    args.package,
                    cutoff_hours=args.cutoff,
                    stable_version=stable,
                    new_version=new,
                    callback=None,
                    config=config,
                    content=not args.fast,
                    last_two=(mode == "check-last"),
                    last=(mode == "check-last"),
                    pkg_info=pkg_info,
                    save_dir=args.save_artifacts or None,
                )
                risk = _risk_from_diffs(diffs, config)
    except ScanSkipped:
        _assess_emit(project if 'project' in locals() else args.package, "did not scan", as_json)
        return 0
    except requests.HTTPError as e:
        if getattr(e.response, "status_code", None) == 404:
            _assess_error(args.package, f"{args.package} not found (HTTP 404)", as_json)
            return 1
        raise
    except ValueError as e:
        _assess_error(project if 'project' in locals() else args.package, str(e), as_json)
        return 1

    _assess_emit(project, risk, as_json)
    return 1 if risk == "high" else 0


def cmd_inspect(args: argparse.Namespace) -> int:
    try:
        config = load_config(Path(args.config) if args.config else None)
        local_path = Path(args.package)
        if local_path.exists() and local_path.is_file():
            label = str(local_path)
            artifact = make_local_artifact(local_path)
            if args.finder:
                findings = _run_finder_by_name(artifact, config, args.finder, content=not args.fast)
            else:
                findings = analyze_artifacts([artifact], config, content=not args.fast)
        else:
            _validate_supplied_versions(args.version)
            version = args.version or get_latest_version(args.package)
            pkg_info = get_package_info(args.package)
            label = f"{args.package} {version}"
            artifacts = get_artifacts(args.package, version, pkg_info=pkg_info, save_dir=args.save_artifacts or None)
            if args.finder:
                findings = []
                for artifact in artifacts:
                    findings.extend(_run_finder_by_name(artifact, config, args.finder, content=not args.fast))
            else:
                findings = analyze_release(artifacts, pkg_info, version, config, content=not args.fast)
    except ScanSkipped:
        print(f"{label if 'label' in locals() else args.package}: did not scan")
        return 0
    except requests.HTTPError as e:
        if getattr(e.response, "status_code", None) == 404:
            if args.finder:
                print(f"error: {args.package} not found (HTTP 404)", file=sys.stderr)
                return 0
            print(f"error: {args.package} not found (HTTP 404)", file=sys.stderr)
            return 1
        raise
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    if not findings:
        print(f"{label}: no findings")
        return 0
    print(f"{label}:")
    for line in _inspect_lines(findings, summary=args.summary):
        print(line)
    return 1 if args.finder else 0


def cmd_list_finders(args: argparse.Namespace) -> int:
    config = load_config(Path(args.config) if args.config else None)
    print(f"{'NAME':<35} {'SCOPE':<12} {'KIND':<14} {'CONTENT':<8} {'ON':<4} DESCRIPTION")
    print("-" * 110)
    for spec in get_finders():
        enabled = is_enabled(config, spec.name, spec.default_enabled)
        print(
            f"{spec.name:<35} {spec.scope:<12} {spec.kind:<14} "
            f"{'yes' if spec.needs_content else 'no':<8} "
            f"{'y' if enabled else 'N':<4} {spec.description}"
        )
    return 0


def _add_common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--config", default="", metavar="FILE", help="Path to brumby.toml")
    p.add_argument("--fast", action="store_true", help="Skip finders that read file content")
    p.add_argument("--save-artifacts", default="", metavar="DIR",
                   help="Download examined artifacts into DIR and use local files")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="brumby",
        description="Compare PyPI releases for suspicious changes.",
    )
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    check = sub.add_parser("check", help="Compare two releases (stable vs new by default)")
    check.add_argument("package", help="Package name or local artifact path")
    check.add_argument("other", nargs="?", default="",
                       help="Optional second local artifact path for artifact-only compare")
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
        help="Extract two matching artifacts to source trees, diff them, and write a PROMPT.md for LLM review",
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
    export.add_argument("--save-artifacts", default="", metavar="DIR",
                        help="Also save downloaded artifacts into DIR")

    args = parser.parse_args()
    if args.command == "check":
        sys.exit(cmd_check(args))
    elif args.command == "assess":
        sys.exit(cmd_assess(args))
    elif args.command == "inspect":
        sys.exit(cmd_inspect(args))
    elif args.command == "finders":
        sys.exit(cmd_list_finders(args))
    elif args.command == "export":
        sys.exit(cmd_export(args))
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
