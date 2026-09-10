"""Run brumby operations without coupling analysis to terminal output.

The CLI formats the result objects from this module.  Library callers get the same
version selection, scanning, and risk decisions without capturing stdout or
reconstructing command-line arguments.
"""

from dataclasses import dataclass
import datetime
from pathlib import Path
import tarfile
from typing import Any, Literal, cast

import keke

from . import network
from .analyze import (
    ScanSkipped,
    analyze_artifacts,
    analyze_release,
    check_artifacts,
    check_package,
    check_urls,
    get_artifacts,
    resolve_versions,
    select_assess_mode,
)
from .artifact import ArtifactView, make_local_artifact
from .compare import Diff
from .config import get_settings, get_thresholds, is_enabled
from .finding import Finding
from .pypi import get_latest_version, get_package_info, release_upload_bounds, validate_version
from .registry import get_finders

Risk = Literal["high", "average", "too new", "did not scan"]
SourceKind = Literal["package", "local", "url"]


@dataclass(frozen=True)
class ReleaseRef:
    """Name one side of a comparison and retain its upload range when known."""

    label: str
    version: str | None = None
    upload_bounds: tuple[datetime.datetime | None, datetime.datetime | None] = (None, None)


@dataclass(frozen=True)
class Difference:
    """Describe one finding that changed between two scans."""

    name: str
    resource: str | None
    old_values: frozenset[Any]
    new_values: frozenset[Any]
    old_sources: frozenset[str | None]
    new_sources: frozenset[str | None]
    kind: Literal["informational", "sketchy"]

    @property
    def added(self) -> frozenset[Any]:
        return self.new_values - self.old_values

    @property
    def removed(self) -> frozenset[Any]:
        return self.old_values - self.new_values


@dataclass(frozen=True)
class CheckResult:
    """Describe a comparison, including the raw findings behind each difference."""

    label: str
    source: SourceKind
    old: ReleaseRef
    new: ReleaseRef
    old_findings: list[Finding]
    new_findings: list[Finding]
    diffs: list[Difference]
    list_only: bool = False

    @property
    def added(self) -> int:
        return sum(len(diff.added) for diff in self.diffs)

    @property
    def removed(self) -> int:
        return sum(len(diff.removed) for diff in self.diffs)

    @property
    def delta(self) -> int:
        return self.added - self.removed


@dataclass(frozen=True)
class AssessResult:
    """Return the verdict and the evidence used to reach it."""

    project: str
    risk: Risk
    mode: str
    stable_version: str | None = None
    new_version: str | None = None
    findings: list[Finding] | None = None
    diffs: list[Difference] | None = None


@dataclass(frozen=True)
class InspectResult:
    """Return findings for one artifact or package release."""

    label: str
    findings: list[Finding]
    finder: str | None = None


@dataclass(frozen=True)
class FinderInfo:
    """Describe a registered finder and whether the active config enables it."""

    name: str
    description: str
    scope: Literal["artifact", "release", "metadata", "comparison"]
    kind: Literal["informational", "sketchy"]
    default_enabled: bool
    needs_content: bool
    enabled: bool


@dataclass(frozen=True)
class ExportResult:
    """Name the files and labels produced for an offline review."""

    output: Path
    old: ReleaseRef
    new: ReleaseRef
    old_dir: Path
    new_dir: Path
    prompt: Path


_EXPORT_PROMPT = """\
This directory contains two extracted PyPI release source trees for comparison.

  old/       {old}
  new/       {new}

Review the full source trees in old/ and new/ for signs of malicious or suspicious
behavior introduced in the new release: exfiltration, obfuscation, unexpected
network/filesystem/process access, credential harvesting, or other supply-chain
tampering. As a starting point, you can run `diff -qr old new` yourself to list
files that differ.

Output format (exactly):
  - First line: a single integer from 0 to 100 rating how malicious this change
    appears (0 = clearly benign, 100 = clearly malicious).
  - Last line: the literal text DONE
"""

def _configure(config: dict | None = None) -> dict:
    """Apply an explicit config, using defaults when no config is supplied.

    Config-file discovery belongs to the CLI. Library callers pass the loaded
    dict when they want non-default settings; None provides an isolated default.
    """
    settings = config if config is not None else {}
    network.configure(settings)
    return settings


def _differences(diffs: list[Diff]) -> list[Difference]:
    return [
        Difference(
            name,
            resource,
            old_values,
            new_values,
            old_sources,
            new_sources,
            cast(Literal["informational", "sketchy"], kind),
        )
        for name, resource, old_values, new_values, old_sources, new_sources, kind in diffs
    ]


def _validate_versions(*versions: str | None) -> None:
    for version in versions:
        if version:
            validate_version(version)


def _looks_like_url(value: str) -> bool:
    return value.startswith("http://") or value.startswith("https://")


@keke.ktrace("package", "other")
def check(
    package: str,
    other: str | None = None,
    *,
    stable_version: str | None = None,
    new_version: str | None = None,
    cutoff_hours: int = 24,
    last_two: bool = False,
    last: bool = False,
    list_only: bool = False,
    content: bool = True,
    save_dir: str | None = None,
    config: dict | None = None,
) -> CheckResult:
    """Compare package releases, local artifacts, or two artifact URLs."""
    settings = _configure(config)
    old_path = Path(package)
    new_path = Path(other) if other else None

    if other and _looks_like_url(package) and _looks_like_url(other):
        old_findings, new_findings, diffs = check_urls(
            package, other, callback=None, config=settings, content=content,
        )
        return CheckResult(
            "url compare", "url", ReleaseRef(package), ReleaseRef(other),
            old_findings, new_findings, _differences(diffs),
        )

    if old_path.is_file() and new_path is not None and new_path.is_file():
        old_artifact = make_local_artifact(old_path)
        new_artifact = make_local_artifact(new_path)
        old_findings, new_findings, diffs = check_artifacts(
            [old_artifact], [new_artifact], old_label=str(old_path),
            new_label=str(new_path), callback=None, config=settings, content=content,
        )
        return CheckResult(
            "local compare", "local", ReleaseRef(str(old_path)), ReleaseRef(str(new_path)),
            old_findings, new_findings, _differences(diffs),
        )

    _validate_versions(stable_version, new_version)
    pkg_info = get_package_info(package)
    stable, new = resolve_versions(
        package,
        cutoff_hours=cutoff_hours,
        stable_version=stable_version,
        new_version=new_version,
        last_two=last_two,
        last=last,
        pkg_info=pkg_info,
    )
    old_ref = ReleaseRef(
        f"{package} {stable}" if stable else package,
        stable,
        release_upload_bounds(pkg_info, stable) if stable else (None, None),
    )
    new_ref = ReleaseRef(
        f"{package} {new}" if new else package,
        new,
        release_upload_bounds(pkg_info, new) if new else (None, None),
    )
    if list_only:
        return CheckResult(package, "package", old_ref, new_ref, [], [], [], True)
    if not stable:
        raise ValueError(f"No previous version found for {package}")
    if not new or stable == new:
        raise ValueError(f"Only one version found for {package}")

    old_findings, new_findings, diffs = check_package(
        package,
        cutoff_hours=cutoff_hours,
        stable_version=stable,
        new_version=new,
        callback=None,
        config=settings,
        content=content,
        last_two=last_two,
        last=last,
        pkg_info=pkg_info,
        save_dir=save_dir,
    )
    return CheckResult(
        package, "package", old_ref, new_ref,
        old_findings, new_findings, _differences(diffs),
    )


@keke.ktrace()
def classify_diffs(diffs: list[Difference] | list[Diff], config: dict) -> Risk:
    sketchy_threshold, informational_threshold = get_thresholds(config)
    kinds = [diff.kind if isinstance(diff, Difference) else diff[6] for diff in diffs]
    sketchy = sum(kind == "sketchy" for kind in kinds)
    informational = sum(kind == "informational" for kind in kinds)
    return "high" if sketchy >= sketchy_threshold and informational >= informational_threshold else "average"


@keke.ktrace()
def classify_findings(findings: list[Finding], config: dict) -> Risk:
    sketchy_threshold, informational_threshold = get_thresholds(config)
    kinds = {spec.name: spec.kind for spec in get_finders()}
    sketchy = sum(kinds.get(finding.name, "informational") == "sketchy" for finding in findings)
    informational = sum(kinds.get(finding.name, "informational") == "informational" for finding in findings)
    return "high" if sketchy >= sketchy_threshold and informational >= informational_threshold else "average"


@keke.ktrace("package")
def assess(
    package: str,
    *,
    stable_version: str | None = None,
    new_version: str | None = None,
    cutoff_hours: int = 24,
    content: bool = True,
    save_dir: str | None = None,
    config: dict | None = None,
) -> AssessResult:
    """Classify one local artifact or package release pair."""
    settings = _configure(config)
    local_path = Path(package)
    if local_path.is_file():
        if stable_version or new_version:
            raise ValueError("--stable and --new cannot be used with a local artifact path")
        findings = analyze_artifacts(
            [make_local_artifact(local_path)], settings, content=content,
        )
        return AssessResult(local_path.name, classify_findings(findings, settings), "inspect", findings=findings)

    _validate_versions(stable_version, new_version)
    pkg_info = get_package_info(package)
    mode, stable, new = select_assess_mode(
        package,
        cutoff_hours=cutoff_hours,
        pkg_info=pkg_info,
        stable_version=stable_version,
        new_version=new_version,
    )
    if mode in ("first-release", "too-new"):
        return AssessResult(package, "too new", mode, stable, new)
    if mode == "inspect":
        if not new:
            raise ValueError(f"Only one version found for {package}")
        artifacts = get_artifacts(package, new, pkg_info=pkg_info, save_dir=save_dir)
        findings = analyze_release(artifacts, pkg_info, new, settings, content=content)
        return AssessResult(package, classify_findings(findings, settings), mode, stable, new, findings=findings)
    if not stable or not new:
        raise ValueError(f"Only one version found for {package}")
    _, _, diffs = check_package(
        package,
        cutoff_hours=cutoff_hours,
        stable_version=stable,
        new_version=new,
        callback=None,
        config=settings,
        content=content,
        last_two=(mode == "check-last"),
        last=(mode == "check-last"),
        pkg_info=pkg_info,
        save_dir=save_dir,
    )
    differences = _differences(diffs)
    return AssessResult(
        package, classify_diffs(differences, settings), mode, stable, new,
        diffs=differences,
    )


def _run_finder(artifact: Any, config: dict, name: str, content: bool) -> list[Finding]:
    specs = [spec for spec in get_finders(scope="artifact") if spec.name == name]
    if not specs:
        raise ValueError(f"unknown artifact finder: {name}")
    spec = specs[0]
    if not content and spec.needs_content:
        return []
    view = ArtifactView(artifact)
    try:
        return spec.fn(view, get_settings(config, spec.name))
    finally:
        view.close()


@keke.ktrace("package", "version", "finder")
def inspect(
    package: str,
    version: str | None = None,
    *,
    finder: str | None = None,
    content: bool = True,
    save_dir: str | None = None,
    config: dict | None = None,
) -> InspectResult:
    """Inspect one local artifact or one package release."""
    settings = _configure(config)
    local_path = Path(package)
    if local_path.is_file():
        label = str(local_path)
        artifact = make_local_artifact(local_path)
        findings = (
            _run_finder(artifact, settings, finder, content)
            if finder
            else analyze_artifacts([artifact], settings, content=content)
        )
        return InspectResult(label, findings, finder)

    _validate_versions(version)
    selected = version or get_latest_version(package)
    pkg_info = get_package_info(package)
    artifacts = get_artifacts(package, selected, pkg_info=pkg_info, save_dir=save_dir)
    if finder:
        findings = []
        for artifact in artifacts:
            findings.extend(_run_finder(artifact, settings, finder, content))
    else:
        findings = analyze_release(artifacts, pkg_info, selected, settings, content=content)
    return InspectResult(f"{package} {selected}", findings, finder)


@keke.ktrace()
def finders(config: dict | None = None) -> list[FinderInfo]:
    """List registered finders under the active configuration."""
    settings = _configure(config)
    return [
        FinderInfo(
            spec.name,
            spec.description,
            spec.scope,
            spec.kind,
            spec.default_enabled,
            spec.needs_content,
            is_enabled(settings, spec.name, spec.default_enabled),
        )
        for spec in get_finders()
    ]


def _pick_export_artifact(artifacts: list[Any]) -> Any:
    return next((artifact for artifact in artifacts if artifact.filetype == "sdist"), artifacts[0])


def _open_archive(artifact: Any):
    try:
        return artifact.open_local()
    except ValueError:
        return artifact.open_sdist_remote() if artifact.filetype == "sdist" else artifact.open_zip_remote()


def _common_top_level(names: list[str]) -> str | None:
    tops = {name.split("/", 1)[0] for name in names if name.strip("/")}
    return next(iter(tops)) if len(tops) == 1 else None


def _safe_member_target(dest: Path, name: str) -> Path:
    resolved = dest.resolve()
    target = (dest / name).resolve()
    if target != resolved and resolved not in target.parents:
        raise ValueError(f"unsafe path in archive member: {name}")
    return target


def _extract_artifact(artifact: Any, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    archive = _open_archive(artifact)
    try:
        if isinstance(archive, tarfile.TarFile):
            members = archive.getmembers()
            top = _common_top_level([member.name for member in members])
            if top is not None:
                prefix = top + "/"
                for member in members:
                    member.name = member.name[len(prefix):] if member.name.startswith(prefix) else ""
                members = [member for member in members if member.name]
            archive.extractall(dest, members=members, filter="data")
            return
        names = archive.namelist()
        top = _common_top_level(names)
        prefix = top + "/" if top is not None else ""
        for info in archive.infolist():
            relative = info.filename[len(prefix):] if info.filename.startswith(prefix) else info.filename
            if not relative:
                continue
            target = _safe_member_target(dest, relative)
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info) as source, target.open("wb") as destination:
                    destination.write(source.read())
    finally:
        archive.close()


@keke.ktrace("package", "other")
def export(
    package: str,
    other: str | None = None,
    *,
    stable_version: str | None = None,
    new_version: str | None = None,
    cutoff_hours: int = 24,
    last_two: bool = False,
    last: bool = False,
    output: str | Path | None = None,
    save_dir: str | None = None,
    config: dict | None = None,
) -> ExportResult:
    """Extract two artifacts and write the prompt used for offline review."""
    _configure(config)
    old_path = Path(package)
    new_path = Path(other) if other else None
    target = Path(output) if output else Path(f"brumby-export-{old_path.stem}")
    if old_path.is_file() and new_path is not None and new_path.is_file():
        old_artifact = make_local_artifact(old_path)
        new_artifact = make_local_artifact(new_path)
        old_ref, new_ref = ReleaseRef(str(old_path)), ReleaseRef(str(new_path))
    else:
        _validate_versions(stable_version, new_version)
        pkg_info = get_package_info(package)
        stable, new = resolve_versions(
            package,
            cutoff_hours=cutoff_hours,
            stable_version=stable_version,
            new_version=new_version,
            last_two=last_two,
            last=last,
            pkg_info=pkg_info,
        )
        if not stable:
            raise ValueError(f"No previous version found for {package}")
        if not new or stable == new:
            raise ValueError(f"Only one version found for {package}")
        old_artifact = _pick_export_artifact(
            get_artifacts(package, stable, pkg_info=pkg_info, save_dir=save_dir)
        )
        new_artifact = _pick_export_artifact(
            get_artifacts(package, new, pkg_info=pkg_info, save_dir=save_dir)
        )
        old_ref = ReleaseRef(f"{package} {stable}", stable, release_upload_bounds(pkg_info, stable))
        new_ref = ReleaseRef(f"{package} {new}", new, release_upload_bounds(pkg_info, new))

    old_dir, new_dir = target / "old", target / "new"
    _extract_artifact(old_artifact, old_dir)
    _extract_artifact(new_artifact, new_dir)
    prompt = target / "PROMPT.md"
    prompt.write_text(_EXPORT_PROMPT.format(old=old_ref.label, new=new_ref.label))
    return ExportResult(target, old_ref, new_ref, old_dir, new_dir, prompt)


__all__ = [
    "AssessResult",
    "CheckResult",
    "Difference",
    "ExportResult",
    "FinderInfo",
    "Finding",
    "InspectResult",
    "ReleaseRef",
    "Risk",
    "ScanSkipped",
    "SourceKind",
    "assess",
    "check",
    "classify_diffs",
    "classify_findings",
    "export",
    "finders",
    "inspect",
]
