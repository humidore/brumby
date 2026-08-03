import datetime

from . import finders as _finders_pkg  # ensures all finders are registered
from .artifact import Artifact, ArtifactView, make_artifact
from .compare import DiffCallback, compare_releases
from .config import get_settings, is_enabled, load_config
from .finding import Finding
from .pypi import (
    find_stable_before,
    find_versions,
    get_package_info,
    get_release_files,
    uploaded_versions,
)
from .registry import get_finders

_MAX_SCAN_BYTES = 300 * 1024 * 1024


class ScanSkipped(RuntimeError):
    """Raised when a release is too large to scan safely."""


def _wheel_platform_tag(filename: str) -> str | None:
    parts = filename[:-4].rsplit("-", 4)
    if len(parts) != 5:
        return None
    return parts[4]


def _wheel_os_bucket(filename: str) -> str | None:
    platform = _wheel_platform_tag(filename)
    if platform is None:
        return None
    if platform == "any":
        return "any"
    if "linux" in platform or "musllinux" in platform:
        return "linux"
    if platform.startswith(("macosx", "macos", "darwin")):
        return "mac"
    if platform.startswith("win"):
        return "windows"
    return platform


def _python_tag_score(py_tag: str) -> int:
    best = -1
    for tag in py_tag.split("."):
        if tag.startswith(("cp", "pp", "py")) and tag[2:].isdigit():
            best = max(best, int(tag[2:]))
    return best


def _python_tag_family_score(py_tag: str) -> int:
    if py_tag.startswith("cp"):
        return 2
    if py_tag.startswith("pp"):
        return 1
    return 0


def _wheel_arch_score(platform: str) -> int:
    if any(tag in platform for tag in ("aarch64", "arm64")):
        return 2
    if any(tag in platform for tag in ("x86_64", "amd64")):
        return 1
    return 0


def _wheel_scan_score(artifact: Artifact) -> tuple[int, int, int, str]:
    parts = artifact.filename[:-4].rsplit("-", 4)
    if len(parts) != 5:
        return (-1, -1, -1, artifact.filename)
    platform = parts[4]
    python_family = _python_tag_family_score(parts[2])
    arch_preference = _wheel_arch_score(platform)
    linux_preference = 1 if platform.startswith("manylinux") else 0
    return (_python_tag_score(parts[2]), python_family, arch_preference, linux_preference, artifact.filename)


def prepare_scan_artifacts(artifacts: list[Artifact]) -> list[Artifact]:
    """Keep at most one wheel per OS family and reject releases that remain too large."""
    selected: list[tuple[int, Artifact]] = []
    best_wheels: dict[str, tuple[int, Artifact]] = {}

    for idx, artifact in enumerate(artifacts):
        if artifact.filetype != "wheel":
            selected.append((idx, artifact))
            continue
        bucket = _wheel_os_bucket(artifact.filename)
        if bucket is None:
            selected.append((idx, artifact))
            continue
        current = best_wheels.get(bucket)
        candidate = (idx, artifact)
        if current is None or _wheel_scan_score(artifact) > _wheel_scan_score(current[1]):
            best_wheels[bucket] = candidate

    selected.extend(best_wheels.values())
    scan_artifacts = [artifact for _idx, artifact in sorted(selected, key=lambda item: item[0])]
    total_size = sum(artifact.size for artifact in scan_artifacts)
    if total_size > _MAX_SCAN_BYTES:
        raise ScanSkipped(f"did not scan: selected artifacts total {total_size} bytes")
    return scan_artifacts


def get_artifacts(
    package: str,
    version: str,
    pkg_info: dict | None = None,
    save_dir: str | None = None,
) -> list[Artifact]:
    if pkg_info is not None:
        artifacts = [make_artifact(f) for f in pkg_info.get("releases", {}).get(version, [])]
    else:
        artifacts = [make_artifact(f) for f in get_release_files(package, version)]
    artifacts = prepare_scan_artifacts(artifacts)
    if save_dir:
        from pathlib import Path
        target = Path(save_dir) / package / version
        if pkg_info is not None:
            save_release_info(save_dir, package, version, pkg_info)
        for artifact in artifacts:
            artifact.save_local(target)
    return artifacts


def save_release_info(
    save_dir: str,
    package: str,
    version: str,
    pkg_info: dict,
) -> None:
    from pathlib import Path
    import json

    target = Path(save_dir) / package / version
    target.mkdir(parents=True, exist_ok=True)
    (target / f"{version}.json").write_text(json.dumps(pkg_info, indent=2, sort_keys=True) + "\n")


def _kinds_map() -> dict[str, str]:
    return {s.name: s.kind for s in get_finders()}


def analyze_artifacts(
    artifacts: list[Artifact],
    config: dict,
    content: bool = True,
) -> list[Finding]:
    artifacts = prepare_scan_artifacts(artifacts)
    findings: list[Finding] = []
    artifact_specs = [
        s for s in get_finders(scope="artifact")
        if is_enabled(config, s.name, s.default_enabled)
        and (content or not s.needs_content)
    ]

    views = [ArtifactView(a) for a in artifacts]
    try:
        for view in views:
            for spec in artifact_specs:
                try:
                    findings.extend(spec.fn(view, get_settings(config, spec.name)))
                except Exception:
                    pass
    finally:
        for v in views:
            v.close()

    return findings


def resolve_versions(
    package: str,
    cutoff_hours: int = 24,
    stable_version: str | None = None,
    new_version: str | None = None,
    last_two: bool = False,
    last: bool = False,
    pkg_info: dict | None = None,
) -> tuple[str | None, str | None]:
    if stable_version is not None and new_version is not None:
        return stable_version, new_version

    if pkg_info is None:
        pkg_info = get_package_info(package)

    if new_version is not None:
        # An explicitly chosen new version anchors the baseline on its own upload
        # time, so the stable side can never end up newer than the new side.
        found_stable = find_stable_before(
            package,
            new_version,
            cutoff_hours,
            info=pkg_info,
            use_cutoff=not last_two,
        )
        return found_stable, new_version

    if last:
        found_stable, found_new = find_last_with_cutoff(package, cutoff_hours, pkg_info)
    elif last_two:
        found_stable, found_new = find_last_two_versions(package, pkg_info)
    else:
        found_stable, found_new = find_versions(package, cutoff_hours, info=pkg_info)

    return stable_version or found_stable, new_version or found_new


def _release_days(pkg_info: dict) -> set[datetime.date]:
    return {upload_time.date() for upload_time, _version in uploaded_versions(pkg_info)}


def select_assess_mode(
    package: str,
    cutoff_hours: int = 24,
    pkg_info: dict | None = None,
    stable_version: str | None = None,
    new_version: str | None = None,
) -> tuple[str, str | None, str | None]:
    """Pick the assess mode and target versions for a package.

    Returns (mode, stable_version, new_version).
    mode is one of: "check", "check-last", "inspect", "first-release".

    Supplying stable_version and/or new_version skips auto-detection and uses those
    versions directly, falling back to "inspect" when they yield no distinct baseline.
    """
    if pkg_info is None:
        pkg_info = get_package_info(package)

    versioned = uploaded_versions(pkg_info)
    if len(versioned) == 1:
        # A package's first-ever release has nothing to diff against, so it is
        # unvetted by definition regardless of what the finders would report.
        return "first-release", None, versioned[0][1]

    if stable_version or new_version:
        stable, new = resolve_versions(
            package,
            cutoff_hours=cutoff_hours,
            stable_version=stable_version,
            new_version=new_version,
            pkg_info=pkg_info,
        )
        if stable and new and stable != new:
            return "check", stable, new
        return "inspect", None, new or stable

    stable, new = resolve_versions(package, cutoff_hours=cutoff_hours, pkg_info=pkg_info)
    initial_latest = stable
    if stable and new and stable != new:
        return "check", stable, new

    if len(_release_days(pkg_info)) >= 2:
        stable, new = resolve_versions(package, cutoff_hours=cutoff_hours, last=True, pkg_info=pkg_info)
        if stable and new and stable != new:
            return "check-last", stable, new

    latest = pkg_info.get("info", {}).get("version") or initial_latest
    return "inspect", None, latest


def analyze_release(
    artifacts: list[Artifact],
    pkg_info: dict,
    version: str,
    config: dict,
    content: bool = True,
) -> list[Finding]:
    """Run all enabled finders against a release and return findings."""
    scan_artifacts = prepare_scan_artifacts(artifacts)
    findings = analyze_artifacts(scan_artifacts, config, content=content)

    for spec in get_finders(scope="metadata"):
        if not is_enabled(config, spec.name, spec.default_enabled):
            continue
        try:
            findings.extend(spec.fn(pkg_info, version, get_settings(config, spec.name)))
        except Exception:
            pass

    release_specs = [
        s for s in get_finders(scope="release")
        if is_enabled(config, s.name, s.default_enabled)
    ]
    views = [ArtifactView(a) for a in scan_artifacts]
    try:
        for spec in release_specs:
            try:
                findings.extend(spec.fn(views, get_settings(config, spec.name)))
            except Exception:
                pass
    finally:
        for v in views:
            v.close()

    return findings


def check_artifacts(
    old_artifacts: list[Artifact],
    new_artifacts: list[Artifact],
    *,
    old_label: str,
    new_label: str,
    callback: DiffCallback | None = None,
    config: dict | None = None,
    content: bool = True,
) -> tuple[list[Finding], list[Finding], list[tuple]]:
    """Compare two arbitrary artifact sets without any PyPI metadata."""
    if config is None:
        config = load_config()

    old_findings = analyze_artifacts(old_artifacts, config, content=content)
    new_findings = analyze_artifacts(new_artifacts, config, content=content)

    diffs: list[tuple] = []
    if callback:
        diffs = compare_releases(
            old_label,
            old_label,
            old_findings,
            new_label,
            new_findings,
            callback,
            kinds=_kinds_map(),
        )
    return old_findings, new_findings, diffs


def find_last_two_versions(
    package: str, pkg_info: dict | None = None
) -> tuple[str | None, str | None]:
    """Return the two most recently uploaded versions regardless of age."""
    if pkg_info is None:
        pkg_info = get_package_info(package)
    versioned = uploaded_versions(pkg_info)
    if len(versioned) < 2:
        return (versioned[0][1] if versioned else None), None
    return versioned[1][1], versioned[0][1]  # (older, newer)


def find_last_with_cutoff(
    package: str, cutoff_hours: int = 24, pkg_info: dict | None = None
) -> tuple[str | None, str | None]:
    """Return newest version and the newest version at least cutoff_hours older.

    The older target is chosen by upload time, not by version ordering, so it can
    be numerically newer than the latest release if the project's version scheme
    is not chronological.
    """
    if pkg_info is None:
        pkg_info = get_package_info(package)

    versioned = uploaded_versions(pkg_info)
    if not versioned:
        return None, None

    newest_time, newest_version = versioned[0]
    cutoff = newest_time - datetime.timedelta(hours=cutoff_hours)
    older = [item for item in versioned[1:] if item[0] <= cutoff]
    if not older:
        return None, newest_version
    return older[0][1], newest_version


def check_package(
    package: str,
    *,
    cutoff_hours: int = 24,
    stable_version: str | None = None,
    new_version: str | None = None,
    callback: DiffCallback | None = None,
    config: dict | None = None,
    content: bool = True,
    last_two: bool = False,
    last: bool = False,
    pkg_info: dict | None = None,
    save_dir: str | None = None,
) -> tuple[list[Finding], list[Finding], list[tuple]]:
    """Return (stable_findings, new_findings, diffs).

    Versions are auto-detected from PyPI if not provided.
    last_two=True: compare the two most recent releases regardless of age.
    content=False: skip finders that read archive file content.
    callback fires for each finding that differs between the two releases.
    """
    if config is None:
        config = load_config()

    if pkg_info is None:
        pkg_info = get_package_info(package)

    stable_version, new_version = resolve_versions(
        package,
        cutoff_hours=cutoff_hours,
        stable_version=stable_version,
        new_version=new_version,
        last_two=last_two,
        last=last,
        pkg_info=pkg_info,
    )

    if not stable_version:
        raise ValueError(f"No previous version found for {package}")
    if not new_version:
        raise ValueError(f"Only one version found for {package}")
    if stable_version == new_version:
        raise ValueError(f"Only one version found for {package}")

    stable_artifacts = get_artifacts(package, stable_version, pkg_info=pkg_info, save_dir=save_dir)
    new_artifacts = get_artifacts(package, new_version, pkg_info=pkg_info, save_dir=save_dir)

    stable_findings = analyze_release(stable_artifacts, pkg_info, stable_version, config, content)
    new_findings = analyze_release(new_artifacts, pkg_info, new_version, config, content)

    diffs: list[tuple] = []
    if callback:
        diffs = compare_releases(
            package, stable_version, stable_findings,
            new_version, new_findings,
            callback, kinds=_kinds_map(),
        )

    for spec in get_finders(scope="comparison"):
        if not is_enabled(config, spec.name, spec.default_enabled):
            continue
        try:
            results = spec.fn(
                package, stable_version, stable_artifacts,
                new_version, new_artifacts,
                get_settings(config, spec.name),
            )
            for name, old_val, new_val in results:
                old_set = frozenset({old_val} if old_val is not None else set())
                new_set = frozenset({new_val} if new_val is not None else set())
                kind = _kinds_map().get(name, "informational")
                if callback:
                    callback(
                        package,
                        stable_version,
                        new_version,
                        name,
                        None,
                        old_set,
                        new_set,
                        frozenset(),
                        frozenset(),
                        kind,
                    )
                diffs.append((name, None, old_set, new_set, frozenset(), frozenset(), kind))
        except Exception:
            pass

    return stable_findings, new_findings, diffs
