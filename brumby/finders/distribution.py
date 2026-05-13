"""Release-level finders: sdist/wheel presence, back-to-back releases."""

import datetime

from ..artifact import Artifact, ArtifactView
from ..finding import Finding
from ..registry import register


@register(
    "sdist_only",
    "Release has only a source distribution, no wheels (CI pipeline may have been bypassed)",
    kind="sketchy",
    scope="release",
)
def find_sdist_only(views: list[ArtifactView], cfg: dict) -> list[Finding]:
    has_wheel = any(v.filetype == "wheel" for v in views)
    has_sdist = any(v.filetype == "sdist" for v in views)
    findings = []
    if has_sdist and not has_wheel:
        findings.append(Finding("sdist_only", True, None))
    if has_wheel and not has_sdist:
        findings.append(Finding("no_sdist", True, None))
    return findings


def _sdist_wheel_times(
    views: list[ArtifactView],
) -> tuple[list[datetime.datetime], list[datetime.datetime]]:
    """Return (sdist_upload_times, wheel_upload_times) parsed from artifact metadata."""
    sdist_times, wheel_times = [], []
    for v in views:
        t = v.artifact.upload_time
        if not t:
            continue
        dt = datetime.datetime.fromisoformat(t)
        if v.filetype == "sdist":
            sdist_times.append(dt)
        elif v.filetype == "wheel":
            wheel_times.append(dt)
    return sdist_times, wheel_times


@register(
    "wheel_uploaded_before_sdist",
    "A wheel was uploaded before the sdist in the same release (unusual upload ordering)",
    kind="sketchy",
    scope="release",
)
def find_wheel_before_sdist(views: list[ArtifactView], cfg: dict) -> list[Finding]:
    grace_seconds = cfg.get("grace_minutes", 2) * 60
    try:
        sdist_times, wheel_times = _sdist_wheel_times(views)
        if not sdist_times or not wheel_times:
            return []
        earliest_sdist = min(sdist_times)
        earliest_wheel = min(wheel_times)
        gap_s = (earliest_sdist - earliest_wheel).total_seconds()
        if gap_s > grace_seconds:
            return [Finding("wheel_uploaded_before_sdist", f"{gap_s / 3600:.2f}h", None)]
    except Exception:
        pass
    return []


@register(
    "wheel_uploaded_late_after_sdist",
    "A wheel was uploaded more than threshold hours after the sdist (wheel added to existing release)",
    kind="sketchy",
    scope="release",
)
def find_wheel_late_after_sdist(views: list[ArtifactView], cfg: dict) -> list[Finding]:
    threshold_hours = cfg.get("threshold_hours", 1.0)
    try:
        sdist_times, wheel_times = _sdist_wheel_times(views)
        if not sdist_times or not wheel_times:
            return []
        earliest_sdist = min(sdist_times)
        latest_wheel = max(wheel_times)
        gap_h = (latest_wheel - earliest_sdist).total_seconds() / 3600
        if gap_h > threshold_hours:
            return [Finding("wheel_uploaded_late_after_sdist", f"{gap_h:.1f}h", None)]
    except Exception:
        pass
    return []


@register(
    "back_to_back_releases",
    "New release was uploaded less than threshold hours after stable",
    kind="sketchy",
    scope="comparison",
)
def find_back_to_back(
    pkg: str,
    old_ver: str,
    old_artifacts: list[Artifact],
    new_ver: str,
    new_artifacts: list[Artifact],
    cfg: dict,
) -> list[tuple[str, object, object]]:
    threshold_hours = cfg.get("threshold_hours", 1.0)
    if not old_artifacts or not new_artifacts:
        return []
    try:
        old_time = max(
            datetime.datetime.fromisoformat(a.upload_time)
            for a in old_artifacts
            if a.upload_time
        )
        new_time = max(
            datetime.datetime.fromisoformat(a.upload_time)
            for a in new_artifacts
            if a.upload_time
        )
        gap_hours = (new_time - old_time).total_seconds() / 3600
        if gap_hours < threshold_hours:
            label = f"{gap_hours:.2f}h between {old_ver} and {new_ver}"
            return [("back_to_back_releases", None, label)]
    except Exception:
        pass
    return []
