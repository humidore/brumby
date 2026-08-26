"""Finders that use PyPI JSON metadata or cheap zip header fields."""

import datetime
import tarfile
import zipfile
from typing import Any

from ..artifact import ArtifactView
from ..finding import Finding
from ..registry import register

_ZIP_SYSTEMS = {0: "windows", 3: "unix", 7: "macvms", 10: "windows_ntfs", 19: "darwin"}


def _parse_rfc822(content: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in content.splitlines():
        if ": " in line:
            key, _, value = line.partition(": ")
            result[key.strip()] = value.strip()
    return result


def _parse_zip_uid(extra: bytes) -> int | None:
    i = 0
    while i + 4 <= len(extra):
        tag = int.from_bytes(extra[i : i + 2], "little")
        size = int.from_bytes(extra[i + 2 : i + 4], "little")
        data = extra[i + 4 : i + 4 + size]
        i += 4 + size
        if tag == 0x7875 and len(data) >= 3 and data[0] == 1:  # Info-ZIP New Unix
            uid_size = data[1]
            if 2 + uid_size <= len(data):
                return int.from_bytes(data[2 : 2 + uid_size], "little")
        elif tag == 0x5855 and len(data) >= 10:  # Info-ZIP Unix (old)
            return int.from_bytes(data[8:10], "little")
    return None


@register(
    "platform_wheels",
    "Release has at least one platform wheel",
    kind="informational",
    scope="release",
)
def find_platform_wheels(views: list[ArtifactView], cfg: dict) -> list[Finding]:
    saw_wheel = False
    saw_platform = False
    for view in views:
        if view.filetype != "wheel":
            continue
        saw_wheel = True
        parts = view.filename[:-4].rsplit("-", 4)
        if len(parts) == 5 and parts[4] != "any":
            saw_platform = True
            break
    if not saw_wheel:
        return []
    if not saw_platform:
        return []
    return [Finding("platform_wheels", True, None, "wheel")]


@register(
    "wheel_generator",
    "Build tool name and version from WHEEL metadata",
    kind="informational",
    needs_content=True,
)
def find_wheel_generator(view: ArtifactView, cfg: dict) -> list[Finding]:
    if view.filetype != "wheel":
        return []
    try:
        wheel_path = next(
            (i.filename for i in view.infos() if i.filename.endswith(".dist-info/WHEEL")),
            None,
        )
        if not wheel_path:
            return []
        meta = _parse_rfc822(view.read_member(wheel_path).decode())
        if generator := meta.get("Generator"):
            return [Finding("generator", generator, view.filename, view.resource)]
    except Exception:
        pass
    return []


@register(
    "packager_uid",
    "UID (and username if available) of the build user, from zip extra fields or tar headers",
    kind="informational",
)
def find_packager_uid(view: ArtifactView, cfg: dict) -> list[Finding]:
    if view.filetype == "wheel":
        try:
            for info in view.infos():
                if info.extra:
                    uid = _parse_zip_uid(info.extra)
                    if uid is not None:
                        return [Finding("packager_uid", uid, view.filename, view.resource)]
        except Exception:
            pass
    elif view.filetype == "sdist":
        # tar headers carry both numeric uid and the username string
        try:
            with view.artifact.open_tar() as tf:
                for member in tf.getmembers():
                    uid = member.uid
                    uname = member.uname  # empty string if not stored
                    if uid or uname:
                        value = f"{uid}/{uname}" if uname else str(uid)
                        return [Finding("packager_uid", value, view.filename, view.resource)]
        except Exception:
            pass
    return []


@register(
    "packaged_on",
    "Host OS detected from zip create_system field",
    kind="informational",
)
def find_packaged_on(view: ArtifactView, cfg: dict) -> list[Finding]:
    if view.filetype != "wheel":
        return []
    try:
        infos = view.infos()
        if infos:
            system = infos[0].create_system
            return [Finding("packaged_on", _ZIP_SYSTEMS.get(system, str(system)), view.filename, view.resource)]
    except Exception:
        pass
    return []


def _parse_upload_time(upload_time: str) -> datetime.datetime | None:
    if not upload_time:
        return None
    try:
        dt = datetime.datetime.fromisoformat(upload_time)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone(datetime.timezone.utc).replace(tzinfo=None)


def _nearest_hour_offset(delta: datetime.timedelta, tolerance_minutes: int) -> int | None:
    seconds = delta.total_seconds()
    hours = round(seconds / 3600)
    if hours == 0:
        return None
    if abs(hours) > 12:
        return None
    if abs(seconds - (hours * 3600)) > tolerance_minutes * 60:
        return None
    return int(hours)


def _metadata_timestamp(view: ArtifactView) -> tuple[datetime.datetime, str] | None:
    if view.filetype == "wheel":
        try:
            for info in view.infos():
                if info.filename.endswith(".dist-info/METADATA"):
                    return datetime.datetime(*info.date_time), info.filename
        except Exception:
            return None
    elif view.filetype == "sdist":
        try:
            opener = (
                view.artifact.open_local()
                if view.artifact._local_path is not None
                else view.artifact.open_sdist_remote()
            )
            with opener as arc:
                if isinstance(arc, zipfile.ZipFile):
                    for info in arc.infolist():
                        if info.filename.endswith("PKG-INFO"):
                            return datetime.datetime(*info.date_time), info.filename
                elif isinstance(arc, tarfile.TarFile):
                    for member in arc.getmembers():
                        if member.isfile() and member.name.endswith("PKG-INFO"):
                            return (
                                datetime.datetime.fromtimestamp(member.mtime, tz=datetime.timezone.utc)
                                .replace(tzinfo=None),
                                member.name,
                            )
        except Exception:
            return None
    return None


@register(
    "packager_timezone",
    "Metadata file timestamp is close to an hour offset from upload time",
    kind="informational",
    needs_content=True,
)
def find_packager_timezone(view: ArtifactView, cfg: dict) -> list[Finding]:
    upload_time = _parse_upload_time(view.artifact.upload_time)
    if upload_time is None:
        return []
    meta = _metadata_timestamp(view)
    if meta is None:
        return []
    meta_time, _member = meta
    tolerance_minutes = cfg.get("tolerance_minutes", 2)
    offset_hours = _nearest_hour_offset(meta_time - upload_time, tolerance_minutes)
    if offset_hours is None:
        return []
    return [Finding("packager_timezone", f"{offset_hours:+d}h", view.filename, view.resource)]


@register(
    "metadata_version",
    "Core package metadata version from METADATA or PKG-INFO",
    kind="informational",
    needs_content=True,
)
def find_metadata_version(view: ArtifactView, cfg: dict) -> list[Finding]:
    if view.filetype == "wheel":
        candidate_names = (
            i.filename for i in view.infos() if i.filename.endswith(".dist-info/METADATA")
        )
    elif view.filetype == "sdist":
        candidate_names = ("PKG-INFO",)
    else:
        return []

    for name in candidate_names:
        try:
            content = view.read_member(name).decode(errors="replace")
        except Exception:
            continue
        for line in content.splitlines():
            if line.startswith("Metadata-Version:"):
                _, _, value = line.partition(":")
                return [Finding("metadata_version", value.strip(), view.filename, view.resource)]
    return []


@register(
    "giant_version",
    "Version major component exceeds threshold",
    kind="sketchy",
    scope="metadata",
)
def find_giant_version(info: dict, version: str, cfg: dict) -> list[Finding]:
    """Value is the major version number.

    A constant True value only ever fires once, at the release that first
    crosses the threshold -- once a project is on major 6, going to major 7
    or 8 shows old_vals=new_vals={True} to compare_releases, so the sketchy
    diff (which only fires on new_vals - old_vals) stays silent for every
    later jump forever. Reporting the actual major number means each new
    major crossing is itself a new value and fires again, while an ordinary
    same-major bump (8.1.8 -> 8.2.0) still produces old_vals == new_vals and
    stays silent.

    A CalVer major (a plausible year like "2024" or "2025") is the one case
    where reporting the literal number backfires: it would make every single
    year rollover look like a fresh "giant version" event forever, for a
    project where jumping the major every year is the intended, unremarkable
    versioning scheme -- not a sudden unexplained jump. Collapse any
    year-shaped major to the constant "20xx" instead, so CalVer projects
    still fire once (crossing the threshold at all is still worth a look)
    without re-firing on every year boundary.
    """
    threshold = cfg.get("threshold", 5)
    try:
        major_str = version.lstrip("v").split(".")[0]
        major = int(major_str)
        if major > threshold:
            if len(major_str) == 4 and major_str[:2] in ("19", "20"):
                return [Finding("giant_version", "20xx", None, "release")]
            return [Finding("giant_version", major, None, "release")]
    except (ValueError, IndexError):
        pass
    return []


@register(
    "protonmail_account",
    "Maintainer or author email uses protonmail/pm.me",
    kind="sketchy",
    scope="metadata",
)
def find_protonmail(info: dict, version: str, cfg: dict) -> list[Finding]:
    pkg_info = info.get("info", {})
    domains = cfg.get("domains", ["protonmail.com", "pm.me"])
    for field in ("author_email", "maintainer_email"):
        email = pkg_info.get(field) or ""
        for domain in domains:
            if f"@{domain}" in email.lower():
                return [Finding("protonmail_account", email, None, "release")]
    return []
