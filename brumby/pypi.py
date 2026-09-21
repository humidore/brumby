import datetime
import logging
from functools import lru_cache
from typing import Any

import keke
import requests
from packaging.version import InvalidVersion, Version
from requests.adapters import HTTPAdapter, Retry

from . import network

_PYPI_BASE = "https://pypi.org/pypi"

# PyPI briefly caches the 404 for a version that has only just been published, so
# treat 404 as retryable when reading a single release. Exhausting these retries
# surfaces as requests.exceptions.RetryError rather than an HTTPError.
_RELEASE_RETRY = Retry(
    total=3,
    status_forcelist=(404, 413, 429, 502, 503),
    backoff_factor=0.5,
    allowed_methods=("GET",),
)

log = logging.getLogger(__name__)

@lru_cache(maxsize=1)
def _retrying_session() -> requests.Session:
    """A session that retries PyPI's briefly-cached 404s and sets a User-Agent."""
    session = requests.Session()
    session.headers["User-Agent"] = "brumby (https://github.com/humidore/brumby/)"
    session.mount(_PYPI_BASE, HTTPAdapter(max_retries=_RELEASE_RETRY))
    return session


def validate_project_name(project: str) -> str:
    """Reject requirement specifiers where a bare project name is required."""
    if "==" in project:
        raise ValueError(f"invalid project name: {project!r}")
    return project


def validate_version(version: str) -> str:
    """Return version unchanged if it is a valid PEP 440 version.

    Raises ValueError with a readable message otherwise, so callers can surface
    it to the user.
    """
    try:
        Version(version)
    except InvalidVersion:
        raise ValueError(f"invalid version: {version!r}") from None
    return version


@keke.ktrace("package")
def get_package_info(package: str) -> dict[str, Any]:
    validate_project_name(package)
    url, proxies = network.prepare_request("metadata", f"{_PYPI_BASE}/{package}/json")
    resp = requests.get(url, timeout=30, proxies=proxies)
    resp.raise_for_status()
    return resp.json()


@keke.ktrace("package", "version")
def get_release_files(
    package: str, version: str, session: requests.Session | None = None
) -> list[dict[str, Any]]:
    if session is None:
        session = _retrying_session()
    validate_project_name(package)
    url, proxies = network.prepare_request("metadata", f"{_PYPI_BASE}/{package}/{version}/json")
    resp = session.get(url, timeout=30, proxies=proxies)
    resp.raise_for_status()
    return resp.json()["urls"]


def ensure_release(pkg_info: dict[str, Any], package: str, version: str) -> bool:
    """Make sure a release is present in pkg_info, fetching it if it is not.

    ``/pypi/<pkg>/json`` is cached separately from ``/pypi/<pkg>/<version>/json``,
    and the latter has no cached copy predating a release, so a version the project
    index has not caught up to yet can usually be read from its own endpoint.
    Returns True once the release is present, False when the version has no files.
    """
    releases = pkg_info.setdefault("releases", {})
    if releases.get(version):
        return True

    try:
        with _retrying_session() as session:
            files = get_release_files(package, version, session=session)
    except requests.exceptions.RetryError:
        return False
    except requests.HTTPError as e:
        if getattr(e.response, "status_code", None) != 404:
            raise
        return False

    releases[version] = files
    log.info(
        "%s %s absent from the project index, read from its own endpoint instead",
        package,
        version,
    )
    return True


def find_versions(
    package: str, cutoff_hours: int = 24, info: dict[str, Any] | None = None
) -> tuple[str | None, str | None]:
    """Return (stable_version, new_version).

    stable: most recent version uploaded more than cutoff_hours ago.
    new: most recent version uploaded within the last cutoff_hours.
    """
    if info is None:
        info = get_package_info(package)
    cutoff = datetime.datetime.now(tz=datetime.timezone.utc) - datetime.timedelta(
        hours=cutoff_hours
    )

    stable_candidates: list[tuple[datetime.datetime, str]] = []
    new_candidates: list[tuple[datetime.datetime, str]] = []

    for version, files in info["releases"].items():
        if not files:
            continue
        upload_times = [
            datetime.datetime.fromisoformat(f["upload_time_iso_8601"]) for f in files
        ]
        latest = max(upload_times)
        if latest < cutoff:
            stable_candidates.append((latest, version))
        else:
            new_candidates.append((latest, version))

    stable_candidates.sort(reverse=True)
    new_candidates.sort(reverse=True)

    stable = stable_candidates[0][1] if stable_candidates else None
    new = new_candidates[0][1] if new_candidates else None
    return stable, new


def release_upload_bounds(
    info: dict[str, Any], version: str
) -> tuple[datetime.datetime | None, datetime.datetime | None]:
    files = info.get("releases", {}).get(version, [])
    times = [
        datetime.datetime.fromisoformat(f["upload_time_iso_8601"])
        for f in files
        if f.get("upload_time_iso_8601")
    ]
    if not times:
        return None, None
    return min(times), max(times)


def uploaded_versions(info: dict[str, Any]) -> list[tuple[datetime.datetime, str]]:
    """Return (latest_upload_time, version) for every release with files, newest first."""
    versioned: list[tuple[datetime.datetime, str]] = []
    for version in info.get("releases", {}):
        newest = release_upload_bounds(info, version)[1]
        if newest is not None:
            versioned.append((newest, version))
    versioned.sort(reverse=True)
    return versioned


def find_stable_before(
    package: str,
    new_version: str,
    cutoff_hours: int = 24,
    info: dict[str, Any] | None = None,
    use_cutoff: bool = True,
) -> str | None:
    """Return the stable baseline to compare an explicitly chosen new_version against.

    The cutoff is anchored on new_version's own upload time rather than the current
    time. Candidates must both predate new_version's upload and be older according
    to PEP 440, which excludes releases from a newer maintenance branch that happened
    to be uploaded first.
    """
    if info is None:
        info = get_package_info(package)

    if new_version not in info.get("releases", {}):
        raise ValueError(f"version {new_version} not found for {package}")
    versioned = uploaded_versions(info)
    anchor = next((time for time, version in versioned if version == new_version), None)
    if anchor is None:
        raise ValueError(f"version {new_version} has no files for {package}")

    parsed_new_version = Version(new_version)
    older = []
    for item in versioned:
        upload_time, version = item
        try:
            is_older_version = Version(version) < parsed_new_version
        except InvalidVersion:
            is_older_version = False
        if upload_time < anchor and is_older_version:
            older.append(item)
    if not older:
        return None
    if use_cutoff:
        cutoff = anchor - datetime.timedelta(hours=cutoff_hours)
        old_enough = [item for item in older if item[0] <= cutoff]
        if old_enough:
            return old_enough[0][1]
    return older[0][1]


def get_latest_version(package: str) -> str:
    info = get_package_info(package)
    return info["info"]["version"]
