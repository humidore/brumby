import datetime
from typing import Any

import requests

_PYPI_BASE = "https://pypi.org/pypi"


def get_package_info(package: str) -> dict[str, Any]:
    resp = requests.get(f"{_PYPI_BASE}/{package}/json", timeout=30)
    resp.raise_for_status()
    return resp.json()


def get_release_files(package: str, version: str) -> list[dict[str, Any]]:
    resp = requests.get(f"{_PYPI_BASE}/{package}/{version}/json", timeout=30)
    resp.raise_for_status()
    return resp.json()["urls"]


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


def get_latest_version(package: str) -> str:
    info = get_package_info(package)
    return info["info"]["version"]
