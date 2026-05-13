"""Archive structure finders — use only the zip central directory (no content reads)."""

import datetime
import stat

from ..artifact import ArtifactView
from ..finding import Finding
from ..registry import register


def _is_round_timestamp(dt: tuple[int, int, int, int, int, int]) -> bool:
    return dt[3:] == (0, 0, 0) and (dt[1], dt[2]) in {(1, 1), (2, 2)}


def _zipinfo_perms(info) -> int | None:
    if info.create_system != 3:
        return None

    mode = info.external_attr >> 16
    perms = mode & 0o777
    if stat.S_ISDIR(mode) or info.filename.endswith("/"):
        return perms
    elif stat.S_ISREG(mode):
        return perms
    else:
        return None


def _top_level_names(view: ArtifactView) -> list[str]:
    infos = view.infos()

    top_txt = next(
        (i.filename for i in infos if i.filename.endswith(".dist-info/top_level.txt")),
        None,
    )
    if top_txt:
        try:
            return [
                line.strip()
                for line in view.read_member(top_txt).decode().splitlines()
                if line.strip()
            ]
        except Exception:
            return []

    tops: set[str] = set()
    for info in infos:
        parts = info.filename.split("/")
        if (
            len(parts) > 1
            and not parts[0].endswith(".dist-info")
            and not parts[0].endswith(".data")
        ):
            tops.add(parts[0])
    return sorted(tops)


@register(
    "has_pth_file",
    "Wheel contains a .pth file (can modify sys.path on install)",
    kind="sketchy",
)
def find_pth_file(view: ArtifactView, cfg: dict) -> list[Finding]:
    if view.filetype != "wheel":
        return []
    for info in view.infos():
        if info.filename.endswith(".pth"):
            return [Finding("has_pth_file", True, view.filename, view.resource)]
    return []


@register("has_js_file", "Archive contains JavaScript files", kind="sketchy")
def find_js_file(view: ArtifactView, cfg: dict) -> list[Finding]:
    for info in view.infos():
        name = info.filename.lower()
        if name.endswith(".js") and not name.endswith(".min.js"):
            return [Finding("has_js_file", True, view.filename, view.resource)]
    return []


@register(
    "has_minified_js",
    "Archive contains minified JavaScript (.min.js)",
    kind="sketchy",
)
def find_minified_js(view: ArtifactView, cfg: dict) -> list[Finding]:
    for info in view.infos():
        if info.filename.lower().endswith(".min.js"):
            return [Finding("has_minified_js", True, view.filename, view.resource)]
    return []


@register(
    "archive_umask",
    "Infer bits that are never set across Unix permission bits in the archive",
    kind="informational",
)
def find_archive_umask(view: ArtifactView, cfg: dict) -> list[Finding]:
    if view.filetype != "wheel":
        return []

    observed = 0
    saw_any = False
    try:
        for info in view.infos():
            perms = _zipinfo_perms(info)
            if perms is None:
                continue
            saw_any = True
            observed |= perms
    except Exception:
        return []

    if not saw_any:
        return []

    umask = (~observed) & 0o777
    return [Finding("archive_umask", f"{umask:03o}", view.filename, view.resource)]


@register(
    "development_checkout",
    "File timestamps in archive span more than threshold hours (suggests manual build)",
    kind="informational",
)
def find_development_checkout(view: ArtifactView, cfg: dict) -> list[Finding]:
    if view.filetype != "wheel":
        return []
    threshold_hours = cfg.get("threshold_hours", 0.05)
    debug = cfg.get("debug", False)
    ignore_round_dates = cfg.get("ignore_round_dates", True)
    times: list[tuple[datetime.datetime, str]] = []
    seen_any = False
    for info in view.infos():
        seen_any = True
        dt = info.date_time  # (year, month, day, hour, min, sec)
        if dt[0] < 1990:
            continue
        if ignore_round_dates and _is_round_timestamp(dt):
            continue
        try:
            times.append((datetime.datetime(*dt), info.filename))
        except (ValueError, TypeError):
            pass
    if not times:
        if seen_any:
            return [Finding("reproducible_build", True, view.filename, view.resource)]
        return []
    if len(times) < 2:
        return []
    min_dt, min_name = min(times, key=lambda x: x[0])
    max_dt, max_name = max(times, key=lambda x: x[0])
    span_hours = (max_dt - min_dt).total_seconds() / 3600
    if debug:
        print(
            f"development_checkout debug: {view.filename} "
            f"min={min_dt.isoformat()} [{min_name}] "
            f"max={max_dt.isoformat()} [{max_name}] "
            f"span={span_hours:.2f}h"
        )
    if span_hours > threshold_hours:
        return [Finding("development_checkout", f"{span_hours:.1f}h", view.filename, view.resource)]
    return []


@register(
    "multiple_top_level_names",
    "Wheel contains more than one top-level package name",
    kind="informational",
    needs_content=True,
)
def find_top_level_names(view: ArtifactView, cfg: dict) -> list[Finding]:
    if view.filetype != "wheel":
        return []
    top_level = _top_level_names(view)
    if len(top_level) > 1:
        return [Finding("multiple_top_level_names", ",".join(sorted(top_level)), view.filename, view.resource)]
    return []


@register(
    "top_level_name_mismatch",
    "Wheel distribution name does not match top-level package name",
    kind="sketchy",
    needs_content=True,
)
def find_top_level_name_mismatch(view: ArtifactView, cfg: dict) -> list[Finding]:
    if view.filetype != "wheel":
        return []
    top_level = _top_level_names(view)
    parts = view.filename[:-4].rsplit("-", 4)
    if len(parts) == 5 and top_level:
        wheel_name = parts[0].lower().replace("-", "_")
        normalized = [t.lower().replace("-", "_") for t in top_level]
        if wheel_name not in normalized:
            return [
                Finding(
                    "top_level_name_mismatch",
                    f"{wheel_name}!={','.join(top_level)}",
                    view.filename,
                    view.resource,
                )
            ]
    return []
