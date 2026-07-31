import datetime

import pytest

from brumby.analyze import find_last_with_cutoff, resolve_versions, select_assess_mode


def _pkg_info() -> dict:
    def iso(hours_ago: int) -> str:
        return (datetime.datetime(2026, 5, 8, 12, 0, tzinfo=datetime.timezone.utc) - datetime.timedelta(hours=hours_ago)).isoformat()

    return {
        "releases": {
            "1.0": [{"upload_time_iso_8601": iso(50)}],
            "1.1": [{"upload_time_iso_8601": iso(26)}],
            "1.2": [{"upload_time_iso_8601": iso(20)}],
            "1.3": [{"upload_time_iso_8601": iso(1)}],
        }
    }


class _FixedDateTime(datetime.datetime):
    @classmethod
    def now(cls, tz=None):
        return cls(2026, 5, 8, 12, 0, tzinfo=tz or datetime.timezone.utc)


def _freeze_now(monkeypatch) -> None:
    import brumby.analyze as analyze

    monkeypatch.setattr(analyze.datetime, "datetime", _FixedDateTime)


def test_find_last_with_cutoff_picks_latest_old_enough_release() -> None:
    stable, new = find_last_with_cutoff("pkg", 24, _pkg_info())

    assert stable == "1.1"
    assert new == "1.3"


def test_find_last_with_cutoff_returns_only_one_when_no_old_enough_base() -> None:
    info = {
        "releases": {
            "1.0": [{"upload_time_iso_8601": "2026-05-08T11:00:00+00:00"}],
            "1.1": [{"upload_time_iso_8601": "2026-05-08T12:00:00+00:00"}],
        }
    }

    stable, new = find_last_with_cutoff("pkg", 24, info)

    assert stable is None
    assert new == "1.1"


def test_resolve_versions_honors_last_mode() -> None:
    stable, new = resolve_versions("pkg", cutoff_hours=24, last=True, pkg_info=_pkg_info())

    assert stable == "1.1"
    assert new == "1.3"


def test_resolve_versions_anchors_stable_on_new_package_upload_time() -> None:
    stable, new = resolve_versions("pkg", cutoff_hours=24, new_version="1.2", pkg_info=_pkg_info())

    assert new == "1.2"
    assert stable == "1.0"


def test_resolve_versions_falls_back_to_preceding_release_when_none_meets_cutoff() -> None:
    stable, new = resolve_versions("pkg", cutoff_hours=48, new_version="1.2", pkg_info=_pkg_info())

    assert new == "1.2"
    assert stable == "1.1"


def test_resolve_versions_returns_no_stable_when_supplied_new_is_oldest() -> None:
    stable, new = resolve_versions("pkg", cutoff_hours=24, new_version="1.0", pkg_info=_pkg_info())

    assert new == "1.0"
    assert stable is None


def test_resolve_versions_ignores_cutoff_for_last_two_with_supplied_new() -> None:
    stable, new = resolve_versions(
        "pkg", cutoff_hours=24, new_version="1.2", last_two=True, pkg_info=_pkg_info()
    )

    assert new == "1.2"
    assert stable == "1.1"


def test_resolve_versions_rejects_supplied_new_missing_from_releases() -> None:
    with pytest.raises(ValueError, match="9.9"):
        resolve_versions("pkg", cutoff_hours=24, new_version="9.9", pkg_info=_pkg_info())


def test_select_assess_mode_uses_check_for_recent_release(monkeypatch) -> None:
    _freeze_now(monkeypatch)
    mode, stable, new = select_assess_mode("pkg", cutoff_hours=24, pkg_info=_pkg_info())

    assert mode == "check"
    assert stable == "1.1"
    assert new == "1.3"


def test_select_assess_mode_uses_check_last_when_no_recent_release_but_multiple_days(monkeypatch) -> None:
    _freeze_now(monkeypatch)
    info = {
        "releases": {
            "1.0": [{"upload_time_iso_8601": "2026-05-05T10:00:00+00:00"}],
            "1.1": [{"upload_time_iso_8601": "2026-05-06T11:00:00+00:00"}],
        }
    }

    mode, stable, new = select_assess_mode("pkg", cutoff_hours=24, pkg_info=info)

    assert mode == "check-last"
    assert stable == "1.0"
    assert new == "1.1"


def test_select_assess_mode_falls_back_to_inspect_for_single_day_history(monkeypatch) -> None:
    _freeze_now(monkeypatch)
    info = {
        "releases": {
            "1.0": [{"upload_time_iso_8601": "2026-05-06T10:00:00+00:00"}],
            "1.1": [{"upload_time_iso_8601": "2026-05-06T10:30:00+00:00"}],
        }
    }

    mode, stable, new = select_assess_mode("pkg", cutoff_hours=24, pkg_info=info)

    assert mode == "inspect"
    assert stable is None
    assert new == "1.1"
