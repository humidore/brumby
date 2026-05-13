import zipfile

from brumby.finders.archive import (
    find_archive_umask,
    find_development_checkout,
    find_pth_file,
    find_top_level_name_mismatch,
)
from brumby.finding import Finding


def _zipinfo(filename: str, mode: int, create_system: int = 3) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(filename)
    info.create_system = create_system
    info.external_attr = mode << 16
    return info


class _Info:
    def __init__(self, filename: str, date_time: tuple[int, int, int, int, int, int]) -> None:
        self.filename = filename
        self.date_time = date_time


class _DummyView:
    def __init__(self, infos: list[_Info], filename: str = "pkg-1.0.whl") -> None:
        self._infos = infos
        self.filename = filename
        self.filetype = "wheel"
        self.resource = "wheel"

    def infos(self):
        return self._infos


class _TopLevelView(_DummyView):
    def __init__(self, infos: list[_Info], content: bytes, filename: str = "pkg-1.0.whl") -> None:
        super().__init__(infos, filename=filename)
        self._content = content

    def read_member(self, name: str) -> bytes:
        assert name.endswith(".dist-info/top_level.txt")
        return self._content


def test_pth_file_uses_boolean_value() -> None:
    view = _DummyView([_Info("pkg/foo.pth", (2026, 1, 1, 0, 0, 0))])

    assert find_pth_file(view, {}) == [Finding("has_pth_file", True, "pkg-1.0.whl", "wheel")]


def test_top_level_name_mismatch_is_sketchy() -> None:
    view = _TopLevelView(
        [_Info("pkg-1.0.dist-info/top_level.txt", (2026, 1, 1, 0, 0, 0))],
        b"otherpkg\n",
        filename="pkg-1.0-py3-none-any.whl",
    )

    assert find_top_level_name_mismatch(view, {}) == [
        Finding("top_level_name_mismatch", "pkg!=otherpkg", "pkg-1.0-py3-none-any.whl", "wheel")
    ]


def test_development_checkout_ignores_common_sentinel_dates() -> None:
    view = _DummyView(
        [
            _Info("pkg-1.0.dist-info/METADATA", (2024, 1, 1, 0, 0, 0)),
            _Info("pkg-1.0.dist-info/RECORD", (2025, 1, 1, 0, 0, 0)),
            _Info("pkg-1.0.dist-info/WHEEL", (2020, 2, 2, 0, 0, 0)),
            _Info("pkg/module.py", (2026, 5, 1, 12, 0, 0)),
            _Info("pkg/other.py", (2026, 5, 1, 12, 30, 0)),
        ]
    )

    assert find_development_checkout(view, {"threshold_hours": 0.1}) == [
        Finding("development_checkout", "0.5h", "pkg-1.0.whl", "wheel")
    ]


def test_development_checkout_reports_reproducible_build_when_only_round_dates_remain() -> None:
    view = _DummyView(
        [
            _Info("pkg-1.0.dist-info/METADATA", (2016, 1, 1, 0, 0, 0)),
            _Info("pkg-1.0.dist-info/RECORD", (2030, 1, 1, 0, 0, 0)),
        ]
    )

    assert find_development_checkout(view, {"threshold_hours": 1.0}) == [
        Finding("reproducible_build", True, "pkg-1.0.whl", "wheel")
    ]


def test_development_checkout_can_disable_round_date_filter() -> None:
    view = _DummyView(
        [
            _Info("pkg-1.0.dist-info/METADATA", (2016, 1, 1, 0, 0, 0)),
            _Info("pkg-1.0.dist-info/RECORD", (2016, 1, 1, 0, 0, 0)),
            _Info("pkg/module.py", (2026, 5, 1, 12, 0, 0)),
            _Info("pkg/other.py", (2026, 5, 1, 12, 30, 0)),
        ]
    )

    assert find_development_checkout(
        view,
        {"threshold_hours": 0.1, "ignore_round_dates": False},
    ) == [Finding("development_checkout", "90564.5h", "pkg-1.0.whl", "wheel")]


def test_archive_umask_infers_bits_never_set_across_members() -> None:
    view = _DummyView(
        [
            _zipinfo("pkg/module.py", 0o100644),
            _zipinfo("pkg/script", 0o100755),
            _zipinfo("pkg/", 0o40755),
        ]
    )

    assert find_archive_umask(view, {}) == [Finding("archive_umask", "022", "pkg-1.0.whl", "wheel")]


def test_archive_umask_handles_mixed_execute_bits() -> None:
    view = _DummyView(
        [
            _zipinfo("pkg/module.py", 0o100644),
            _zipinfo("pkg/tool", 0o100755),
            _zipinfo("pkg/other.txt", 0o100644),
        ]
    )

    assert find_archive_umask(view, {}) == [Finding("archive_umask", "022", "pkg-1.0.whl", "wheel")]


def test_archive_umask_skips_non_unix_entries() -> None:
    non_unix = _DummyView(
        [
            _zipinfo("pkg/module.py", 0o100644, create_system=0),
        ]
    )

    assert find_archive_umask(non_unix, {}) == []
