import datetime
import tempfile
import zipfile
from pathlib import Path

from brumby.analyze import analyze_artifacts
from brumby.artifact import make_local_artifact
from brumby.finders.metadata import find_platform_wheels, find_giant_version
from brumby.finding import Finding


class _DummyView:
    def __init__(self, filename: str, filetype: str = "wheel", resource: str = "wheel") -> None:
        self.filename = filename
        self.filetype = filetype
        self.resource = resource


def test_packager_timezone_reports_hourish_offset_for_wheel() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "demo-1.0-py3-none-any.whl"
        meta_info = zipfile.ZipInfo("demo-1.0.dist-info/METADATA")
        meta_info.date_time = (2026, 5, 8, 12, 1, 0)
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr(meta_info, b"Metadata-Version: 2.4\nName: demo\n")

        artifact = make_local_artifact(path)
        artifact.upload_time = datetime.datetime(2026, 5, 8, 10, 0, tzinfo=datetime.timezone.utc).isoformat()

        findings = analyze_artifacts([artifact], {}, content=True)

        assert any(f.name == "packager_timezone" and f.value == "+2h" for f in findings)

        artifact.upload_time = datetime.datetime(2026, 5, 8, 12, 1, tzinfo=datetime.timezone.utc).isoformat()
        findings = analyze_artifacts([artifact], {}, content=True)
        assert not any(f.name == "packager_timezone" for f in findings)

        artifact.upload_time = datetime.datetime(2026, 5, 7, 23, 0, tzinfo=datetime.timezone.utc).isoformat()
        findings = analyze_artifacts([artifact], {}, content=True)
        assert not any(f.name == "packager_timezone" for f in findings)


def test_platform_wheels_emits_only_for_platform_wheels() -> None:
    any_only = [_DummyView("pkg-1.0-py3-none-any.whl")]
    platform = [_DummyView("pkg-1.0-py3-none-manylinux_x86_64.whl")]

    assert find_platform_wheels(any_only, {}) == []
    assert find_platform_wheels(platform, {}) == [Finding("platform_wheels", True, None, "wheel")]


def test_giant_version_uses_boolean_value() -> None:
    assert find_giant_version({}, "6.0", {"threshold": 5}) == [
        Finding("giant_version", True, None, "release")
    ]


def test_packager_timezone_works_for_zip_sdist() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "demo-1.0.zip"
        meta_info = zipfile.ZipInfo("demo-1.0/PKG-INFO")
        meta_info.date_time = (2026, 5, 8, 15, 59, 0)
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr(meta_info, b"Metadata-Version: 2.1\nName: demo\n")

        artifact = make_local_artifact(path)
        artifact.upload_time = datetime.datetime(2026, 5, 8, 10, 0, tzinfo=datetime.timezone.utc).isoformat()

        findings = analyze_artifacts([artifact], {}, content=True)

        assert any(f.name == "packager_timezone" and f.value == "+6h" for f in findings)


def test_packager_timezone_defaults_to_two_minutes() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "demo-1.0-py3-none-any.whl"
        meta_info = zipfile.ZipInfo("demo-1.0.dist-info/METADATA")
        meta_info.date_time = (2026, 5, 8, 12, 3, 0)
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr(meta_info, b"Metadata-Version: 2.4\nName: demo\n")

        artifact = make_local_artifact(path)
        artifact.upload_time = datetime.datetime(2026, 5, 8, 10, 0, tzinfo=datetime.timezone.utc).isoformat()

        findings = analyze_artifacts([artifact], {}, content=True)

        assert not any(f.name == "packager_timezone" for f in findings)
