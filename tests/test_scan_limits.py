from brumby.analyze import ScanSkipped, prepare_scan_artifacts
from brumby import cli


class _Artifact:
    def __init__(self, filename: str, size: int, filetype: str = "wheel") -> None:
        self.filename = filename
        self.size = size
        self.filetype = filetype


def test_prepare_scan_artifacts_picks_newest_python_per_os_family() -> None:
    artifacts = [
        _Artifact("pkg-1.0-cp312-cp312-musllinux_x86_64.whl", 10),
        _Artifact("pkg-1.0-cp312-cp312-manylinux_aarch64.whl", 11),
        _Artifact("pkg-1.0-cp311-cp311-macosx_11_0_arm64.whl", 12),
        _Artifact("pkg-1.0-cp312-cp312-win_amd64.whl", 13),
        _Artifact("pkg-1.0.tar.gz", 1, filetype="sdist"),
    ]

    selected = prepare_scan_artifacts(artifacts)

    assert {a.filename for a in selected} == {
        "pkg-1.0-cp312-cp312-manylinux_aarch64.whl",
        "pkg-1.0-cp311-cp311-macosx_11_0_arm64.whl",
        "pkg-1.0-cp312-cp312-win_amd64.whl",
        "pkg-1.0.tar.gz",
    }


def test_prepare_scan_artifacts_prefers_manylinux_over_musllinux_on_tie() -> None:
    artifacts = [
        _Artifact("pkg-1.0-cp312-cp312-musllinux_x86_64.whl", 10),
        _Artifact("pkg-1.0-cp312-cp312-manylinux_x86_64.whl", 11),
    ]

    selected = prepare_scan_artifacts(artifacts)

    assert [a.filename for a in selected] == [
        "pkg-1.0-cp312-cp312-manylinux_x86_64.whl"
    ]


def test_prepare_scan_artifacts_prefers_arm64_over_x86_64_on_tie() -> None:
    artifacts = [
        _Artifact("pkg-1.0-cp312-cp312-manylinux_x86_64.whl", 10),
        _Artifact("pkg-1.0-cp312-cp312-manylinux_aarch64.whl", 11),
        _Artifact("pkg-1.0-cp312-cp312-win32.whl", 12),
    ]

    selected = prepare_scan_artifacts(artifacts)

    assert [a.filename for a in selected] == [
        "pkg-1.0-cp312-cp312-manylinux_aarch64.whl",
        "pkg-1.0-cp312-cp312-win32.whl",
    ]


def test_prepare_scan_artifacts_prefers_cp_over_pp_over_py_on_tie() -> None:
    artifacts = [
        _Artifact("pkg-1.0-py3-none-manylinux_x86_64.whl", 10),
        _Artifact("pkg-1.0-pp3-pp3-manylinux_x86_64.whl", 11),
        _Artifact("pkg-1.0-cp3-cp3-manylinux_x86_64.whl", 12),
    ]

    selected = prepare_scan_artifacts(artifacts)

    assert [a.filename for a in selected] == ["pkg-1.0-cp3-cp3-manylinux_x86_64.whl"]


def test_prepare_scan_artifacts_skips_when_selected_total_exceeds_limit() -> None:
    artifacts = [
        _Artifact("pkg-1.0-cp311-cp311-manylinux_x86_64.whl", 160 * 1024 * 1024),
        _Artifact("pkg-1.0-cp312-cp312-macosx_11_0_arm64.whl", 160 * 1024 * 1024),
        _Artifact("pkg-1.0-cp312-cp312-win_amd64.whl", 160 * 1024 * 1024),
    ]

    try:
        prepare_scan_artifacts(artifacts)
    except ScanSkipped as exc:
        assert "did not scan" in str(exc)
    else:
        raise AssertionError("expected ScanSkipped")


def test_assess_reports_did_not_scan(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        cli,
        "get_package_info",
        lambda package: {"info": {"version": "1.0"}, "releases": {}},
    )
    monkeypatch.setattr(
        cli,
        "select_assess_mode",
        lambda package, cutoff_hours=24, pkg_info=None: ("check", "0.9", "1.0"),
    )
    monkeypatch.setattr(
        cli,
        "check_package",
        lambda *args, **kwargs: (_ for _ in ()).throw(ScanSkipped("did not scan")),
    )

    class Args:
        config = ""
        package = "demo"
        cutoff = 24
        fast = False
        save_artifacts = ""
        json = False

    assert cli.cmd_assess(Args()) == 0
    assert capsys.readouterr().out == cli._assess_line("demo", "did not scan") + "\n"
