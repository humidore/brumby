import brumby.analyze as analyze
from brumby.analyze import ScanSkipped, get_artifacts, prepare_scan_artifacts


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


def test_get_artifacts_fetches_version_endpoint_when_project_index_has_no_files(monkeypatch) -> None:
    release_files = [{
        "filename": "pkg-1.0-py3-none-any.whl",
        "url": "https://files.pythonhosted.org/pkg-1.0-py3-none-any.whl",
        "packagetype": "bdist_wheel",
        "size": 10,
    }]
    calls = []

    def fake_get_release_files(package, version):
        calls.append((package, version))
        return release_files

    monkeypatch.setattr(analyze, "get_release_files", fake_get_release_files)

    artifacts = get_artifacts(
        "pkg",
        "1.0",
        pkg_info={"releases": {"1.0": []}},
    )

    assert calls == [("pkg", "1.0")]
    assert [artifact.filename for artifact in artifacts] == ["pkg-1.0-py3-none-any.whl"]


def test_prepare_scan_artifacts_skips_when_selected_total_exceeds_limit() -> None:
    artifacts = [
        _Artifact("pkg-1.0-cp311-cp311-manylinux_x86_64.whl", 160 * 1024 * 1024),
        _Artifact("pkg-1.0-cp312-cp312-macosx_11_0_arm64.whl", 160 * 1024 * 1024),
        _Artifact("pkg-1.0-cp312-cp312-win_amd64.whl", 160 * 1024 * 1024),
    ]

    try:
        prepare_scan_artifacts(artifacts)
    except ScanSkipped as exc:
        assert str(exc) == "did not scan: selected artifacts total 480.0 MB (limit 300 MB)"
    else:
        raise AssertionError("expected ScanSkipped")
