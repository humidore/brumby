import io
import tarfile
import zipfile
from pathlib import Path

import pytest
from brumby import api
from brumby.finding import Finding


def test_every_public_operation_is_traced() -> None:
    operations = (
        "assess",
        "check",
        "classify_diffs",
        "classify_findings",
        "export",
        "finders",
        "inspect",
    )

    assert all(hasattr(getattr(api, name), "__wrapped__") for name in operations)


def _wheel(path: Path, source: bytes) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("demo/__init__.py", source)


def _pkg_info() -> dict:
    return {
        "info": {"version": "2.0"},
        "releases": {
            "1.0": [{"upload_time_iso_8601": "2025-01-01T00:00:00+00:00"}],
            "2.0": [{"upload_time_iso_8601": "2025-01-03T00:00:00+00:00"}],
        },
    }


def _diff(kind: str = "sketchy") -> tuple:
    return (
        "imports_base64",
        "wheel",
        frozenset({"old.py"}),
        frozenset({"old.py", "new.py"}),
        frozenset({"old.whl"}),
        frozenset({"new.whl"}),
        kind,
    )


def test_check_returns_comparison_without_writing_output(tmp_path, capsys) -> None:
    old = tmp_path / "old.whl"
    new = tmp_path / "new.whl"
    _wheel(old, b"print('old')\n")
    _wheel(new, b"import base64\n")

    result = api.check(str(old), str(new), config={})

    assert result.source == "local"
    assert result.label == "local compare"
    assert result.old.label == str(old)
    assert result.new.label == str(new)
    assert any(diff.name == "imports_base64" for diff in result.diffs)
    assert capsys.readouterr() == ("", "")


def test_difference_and_check_totals() -> None:
    difference = api.Difference(*_diff())
    result = api.CheckResult(
        "demo",
        "package",
        api.ReleaseRef("demo 1.0"),
        api.ReleaseRef("demo 2.0"),
        [],
        [],
        [difference],
    )

    assert difference.added == frozenset({"new.py"})
    assert difference.removed == frozenset()
    assert result.added == 1
    assert result.removed == 0
    assert result.delta == 1


def test_check_compares_urls(monkeypatch) -> None:
    recorded = {}

    def fake_check_urls(old, new, **kwargs):
        recorded.update(kwargs)
        return [Finding("old", 1)], [Finding("new", 2)], [_diff()]

    monkeypatch.setattr(api, "check_urls", fake_check_urls)

    result = api.check("https://old.invalid/a.whl", "https://new.invalid/b.whl", content=False)

    assert result.source == "url"
    assert result.old.label == "https://old.invalid/a.whl"
    assert result.diffs[0].name == "imports_base64"
    assert recorded["callback"] is None
    assert recorded["content"] is False
    assert recorded["config"] == {}


def test_check_lists_package_versions_without_scanning(monkeypatch) -> None:
    monkeypatch.setattr(api, "get_package_info", lambda package: _pkg_info())
    monkeypatch.setattr(api, "resolve_versions", lambda *args, **kwargs: ("1.0", "2.0"))
    monkeypatch.setattr(api, "check_package", lambda *args, **kwargs: pytest.fail("scanned"))

    result = api.check("demo", list_only=True, config={})

    assert result.list_only
    assert result.old.version == "1.0"
    assert result.old.label == "demo 1.0"
    assert result.old.upload_bounds[0].isoformat() == "2025-01-01T00:00:00+00:00"
    assert result.new.version == "2.0"
    assert not result.diffs


def test_check_compares_package_versions_and_passes_options(monkeypatch) -> None:
    recorded = {}
    monkeypatch.setattr(api, "get_package_info", lambda package: _pkg_info())
    monkeypatch.setattr(api, "resolve_versions", lambda *args, **kwargs: ("1.0", "2.0"))

    def fake_check_package(package, **kwargs):
        recorded.update(kwargs)
        return [], [], [_diff("informational")]

    monkeypatch.setattr(api, "check_package", fake_check_package)

    result = api.check(
        "demo",
        stable_version="1.0",
        new_version="2.0",
        cutoff_hours=12,
        last_two=True,
        content=False,
        save_dir="artifacts",
        config={"thresholds": {"sus": 2}},
    )

    assert result.source == "package"
    assert result.diffs[0].kind == "informational"
    assert recorded["stable_version"] == "1.0"
    assert recorded["new_version"] == "2.0"
    assert recorded["cutoff_hours"] == 12
    assert recorded["last_two"] is True
    assert recorded["content"] is False
    assert recorded["save_dir"] == "artifacts"


@pytest.mark.parametrize(
    ("versions", "message"),
    [
        ((None, "2.0"), "No previous version found"),
        (("1.0", None), "Only one version found"),
        (("2.0", "2.0"), "Only one version found"),
    ],
)
def test_check_rejects_unusable_package_pairs(monkeypatch, versions, message) -> None:
    monkeypatch.setattr(api, "get_package_info", lambda package: _pkg_info())
    monkeypatch.setattr(api, "resolve_versions", lambda *args, **kwargs: versions)

    with pytest.raises(ValueError, match=message):
        api.check("demo", config={})


def test_classifiers_accept_structured_and_legacy_differences() -> None:
    structured = api.Difference(*_diff())
    legacy = _diff("informational")
    config = {"thresholds": {"sus": 1, "informational": 1}}

    assert api.classify_diffs([structured], {}) == "high"
    assert api.classify_diffs([legacy], config) == "average"
    findings = [Finding("has_pth_file", True), Finding("metadata_version", "2.4")]
    assert api.classify_findings(findings, config) == "high"
    assert api.classify_findings([], {}) == "average"


def test_inspect_and_assess_return_their_evidence(tmp_path) -> None:
    artifact = tmp_path / "demo.whl"
    _wheel(artifact, b"import subprocess\nsubprocess.run(['true'])\n")

    inspection = api.inspect(str(artifact), config={})
    assessment = api.assess(str(artifact), config={})

    assert inspection.label == str(artifact)
    assert inspection.findings
    assert assessment.project == artifact.name
    assert assessment.findings == inspection.findings
    assert assessment.risk == "high"


def test_assess_rejects_versions_for_local_artifact(tmp_path) -> None:
    artifact = tmp_path / "demo.whl"
    _wheel(artifact, b"")

    with pytest.raises(ValueError, match="local artifact"):
        api.assess(str(artifact), new_version="2.0")


def test_assess_returns_too_new_without_scanning(monkeypatch) -> None:
    monkeypatch.setattr(api, "get_package_info", lambda package: _pkg_info())
    monkeypatch.setattr(
        api, "select_assess_mode", lambda *args, **kwargs: ("first-release", None, "2.0")
    )
    monkeypatch.setattr(api, "get_artifacts", lambda *args, **kwargs: pytest.fail("scanned"))

    result = api.assess("demo", config={})

    assert result.risk == "too new"
    assert result.mode == "first-release"
    assert result.new_version == "2.0"


def test_assess_inspects_package_without_a_baseline(monkeypatch) -> None:
    finding = Finding("has_pth_file", True)
    monkeypatch.setattr(api, "get_package_info", lambda package: _pkg_info())
    monkeypatch.setattr(api, "select_assess_mode", lambda *args, **kwargs: ("inspect", None, "2.0"))
    monkeypatch.setattr(api, "get_artifacts", lambda *args, **kwargs: [object()])
    monkeypatch.setattr(api, "analyze_release", lambda *args, **kwargs: [finding])

    result = api.assess("demo", content=False, save_dir="saved", config={})

    assert result.mode == "inspect"
    assert result.findings == [finding]
    assert result.risk == "high"


def test_assess_rejects_modes_without_a_target_version(monkeypatch) -> None:
    monkeypatch.setattr(api, "get_package_info", lambda package: _pkg_info())
    monkeypatch.setattr(api, "select_assess_mode", lambda *args, **kwargs: ("inspect", None, None))
    with pytest.raises(ValueError, match="Only one version"):
        api.assess("demo")

    monkeypatch.setattr(api, "select_assess_mode", lambda *args, **kwargs: ("check", None, "2.0"))
    with pytest.raises(ValueError, match="Only one version"):
        api.assess("demo")


def test_assess_compares_package_releases(monkeypatch) -> None:
    monkeypatch.setattr(api, "get_package_info", lambda package: _pkg_info())
    monkeypatch.setattr(api, "select_assess_mode", lambda *args, **kwargs: ("check-last", "1.0", "2.0"))
    monkeypatch.setattr(api, "check_package", lambda *args, **kwargs: ([], [], [_diff()]))

    result = api.assess("demo", config={})

    assert result.risk == "high"
    assert result.diffs == [api.Difference(*_diff())]
    assert result.stable_version == "1.0"
    assert result.new_version == "2.0"


def test_local_single_finder_handles_unknown_and_content_modes(tmp_path) -> None:
    artifact = tmp_path / "demo.whl"
    _wheel(artifact, b"import base64\n")

    with pytest.raises(ValueError, match="unknown artifact finder"):
        api.inspect(str(artifact), finder="missing", config={})
    result = api.inspect(str(artifact), finder="imports_base64", content=False, config={})
    assert not result.findings


def test_inspect_remote_release_with_and_without_one_finder(monkeypatch, tmp_path) -> None:
    artifact_path = tmp_path / "demo.whl"
    _wheel(artifact_path, b"import base64\n")
    from brumby.artifact import make_local_artifact
    artifact = make_local_artifact(artifact_path)

    monkeypatch.setattr(api, "get_latest_version", lambda package: "2.0")
    monkeypatch.setattr(api, "get_package_info", lambda package: _pkg_info())
    monkeypatch.setattr(api, "get_artifacts", lambda *args, **kwargs: [artifact, artifact])
    monkeypatch.setattr(
        api, "analyze_release", lambda *args, **kwargs: [Finding("metadata_version", "2.4")]
    )

    whole = api.inspect("demo", config={})
    one = api.inspect("demo", "2.0", finder="imports_base64", config={})

    assert whole.label == "demo 2.0"
    assert whole.findings == [Finding("metadata_version", "2.4")]
    assert len(one.findings) == 2


def test_api_none_config_does_not_search_for_a_config_file(tmp_path, monkeypatch) -> None:
    (tmp_path / "brumby.toml").write_text("[finders]\nimports_base64 = false\n")
    monkeypatch.chdir(tmp_path)

    by_name = {item.name: item for item in api.finders()}

    assert by_name["imports_base64"].enabled
    assert not {
        item.name: item
        for item in api.finders({"finders": {"imports_base64": False}})
    }["imports_base64"].enabled


def test_export_returns_paths_and_handles_non_utf8_files(tmp_path) -> None:
    old = tmp_path / "old.whl"
    new = tmp_path / "new.whl"
    with zipfile.ZipFile(old, "w") as archive:
        archive.mkdir("demo/")
        archive.writestr("demo/data.bin", b"old\xffdata")
    with zipfile.ZipFile(new, "w") as archive:
        archive.mkdir("demo/")
        archive.writestr("demo/data.bin", b"new\xffdata")

    result = api.export(str(old), str(new), output=tmp_path / "export", config={})

    assert result.prompt.read_text().endswith("  - Last line: the literal text DONE\n")
    assert (result.old_dir / "data.bin").read_bytes() == b"old\xffdata"
    assert (result.new_dir / "data.bin").read_bytes() == b"new\xffdata"
    assert not (result.output / "diff.txt").exists()


def test_export_extracts_local_tar_archives(tmp_path) -> None:
    old = tmp_path / "old.tar.gz"
    new = tmp_path / "new.tar.gz"
    for path, data in ((old, b"old"), (new, b"new")):
        with tarfile.open(path, "w:gz") as archive:
            info = tarfile.TarInfo("demo/data.bin")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
            metadata = tarfile.TarInfo("metadata.txt")
            metadata.size = len(data)
            archive.addfile(metadata, io.BytesIO(data))

    result = api.export(str(old), str(new), output=tmp_path / "tar-export")

    assert (result.old_dir / "demo" / "data.bin").read_bytes() == b"old"
    assert (result.new_dir / "demo" / "data.bin").read_bytes() == b"new"


class _RemoteArtifact:
    def __init__(self, filetype: str, data: bytes, filename: str) -> None:
        self.filetype = filetype
        self.data = data
        self.filename = filename

    def open_local(self):
        raise ValueError("not local")

    def open_sdist_remote(self):
        return tarfile.open(fileobj=io.BytesIO(self.data), mode="r:gz")

    def open_zip_remote(self):
        return zipfile.ZipFile(io.BytesIO(self.data))


def _tar_bytes(data: bytes) -> bytes:
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz") as archive:
        info = tarfile.TarInfo("demo/data.bin")
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
    return out.getvalue()


def _zip_bytes(data: bytes) -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as archive:
        archive.writestr("demo/data.bin", data)
    return out.getvalue()


def test_export_downloads_package_sdists(monkeypatch, tmp_path) -> None:
    artifacts = {
        "1.0": [_RemoteArtifact("wheel", _zip_bytes(b"wheel"), "demo.whl"),
                _RemoteArtifact("sdist", _tar_bytes(b"old"), "demo.tar.gz")],
        "2.0": [_RemoteArtifact("sdist", _tar_bytes(b"new"), "demo.tar.gz")],
    }
    recorded = []
    monkeypatch.setattr(api, "get_package_info", lambda package: _pkg_info())
    monkeypatch.setattr(api, "resolve_versions", lambda *args, **kwargs: ("1.0", "2.0"))

    def get_artifacts(package, version, **kwargs):
        recorded.append((version, kwargs["save_dir"]))
        return artifacts[version]

    monkeypatch.setattr(api, "get_artifacts", get_artifacts)

    result = api.export(
        "demo", output=tmp_path / "remote", save_dir="saved",
        stable_version="1.0", new_version="2.0", config={},
    )

    assert result.old.version == "1.0"
    assert result.new.version == "2.0"
    assert (result.old_dir / "data.bin").read_bytes() == b"old"
    assert recorded == [("1.0", "saved"), ("2.0", "saved")]


def test_export_downloads_package_wheels(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(api, "get_package_info", lambda package: _pkg_info())
    monkeypatch.setattr(api, "resolve_versions", lambda *args, **kwargs: ("1.0", "2.0"))
    monkeypatch.setattr(
        api,
        "get_artifacts",
        lambda package, version, **kwargs: [
            _RemoteArtifact("wheel", _zip_bytes(version.encode()), "demo.whl")
        ],
    )

    result = api.export("demo", output=tmp_path / "wheels", config={})

    assert (result.old_dir / "data.bin").read_bytes() == b"1.0"
    assert (result.new_dir / "data.bin").read_bytes() == b"2.0"


@pytest.mark.parametrize(
    ("versions", "message"),
    [
        ((None, "2.0"), "No previous version found"),
        (("1.0", None), "Only one version found"),
        (("2.0", "2.0"), "Only one version found"),
    ],
)
def test_export_rejects_unusable_package_pairs(monkeypatch, versions, message) -> None:
    monkeypatch.setattr(api, "get_package_info", lambda package: _pkg_info())
    monkeypatch.setattr(api, "resolve_versions", lambda *args, **kwargs: versions)

    with pytest.raises(ValueError, match=message):
        api.export("demo", config={})


def test_export_rejects_unsafe_zip_member(tmp_path) -> None:
    old = tmp_path / "old.whl"
    new = tmp_path / "new.whl"
    for path in (old, new):
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("safe/data.bin", b"safe")
            archive.writestr("../escape.bin", b"escape")

    with pytest.raises(ValueError, match="unsafe path"):
        api.export(str(old), str(new), output=tmp_path / "unsafe")


def test_export_keeps_zip_directories_without_one_shared_root(tmp_path) -> None:
    old = tmp_path / "old.whl"
    new = tmp_path / "new.whl"
    for path in (old, new):
        with zipfile.ZipFile(path, "w") as archive:
            archive.mkdir("first/")
            archive.writestr("first/data.bin", b"first")
            archive.writestr("second/data.bin", b"second")

    result = api.export(str(old), str(new), output=tmp_path / "dirs")

    assert (result.old_dir / "first").is_dir()
    assert (result.old_dir / "second" / "data.bin").read_bytes() == b"second"
