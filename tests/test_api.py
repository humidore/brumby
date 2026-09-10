import zipfile
from pathlib import Path

from brumby import api


def _wheel(path: Path, source: bytes) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("demo/__init__.py", source)


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


def test_api_none_config_does_not_search_for_a_config_file(tmp_path, monkeypatch) -> None:
    (tmp_path / "brumby.toml").write_text("[finders]\nimports_base64 = false\n")
    monkeypatch.chdir(tmp_path)

    by_name = {item.name: item for item in api.finders()}

    assert by_name["imports_base64"].enabled
    assert not {
        item.name: item
        for item in api.finders({"finders": {"imports_base64": False}})
    }["imports_base64"].enabled


def test_export_returns_review_paths(tmp_path) -> None:
    old = tmp_path / "old.whl"
    new = tmp_path / "new.whl"
    with zipfile.ZipFile(old, "w") as archive:
        archive.writestr("demo/data.bin", b"old data")
    with zipfile.ZipFile(new, "w") as archive:
        archive.writestr("demo/data.bin", b"new data")

    result = api.export(str(old), str(new), output=tmp_path / "export", config={})

    assert result.prompt.read_text().endswith("  - Last line: the literal text DONE\n")
    assert (result.old_dir / "data.bin").read_bytes() == b"old data"
    assert (result.new_dir / "data.bin").read_bytes() == b"new data"
    assert (result.output / "diff.txt").exists()
