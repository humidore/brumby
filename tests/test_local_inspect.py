import tempfile
import zipfile
from pathlib import Path

from brumby.analyze import analyze_artifacts, check_artifacts
from brumby.cli import _inspect_lines
from brumby.finding import Finding
from brumby.artifact import make_local_artifact


def test_local_artifact_infers_wheel_type() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "demo-1.0-py3-none-any.whl"
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("demo/__init__.py", b"print('hi')\n")

        artifact = make_local_artifact(path)

        assert artifact.filetype == "wheel"
        assert artifact.resource == "wheel"


def test_local_inspect_runs_only_artifact_checks() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "demo-1.0-py3-none-any.whl"
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("demo/__init__.py", b"import subprocess\nsubprocess.run(['true'])\n")

        artifact = make_local_artifact(path)
        findings = analyze_artifacts([artifact], {"finders": {}}, content=True)
        names = sorted(f.name for f in findings)

        assert "spawns_at_import" in names
        assert "platform_wheels" not in names
        assert "reproducible_build" not in names


def test_metadata_version_is_informational() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "demo-1.0-py3-none-any.whl"
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("demo-1.0.dist-info/METADATA", b"Metadata-Version: 2.4\nName: demo\n")

        artifact = make_local_artifact(path)
        findings = analyze_artifacts([artifact], {"finders": {}}, content=True)

        assert any(f.name == "metadata_version" and f.value == "2.4" for f in findings)


def test_inspect_summary_collapses_repeated_findings() -> None:
    findings = [
        Finding("has_elf_binary", "uv", "a.whl", "wheel"),
        Finding("has_elf_binary", "uv", "b.whl", "wheel"),
        Finding("has_elf_binary", "uv", "c.whl", "wheel"),
        Finding("has_elf_binary", "uv", "d.whl", "wheel"),
    ]

    assert _inspect_lines(findings, summary=True) == [
        "  \033[31m[X]\033[0m has_elf_binary=uv @ wheel [*]",
    ]


def test_inspect_summary_keeps_small_groups_detailed() -> None:
    findings = [
        Finding("has_pe_binary", "a", "pkg.whl", "wheel"),
        Finding("has_pe_binary", "b", "pkg.whl", "wheel"),
        Finding("has_pe_binary", "c", "pkg.whl", "wheel"),
    ]

    assert _inspect_lines(findings, summary=True) == [
        "  \033[31m[X]\033[0m has_pe_binary=a  [pkg.whl]",
        "  \033[31m[X]\033[0m has_pe_binary=b  [pkg.whl]",
        "  \033[31m[X]\033[0m has_pe_binary=c  [pkg.whl]",
    ]


def test_inspect_summary_collapses_same_value_across_many_files() -> None:
    findings = [
        Finding("zip_version_needed", 20, "a.whl", "wheel"),
        Finding("zip_version_needed", 20, "b.whl", "wheel"),
        Finding("zip_version_needed", 20, "c.whl", "wheel"),
        Finding("zip_version_needed", 20, "d.whl", "wheel"),
    ]

    assert _inspect_lines(findings, summary=True) == [
        "  [i] zip_version_needed=20 @ wheel [*]",
    ]


def test_check_artifacts_compares_two_local_wheels() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        old_path = Path(tmpdir) / "old.whl"
        new_path = Path(tmpdir) / "new.whl"
        with zipfile.ZipFile(old_path, "w") as zf:
            zf.writestr("demo/__init__.py", b"print('hi')\n")
        with zipfile.ZipFile(new_path, "w") as zf:
            zf.writestr("demo/__init__.py", b"import base64\n")

        old_artifact = make_local_artifact(old_path)
        new_artifact = make_local_artifact(new_path)
        _old_findings, _new_findings, diffs = check_artifacts(
            [old_artifact],
            [new_artifact],
            old_label=str(old_path),
            new_label=str(new_path),
            callback=lambda *args, **kwargs: None,
            content=True,
        )

        assert any(name == "imports_base64" for name, *_ in diffs)
