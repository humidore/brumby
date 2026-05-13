import tempfile
import zipfile
from pathlib import Path

from brumby.analyze import analyze_artifacts, check_artifacts
from brumby.cli import _inspect_lines, cmd_inspect
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

        assert "spawns_from_init" in names
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


def test_inspect_single_finder_exits_one_on_hit() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "demo-1.0-py3-none-any.whl"
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("demo/proxy.py", b"import base64\n")

        args = type("Args", (), {
            "config": "",
            "package": str(path),
            "version": "",
            "summary": False,
            "finder": "imports_base64",
            "fast": False,
            "save_artifacts": "",
        })()

        assert cmd_inspect(args) == 1


def test_inspect_single_finder_uses_kind_prefix(capsys) -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "demo-1.0-py3-none-any.whl"
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("demo/proxy.py", b"import base64\n")

        args = type("Args", (), {
            "config": "",
            "package": str(path),
            "version": "",
            "summary": False,
            "finder": "imports_base64",
            "fast": False,
            "save_artifacts": "",
        })()

        assert cmd_inspect(args) == 1
        out = capsys.readouterr().out
        assert "[i] imports_base64=proxy.py" in out


def test_inspect_single_finder_reports_metadata_version_as_informational(capsys) -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "demo-1.0-py3-none-any.whl"
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("demo-1.0.dist-info/METADATA", b"Metadata-Version: 2.4\nName: demo\n")

        args = type("Args", (), {
            "config": "",
            "package": str(path),
            "version": "",
            "summary": False,
            "finder": "metadata_version",
            "fast": False,
            "save_artifacts": "",
        })()

        assert cmd_inspect(args) == 1
        out = capsys.readouterr().out
        assert "[i] metadata_version=2.4" in out


def test_inspect_single_finder_rejects_unknown_name() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "demo-1.0-py3-none-any.whl"
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("demo/proxy.py", b"import base64\n")

        args = type("Args", (), {
            "config": "",
            "package": str(path),
            "version": "",
            "summary": False,
            "finder": "does_not_exist",
            "fast": False,
            "save_artifacts": "",
        })()

        assert cmd_inspect(args) == 1


def test_inspect_single_finder_404_exits_zero() -> None:
    import requests

    class _Resp:
        status_code = 404

    class _Err(requests.HTTPError):
        def __init__(self) -> None:
            super().__init__("404")
            self.response = _Resp()

    from brumby import cli

    orig_get_latest_version = cli.get_latest_version
    try:
        cli.get_latest_version = lambda package: (_ for _ in ()).throw(_Err())
        args = type("Args", (), {
            "config": "",
            "package": "missing-pkg",
            "version": "",
            "summary": False,
            "finder": "imports_base64",
            "fast": False,
            "save_artifacts": "",
        })()
        assert cli.cmd_inspect(args) == 0
    finally:
        cli.get_latest_version = orig_get_latest_version


def test_inspect_single_finder_works_for_remote_package_version() -> None:
    from brumby import cli

    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "demo-1.0-py3-none-any.whl"
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("demo/proxy.py", b"import base64\n")

        artifact = make_local_artifact(path)
        orig_get_latest_version = cli.get_latest_version
        orig_get_package_info = cli.get_package_info
        orig_get_artifacts = cli.get_artifacts
        try:
            cli.get_latest_version = lambda package: "1.0"
            cli.get_package_info = lambda package: {"releases": {"1.0": []}}
            cli.get_artifacts = lambda package, version, pkg_info=None, save_dir=None: [artifact]
            args = type("Args", (), {
                "config": "",
                "package": "demo",
                "version": "1.0",
                "summary": False,
                "finder": "imports_base64",
                "fast": False,
                "save_artifacts": "",
            })()
            assert cmd_inspect(args) == 1
        finally:
            cli.get_latest_version = orig_get_latest_version
            cli.get_package_info = orig_get_package_info
            cli.get_artifacts = orig_get_artifacts
