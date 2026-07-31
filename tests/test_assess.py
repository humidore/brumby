import json

import requests

from brumby import cli
from brumby.finding import Finding


def _pkg_info() -> dict:
    return {
        "info": {"version": "1.1"},
        "releases": {
            "1.0": [{"upload_time_iso_8601": "2026-05-06T10:00:00+00:00"}],
            "1.1": [{"upload_time_iso_8601": "2026-05-08T11:00:00+00:00"}],
        },
    }


def _args(
    package: str = "demo",
    fast: bool = False,
    as_json: bool = False,
    stable: str = "",
    new: str = "",
) -> object:
    return type(
        "Args",
        (),
        {
            "config": "",
            "package": package,
            "cutoff": 24,
            "fast": fast,
            "save_artifacts": "",
            "json": as_json,
            "stable": stable,
            "new": new,
        },
    )()


def _boom(*args, **kwargs):
    raise AssertionError("auto-detection should not run for supplied versions")


def test_assess_check_mode_is_high_risk_for_any_sketchy_diff_by_default(
    monkeypatch, capsys
) -> None:
    monkeypatch.setattr(cli, "get_package_info", lambda package: _pkg_info())
    monkeypatch.setattr(
        cli,
        "select_assess_mode",
        lambda package, **kwargs: ("check", "1.0", "1.1"),
    )
    monkeypatch.setattr(
        cli,
        "check_package",
        lambda *args, **kwargs: (
            [],
            [],
            [
                (
                    "has_elf_binary",
                    None,
                    frozenset(),
                    frozenset(),
                    frozenset(),
                    frozenset(),
                    "sketchy",
                ),
            ],
        ),
    )

    assert cli.cmd_assess(_args()) == 1
    out = capsys.readouterr().out
    assert out == cli._assess_line("demo", "high") + "\n"


def test_assess_check_mode_respects_configured_sus_threshold(
    monkeypatch, capsys
) -> None:
    monkeypatch.setattr(cli, "get_package_info", lambda package: _pkg_info())
    monkeypatch.setattr(
        cli,
        "select_assess_mode",
        lambda package, **kwargs: ("check", "1.0", "1.1"),
    )
    monkeypatch.setattr(cli, "load_config", lambda path: {"thresholds": {"sus": 2}})
    monkeypatch.setattr(
        cli,
        "check_package",
        lambda *args, **kwargs: (
            [],
            [],
            [
                (
                    "has_elf_binary",
                    None,
                    frozenset(),
                    frozenset(),
                    frozenset(),
                    frozenset(),
                    "sketchy",
                ),
            ],
        ),
    )

    assert cli.cmd_assess(_args()) == 0
    out = capsys.readouterr().out
    assert out == cli._assess_line("demo", "average") + "\n"


def test_assess_inspect_mode_is_high_risk_for_any_sketchy_finding(
    monkeypatch, capsys
) -> None:
    monkeypatch.setattr(cli, "get_package_info", lambda package: _pkg_info())
    monkeypatch.setattr(
        cli,
        "select_assess_mode",
        lambda package, **kwargs: ("inspect", None, "1.1"),
    )
    monkeypatch.setattr(cli, "get_artifacts", lambda *args, **kwargs: [object()])
    monkeypatch.setattr(
        cli,
        "analyze_release",
        lambda *args, **kwargs: [
            Finding("has_pth_file", True, "demo-1.1-py3-none-any.whl", "wheel"),
            Finding("metadata_version", "2.4", "demo-1.1-py3-none-any.whl", "wheel"),
        ],
    )

    assert cli.cmd_assess(_args()) == 1
    out = capsys.readouterr().out
    assert out == cli._assess_line("demo", "high") + "\n"


def test_assess_uses_supplied_versions(monkeypatch, capsys) -> None:
    recorded: dict = {}

    def _fake_check_package(package, **kwargs):
        recorded.update(kwargs)
        return ([], [], [])

    monkeypatch.setattr(cli, "get_package_info", lambda package: _pkg_info())
    monkeypatch.setattr(cli, "check_package", _fake_check_package)

    assert cli.cmd_assess(_args(stable="1.0", new="1.1")) == 0
    assert recorded["stable_version"] == "1.0"
    assert recorded["new_version"] == "1.1"
    assert capsys.readouterr().out == cli._assess_line("demo", "average") + "\n"


def test_assess_supplied_new_resolves_stable_from_its_release_time(monkeypatch) -> None:
    recorded: dict = {}

    def _fake_check_package(package, **kwargs):
        recorded.update(kwargs)
        return ([], [], [])

    monkeypatch.setattr(cli, "get_package_info", lambda package: _pkg_info())
    monkeypatch.setattr(cli, "check_package", _fake_check_package)

    assert cli.cmd_assess(_args(new="1.1")) == 0
    assert recorded["stable_version"] == "1.0"
    assert recorded["new_version"] == "1.1"


def test_assess_supplied_new_without_baseline_falls_back_to_inspect(monkeypatch) -> None:
    recorded: dict = {}

    def _fake_get_artifacts(package, version, **kwargs):
        recorded["version"] = version
        return [object()]

    monkeypatch.setattr(cli, "get_package_info", lambda package: _pkg_info())
    monkeypatch.setattr(cli, "check_package", _boom)
    monkeypatch.setattr(cli, "get_artifacts", _fake_get_artifacts)
    monkeypatch.setattr(cli, "analyze_release", lambda *args, **kwargs: [])

    assert cli.cmd_assess(_args(new="1.0")) == 0
    assert recorded["version"] == "1.0"


def test_assess_rejects_supplied_versions_for_local_artifact(tmp_path, capsys) -> None:
    artifact = tmp_path / "demo-1.0.tar.gz"
    artifact.touch()

    assert cli.cmd_assess(_args(package=str(artifact), new="1.1")) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "local artifact" in captured.err


def test_assess_rejects_invalid_supplied_version(monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "get_package_info", lambda package: _pkg_info())

    assert cli.cmd_assess(_args(new="not a version")) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "invalid version" in captured.err


def test_assess_json_emits_project_and_risk(monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "get_package_info", lambda package: _pkg_info())
    monkeypatch.setattr(
        cli,
        "select_assess_mode",
        lambda package, **kwargs: ("check", "1.0", "1.1"),
    )
    monkeypatch.setattr(cli, "check_package", lambda *args, **kwargs: ([], [], []))

    assert cli.cmd_assess(_args(as_json=True)) == 0
    out = capsys.readouterr().out
    assert json.loads(out) == {"project": "demo", "risk": "average"}


def test_assess_json_high_risk_still_exits_1(monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "get_package_info", lambda package: _pkg_info())
    monkeypatch.setattr(
        cli,
        "select_assess_mode",
        lambda package, **kwargs: ("check", "1.0", "1.1"),
    )
    monkeypatch.setattr(
        cli,
        "check_package",
        lambda *args, **kwargs: (
            [],
            [],
            [
                (
                    "has_elf_binary",
                    None,
                    frozenset(),
                    frozenset(),
                    frozenset(),
                    frozenset(),
                    "sketchy",
                ),
            ],
        ),
    )

    assert cli.cmd_assess(_args(as_json=True)) == 1
    out = capsys.readouterr().out
    assert json.loads(out) == {"project": "demo", "risk": "high"}


def test_assess_json_did_not_scan(monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "get_package_info", lambda package: _pkg_info())
    monkeypatch.setattr(
        cli,
        "select_assess_mode",
        lambda package, **kwargs: ("check", "1.0", "1.1"),
    )
    monkeypatch.setattr(
        cli,
        "check_package",
        lambda *args, **kwargs: (_ for _ in ()).throw(cli.ScanSkipped("did not scan")),
    )

    assert cli.cmd_assess(_args(as_json=True)) == 0
    out = capsys.readouterr().out
    assert json.loads(out) == {"project": "demo", "risk": "did not scan"}


def test_assess_json_error_on_404_goes_to_stderr(monkeypatch, capsys) -> None:
    response = requests.Response()
    response.status_code = 404

    def _raise_404(package: str) -> dict:
        raise requests.HTTPError(response=response)

    monkeypatch.setattr(cli, "get_package_info", _raise_404)

    assert cli.cmd_assess(_args(package="nope", as_json=True)) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert json.loads(captured.err) == {
        "project": "nope",
        "error": "nope not found (HTTP 404)",
    }


def test_assess_json_error_on_only_one_version_goes_to_stderr(
    monkeypatch, capsys
) -> None:
    monkeypatch.setattr(cli, "get_package_info", lambda package: _pkg_info())
    monkeypatch.setattr(
        cli,
        "select_assess_mode",
        lambda package, **kwargs: ("inspect", None, ""),
    )

    assert cli.cmd_assess(_args(as_json=True)) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert json.loads(captured.err) == {
        "project": "demo",
        "error": "Only one version found for demo",
    }
