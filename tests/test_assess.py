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


def _args(package: str = "demo", fast: bool = False) -> object:
    return type(
        "Args",
        (),
        {
            "config": "",
            "package": package,
            "cutoff": 24,
            "fast": fast,
            "save_artifacts": "",
        },
    )()


def test_assess_check_mode_is_high_risk_for_any_sketchy_diff_by_default(monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "get_package_info", lambda package: _pkg_info())
    monkeypatch.setattr(cli, "select_assess_mode", lambda package, cutoff_hours=24, pkg_info=None: ("check", "1.0", "1.1"))
    monkeypatch.setattr(
        cli,
        "check_package",
        lambda *args, **kwargs: (
            [],
            [],
            [
                ("has_elf_binary", None, frozenset(), frozenset(), frozenset(), frozenset(), "sketchy"),
            ],
        ),
    )

    assert cli.cmd_assess(_args()) == 1
    out = capsys.readouterr().out
    assert out == cli._assess_line("demo", "high") + "\n"


def test_assess_check_mode_respects_configured_sus_threshold(monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "get_package_info", lambda package: _pkg_info())
    monkeypatch.setattr(cli, "select_assess_mode", lambda package, cutoff_hours=24, pkg_info=None: ("check", "1.0", "1.1"))
    monkeypatch.setattr(cli, "load_config", lambda path: {"thresholds": {"sus": 2}})
    monkeypatch.setattr(
        cli,
        "check_package",
        lambda *args, **kwargs: (
            [],
            [],
            [
                ("has_elf_binary", None, frozenset(), frozenset(), frozenset(), frozenset(), "sketchy"),
            ],
        ),
    )

    assert cli.cmd_assess(_args()) == 0
    out = capsys.readouterr().out
    assert out == cli._assess_line("demo", "average") + "\n"


def test_assess_inspect_mode_is_high_risk_for_any_sketchy_finding(monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "get_package_info", lambda package: _pkg_info())
    monkeypatch.setattr(cli, "select_assess_mode", lambda package, cutoff_hours=24, pkg_info=None: ("inspect", None, "1.1"))
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
