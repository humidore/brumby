import json

import pytest
import requests

from brumby import api, cli


def _args(package: str = "demo", as_json: bool = False) -> object:
    return type(
        "Args",
        (),
        {
            "config": "",
            "package": package,
            "cutoff": 24,
            "fast": False,
            "save_artifacts": "",
            "json": as_json,
            "stable": "",
            "new": "",
        },
    )()


@pytest.mark.parametrize(
    ("risk", "fragment"),
    [
        ("high", "\033[31mhigh risk\033[0m"),
        ("average", "\033[32maverage risk\033[0m"),
        ("too new", "\033[33mtoo new to evaluate\033[0m"),
        ("did not scan", "did not scan"),
    ],
)
def test_assess_formats_each_verdict(risk, fragment) -> None:
    assert fragment in cli._assess_line("demo", risk)


def test_assess_passes_cli_options_and_prints_result(monkeypatch, capsys) -> None:
    recorded = {}
    config = {"thresholds": {"sus": 2}}
    monkeypatch.setattr(cli, "load_config", lambda path: config)

    def fake_assess(package, **kwargs):
        recorded["package"] = package
        recorded.update(kwargs)
        return api.AssessResult(package, "average", "check", "1.0", "2.0")

    monkeypatch.setattr(api, "assess", fake_assess)
    args = _args()
    args.stable = "1.0"
    args.new = "2.0"
    args.cutoff = 12
    args.fast = True
    args.save_artifacts = "saved"

    assert cli.cmd_assess(args) == 0
    assert capsys.readouterr().out == cli._assess_line("demo", "average") + "\n"
    assert recorded == {
        "package": "demo",
        "stable_version": "1.0",
        "new_version": "2.0",
        "cutoff_hours": 12,
        "content": False,
        "save_dir": "saved",
        "config": config,
    }


def test_assess_json_prints_structured_result(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        api, "assess", lambda *args, **kwargs: api.AssessResult("demo", "high", "check")
    )

    assert cli.cmd_assess(_args(as_json=True)) == 0
    assert json.loads(capsys.readouterr().out) == {"project": "demo", "risk": "high"}


def test_assess_scan_skip_is_not_an_error(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        api, "assess", lambda *args, **kwargs: (_ for _ in ()).throw(api.ScanSkipped("large"))
    )

    assert cli.cmd_assess(_args(as_json=True)) == 0
    assert json.loads(capsys.readouterr().out) == {"project": "demo", "risk": "did not scan"}


def test_assess_404_is_a_json_error(monkeypatch, capsys) -> None:
    response = requests.Response()
    response.status_code = 404
    monkeypatch.setattr(
        api,
        "assess",
        lambda *args, **kwargs: (_ for _ in ()).throw(requests.HTTPError(response=response)),
    )

    assert cli.cmd_assess(_args(package="missing", as_json=True)) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert json.loads(captured.err) == {
        "project": "missing",
        "error": "missing not found (HTTP 404)",
    }


def test_assess_value_error_goes_to_stderr(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        api, "assess", lambda *args, **kwargs: (_ for _ in ()).throw(ValueError("bad input"))
    )

    assert cli.cmd_assess(_args()) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "error: bad input\n"
