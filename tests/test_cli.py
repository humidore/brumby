import datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
import requests
from brumby import api, cli
from brumby.finding import Finding


def _args(**changes):
    values = {
        "command": "",
        "config": "",
        "package": "demo",
        "other": "",
        "stable": "",
        "new": "",
        "cutoff": 24,
        "last_two": False,
        "last": False,
        "list_only": False,
        "fast": False,
        "save_artifacts": "",
        "version": "",
        "summary": False,
        "finder": "",
        "output": "",
        "json": False,
        "trace": "",
    }
    values.update(changes)
    return SimpleNamespace(**values)


def _difference(kind="sketchy") -> api.Difference:
    return api.Difference(
        "changed_finding",
        "wheel",
        frozenset({"gone"}),
        frozenset({"added"}),
        frozenset({"old.whl", None}),
        frozenset({"new.whl"}),
        kind,
    )


def test_format_helpers_handle_empty_values_and_sources(monkeypatch) -> None:
    recorded = []
    monkeypatch.setattr(cli, "load_config", lambda path: recorded.append(path) or {})

    assert cli._fmt_vals(frozenset()) == "(absent)"
    assert cli._fmt_vals(frozenset({"a", "b"})) == "{a, b}"
    assert cli._fmt_source_set(frozenset()) == ""
    assert cli._load_config(_args(config="custom.toml")) == {}
    assert recorded == [Path("custom.toml")]


def test_sketchy_formatter_handles_one_sided_changes(capsys) -> None:
    cli._default_callback(
        "demo", "1.0", "2.0", "added", None,
        frozenset(), frozenset({"new"}), frozenset(), frozenset(), "sketchy",
    )
    cli._default_callback(
        "demo", "1.0", "2.0", "removed", None,
        frozenset({"old"}), frozenset(), frozenset(), frozenset(), "sketchy",
    )

    out = capsys.readouterr().out
    assert "added @ (release): new: new" in out
    assert "removed @ (release): gone: old" in out


def test_check_prints_package_differences_and_totals(monkeypatch, capsys) -> None:
    old_date = datetime.datetime(2025, 1, 1, tzinfo=datetime.UTC)
    result = api.CheckResult(
        "demo",
        "package",
        api.ReleaseRef("demo 1.0", "1.0", (old_date, old_date)),
        api.ReleaseRef("demo 2.0", "2.0"),
        [],
        [],
        [_difference(), _difference("informational")],
    )
    monkeypatch.setattr(api, "check", lambda *args, **kwargs: result)

    assert cli.cmd_check(_args()) == 2
    out = capsys.readouterr().out
    assert "Package: demo" in out
    assert "stable: 1.0 (base: 2025-01-01)" in out
    assert "new:    2.0 (base: unknown)" in out
    assert "[X]" in out
    assert "new: added, gone: gone" in out
    assert "[i]" in out
    assert "gone → added" in out
    assert "[(release), new.whl, old.whl]" in out
    assert "demo: 2 difference(s) found" in out
    assert "delta: +0 (add=2 remove=2)" in out


@pytest.mark.parametrize(
    ("source", "label", "heading"),
    [("local", "local compare", "Local compare:"), ("url", "url compare", "URL compare:")],
)
def test_check_prints_nonpackage_comparisons(monkeypatch, capsys, source, label, heading) -> None:
    result = api.CheckResult(
        label, source, api.ReleaseRef("old"), api.ReleaseRef("new"), [], [], []
    )
    monkeypatch.setattr(api, "check", lambda *args, **kwargs: result)

    assert cli.cmd_check(_args()) == 0
    out = capsys.readouterr().out
    assert heading in out
    assert "old: old" in out
    assert "new: new" in out
    assert f"{label}: no differences found" in out


def test_check_list_only_prints_missing_versions(monkeypatch, capsys) -> None:
    result = api.CheckResult(
        "demo", "package", api.ReleaseRef("demo"), api.ReleaseRef("demo"),
        [], [], [], list_only=True,
    )
    monkeypatch.setattr(api, "check", lambda *args, **kwargs: result)

    assert cli.cmd_check(_args(list_only=True)) == 0
    assert capsys.readouterr().out.endswith("  stable: (none)\n  new:    (none)\n")


@pytest.mark.parametrize(
    ("error", "code", "stream", "text"),
    [
        (api.ScanSkipped("large"), 0, "out", "demo: did not scan"),
        (ValueError("bad pair"), 1, "err", "error: bad pair"),
    ],
)
def test_check_formats_expected_failures(monkeypatch, capsys, error, code, stream, text) -> None:
    monkeypatch.setattr(api, "check", lambda *args, **kwargs: (_ for _ in ()).throw(error))

    assert cli.cmd_check(_args()) == code
    assert text in getattr(capsys.readouterr(), stream)


def test_check_formats_404(monkeypatch, capsys) -> None:
    response = requests.Response()
    response.status_code = 404
    monkeypatch.setattr(
        api,
        "check",
        lambda *args, **kwargs: (_ for _ in ()).throw(requests.HTTPError(response=response)),
    )

    assert cli.cmd_check(_args()) == 1
    assert capsys.readouterr().err == "error: demo not found (HTTP 404)\n"


def test_inspect_prints_findings_and_uses_finder_exit_status(monkeypatch, capsys) -> None:
    result = api.InspectResult(
        "demo 2.0", [Finding("has_pth_file", True, "demo.whl", "wheel")], "has_pth_file"
    )
    monkeypatch.setattr(api, "inspect", lambda *args, **kwargs: result)

    assert cli.cmd_inspect(_args(finder="has_pth_file")) == 1
    out = capsys.readouterr().out
    assert "demo 2.0:" in out
    assert "[X]" in out
    assert "has_pth_file  [demo.whl]" in out


def test_inspect_prints_no_findings(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        api, "inspect", lambda *args, **kwargs: api.InspectResult("demo 2.0", [])
    )

    assert cli.cmd_inspect(_args()) == 0
    assert capsys.readouterr().out == "demo 2.0: no findings\n"


@pytest.mark.parametrize(
    ("error", "finder", "code", "stream", "text"),
    [
        (api.ScanSkipped("large"), "", 0, "out", "demo: did not scan"),
        (ValueError("bad finder"), "", 1, "err", "error: bad finder"),
    ],
)
def test_inspect_formats_expected_failures(
    monkeypatch, capsys, error, finder, code, stream, text
) -> None:
    monkeypatch.setattr(api, "inspect", lambda *args, **kwargs: (_ for _ in ()).throw(error))

    assert cli.cmd_inspect(_args(finder=finder)) == code
    assert text in getattr(capsys.readouterr(), stream)


@pytest.mark.parametrize(("finder", "code"), [("", 1), ("one_finder", 0)])
def test_inspect_preserves_special_finder_404_status(monkeypatch, capsys, finder, code) -> None:
    response = requests.Response()
    response.status_code = 404
    monkeypatch.setattr(
        api,
        "inspect",
        lambda *args, **kwargs: (_ for _ in ()).throw(requests.HTTPError(response=response)),
    )

    assert cli.cmd_inspect(_args(finder=finder)) == code
    assert capsys.readouterr().err == "error: demo not found (HTTP 404)\n"


@pytest.mark.parametrize(
    ("api_name", "command_name"),
    [
        ("export", "cmd_export"),
        ("check", "cmd_check"),
        ("assess", "cmd_assess"),
        ("inspect", "cmd_inspect"),
    ],
)
def test_commands_reraise_non_404_http_errors(monkeypatch, api_name, command_name) -> None:
    response = requests.Response()
    response.status_code = 500
    monkeypatch.setattr(
        api,
        api_name,
        lambda *args, **kwargs: (_ for _ in ()).throw(requests.HTTPError(response=response)),
    )

    with pytest.raises(requests.HTTPError):
        getattr(cli, command_name)(_args())


def test_assess_scan_skip_uses_local_filename(monkeypatch, capsys, tmp_path) -> None:
    artifact = tmp_path / "demo.whl"
    artifact.touch()
    monkeypatch.setattr(
        api, "assess", lambda *args, **kwargs: (_ for _ in ()).throw(api.ScanSkipped("large"))
    )

    assert cli.cmd_assess(_args(package=str(artifact))) == 0
    assert capsys.readouterr().out.startswith("demo.whl")


def test_export_prints_returned_paths_and_passes_config(monkeypatch, capsys, tmp_path) -> None:
    config = {"finders": {}}
    monkeypatch.setattr(cli, "load_config", lambda path: config)
    recorded = {}

    def fake_export(package, other, **kwargs):
        recorded.update(kwargs)
        return api.ExportResult(
            tmp_path / "export",
            api.ReleaseRef("demo 1.0"),
            api.ReleaseRef("demo 2.0"),
            tmp_path / "export/old",
            tmp_path / "export/new",
            tmp_path / "export/PROMPT.md",
        )

    monkeypatch.setattr(api, "export", fake_export)

    assert cli.cmd_export(_args(other="other.whl", output=str(tmp_path / "export"))) == 0
    out = capsys.readouterr().out
    assert f"Exported to {tmp_path / 'export'}" in out
    assert "old:    demo 1.0  -> old/" in out
    assert "new:    demo 2.0  -> new/" in out
    assert recorded["config"] is config


@pytest.mark.parametrize(
    ("error", "code", "stream", "text"),
    [
        (api.ScanSkipped("large"), 0, "out", "demo: large"),
        (ValueError("bad export"), 1, "err", "error: bad export"),
    ],
)
def test_export_formats_expected_failures(monkeypatch, capsys, error, code, stream, text) -> None:
    monkeypatch.setattr(api, "export", lambda *args, **kwargs: (_ for _ in ()).throw(error))

    assert cli.cmd_export(_args()) == code
    assert text in getattr(capsys.readouterr(), stream)


def test_export_formats_404(monkeypatch, capsys) -> None:
    response = requests.Response()
    response.status_code = 404
    monkeypatch.setattr(
        api,
        "export",
        lambda *args, **kwargs: (_ for _ in ()).throw(requests.HTTPError(response=response)),
    )

    assert cli.cmd_export(_args()) == 1
    assert capsys.readouterr().err == "error: demo not found (HTTP 404)\n"


def test_finders_prints_api_rows(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        api,
        "finders",
        lambda config: [
            api.FinderInfo("demo", "description", "artifact", "sketchy", True, True, False)
        ],
    )

    assert cli.cmd_list_finders(_args()) == 0
    out = capsys.readouterr().out
    assert "NAME" in out
    assert "demo" in out
    assert "artifact" in out
    assert "sketchy" in out
    assert "yes" in out
    assert "N" in out
    assert "description" in out


@pytest.mark.parametrize(
    ("argv", "handler"),
    [
        (["brumby", "check", "demo", "--list-only"], "cmd_check"),
        (["brumby", "assess", "demo"], "cmd_assess"),
        (["brumby", "inspect", "demo"], "cmd_inspect"),
        (["brumby", "finders"], "cmd_list_finders"),
        (["brumby", "export", "old.whl", "new.whl"], "cmd_export"),
    ],
)
def test_main_routes_each_command(monkeypatch, argv, handler) -> None:
    called = []
    monkeypatch.setattr(cli.sys, "argv", argv)
    monkeypatch.setattr(cli, handler, lambda args: called.append(args.command) or 0)

    with pytest.raises(SystemExit, match="0"):
        cli.main()
    assert called == [argv[1]]


def test_main_opens_trace_output(monkeypatch, tmp_path) -> None:
    trace = tmp_path / "trace.json"
    monkeypatch.setattr(
        cli.sys, "argv", ["brumby", "assess", "demo", "--trace", str(trace)]
    )
    monkeypatch.setattr(cli, "cmd_assess", lambda args: 0)

    with pytest.raises(SystemExit, match="0"):
        cli.main()
    assert trace.exists()


def test_main_prints_distribution_version(monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli.sys, "argv", ["brumby", "--version"])
    monkeypatch.setattr(cli, "distribution_version", lambda name: "1.2.3")

    with pytest.raises(SystemExit, match="0"):
        cli.main()
    assert capsys.readouterr().out == "brumby 1.2.3\n"


def test_main_without_command_prints_help(monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli.sys, "argv", ["brumby"])

    with pytest.raises(SystemExit, match="1"):
        cli.main()
    assert "usage: brumby" in capsys.readouterr().out
