import tempfile
import zipfile
from pathlib import Path

from brumby.analyze import analyze_artifacts
from brumby.artifact import make_local_artifact
from brumby.finders.source import find_high_entropy_blob, find_high_entropy_source, find_long_source_line
from brumby.finding import Finding


class _DummyView:
    def __init__(
        self,
        files: list[tuple[str, bytes]],
        filename: str = "pkg-1.0.whl",
        filetype: str = "wheel",
        resource: str = "wheel",
    ) -> None:
        self._files = files
        self.filename = filename
        self.filetype = filetype
        self.resource = resource

    def iter_files(self, exts=None):
        yield from self._files


def test_long_source_line_uses_filename_value() -> None:
    view = _DummyView([("pkg/module.py", b"ok\n" + b"x" * 12)])

    findings = find_long_source_line(view, {"threshold": 10})

    assert findings == [Finding("long_source_line", "module.py", "pkg-1.0.whl", "wheel")]


def test_long_source_line_respects_threshold() -> None:
    view = _DummyView([("pkg/module.py", b"ok\n" + b"x" * 12)])

    assert find_long_source_line(view, {"threshold": 20}) == []


def test_long_source_line_reports_multiple_files() -> None:
    view = _DummyView(
        [
            ("litellm/constants.py", b"ok\n" + b"x" * 12),
            ("litellm/proxy/proxy_server.py", b"ok\n" + b"y" * 12),
        ]
    )

    assert find_long_source_line(view, {"threshold": 10}) == [
        Finding("long_source_line", "constants.py", "pkg-1.0.whl", "wheel"),
        Finding("long_source_line", "proxy_server.py", "pkg-1.0.whl", "wheel"),
    ]


def test_high_entropy_source_uses_lines_not_sliding_windows() -> None:
    base64ish = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    view = _DummyView([("pkg/proxy.py", b"prefix\n" + base64ish * 4 + b"\nsuffix\n")])

    findings = find_high_entropy_source(view, {"threshold": 5.5, "max_line_length": 8192})

    assert findings == [Finding("high_entropy_source", "proxy.py", "pkg-1.0.whl", "wheel")]


def test_high_entropy_source_skips_overly_long_lines() -> None:
    base64ish = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    view = _DummyView([("pkg/proxy.py", base64ish * 200 + b"\n")])

    assert find_high_entropy_source(view, {"threshold": 5.5, "max_line_length": 8192}) == []


def test_high_entropy_blob_reports_overly_long_lines() -> None:
    base64ish = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    view = _DummyView([("pkg/proxy.py", base64ish * 200 + b"\n")])

    assert find_high_entropy_blob(view, {"max_line_length": 8192}) == [
        Finding("high_entropy_blob", "proxy.py", "pkg-1.0.whl", "wheel")
    ]


def test_setup_install_hook_triggers() -> None:
    from brumby.finders.source import find_setup_install_hook

    view = _DummyView(
        [("pkg-1.0/setup.py", b"from setuptools.command.install import install\nclass P(install):\n    def run(self): install.run(self)\n")]
    )

    assert find_setup_install_hook(view, {}) == [Finding("setup_install_hook", True, "pkg-1.0.whl", "wheel")]


def test_setup_install_hook_no_trigger_plain_setup() -> None:
    from brumby.finders.source import find_setup_install_hook

    view = _DummyView([("pkg-1.0/setup.py", b"from setuptools import setup\nsetup(name='foo')\n")])

    assert find_setup_install_hook(view, {}) == []


def test_setup_install_hook_no_trigger_non_setup_file() -> None:
    from brumby.finders.source import find_setup_install_hook

    view = _DummyView([("pkg/helper.py", b"from setuptools.command.install import install\n")])

    assert find_setup_install_hook(view, {}) == []


def test_spawns_from_init_triggers_on_execv() -> None:
    from brumby.finders.source import find_spawns_from_init

    view = _DummyView([("pkg/__init__.py", b"import os\nos.execv('/bin/sh', ['/bin/sh'])\n")])

    assert find_spawns_from_init(view, {}) == [Finding("spawns_from_init", True, "pkg-1.0.whl", "wheel")]


def test_spawns_from_init_triggers_on_execve_variant() -> None:
    from brumby.finders.source import find_spawns_from_init

    view = _DummyView([("pkg/__init__.py", b"import os\nos.execve('/bin/sh', ['/bin/sh'], {})\n")])

    assert find_spawns_from_init(view, {}) == [Finding("spawns_from_init", True, "pkg-1.0.whl", "wheel")]


def test_spawns_from_init_triggers_on_execvp_variant() -> None:
    from brumby.finders.source import find_spawns_from_init

    view = _DummyView([("pkg/__init__.py", b"import os\nos.execvp('sh', ['sh'])\n")])

    assert find_spawns_from_init(view, {}) == [Finding("spawns_from_init", True, "pkg-1.0.whl", "wheel")]


def test_spawns_from_init_triggers_on_spawnve_variant() -> None:
    from brumby.finders.source import find_spawns_from_init

    view = _DummyView([("pkg/__init__.py", b"import os\nos.spawnve(0, '/bin/sh', ['/bin/sh'], {})\n")])

    assert find_spawns_from_init(view, {}) == [Finding("spawns_from_init", True, "pkg-1.0.whl", "wheel")]


def test_spawns_from_init_ignores_unrelated_os_calls() -> None:
    from brumby.finders.source import find_spawns_from_init

    view = _DummyView([("pkg/__init__.py", b"import os\nos.path.join('a', 'b')\n")])

    assert find_spawns_from_init(view, {}) == []


def test_imports_base64_reports_every_matching_file() -> None:
    from brumby.finders.source import find_imports_base64

    view = _DummyView(
        [
            ("pkg/a.py", b"import base64\n"),
            ("pkg/b.py", b"from base64 import b64decode\n"),
        ]
    )

    assert find_imports_base64(view, {}) == [
        Finding("imports_base64", "a.py", "pkg-1.0.whl", "wheel"),
        Finding("imports_base64", "b.py", "pkg-1.0.whl", "wheel"),
    ]


def test_python_in_non_py_file_flags_docstring_and_imports() -> None:
    from brumby.finders.source import find_python_in_non_py_file

    view = _DummyView([("pkg/script", b'"""Module docstring"""\nimport os\n')], filetype="wheel")

    assert find_python_in_non_py_file(view, {}) == [
        Finding("python_in_non_py_file", "script", "pkg-1.0.whl", "wheel")
    ]


def test_python_in_non_py_file_flags_python_shebang() -> None:
    from brumby.finders.source import find_python_in_non_py_file

    view = _DummyView([("pkg/script", b"#!/usr/bin/env python3\nprint('hi')\n")], filetype="wheel")

    assert find_python_in_non_py_file(view, {}) == [
        Finding("python_in_non_py_file", "script", "pkg-1.0.whl", "wheel")
    ]


def test_high_entropy_source_is_enabled_by_default() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "demo-1.0-py3-none-any.whl"
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("demo/proxy.py", b"prefix\n" + (b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" * 4) + b"\n")

        findings = analyze_artifacts([make_local_artifact(path)], {}, content=True)

        assert any(f.name == "high_entropy_source" and f.value == "proxy.py" for f in findings)


def test_high_entropy_blob_is_enabled_by_default() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "demo-1.0-py3-none-any.whl"
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("demo/proxy.py", (b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" * 200) + b"\n")

        findings = analyze_artifacts([make_local_artifact(path)], {}, content=True)

        assert any(f.name == "high_entropy_blob" and f.value == "proxy.py" for f in findings)


def test_python_in_non_py_file_is_enabled_by_default() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "demo-1.0-py3-none-any.whl"
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("demo/script", b'"""Module docstring"""\nimport os\n')

        findings = analyze_artifacts([make_local_artifact(path)], {}, content=True)

        assert any(f.name == "python_in_non_py_file" and f.value == "script" for f in findings)
