import tempfile
import zipfile
from pathlib import Path

import brumby.finders.source as source_mod
from brumby.analyze import analyze_artifacts
from brumby.artifact import make_local_artifact
from brumby.finders.source import (
    find_giant_python_file,
    find_high_entropy_blob,
    find_high_entropy_source,
    find_long_source_line,
    find_spawns_at_import,
)
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

    def relative_name(self, name: str) -> str:
        if self.filetype == "sdist" and "/" in name:
            return name.split("/", 1)[1]
        return name


def test_long_source_line_uses_filename_value() -> None:
    view = _DummyView([("pkg/module.py", b"ok\n" + b"x" * 12)])

    findings = find_long_source_line(view, {"threshold": 10})

    assert findings == [Finding("long_source_line", "pkg/module.py", "pkg-1.0.whl", "wheel")]


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
        Finding("long_source_line", "litellm/constants.py", "pkg-1.0.whl", "wheel"),
        Finding("long_source_line", "litellm/proxy/proxy_server.py", "pkg-1.0.whl", "wheel"),
    ]


def test_high_entropy_source_uses_lines_not_sliding_windows() -> None:
    base64ish = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    view = _DummyView([("pkg/proxy.py", b"prefix\n" + base64ish * 4 + b"\nsuffix\n")])

    findings = find_high_entropy_source(view, {"threshold": 5.5, "max_line_length": 8192})

    assert findings == [Finding("high_entropy_source", "pkg/proxy.py", "pkg-1.0.whl", "wheel")]


def test_high_entropy_source_skips_overly_long_lines() -> None:
    base64ish = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    view = _DummyView([("pkg/proxy.py", base64ish * 200 + b"\n")])

    assert find_high_entropy_source(view, {"threshold": 5.5, "max_line_length": 8192}) == []


def test_high_entropy_source_skips_sorted_alphabet_constant() -> None:
    # The base58 alphabet: high per-character entropy, but every character is
    # used exactly once -- a charset definition, not encoded/obfuscated data.
    line = b'    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"\n'
    view = _DummyView([("pkg/validation.py", line)])

    assert find_high_entropy_source(view, {"threshold": 5.5, "max_line_length": 8192}) == []


def test_high_entropy_source_skips_unsorted_charset_with_no_repeats() -> None:
    # A url-safe-token charset in "readable" order (lowercase, then uppercase,
    # then digits) rather than ascending byte order -- still a set of unique
    # symbols, not encoded data, so it should be skipped the same way.
    line = b'    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"\n'
    view = _DummyView([("pkg/service.py", line)])

    assert find_high_entropy_source(view, {"threshold": 5.5, "max_line_length": 8192}) == []


def test_high_entropy_source_still_reports_string_with_repeated_characters() -> None:
    # Same alphabet, shuffled, with four characters (h, i, g, j) repeated --
    # no longer a clean set of unique symbols, still looks like a real payload.
    shuffled = b"qatyxbmpencrfd39ks6ug5wojhi2z710vl48UVWXYZABCDEFGHJKLMNPQRSTghij"
    line = b'    blob = "' + shuffled + b'"\n'
    view = _DummyView([("pkg/validation.py", line)])

    assert find_high_entropy_source(view, {"threshold": 5.5, "max_line_length": 8192}) == [
        Finding("high_entropy_source", "pkg/validation.py", "pkg-1.0.whl", "wheel")
    ]


def test_giant_python_file_reports_line_count_over_threshold() -> None:
    content = b"\n" * 150
    view = _DummyView([("pkg/data.py", content)])

    assert find_giant_python_file(view, {"threshold": 100}) == [
        Finding("giant_python_file", "pkg/data.py", "pkg-1.0.whl", "wheel")
    ]


def test_giant_python_file_quiet_under_threshold() -> None:
    content = b"\n" * 50
    view = _DummyView([("pkg/data.py", content)])

    assert find_giant_python_file(view, {"threshold": 100}) == []


def test_high_entropy_source_skips_giant_files(monkeypatch) -> None:
    # A file over the giant-file byte-size cutoff is skipped entirely rather
    # than scored line by line -- giant_python_file covers oversized files
    # instead. Patch the module constant down so the test doesn't need an
    # actual megabyte-plus fixture to exercise the skip.
    monkeypatch.setattr(source_mod, "_GIANT_FILE_BYTES", 100)
    base64ish = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    content = b"\n".join([base64ish * 4] * 5)  # well over 100 bytes
    view = _DummyView([("pkg/proxy.py", content)])

    assert find_high_entropy_source(view, {"threshold": 5.5, "max_line_length": 8192}) == []


def test_spawns_at_import_skips_giant_files(monkeypatch) -> None:
    monkeypatch.setattr(source_mod, "_GIANT_FILE_BYTES", 10)
    content = b"import subprocess\n" + b"\n" * 5 + b"subprocess.call(['ls'])\n"
    view = _DummyView([("pkg/module.py", content)])

    assert find_spawns_at_import(view, {}) == []


def test_high_entropy_blob_reports_overly_long_lines() -> None:
    base64ish = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    view = _DummyView([("pkg/proxy.py", base64ish * 200 + b"\n")])

    assert find_high_entropy_blob(view, {"max_line_length": 8192}) == [
        Finding("high_entropy_blob", "pkg/proxy.py", "pkg-1.0.whl", "wheel")
    ]


def test_imports_base64_reports_every_matching_file() -> None:
    from brumby.finders.source import find_imports_base64

    view = _DummyView(
        [
            ("pkg/a.py", b"import base64\n"),
            ("pkg/b.py", b"from base64 import b64decode\n"),
        ]
    )

    assert find_imports_base64(view, {}) == [
        Finding("imports_base64", "pkg/a.py", "pkg-1.0.whl", "wheel"),
        Finding("imports_base64", "pkg/b.py", "pkg-1.0.whl", "wheel"),
    ]


def test_high_entropy_source_is_enabled_by_default() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "demo-1.0-py3-none-any.whl"
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("demo/proxy.py", b"prefix\n" + (b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" * 4) + b"\n")

        findings = analyze_artifacts([make_local_artifact(path)], {}, content=True)

        assert any(f.name == "high_entropy_source" and f.value == "demo/proxy.py" for f in findings)


def test_high_entropy_blob_is_enabled_by_default() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "demo-1.0-py3-none-any.whl"
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("demo/proxy.py", (b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" * 200) + b"\n")

        findings = analyze_artifacts([make_local_artifact(path)], {}, content=True)

        assert any(f.name == "high_entropy_blob" and f.value == "demo/proxy.py" for f in findings)
