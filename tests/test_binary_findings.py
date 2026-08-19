from brumby.finders.binary import find_binary_types
from brumby.finding import Finding


class _DummyView:
    def __init__(self, files: list[tuple[str, bytes]], filename: str = "pkg-1.0.whl") -> None:
        self._files = files
        self.filename = filename
        self.filetype = "wheel"
        self.resource = "wheel"

    def iter_file_headers(self, n=4, exts=None):
        for name, header in self._files:
            leaf = name.rsplit("/", 1)[-1]
            if exts is not None:
                ext = "." + leaf.rsplit(".", 1)[-1].lower() if "." in leaf else ""
                if ext not in exts:
                    continue
            yield name, header[:n]


def test_binary_types_detects_scr_extension() -> None:
    view = _DummyView([("pkg/tool.scr", b"MZ....")])

    assert find_binary_types(view, {}) == [Finding("has_pe_binary", "tool.scr", "pkg-1.0.whl", "wheel")]


def test_binary_types_detects_extensionless_elf() -> None:
    view = _DummyView([("pkg/bin/tool", b"\x7fELF....")])

    assert find_binary_types(view, {}) == [Finding("has_elf_binary", "tool", "pkg-1.0.whl", "wheel")]


def test_binary_types_detects_uppercase_exe_extension() -> None:
    view = _DummyView([("pkg/APP.EXE", b"MZ....")])

    assert find_binary_types(view, {}) == [Finding("has_pe_binary", "APP.EXE", "pkg-1.0.whl", "wheel")]


def test_binary_types_detects_versioned_shared_library() -> None:
    view = _DummyView([("pkg/lib/libcmake.so.3", b"\x7fELF....")])

    assert find_binary_types(view, {}) == [Finding("has_elf_binary", "libcmake.so.3", "pkg-1.0.whl", "wheel")]


def test_binary_types_detects_aout_binary() -> None:
    view = _DummyView([("pkg/bin/legacy", b"\x07\x01....")])

    assert find_binary_types(view, {}) == [Finding("has_aout_binary", "legacy", "pkg-1.0.whl", "wheel")]


def test_binary_types_detects_efi_binary() -> None:
    dos = bytearray(0x100)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = (0x80).to_bytes(4, "little")
    dos[0x80:0x84] = b"PE\x00\x00"
    dos[0x98:0x9A] = (0x10B).to_bytes(2, "little")
    dos[0xDC:0xDE] = (10).to_bytes(2, "little")
    view = _DummyView([("pkg/boot/BOOTX64.EFI", bytes(dos))])

    assert find_binary_types(view, {}) == [
        Finding("has_pe_binary", "BOOTX64.EFI", "pkg-1.0.whl", "wheel"),
        Finding("has_efi_binary", "BOOTX64.EFI", "pkg-1.0.whl", "wheel"),
    ]


def test_binary_types_detects_com_binary_by_extension() -> None:
    view = _DummyView([("pkg/bin/driver.com", b"\x01\x02\x03\x04")])

    assert find_binary_types(view, {}) == [Finding("has_com_binary", "driver.com", "pkg-1.0.whl", "wheel")]


def test_binary_types_uses_member_name_for_sdist_values() -> None:
    view = _DummyView([("uv-0.11.10.data/scripts/uv", b"\x7fELF....")])
    view.filetype = "sdist"
    view.resource = "sdist-format=tar.gz"
    view.filename = "uv-0.11.10.tar.gz"

    assert find_binary_types(view, {}) == [Finding("has_elf_binary", "uv", "uv-0.11.10.tar.gz", "sdist-format=tar.gz")]


def test_binary_types_strips_sdist_directory_from_value() -> None:
    view = _DummyView([("uv-0.11.10.data/scripts/uv.exe", b"MZ....")])
    view.filetype = "sdist"
    view.resource = "sdist-format=tar.gz"
    view.filename = "uv-0.11.10.tar.gz"

    assert find_binary_types(view, {}) == [Finding("has_pe_binary", "uv.exe", "uv-0.11.10.tar.gz", "sdist-format=tar.gz")]


def test_py_file_not_python_flags_non_python_shebang() -> None:
    from brumby.finders.binary import find_py_file_not_python

    view = _DummyView([("pkg/tool.py", b"#!/bin/sh\necho hi\n")])

    assert find_py_file_not_python(view, {}) == [
        Finding("py_file_not_python", "tool.py", "pkg-1.0.whl", "wheel")
    ]


def test_py_file_not_python_ignores_ordinary_python_shebang() -> None:
    from brumby.finders.binary import find_py_file_not_python

    view = _DummyView([("pkg/tool.py", b"#!/usr/bin/env python3\nprint('hi')\n")])

    assert find_py_file_not_python(view, {}) == []


def test_py_file_not_python_ignores_freethreaded_shebang() -> None:
    from brumby.finders.binary import find_py_file_not_python

    view = _DummyView([("pkg/tool.py", b"#!/usr/bin/env python3.13t\nprint('hi')\n")])

    assert find_py_file_not_python(view, {}) == []


def test_py_file_not_python_flags_binary_python_file() -> None:
    from brumby.finders.binary import find_py_file_not_python

    view = _DummyView([("pkg/tool.py", b"MZ....")])

    assert find_py_file_not_python(view, {}) == [
        Finding("py_file_not_python", "tool.py", "pkg-1.0.whl", "wheel")
    ]


def test_py_file_not_python_is_enabled_by_default() -> None:
    import tempfile
    import zipfile
    from pathlib import Path

    from brumby.analyze import analyze_artifacts
    from brumby.artifact import make_local_artifact

    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "demo-1.0-py3-none-any.whl"
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("demo/tool.py", b"#!/bin/sh\necho hi\n")

        findings = analyze_artifacts([make_local_artifact(path)], {}, content=True)

        assert any(f.name == "py_file_not_python" and f.value == "tool.py" for f in findings)
