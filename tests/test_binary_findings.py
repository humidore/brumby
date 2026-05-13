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
