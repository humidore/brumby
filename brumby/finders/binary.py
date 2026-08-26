"""Native binary detection: ELF, PE/EFI, Mach-O, a.out, COM, musl-in-glibc-wheel."""

import re

from ..artifact import ArtifactView
from ..finding import Finding
from ..registry import register

_ELF = b"\x7fELF"
_PE = b"MZ"
_PE_SIGNATURE = b"PE\x00\x00"
_MACHO = frozenset(
    {b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"}
)
_AOUT_MAGICS = {
    b"\x07\x01",  # OMAGIC 0407
    b"\x08\x01",  # NMAGIC 0410
    b"\x09\x01",  # IMAGIC 0411
    b"\x0b\x01",  # ZMAGIC 0413
    b"\x05\x01",  # A_MAGIC4 0405
    b"\x30\x01",  # A_MAGIC5 0430
    b"\x31\x01",  # A_MAGIC6 0431
    b"\x01\x07",
    b"\x01\x08",
    b"\x01\x09",
    b"\x01\x0b",
    b"\x01\x05",
    b"\x01\x30",
    b"\x01\x31",
}
_EFI_SUBSYSTEMS = {10, 11, 12}
_BINARY_TYPES = ("elf", "pe", "macho", "aout", "efi", "com")
_PYTHON_SHEBANG = re.compile(rb"^#!.*\b(?:python(?:\d+(?:\.\d+)*)?|pypy(?:\d+(?:\.\d+)*)?)t?\b", re.IGNORECASE)


def _wheel_tags(filename: str) -> str:
    """Return the python-abi-platform tag portion of a wheel filename."""
    parts = filename[:-4].rsplit("-", 4)
    return "-".join(parts[2:]) if len(parts) == 5 else filename


_NATIVE_EXTS = {"so", "pyd", "dylib"}


def _normalize_native_leaf(leaf: str) -> str:
    """Strip the CPython ABI/platform tag from a compiled extension's filename
    (e.g. "_native.cpython-311-darwin.so" -> "_native.so", "_native.cp311-
    cp311-win_amd64.pyd" -> "_native.pyd"), so a routine Python-version or
    arch rebuild isn't seen as a brand new binary.

    Only strips when the final segment is itself a known extension -- Unix's
    "libfoo.so.3" convention puts a version number *after* the real
    extension, and collapsing that would eat the ".so" instead of a tag.
    """
    parts = leaf.split(".")
    if len(parts) <= 2 or parts[-1].lower() not in _NATIVE_EXTS:
        return leaf
    return f"{parts[0]}.{parts[-1]}"


def _binary_value(view: ArtifactView, name: str) -> str:
    rel = view.relative_name(name)
    dirpart, sep, leaf = rel.rpartition("/")
    return f"{dirpart}{sep}{_normalize_native_leaf(leaf)}"


def _scan_binary_headers(view: ArtifactView) -> dict[str, str]:
    """Single-pass binary type scan, result cached on the view."""
    # This is slowly turning into binwalk; if we keep widening the format set,
    # we should consider deferring to it when it's fast enough for our use case.
    cache = getattr(view, "_cache", None)
    if cache is not None and "binary_headers" in cache:
        return cache["binary_headers"]
    found: dict[str, str] = {}
    if view.filetype in ("wheel", "sdist"):
        for name, header in view.iter_file_headers(4096):
            if header[:4] == _ELF:
                found.setdefault("elf", name)
            elif header[:2] == _PE:
                found.setdefault("pe", name)
                if _is_efi_binary(header):
                    found.setdefault("efi", name)
            elif header[:4] in _MACHO:
                found.setdefault("macho", name)
            elif header[:2] in _AOUT_MAGICS:
                found.setdefault("aout", name)
            elif name.lower().endswith(".com"):
                # DOS .com binaries do not carry a distinctive magic number, so
                # we fall back to the archive member extension here.
                found.setdefault("com", name)
            if len(found) == len(_BINARY_TYPES):
                break
    if cache is not None:
        cache["binary_headers"] = found
    return found


def _is_efi_binary(header: bytes) -> bool:
    """Return True when a PE image looks like a UEFI image."""
    if len(header) < 0x40:
        return False
    pe_offset = int.from_bytes(header[0x3C:0x40], "little", signed=False)
    if pe_offset <= 0 or pe_offset + 24 > len(header):
        return False
    if header[pe_offset : pe_offset + 4] != _PE_SIGNATURE:
        return False
    coff_offset = pe_offset + 4
    opt_offset = coff_offset + 20
    if opt_offset + 2 > len(header):
        return False
    magic = int.from_bytes(header[opt_offset : opt_offset + 2], "little", signed=False)
    if magic == 0x10B:
        subsystem_offset = opt_offset + 68
    elif magic == 0x20B:
        subsystem_offset = opt_offset + 88
    else:
        return False
    if subsystem_offset + 2 > len(header):
        return False
    subsystem = int.from_bytes(header[subsystem_offset : subsystem_offset + 2], "little", signed=False)
    return subsystem in _EFI_SUBSYSTEMS


def _scan_non_python_py_files(view: ArtifactView) -> dict[str, str]:
    """Return .py files that look non-Python, cached on the view."""
    cache = getattr(view, "_cache", None)
    if cache is not None and "non_python_py_files" in cache:
        return cache["non_python_py_files"]
    found: dict[str, str] = {}
    if view.filetype in ("wheel", "sdist"):
        for name, header in view.iter_file_headers(256, exts={".py"}):
            if header[:4] == _ELF:
                found.setdefault(name, "elf")
                continue
            if header[:2] == _PE:
                found.setdefault(name, "pe")
                continue
            if header[:4] in _MACHO:
                found.setdefault(name, "macho")
                continue
            if header.startswith(b"#!"):
                first_line = header.splitlines()[0]
                if not _PYTHON_SHEBANG.match(first_line):
                    found.setdefault(name, first_line[2:].decode("utf-8", errors="replace").strip() or "shebang")
    if cache is not None:
        cache["non_python_py_files"] = found
    return found


def find_binary_types(view: ArtifactView, cfg: dict) -> list[Finding]:
    """Return findings for all binary types detected (ELF, PE, Mach-O, a.out, EFI, COM)."""
    found = _scan_binary_headers(view)
    results = []
    if "elf" in found:
        results.append(Finding("has_elf_binary", _binary_value(view, found["elf"]), view.filename, view.resource))
    if "pe" in found:
        results.append(Finding("has_pe_binary", _binary_value(view, found["pe"]), view.filename, view.resource))
    if "macho" in found:
        results.append(Finding("has_macho_binary", _binary_value(view, found["macho"]), view.filename, view.resource))
    if "aout" in found:
        results.append(Finding("has_aout_binary", _binary_value(view, found["aout"]), view.filename, view.resource))
    if "efi" in found:
        results.append(Finding("has_efi_binary", _binary_value(view, found["efi"]), view.filename, view.resource))
    if "com" in found:
        results.append(Finding("has_com_binary", _binary_value(view, found["com"]), view.filename, view.resource))
    return results


@register(
    "py_file_not_python",
    ".py files that are actually binary data or use a non-Python shebang",
    kind="sketchy",
    needs_content=True,
)
def find_py_file_not_python(view: ArtifactView, cfg: dict) -> list[Finding]:
    found = _scan_non_python_py_files(view)
    return [Finding("py_file_not_python", _binary_value(view, name), view.filename, view.resource) for name in found]


@register("has_elf_binary", "Archive contains an ELF binary", kind="sketchy", needs_content=True)
def find_elf_binary(view: ArtifactView, cfg: dict) -> list[Finding]:
    found = _scan_binary_headers(view)
    if "elf" in found:
        return [Finding("has_elf_binary", _binary_value(view, found["elf"]), view.filename, view.resource)]
    return []


@register("has_pe_binary", "Archive contains a PE binary", kind="sketchy", needs_content=True)
def find_pe_binary(view: ArtifactView, cfg: dict) -> list[Finding]:
    found = _scan_binary_headers(view)
    if "pe" in found:
        return [Finding("has_pe_binary", _binary_value(view, found["pe"]), view.filename, view.resource)]
    return []


@register("has_macho_binary", "Archive contains a Mach-O binary", kind="sketchy", needs_content=True)
def find_macho_binary(view: ArtifactView, cfg: dict) -> list[Finding]:
    found = _scan_binary_headers(view)
    if "macho" in found:
        return [Finding("has_macho_binary", _binary_value(view, found["macho"]), view.filename, view.resource)]
    return []


@register("has_aout_binary", "Archive contains an a.out binary", kind="sketchy", needs_content=True)
def find_aout_binary(view: ArtifactView, cfg: dict) -> list[Finding]:
    found = _scan_binary_headers(view)
    if "aout" in found:
        return [Finding("has_aout_binary", _binary_value(view, found["aout"]), view.filename, view.resource)]
    return []


@register("has_efi_binary", "Archive contains a UEFI PE binary", kind="sketchy", needs_content=True)
def find_efi_binary(view: ArtifactView, cfg: dict) -> list[Finding]:
    found = _scan_binary_headers(view)
    if "efi" in found:
        return [Finding("has_efi_binary", _binary_value(view, found["efi"]), view.filename, view.resource)]
    return []


@register("has_com_binary", "Archive contains a DOS COM binary", kind="sketchy", needs_content=True)
def find_com_binary(view: ArtifactView, cfg: dict) -> list[Finding]:
    found = _scan_binary_headers(view)
    if "com" in found:
        return [Finding("has_com_binary", _binary_value(view, found["com"]), view.filename, view.resource)]
    return []


@register(
    "musl_in_nonmusl_wheel",
    "musl-linked .so in a wheel whose platform tag is not musllinux",
    kind="sketchy",
    needs_content=True,
)
def find_musl_in_nonmusl(view: ArtifactView, cfg: dict) -> list[Finding]:
    if view.filetype != "wheel":
        return []
    parts = view.filename[:-4].rsplit("-", 4)
    if len(parts) != 5:
        return []
    if "musl" in parts[4].lower():
        return []
    for name, header in view.iter_file_headers(4096, exts={".so"}):
        if b"ld-musl" in header or b"libc.musl" in header:
            return [Finding("musl_in_nonmusl_wheel", parts[4], view.filename, view.resource)]
    return []
