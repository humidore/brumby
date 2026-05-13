"""Native binary detection: ELF, PE, Mach-O, musl-in-glibc-wheel."""

from ..artifact import ArtifactView
from ..finding import Finding
from ..registry import register

_ELF = b"\x7fELF"
_PE = b"MZ"
_MACHO = frozenset(
    {b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"}
)


def _wheel_tags(filename: str) -> str:
    """Return the python-abi-platform tag portion of a wheel filename."""
    parts = filename[:-4].rsplit("-", 4)
    return "-".join(parts[2:]) if len(parts) == 5 else filename


def _leaf_name(path: str) -> str:
    return path.rsplit("/", 1)[-1]


def _scan_binary_headers(view: ArtifactView) -> dict[str, str]:
    """Single-pass binary type scan, result cached on the view."""
    cache = getattr(view, "_cache", None)
    if cache is not None and "binary_headers" in cache:
        return cache["binary_headers"]
    found: dict[str, str] = {}
    if view.filetype in ("wheel", "sdist"):
        for name, header in view.iter_file_headers(4):
            if header[:4] == _ELF:
                found.setdefault("elf", name)
            elif header[:2] == _PE:
                found.setdefault("pe", name)
            elif header[:4] in _MACHO:
                found.setdefault("macho", name)
            if len(found) == 3:
                break
    if cache is not None:
        cache["binary_headers"] = found
    return found


def find_binary_types(view: ArtifactView, cfg: dict) -> list[Finding]:
    """Return findings for all binary types detected (ELF, PE, Mach-O)."""
    found = _scan_binary_headers(view)
    results = []
    if "elf" in found:
        results.append(Finding("has_elf_binary", _leaf_name(found["elf"]), view.filename, view.resource))
    if "pe" in found:
        results.append(Finding("has_pe_binary", _leaf_name(found["pe"]), view.filename, view.resource))
    if "macho" in found:
        results.append(Finding("has_macho_binary", _leaf_name(found["macho"]), view.filename, view.resource))
    return results


@register("has_elf_binary", "Archive contains an ELF binary", kind="sketchy", needs_content=True)
def find_elf_binary(view: ArtifactView, cfg: dict) -> list[Finding]:
    found = _scan_binary_headers(view)
    if "elf" in found:
        return [Finding("has_elf_binary", _leaf_name(found["elf"]), view.filename, view.resource)]
    return []


@register("has_pe_binary", "Archive contains a PE binary", kind="sketchy", needs_content=True)
def find_pe_binary(view: ArtifactView, cfg: dict) -> list[Finding]:
    found = _scan_binary_headers(view)
    if "pe" in found:
        return [Finding("has_pe_binary", _leaf_name(found["pe"]), view.filename, view.resource)]
    return []


@register("has_macho_binary", "Archive contains a Mach-O binary", kind="sketchy", needs_content=True)
def find_macho_binary(view: ArtifactView, cfg: dict) -> list[Finding]:
    found = _scan_binary_headers(view)
    if "macho" in found:
        return [Finding("has_macho_binary", _leaf_name(found["macho"]), view.filename, view.resource)]
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
