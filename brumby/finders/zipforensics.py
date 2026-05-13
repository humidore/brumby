"""Zip structural integrity checks for wheel files."""

from typing import Iterator

from ..artifact import ArtifactView
from ..finding import Finding
from ..registry import register

# Zip version_needed_to_extract values above this are unusual for plain wheels.
_NORMAL_MAX_VERSION = 45  # Zip64

# Well-known extra field tag IDs → short name.  Unlisted tags are shown as hex.
_TAG_NAMES: dict[int, str] = {
    0x0001: "zip64",
    0x0007: "av_info",
    0x0009: "os2",
    0x000A: "ntfs",
    0x000D: "unix",
    0x000F: "patch_descriptor",
    0x0014: "pkware_unix",
    0x0017: "pkware_strong_encryption",
    0x0018: "record_management",
    0x0019: "pkware_encryption_header",
    0x0065: "ibm_translate",
    0x0066: "ibm_compress",
    0x4453: "windows_sd",
    0x4704: "openvms",
    0x470F: "sharepoint",
    0x4B46: "fwkcs",
    0x4C41: "info_zip_os2_old",
    0x4D49: "info_zip_vms",
    0x4F4C: "xceed_original_location",
    0x5455: "ext_timestamp",
    0x554E: "xceed_unicode",
    0x5855: "unix_uidgid_old",
    0x6375: "unicode_comment",
    0x6542: "beos",
    0x7075: "unicode_path",
    0x7855: "info_zip_unix2",
    0x7875: "unix_uidgid",
    0xA11E: "data_stream_align",
    0xA220: "microsoft_open_packaging",
    0xFD4A: "sms_qdos",
}


def _iter_extra_tags(extra: bytes) -> Iterator[int]:
    i = 0
    while i + 4 <= len(extra):
        tag = int.from_bytes(extra[i : i + 2], "little")
        size = int.from_bytes(extra[i + 2 : i + 4], "little")
        yield tag
        i += 4 + size


@register(
    "zip_prepended_data",
    "First Local File Header is not at offset 0 (data prepended before the zip)",
    kind="sketchy",
)
def find_zip_prepended_data(view: ArtifactView, cfg: dict) -> list[Finding]:
    if view.filetype != "wheel":
        return []
    try:
        infos = view.infos()
        if not infos:
            return []
        min_offset = min(i.header_offset for i in infos)
        if min_offset > 0:
            return [Finding("zip_prepended_data", min_offset, view.filename, view.resource)]
    except Exception:
        pass
    return []


@register(
    "zip_crc_collision",
    "Two non-empty entries share the same CRC-32 but have different uncompressed sizes",
    kind="sketchy",
)
def find_zip_crc_collision(view: ArtifactView, cfg: dict) -> list[Finding]:
    if view.filetype != "wheel":
        return []
    try:
        seen: dict[int, int] = {}  # crc -> file_size
        for info in view.infos():
            if info.file_size == 0:
                continue
            crc = info.CRC
            if crc in seen and seen[crc] != info.file_size:
                return [Finding("zip_crc_collision", hex(crc), view.filename, view.resource)]
            seen[crc] = info.file_size
    except Exception:
        pass
    return []


@register(
    "zip_extra_present",
    "Extra field tag IDs present across wheel zip entries (fingerprints the build toolchain)",
    kind="informational",
)
def find_zip_extra_present(view: ArtifactView, cfg: dict) -> list[Finding]:
    if view.filetype != "wheel":
        return []
    tags: set[int] = set()
    try:
        for info in view.infos():
            if info.extra:
                for tag in _iter_extra_tags(info.extra):
                    tags.add(tag)
    except Exception:
        pass
    return [
        Finding("zip_extra_present", _TAG_NAMES.get(tag, f"{tag:04x}"), view.filename, view.resource)
        for tag in sorted(tags)
    ]


@register(
    "zip_version_needed",
    "version_needed_to_extract field in the wheel zip",
    kind="informational",
)
def find_zip_version_needed(view: ArtifactView, cfg: dict) -> list[Finding]:
    if view.filetype != "wheel":
        return []
    warn_above = cfg.get("warn_above", _NORMAL_MAX_VERSION)
    try:
        versions = {i.extract_version for i in view.infos()}
        findings = []
        for v in sorted(versions):
            findings.append(Finding("zip_version_needed", v, view.filename, view.resource))
            if v > warn_above:
                findings.append(Finding("zip_unusual_version_needed", v, view.filename, view.resource))
        return findings
    except Exception:
        return []
