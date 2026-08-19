"""Zip structural integrity checks for wheel files."""

import stat
import struct
from typing import Iterator

from ..artifact import ArtifactView
from ..finding import Finding
from ..registry import register

# Zip version_needed_to_extract values above this are unusual for plain wheels.
_NORMAL_MAX_VERSION = 45  # Zip64

# Local file header: signature(4) version_needed(2) flag_bits(2) method(2) time(2)
# date(2) crc32(4) comp_size(4) uncomp_size(4) fname_len(2) extra_len(2).
_LFH_SIZE = 30
_LFH_SIGNATURE = b"PK\x03\x04"

# Unix file-type bits (from external_attr >> 16, S_IFMT-masked) that have no
# business appearing in a wheel or sdist.
_SUSPECT_TYPES: tuple[tuple[int, str], ...] = (
    (stat.S_IFLNK, "symlink"),
    (stat.S_IFIFO, "fifo"),
    (stat.S_IFSOCK, "socket"),
    (stat.S_IFCHR, "char_device"),
    (stat.S_IFBLK, "block_device"),
)

_DOS_DIR_ATTR = 0x10  # FILE_ATTRIBUTE_DIRECTORY, low word of external_attr

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


@register(
    "zip_member_order",
    "Local file headers are stored in a different order than the central directory lists them",
    kind="sketchy",
)
def find_zip_member_order(view: ArtifactView, cfg: dict) -> list[Finding]:
    if view.filetype != "wheel":
        return []
    try:
        infos = view.infos()
        cd_order = [i.filename for i in infos]
        physical_order = [i.filename for i in sorted(infos, key=lambda i: i.header_offset)]
        for idx, (cd_name, phys_name) in enumerate(zip(cd_order, physical_order)):
            if cd_name != phys_name:
                return [
                    Finding(
                        "zip_member_order",
                        f"cd[{idx}]={cd_name} lfh[{idx}]={phys_name}",
                        view.filename,
                        view.resource,
                    )
                ]
    except Exception:
        pass
    return []


@register(
    "zip_not_contiguous",
    "Local file entries have a gap or overlap between them instead of being packed back-to-back",
    kind="sketchy",
)
def find_zip_not_contiguous(view: ArtifactView, cfg: dict) -> list[Finding]:
    if view.filetype != "wheel":
        return []
    try:
        infos = sorted(view.infos(), key=lambda i: i.header_offset)
        for cur, nxt in zip(infos, infos[1:]):
            header = view.read_at(cur.header_offset, _LFH_SIZE)
            if len(header) < _LFH_SIZE or header[:4] != _LFH_SIGNATURE:
                continue  # can't verify this member's real header, skip the gap it bounds
            name_len, extra_len = struct.unpack("<HH", header[26:30])
            data_end = cur.header_offset + _LFH_SIZE + name_len + extra_len + cur.compress_size
            gap = nxt.header_offset - data_end
            # A streamed entry (general-purpose bit 3) is followed by a 12- or
            # 16-byte data descriptor that isn't counted in compress_size above.
            allowed = {0, 12, 16} if cur.flag_bits & 0x08 else {0}
            if gap not in allowed:
                return [
                    Finding(
                        "zip_not_contiguous",
                        f"{cur.filename}->{nxt.filename}:{gap:+d}",
                        view.filename,
                        view.resource,
                    )
                ]
    except Exception:
        pass
    return []


@register(
    "zip_member_type",
    "Zip member's Unix mode reports a file type other than regular file or directory",
    kind="sketchy",
)
def find_zip_member_type(view: ArtifactView, cfg: dict) -> list[Finding]:
    if view.filetype != "wheel":
        return []
    findings = []
    try:
        for info in view.infos():
            if info.create_system != 3:  # not Unix-produced, no mode bits to read
                continue
            mode = info.external_attr >> 16
            filetype = stat.S_IFMT(mode)
            for bit, name in _SUSPECT_TYPES:
                if filetype == bit:
                    findings.append(
                        Finding("zip_member_type", f"{name}:{info.filename}", view.filename, view.resource)
                    )
                    break
    except Exception:
        return []
    return findings


@register(
    "zip_dir_no_slash",
    "Zip entry looks like a directory (by Unix mode or DOS attribute) but its name lacks a trailing slash",
    kind="sketchy",
)
def find_zip_dir_no_slash(view: ArtifactView, cfg: dict) -> list[Finding]:
    if view.filetype != "wheel":
        return []
    findings = []
    try:
        for info in view.infos():
            if info.filename.endswith("/"):
                continue
            is_dir = info.external_attr & _DOS_DIR_ATTR != 0
            if info.create_system == 3:
                is_dir = is_dir or stat.S_ISDIR(info.external_attr >> 16)
            if is_dir:
                findings.append(Finding("zip_dir_no_slash", info.filename, view.filename, view.resource))
    except Exception:
        return []
    return findings
