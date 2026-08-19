import stat
import struct
import zipfile
import zlib

from brumby.finders.zipforensics import (
    find_zip_dir_no_slash,
    find_zip_member_order,
    find_zip_member_type,
    find_zip_not_contiguous,
)
from brumby.finding import Finding


def _zipinfo(filename: str, mode: int, create_system: int = 3) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(filename)
    info.create_system = create_system
    info.external_attr = mode << 16
    return info


class _OrderInfo:
    def __init__(self, filename: str, header_offset: int) -> None:
        self.filename = filename
        self.header_offset = header_offset


class _DummyView:
    def __init__(self, infos: list, filename: str = "pkg-1.0-py3-none-any.whl") -> None:
        self._infos = infos
        self.filename = filename
        self.filetype = "wheel"
        self.resource = "wheel"

    def infos(self):
        return self._infos


def test_zip_member_order_matches_is_silent() -> None:
    view = _DummyView([_OrderInfo("a.txt", 0), _OrderInfo("b.txt", 100)])
    assert find_zip_member_order(view, {}) == []


def test_zip_member_order_flags_lfh_cd_mismatch() -> None:
    view = _DummyView([_OrderInfo("a.txt", 100), _OrderInfo("b.txt", 0)])
    assert find_zip_member_order(view, {}) == [
        Finding("zip_member_order", "cd[0]=a.txt lfh[0]=b.txt", "pkg-1.0-py3-none-any.whl", "wheel")
    ]


def test_zip_member_type_flags_symlink() -> None:
    view = _DummyView([_zipinfo("pkg/evil_link", stat.S_IFLNK | 0o777)])
    assert find_zip_member_type(view, {}) == [
        Finding("zip_member_type", "symlink:pkg/evil_link", "pkg-1.0-py3-none-any.whl", "wheel")
    ]


def test_zip_member_type_flags_fifo() -> None:
    view = _DummyView([_zipinfo("pkg/pipe", stat.S_IFIFO | 0o644)])
    assert find_zip_member_type(view, {}) == [
        Finding("zip_member_type", "fifo:pkg/pipe", "pkg-1.0-py3-none-any.whl", "wheel")
    ]


def test_zip_member_type_ignores_regular_files_and_dirs() -> None:
    view = _DummyView(
        [
            _zipinfo("pkg/module.py", stat.S_IFREG | 0o644),
            _zipinfo("pkg/", stat.S_IFDIR | 0o755),
        ]
    )
    assert find_zip_member_type(view, {}) == []


def test_zip_member_type_ignores_permission_only_external_attr() -> None:
    # Common in the wild: external_attr encodes permission bits with no
    # S_IFMT file-type bits at all. Must not be mistaken for a special type.
    view = _DummyView([_zipinfo("pkg/module.py", 0o644)])
    assert find_zip_member_type(view, {}) == []


def test_zip_member_type_ignores_non_unix_entries() -> None:
    view = _DummyView([_zipinfo("pkg/module.py", stat.S_IFLNK | 0o777, create_system=0)])
    assert find_zip_member_type(view, {}) == []


def test_zip_dir_no_slash_flags_unix_dir_missing_slash() -> None:
    view = _DummyView([_zipinfo("pkg/data", stat.S_IFDIR | 0o755)])
    assert find_zip_dir_no_slash(view, {}) == [
        Finding("zip_dir_no_slash", "pkg/data", "pkg-1.0-py3-none-any.whl", "wheel")
    ]


def test_zip_dir_no_slash_flags_dos_dir_attr_missing_slash() -> None:
    info = _zipinfo("pkg/data", 0, create_system=0)
    info.external_attr = 0x10
    view = _DummyView([info])
    assert find_zip_dir_no_slash(view, {}) == [
        Finding("zip_dir_no_slash", "pkg/data", "pkg-1.0-py3-none-any.whl", "wheel")
    ]


def test_zip_dir_no_slash_silent_when_dir_is_named_correctly() -> None:
    view = _DummyView([_zipinfo("pkg/data/", stat.S_IFDIR | 0o755)])
    assert find_zip_dir_no_slash(view, {}) == []


def test_zip_dir_no_slash_silent_for_regular_files() -> None:
    view = _DummyView([_zipinfo("pkg/module.py", stat.S_IFREG | 0o644)])
    assert find_zip_dir_no_slash(view, {}) == []


def _lfh_bytes(name: str, data: bytes, flag_bits: int = 0) -> bytes:
    name_b = name.encode()
    return (
        struct.pack(
            "<4sHHHHHLLLHH",
            b"PK\x03\x04",
            20,
            flag_bits,
            0,
            0,
            0,
            zlib.crc32(data),
            len(data),
            len(data),
            len(name_b),
            0,
        )
        + name_b
    )


class _FakeInfo:
    def __init__(self, filename: str, header_offset: int, compress_size: int, flag_bits: int = 0) -> None:
        self.filename = filename
        self.header_offset = header_offset
        self.compress_size = compress_size
        self.flag_bits = flag_bits


class _ByteView:
    def __init__(self, infos: list, buf: bytes, filename: str = "pkg-1.0-py3-none-any.whl") -> None:
        self._infos = infos
        self._buf = buf
        self.filename = filename
        self.filetype = "wheel"
        self.resource = "wheel"

    def infos(self):
        return self._infos

    def read_at(self, offset: int, size: int) -> bytes:
        return self._buf[offset : offset + size]


def _laid_out(*members: tuple[str, bytes], gap_after_first: int = 0) -> tuple[bytes, list[_FakeInfo]]:
    name_a, data_a = members[0]
    name_b, data_b = members[1]

    lfh_a = _lfh_bytes(name_a, data_a)
    offset_a = 0
    end_a = offset_a + len(lfh_a) + len(data_a)
    offset_b = end_a + gap_after_first
    lfh_b = _lfh_bytes(name_b, data_b)

    buf = bytearray(offset_b + len(lfh_b) + len(data_b))
    buf[offset_a : offset_a + len(lfh_a)] = lfh_a
    buf[offset_a + len(lfh_a) : end_a] = data_a
    buf[offset_b : offset_b + len(lfh_b)] = lfh_b
    buf[offset_b + len(lfh_b) :] = data_b

    infos = [
        _FakeInfo(name_a, offset_a, len(data_a)),
        _FakeInfo(name_b, offset_b, len(data_b)),
    ]
    return bytes(buf), infos


def test_zip_not_contiguous_silent_when_packed_back_to_back() -> None:
    buf, infos = _laid_out(("a.txt", b"hello world"), ("b.txt", b"second file"), gap_after_first=0)
    view = _ByteView(infos, buf)
    assert find_zip_not_contiguous(view, {}) == []


def test_zip_not_contiguous_flags_gap_between_members() -> None:
    buf, infos = _laid_out(("a.txt", b"hello world"), ("b.txt", b"second file"), gap_after_first=8)
    view = _ByteView(infos, buf)
    assert find_zip_not_contiguous(view, {}) == [
        Finding("zip_not_contiguous", "a.txt->b.txt:+8", "pkg-1.0-py3-none-any.whl", "wheel")
    ]


def test_zip_not_contiguous_flags_overlap_between_members() -> None:
    buf, infos = _laid_out(("a.txt", b"hello world"), ("b.txt", b"second file"), gap_after_first=-4)
    view = _ByteView(infos, buf)
    assert find_zip_not_contiguous(view, {}) == [
        Finding("zip_not_contiguous", "a.txt->b.txt:-4", "pkg-1.0-py3-none-any.whl", "wheel")
    ]
