import io
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Literal

import requests


@dataclass
class Artifact:
    filename: str
    url: str
    filetype: Literal["wheel", "sdist", "other"]
    resource: str
    size: int
    upload_time: str = ""
    digests: dict[str, str] = field(default_factory=dict)
    _data: bytes | None = field(default=None, repr=False)
    _local_path: Path | None = field(default=None, repr=False)

    def data(self) -> bytes:
        if self._data is None:
            resp = requests.get(self.url, timeout=120)
            resp.raise_for_status()
            self._data = resp.content
        return self._data

    def open_zip_remote(self) -> zipfile.ZipFile:
        return zipfile.ZipFile(io.BytesIO(self.data()))

    def open_tar(self) -> tarfile.TarFile:
        return tarfile.open(fileobj=io.BytesIO(self.data()))

    def open_sdist_remote(self) -> zipfile.ZipFile | tarfile.TarFile:
        if self.resource == "sdist-format=zip" or self.filename.lower().endswith(".zip"):
            return zipfile.ZipFile(io.BytesIO(self.data()))
        return tarfile.open(fileobj=io.BytesIO(self.data()))

    def save_local(self, dirpath: Path) -> Path:
        dirpath.mkdir(parents=True, exist_ok=True)
        path = dirpath / self.filename.rsplit("/", 1)[-1]
        if not path.exists():
            if self._data is not None:
                path.write_bytes(self._data)
            else:
                path.write_bytes(self.data())
        self._local_path = path
        return path

    def open_local(self) -> zipfile.ZipFile | tarfile.TarFile:
        path = self._local_path
        if path is None:
            raise ValueError("local artifact not saved")
        if self.filetype == "sdist" and (self.resource == "sdist-format=zip" or path.name.lower().endswith(".zip")):
            return zipfile.ZipFile(path)
        if self.filetype == "sdist":
            return tarfile.open(path)
        return zipfile.ZipFile(path)


def _file_ext(filename: str) -> str:
    """Return lowercase extension including dot, or '' if none."""
    if "." not in filename.rsplit("/", 1)[-1]:
        return ""
    return "." + filename.rsplit(".", 1)[-1].lower()


def _sdist_resource(filename: str) -> str:
    lower = filename.lower()
    if lower.endswith((".tar.gz", ".tgz")):
        return "sdist-format=tar.gz"
    if lower.endswith((".tar.bz2", ".tbz2")):
        return "sdist-format=tar.bz2"
    if lower.endswith(".tar.xz"):
        return "sdist-format=tar.xz"
    if lower.endswith(".tar"):
        return "sdist-format=tar"
    if lower.endswith(".zip"):
        return "sdist-format=zip"
    return "sdist-format=other"


def _infer_filetype(filename: str) -> tuple[Literal["wheel", "sdist", "other"], str]:
    lower = filename.lower()
    if lower.endswith(".whl"):
        return "wheel", "wheel"
    if lower.endswith((".tar.gz", ".tgz")):
        return "sdist", "sdist-format=tar.gz"
    if lower.endswith((".tar.bz2", ".tbz2")):
        return "sdist", "sdist-format=tar.bz2"
    if lower.endswith(".tar.xz"):
        return "sdist", "sdist-format=tar.xz"
    if lower.endswith(".tar"):
        return "sdist", "sdist-format=tar"
    if lower.endswith(".zip"):
        return "sdist", "sdist-format=zip"
    return "other", "other"


class ArtifactView:
    """Wraps an Artifact with a single persistent open archive for multi-finder efficiency.

    The archive is downloaded once and reused across finders.
    Individual file reads are deferred until needed.
    """

    def __init__(self, artifact: Artifact) -> None:
        self.artifact = artifact
        self.filename = artifact.filename
        self.filetype = artifact.filetype
        self.resource = artifact.resource
        self._zf: zipfile.ZipFile | None = None
        self._infos: list[zipfile.ZipInfo] | None = None
        self._cache: dict = {}

    def __enter__(self) -> "ArtifactView":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def close(self) -> None:
        if self._zf is not None:
            self._zf.close()
            self._zf = None

    def _zip(self) -> zipfile.ZipFile:
        if self._zf is None:
            if self.artifact._local_path is not None:
                local = self.artifact.open_local()
                assert isinstance(local, zipfile.ZipFile)
                self._zf = local
            else:
                self._zf = self.artifact.open_zip_remote()
        return self._zf

    def infos(self) -> list[zipfile.ZipInfo]:
        """Zip central directory entries."""
        if self._infos is None:
            self._infos = self._zip().infolist()
        return self._infos

    def read_member(self, name: str) -> bytes:
        return self._zip().read(name)

    def member_names(self) -> list[str]:
        """File member names, for wheels and for sdists in either tar or zip form.

        Reads only the archive index, never member content. Directory entries are
        excluded. Prefer this over infos() in finders that apply to any archive
        type, since infos() can only read zips and raises on a tar sdist.
        """
        if "member_names" not in self._cache:
            self._cache["member_names"] = self._member_names()
        return self._cache["member_names"]

    def _member_names(self) -> list[str]:
        if self.filetype == "wheel":
            return [i.filename for i in self.infos() if not i.is_dir()]
        opener = (
            self.artifact.open_local()
            if self.artifact._local_path is not None
            else self.artifact.open_sdist_remote()
        )
        with opener as arc:
            if isinstance(arc, zipfile.ZipFile):
                return [i.filename for i in arc.infolist() if not i.is_dir()]

            # arc has to be tarfile.Tarfile in this case
            return [m.name for m in arc.getmembers() if not m.isdir()]

    def read_at(self, offset: int, size: int) -> bytes:
        """Read raw bytes directly from the underlying archive file at a byte offset,
        bypassing the central directory (used to inspect local file headers)."""
        fp = self._zip().fp
        if fp is None:
            raise ValueError("archive is not open")
        fp.seek(offset)
        return fp.read(size)

    def iter_file_headers(
        self, n: int = 4, exts: frozenset[str] | set[str] | None = None
    ) -> Iterator[tuple[str, bytes]]:
        """Yield (filename, first_n_bytes) for entries matching exts (or all if None).
        """
        if self.filetype == "wheel":
            zf = self._zip()
            for info in self.infos():
                if info.file_size == 0:
                    continue
                if exts is not None and _file_ext(info.filename) not in exts:
                    continue
                with zf.open(info) as f:
                    yield info.filename, f.read(n)
        elif self.filetype == "sdist":
            opener = self.artifact.open_local() if self.artifact._local_path is not None else self.artifact.open_sdist_remote()
            with opener as arc:
                if isinstance(arc, zipfile.ZipFile):
                    for info in arc.infolist():
                        if info.file_size == 0:
                            continue
                        if exts is not None and _file_ext(info.filename) not in exts:
                            continue
                        with arc.open(info) as f:
                            yield info.filename, f.read(n)
                else:
                    for member in arc.getmembers():
                        if not member.isfile() or member.size == 0:
                            continue
                        if exts is not None and _file_ext(member.name) not in exts:
                            continue
                        fobj = arc.extractfile(member)
                        if fobj:
                            yield member.name, fobj.read(n)

    def iter_files(
        self, exts: frozenset[str] | set[str] | None = None
    ) -> Iterator[tuple[str, bytes]]:
        """Yield (filename, full_content) for entries matching exts (or all if None)."""
        if self.filetype == "wheel":
            zf = self._zip()
            for info in self.infos():
                if info.file_size == 0:
                    continue
                if exts is not None and _file_ext(info.filename) not in exts:
                    continue
                with zf.open(info) as f:
                    yield info.filename, f.read()
        elif self.filetype == "sdist":
            opener = self.artifact.open_local() if self.artifact._local_path is not None else self.artifact.open_sdist_remote()
            with opener as arc:
                if isinstance(arc, zipfile.ZipFile):
                    for info in arc.infolist():
                        if info.file_size == 0:
                            continue
                        if exts is not None and _file_ext(info.filename) not in exts:
                            continue
                        with arc.open(info) as f:
                            yield info.filename, f.read()
                else:
                    for member in arc.getmembers():
                        if not member.isfile() or member.size == 0:
                            continue
                        if exts is not None and _file_ext(member.name) not in exts:
                            continue
                        fobj = arc.extractfile(member)
                        if fobj:
                            yield member.name, fobj.read()


def make_artifact(file_info: dict) -> Artifact:
    packagetype = file_info.get("packagetype", "")
    filename = file_info["filename"]

    if packagetype == "bdist_wheel" or filename.endswith(".whl"):
        filetype: Literal["wheel", "sdist", "other"] = "wheel"
        resource = "wheel"
    elif packagetype == "sdist":
        filetype = "sdist"
        resource = _sdist_resource(filename)
    else:
        filetype = "other"
        resource = "other"

    return Artifact(
        filename=filename,
        url=file_info["url"],
        filetype=filetype,
        resource=resource,
        size=file_info.get("size", 0),
        upload_time=file_info.get("upload_time_iso_8601", ""),
        digests=file_info.get("digests", {}),
    )


def make_local_artifact(path: Path) -> Artifact:
    filetype, resource = _infer_filetype(path.name)
    artifact = Artifact(
        filename=path.name,
        url=path.resolve().as_uri(),
        filetype=filetype,
        resource=resource,
        size=path.stat().st_size,
    )
    artifact._local_path = path
    return artifact
