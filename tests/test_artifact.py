import tempfile
import zipfile
from pathlib import Path

from brumby.artifact import make_local_artifact


def test_make_local_artifact_accepts_str_path() -> None:
    # A bare str (e.g. from a CLI arg or an f-string-built path) shouldn't
    # blow up with AttributeError on path.name -- only Path has that.
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "demo-1.0-py3-none-any.whl"
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("demo/__init__.py", b"")

        artifact = make_local_artifact(str(path))

        assert artifact.filename == "demo-1.0-py3-none-any.whl"
        assert artifact.filetype == "wheel"
