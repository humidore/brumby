import tempfile
import zipfile
from pathlib import Path

from brumby import network
from brumby.artifact import Artifact, ArtifactView, make_local_artifact


def _view(filetype: str) -> ArtifactView:
    artifact = Artifact(filename="pkg-1.0.whl", url="", filetype=filetype, resource=filetype, size=0)
    return ArtifactView(artifact)


def test_relative_name_wheel_passes_through_ordinary_paths() -> None:
    view = _view("wheel")

    assert view.relative_name("pkg/module.py") == "pkg/module.py"
    assert view.relative_name("module.py") == "module.py"


def test_relative_name_strips_sdist_top_level_dir() -> None:
    view = _view("sdist")

    assert view.relative_name("durabletask-1.4.2/durabletask/__init__.py") == "durabletask/__init__.py"


def test_relative_name_strips_wheel_data_dir() -> None:
    view = _view("wheel")

    assert view.relative_name("cacheferret-0.3.1.data/scripts/cacheferret") == "scripts/cacheferret"


def test_relative_name_leaves_wheel_dist_info_alone() -> None:
    # Only ".data" directories carry a redundant version-tagged wrapper worth
    # stripping -- .dist-info paths aren't the ones colliding across versions
    # in a way that matters to path-valued findings.
    view = _view("wheel")

    assert view.relative_name("pkg-1.0.dist-info/METADATA") == "pkg-1.0.dist-info/METADATA"


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


def test_data_applies_artifacts_network_config(monkeypatch) -> None:
    network.configure(
        {
            "network": {
                "artifacts": {
                    "proxy": "http://127.0.0.1:9090",
                    "url_replace": {"https://": "http://"},
                }
            }
        }
    )
    try:
        calls = []

        class _Resp:
            content = b"data"

            def raise_for_status(self):
                pass

        def _fake_get(url, timeout, proxies):
            calls.append((url, proxies))
            return _Resp()

        monkeypatch.setattr("brumby.artifact.requests.get", _fake_get)

        artifact = Artifact(
            filename="pkg-1.0.whl",
            url="https://files.pythonhosted.org/pkg-1.0.whl",
            filetype="wheel",
            resource="wheel",
            size=0,
        )
        assert artifact.data() == b"data"
        assert calls == [
            ("http://files.pythonhosted.org/pkg-1.0.whl", {"http": "http://127.0.0.1:9090", "https": "http://127.0.0.1:9090"})
        ]
    finally:
        network.configure({})
