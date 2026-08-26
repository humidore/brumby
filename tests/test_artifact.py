from brumby.artifact import Artifact, ArtifactView


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
