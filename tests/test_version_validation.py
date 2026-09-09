import pytest

from brumby.pypi import (
    get_package_info,
    get_release_files,
    validate_project_name,
    validate_version,
)


def test_validate_project_name_rejects_pinned_requirement() -> None:
    with pytest.raises(ValueError, match="invalid project name"):
        validate_project_name("demo==1.0")


def test_metadata_requests_reject_pinned_requirement_before_request() -> None:
    with pytest.raises(ValueError, match="invalid project name"):
        get_package_info("demo==1.0")
    with pytest.raises(ValueError, match="invalid project name"):
        get_release_files("demo==1.0", "1.0", session=object())


def test_validate_version_returns_valid_version_unchanged() -> None:
    assert validate_version("1.2.3") == "1.2.3"
    assert validate_version("2.0.0rc1") == "2.0.0rc1"
    assert validate_version("1.0") == "1.0"


def test_validate_version_rejects_invalid_version() -> None:
    with pytest.raises(ValueError, match="invalid version"):
        validate_version("not a version")


def test_validate_version_rejects_empty_string() -> None:
    with pytest.raises(ValueError, match="invalid version"):
        validate_version("")
