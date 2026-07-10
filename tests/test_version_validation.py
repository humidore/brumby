import pytest

from brumby.pypi import validate_version


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
