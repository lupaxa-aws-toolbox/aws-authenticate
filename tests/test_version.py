"""Semantic version shape for lupaxa.aws_authenticate."""

from lupaxa.aws_authenticate.version import __version__, get_version


def test_version_is_dotted_semver() -> None:
    """Major and minor are numeric. The patch may carry a suffix."""
    assert isinstance(__version__, str)
    parts = __version__.split(".")
    assert len(parts) >= 2
    assert all(part.isdigit() for part in parts[:2])
    assert get_version() == __version__
