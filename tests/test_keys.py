"""Static keys ignore every other credential source."""

import pytest

from lupaxa.aws_authenticate.credentials import AwsCredentials
from lupaxa.aws_authenticate.session import AuthenticatedSession


def test_from_keys_returns_explicit_session(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIA_ENV")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "env-secret")
    session = AuthenticatedSession.from_keys(
        "AKIA_STATIC",
        "static-secret",
        session_token="static-token",
        region="eu-west-1",
    )
    assert session.method == "explicit"
    assert session.credentials == AwsCredentials(
        "AKIA_STATIC",
        "static-secret",
        "static-token",
    )
    assert session.region_name == "eu-west-1"


def test_from_keys_rejects_blank_secret() -> None:
    with pytest.raises(ValueError, match="secret_key"):
        AuthenticatedSession.from_keys("AKIA_STATIC", "  ")


def test_whitespace_session_token_is_omitted() -> None:
    session = AuthenticatedSession.from_keys(
        "AKIA_STATIC",
        "static-secret",
        session_token="   ",
    )
    assert session.credentials.token is None
