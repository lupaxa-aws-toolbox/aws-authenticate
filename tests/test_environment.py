"""Environment credentials do not fall through."""

import pytest

from lupaxa.aws_authenticate.credentials import AwsCredentials
from lupaxa.aws_authenticate.errors import CredentialsNotFoundError
from lupaxa.aws_authenticate.session import AuthenticatedSession


def test_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIA_ENV")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "env-secret")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "env-token")
    session = AuthenticatedSession.from_environment()
    assert session.method == "env"
    assert session.credentials == AwsCredentials("AKIA_ENV", "env-secret", "env-token")


def test_from_environment_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
    with pytest.raises(CredentialsNotFoundError):
        AuthenticatedSession.from_environment()
