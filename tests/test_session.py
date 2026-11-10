"""AuthenticatedSession exposes method and a credential snapshot."""

import botocore.session
from botocore.credentials import CredentialResolver, Credentials

from lupaxa.aws_authenticate.credentials import AwsCredentials
from lupaxa.aws_authenticate.errors import (
    AuthenticationError,
    CredentialsNotFoundError,
    LoginError,
    MfaRequiredError,
    RoleAssumptionError,
)
from lupaxa.aws_authenticate.session import AuthenticatedSession, open_session


class _Static:
    """One provider that returns the credentials it was given."""

    METHOD = "explicit"

    def __init__(self, creds: Credentials | None) -> None:
        self._creds = creds

    def load(self) -> Credentials | None:
        return self._creds


def _session_with(creds: Credentials | None) -> botocore.session.Session:
    raw = botocore.session.Session()
    raw.register_component("credential_provider", CredentialResolver([_Static(creds)]))
    return raw


def test_error_types() -> None:
    assert issubclass(CredentialsNotFoundError, AuthenticationError)
    assert issubclass(LoginError, AuthenticationError)
    assert issubclass(MfaRequiredError, AuthenticationError)
    assert issubclass(RoleAssumptionError, AuthenticationError)


def test_open_session_snapshots_credentials() -> None:
    creds = Credentials("AKIA_TEST", "secret", "token", method="explicit")
    session = open_session(_session_with(creds), method="explicit")
    assert isinstance(session, AuthenticatedSession)
    assert session.method == "explicit"
    assert session.credentials == AwsCredentials("AKIA_TEST", "secret", "token")


def test_open_session_without_credentials() -> None:
    try:
        open_session(_session_with(None), method="explicit")
    except CredentialsNotFoundError:
        return
    raise AssertionError("expected CredentialsNotFoundError")
