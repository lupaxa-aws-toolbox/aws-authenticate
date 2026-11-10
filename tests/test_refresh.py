"""A session refreshes keys and a client signs with them."""

from datetime import UTC, datetime, timedelta

import botocore.session
from botocore.credentials import CredentialResolver, RefreshableCredentials

from lupaxa.aws_authenticate.session import AuthenticatedSession, open_session


def test_second_read_sees_the_refresh() -> None:
    calls = {"n": 0}

    def refresh() -> dict[str, object]:
        calls["n"] += 1
        return {
            "access_key": "AKIA_REFRESH",
            "secret_key": "refresh-secret",
            "token": f"token-{calls['n']}",
            "expiry_time": (datetime.now(UTC) + timedelta(hours=1)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
        }

    class _Provider:
        METHOD = "explicit"

        def load(self) -> RefreshableCredentials:
            return RefreshableCredentials.create_from_metadata(
                refresh(),
                method="explicit",
                refresh_using=refresh,
            )

    raw = botocore.session.Session()
    raw.register_component("credential_provider", CredentialResolver([_Provider()]))
    session = open_session(raw, method="explicit")
    first = session.credentials.token
    resolved = session.get_credentials()
    resolved._expiry_time = datetime.now(UTC) - timedelta(hours=1)
    resolved._advisory_refresh_timeout = 0
    resolved._mandatory_refresh_timeout = 0
    second = session.credentials.token
    assert first == "token-1"
    assert second == "token-2"
    assert session.method == "explicit"


def test_client_uses_the_resolved_keys() -> None:
    session = AuthenticatedSession.from_keys(
        "AKIA_CLIENT",
        "client-secret",
        session_token="client-token",
    )
    client = session.client("sts", region_name="us-east-1")
    frozen = client._request_signer._credentials.get_frozen_credentials()
    assert frozen.access_key == "AKIA_CLIENT"
    assert frozen.secret_key == "client-secret"
    assert frozen.token == "client-token"
