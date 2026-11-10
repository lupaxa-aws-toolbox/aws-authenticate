"""Web identity tokens call AssumeRoleWithWebIdentity."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import botocore.session
import pytest
from botocore.credentials import AssumeRoleWithWebIdentityCredentialFetcher
from botocore.exceptions import ClientError
from botocore.utils import FileWebIdentityTokenLoader

from lupaxa.aws_authenticate.credentials import AwsCredentials
from lupaxa.aws_authenticate.errors import CredentialsNotFoundError, RoleAssumptionError
from lupaxa.aws_authenticate.session import AuthenticatedSession

ROLE = "arn:aws:iam::123456789012:role/Web"


def _ok_credentials() -> dict[str, object]:
    return {
        "AccessKeyId": "ASIA_WEB",
        "SecretAccessKey": "web-secret",
        "SessionToken": "web-token",
        "Expiration": datetime.now(UTC) + timedelta(hours=1),
    }


def test_token_string(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    def fake_create_client(self: object, service: str, **kwargs: object) -> object:
        class _STS:
            def assume_role_with_web_identity(self, **params: object) -> object:
                seen.update(params)
                return {"Credentials": _ok_credentials()}

        return _STS()

    monkeypatch.setattr(botocore.session.Session, "create_client", fake_create_client)
    session = AuthenticatedSession.from_web_identity(ROLE, token="header.payload.sig")
    assert session.method == "assume-role-with-web-identity"
    assert session.credentials == AwsCredentials("ASIA_WEB", "web-secret", "web-token")
    assert seen["WebIdentityToken"] == "header.payload.sig"
    assert seen["RoleSessionName"] == "aws-authenticate"


def test_token_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    token_path = tmp_path / "token"
    token_path.write_text("file-token\n", encoding="utf-8")
    captured: dict[str, object] = {}

    def spy_fetcher(
        client_creator: object,
        web_identity_token_loader: object,
        role_arn: str,
        extra_args: object = None,
        cache: object = None,
        expiry_window_seconds: object = None,
    ) -> AssumeRoleWithWebIdentityCredentialFetcher:
        captured["loader"] = web_identity_token_loader
        return AssumeRoleWithWebIdentityCredentialFetcher(
            client_creator=client_creator,
            web_identity_token_loader=web_identity_token_loader,
            role_arn=role_arn,
            extra_args=extra_args,
            cache=cache,
            expiry_window_seconds=expiry_window_seconds,
        )

    def fake_create_client(self: object, service: str, **kwargs: object) -> object:
        class _STS:
            def assume_role_with_web_identity(self, **params: object) -> object:
                assert params["WebIdentityToken"] == "file-token\n"
                return {"Credentials": _ok_credentials()}

        return _STS()

    monkeypatch.setattr(
        "lupaxa.aws_authenticate.session.AssumeRoleWithWebIdentityCredentialFetcher",
        spy_fetcher,
    )
    monkeypatch.setattr(botocore.session.Session, "create_client", fake_create_client)
    session = AuthenticatedSession.from_web_identity(ROLE, token_file=str(token_path))
    assert session.credentials.access_key_id == "ASIA_WEB"
    loader = captured["loader"]
    assert isinstance(loader, FileWebIdentityTokenLoader)
    token_path.write_text("next-token\n", encoding="utf-8")
    assert loader() == "next-token\n"


def test_token_choice_is_exclusive() -> None:
    with pytest.raises(ValueError, match="exactly one"):
        AuthenticatedSession.from_web_identity(ROLE)
    with pytest.raises(ValueError, match="exactly one"):
        AuthenticatedSession.from_web_identity(ROLE, token="a", token_file="b")


def test_missing_token_file(tmp_path: Path) -> None:
    with pytest.raises(CredentialsNotFoundError):
        AuthenticatedSession.from_web_identity(ROLE, token_file=str(tmp_path / "nope"))
    with pytest.raises(CredentialsNotFoundError):
        AuthenticatedSession.from_web_identity(ROLE, token_file=str(tmp_path))


def test_sts_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_create_client(self: object, service: str, **kwargs: object) -> object:
        class _STS:
            def assume_role_with_web_identity(self, **params: object) -> object:
                raise ClientError(
                    {"Error": {"Code": "AccessDenied", "Message": "denied"}},
                    "AssumeRoleWithWebIdentity",
                )

        return _STS()

    monkeypatch.setattr(botocore.session.Session, "create_client", fake_create_client)
    with pytest.raises(RoleAssumptionError):
        AuthenticatedSession.from_web_identity(ROLE, token="header.payload.sig")
