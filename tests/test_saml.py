"""SAML assertions call AssumeRoleWithSAML."""

import botocore
import botocore.session
import pytest
from botocore.exceptions import ClientError, ProfileNotFound

from lupaxa.aws_authenticate.credentials import AwsCredentials
from lupaxa.aws_authenticate.errors import CredentialsNotFoundError, RoleAssumptionError
from lupaxa.aws_authenticate.session import AuthenticatedSession

ROLE = "arn:aws:iam::123456789012:role/Saml"
PRINCIPAL = "arn:aws:iam::123456789012:saml-provider/IdP"


def test_assertion(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    def fake_create_client(self: object, service: str, **kwargs: object) -> object:
        config = kwargs.get("config")
        assert getattr(config, "signature_version", None) == botocore.UNSIGNED

        class _STS:
            def assume_role_with_saml(self, **params: object) -> object:
                seen.update(params)
                return {
                    "Credentials": {
                        "AccessKeyId": "ASIA_SAML",
                        "SecretAccessKey": "saml-secret",
                        "SessionToken": "saml-token",
                    }
                }

        return _STS()

    monkeypatch.setattr(botocore.session.Session, "create_client", fake_create_client)
    session = AuthenticatedSession.from_saml(ROLE, PRINCIPAL, "YXNzZXJ0aW9u")
    assert session.method == "saml"
    assert session.credentials == AwsCredentials(
        "ASIA_SAML",
        "saml-secret",
        "saml-token",
    )
    assert seen["SAMLAssertion"] == "YXNzZXJ0aW9u"
    assert "DurationSeconds" not in seen


def test_blank_assertion() -> None:
    with pytest.raises(CredentialsNotFoundError):
        AuthenticatedSession.from_saml(ROLE, PRINCIPAL, "  ")


def test_sts_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_create_client(self: object, service: str, **kwargs: object) -> object:
        class _STS:
            def assume_role_with_saml(self, **params: object) -> object:
                raise ClientError(
                    {"Error": {"Code": "ValidationError", "Message": "expired"}},
                    "AssumeRoleWithSAML",
                )

        return _STS()

    monkeypatch.setattr(botocore.session.Session, "create_client", fake_create_client)
    with pytest.raises(RoleAssumptionError):
        AuthenticatedSession.from_saml(ROLE, PRINCIPAL, "YXNzZXJ0aW9u")


def test_profile_not_found_does_not_escape(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_create_client(self: object, service: str, **kwargs: object) -> object:
        raise ProfileNotFound(profile="missing")

    monkeypatch.setattr(botocore.session.Session, "create_client", fake_create_client)
    with pytest.raises(CredentialsNotFoundError):
        AuthenticatedSession.from_saml(ROLE, PRINCIPAL, "YXNzZXJ0aW9u")
