"""Assume-role uses the source session and prompts for MFA when needed."""

from datetime import UTC, datetime, timedelta

import botocore.session
import pytest
from botocore.exceptions import ClientError

from lupaxa.aws_authenticate.credentials import AwsCredentials
from lupaxa.aws_authenticate.errors import MfaRequiredError, RoleAssumptionError
from lupaxa.aws_authenticate.mfa import read_mfa_code
from lupaxa.aws_authenticate.session import AuthenticatedSession

ROLE = "arn:aws:iam::123456789012:role/Admin"


def _source() -> AuthenticatedSession:
    return AuthenticatedSession.from_keys("AKIA_SOURCE", "source-secret")


def _client_error(code: str, message: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": message}}, "AssumeRole")


def _patch_assume(monkeypatch: pytest.MonkeyPatch, response: object) -> None:
    def fake_create_client(self: object, service: str, **kwargs: object) -> object:
        assert service == "sts"

        class _STS:
            def assume_role(self, **params: object) -> object:
                if isinstance(response, Exception):
                    raise response
                return response

        return _STS()

    monkeypatch.setattr(botocore.session.Session, "create_client", fake_create_client)


def _ok(token: str = "assumed-token") -> dict[str, object]:  # noqa: S107
    return {
        "Credentials": {
            "AccessKeyId": "ASIA_ROLE",
            "SecretAccessKey": "role-secret",
            "SessionToken": token,
            "Expiration": datetime.now(UTC) + timedelta(hours=1),
        },
        "AssumedRoleUser": {
            "Arn": "arn:aws:sts::123456789012:assumed-role/Admin/aws-authenticate",
        },
    }


def test_assume_role_uses_default_session_name(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    def fake_create_client(self: object, service: str, **kwargs: object) -> object:
        class _STS:
            def assume_role(self, **params: object) -> object:
                seen.update(params)
                return _ok()

        return _STS()

    monkeypatch.setattr(botocore.session.Session, "create_client", fake_create_client)
    session = AuthenticatedSession.from_assume_role(_source(), ROLE)
    assert session.method == "assume-role"
    assert session.credentials == AwsCredentials(
        "ASIA_ROLE",
        "role-secret",
        "assumed-token",
    )
    assert seen["RoleSessionName"] == "aws-authenticate"
    assert "DurationSeconds" not in seen


def test_assume_role_passes_mfa_code(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    def fake_create_client(self: object, service: str, **kwargs: object) -> object:
        class _STS:
            def assume_role(self, **params: object) -> object:
                seen.update(params)
                return _ok()

        return _STS()

    monkeypatch.setattr(botocore.session.Session, "create_client", fake_create_client)
    AuthenticatedSession.from_assume_role(
        _source(),
        ROLE,
        mfa_serial="arn:aws:iam::123456789012:mfa/user",
        mfa_code="123456",
        external_id="outside",
        duration_seconds=900,
        role_session_name="script",
    )
    assert seen["SerialNumber"] == "arn:aws:iam::123456789012:mfa/user"
    assert seen["TokenCode"] == "123456"
    assert seen["ExternalId"] == "outside"
    assert seen["DurationSeconds"] == 900
    assert seen["RoleSessionName"] == "script"


def test_mfa_prompt_is_used(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "lupaxa.aws_authenticate.session.read_mfa_code",
        lambda prompt: "654321",
    )
    seen: dict[str, object] = {}

    def fake_create_client(self: object, service: str, **kwargs: object) -> object:
        class _STS:
            def assume_role(self, **params: object) -> object:
                seen.update(params)
                return _ok()

        return _STS()

    monkeypatch.setattr(botocore.session.Session, "create_client", fake_create_client)
    AuthenticatedSession.from_assume_role(
        _source(),
        ROLE,
        mfa_serial="arn:aws:iam::123456789012:mfa/user",
    )
    assert seen["TokenCode"] == "654321"


def test_read_mfa_code_without_tty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("lupaxa.aws_authenticate.mfa.sys.stdin.isatty", lambda: False)
    with pytest.raises(MfaRequiredError):
        read_mfa_code("code: ")


def test_sts_mfa_required(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_assume(
        monkeypatch,
        _client_error("AccessDenied", "MultiFactorAuthentication is required"),
    )
    with pytest.raises(MfaRequiredError):
        AuthenticatedSession.from_assume_role(_source(), ROLE)


def test_sts_rejects_invalid_mfa_code(monkeypatch: pytest.MonkeyPatch) -> None:
    err = _client_error(
        "AccessDenied",
        "MultiFactorAuthentication failed with invalid MFA one time pass code",
    )
    _patch_assume(monkeypatch, err)
    with pytest.raises(RoleAssumptionError) as caught:
        AuthenticatedSession.from_assume_role(_source(), ROLE)
    assert isinstance(caught.value.__cause__, ClientError)


def test_sts_rejects_role(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_assume(monkeypatch, _client_error("AccessDenied", "Not authorized"))
    with pytest.raises(RoleAssumptionError) as caught:
        AuthenticatedSession.from_assume_role(_source(), ROLE)
    assert isinstance(caught.value.__cause__, ClientError)


def test_source_must_be_a_session() -> None:
    with pytest.raises(ValueError, match="source"):
        AuthenticatedSession.from_assume_role("keys", ROLE)  # type: ignore[arg-type]


def test_assume_role_mfa_prompt_without_tty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("lupaxa.aws_authenticate.mfa.sys.stdin.isatty", lambda: False)
    _patch_assume(monkeypatch, _ok())
    with pytest.raises(MfaRequiredError) as caught:
        AuthenticatedSession.from_assume_role(
            _source(),
            ROLE,
            mfa_serial="arn:aws:iam::123456789012:mfa/user",
        )
    assert type(caught.value) is MfaRequiredError


def test_assume_role_rejects_whitespace_mfa_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_assume(monkeypatch, _ok())
    with pytest.raises(ValueError, match="mfa_code"):
        AuthenticatedSession.from_assume_role(
            _source(),
            ROLE,
            mfa_serial="arn:aws:iam::123456789012:mfa/user",
            mfa_code="   ",
        )
