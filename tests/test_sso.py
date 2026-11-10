"""SSO uses a cached token or one browser login, then GetRoleCredentials."""

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from botocore.exceptions import ClientError, SSOTokenLoadError

from lupaxa.aws_authenticate.credentials import AwsCredentials
from lupaxa.aws_authenticate.errors import (
    AuthenticationError,
    LoginError,
    RoleAssumptionError,
)
from lupaxa.aws_authenticate.session import AuthenticatedSession
from lupaxa.aws_authenticate.sso import _authorization_code, login_sso

START = "https://example.awsapps.com/start"
OTHER = "https://other.awsapps.com/start"
ACCOUNT = "123456789012"
ROLE = "Admin"


def _session_name(start_url: str) -> str:
    digest = hashlib.sha1(  # noqa: S324
        start_url.encode("utf-8"),
        usedforsecurity=False,
    ).hexdigest()
    return f"aws-authenticate-{digest[:12]}"


def _cache_file(home: Path, session_name: str | None) -> Path:
    key = hashlib.sha1(  # noqa: S324
        (session_name or START).encode("utf-8"),
        usedforsecurity=False,
    ).hexdigest()
    return home / ".aws" / "sso" / "cache" / f"{key}.json"


def _seed(
    home: Path,
    session_name: str | None,
    *,
    access_token: str | None = None,
    expires_at: str = "2999-01-01T00:00:00Z",
) -> None:
    path = _cache_file(home, session_name)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "startUrl": START,
                "region": "us-east-1",
                "accessToken": access_token or "cached-token",
                "expiresAt": expires_at,
            }
        ),
        encoding="utf-8",
    )


def _patch_role(monkeypatch: pytest.MonkeyPatch, result: object) -> None:
    def fake_make_api_call(
        self: object,
        operation_name: str,
        params: dict[str, object],
    ) -> object:
        if operation_name == "GetRoleCredentials":
            if isinstance(result, Exception):
                raise result
            return result
        raise AssertionError(operation_name)

    monkeypatch.setattr(
        "botocore.client.BaseClient._make_api_call",
        fake_make_api_call,
    )


def _role_payload() -> dict[str, object]:
    return {
        "roleCredentials": {
            "accessKeyId": "ASIA_SSO",
            "secretAccessKey": "sso-secret",
            "sessionToken": "sso-token",
            "expiration": 4102444800000,
        }
    }


def test_cached_token_skips_login(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    _seed(tmp_path, _session_name(START))

    def fail_login(**kwargs: object) -> None:
        raise AssertionError("login should not run")

    monkeypatch.setattr("lupaxa.aws_authenticate.session.login_sso", fail_login)
    _patch_role(monkeypatch, _role_payload())
    session = AuthenticatedSession.from_sso(START, "us-east-1", ACCOUNT, ROLE)
    assert session.method == "sso"
    assert session.credentials == AwsCredentials("ASIA_SSO", "sso-secret", "sso-token")


def test_missing_token_logs_in_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    calls = {"n": 0}

    def fake_login(**kwargs: object) -> None:
        calls["n"] += 1
        name = kwargs.get("session_name")
        _seed(tmp_path, name if isinstance(name, str) else None)

    monkeypatch.setattr("lupaxa.aws_authenticate.session.login_sso", fake_login)
    _patch_role(monkeypatch, _role_payload())
    session = AuthenticatedSession.from_sso(START, "us-east-1", ACCOUNT, ROLE)
    assert calls["n"] == 1
    assert session.credentials.access_key_id == "ASIA_SSO"


def test_login_failure(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))

    def fake_login(**kwargs: object) -> None:
        raise LoginError("browser closed")

    monkeypatch.setattr("lupaxa.aws_authenticate.session.login_sso", fake_login)
    with pytest.raises(LoginError):
        AuthenticatedSession.from_sso(START, "us-east-1", ACCOUNT, ROLE)


def test_role_rejected(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    _seed(tmp_path, _session_name(START))
    _patch_role(
        monkeypatch,
        ClientError(
            {"Error": {"Code": "ForbiddenException", "Message": "no such role"}},
            "GetRoleCredentials",
        ),
    )
    with pytest.raises(RoleAssumptionError):
        AuthenticatedSession.from_sso(START, "us-east-1", ACCOUNT, ROLE)


def test_login_sso_writes_the_cache(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))

    class _Oidc:
        def register_client(self, **kwargs: object) -> dict[str, object]:
            return {
                "clientId": "cid",
                "clientSecret": "csec",
                "clientSecretExpiresAt": 4102444800,
            }

        def create_token(self, **kwargs: object) -> dict[str, object]:
            assert kwargs["grantType"] == "authorization_code"
            assert kwargs["code"] == "auth-code"
            return {
                "accessToken": "fresh-token",
                "expiresIn": 3600,
                "refreshToken": "refresh-token",
            }

    def fake_create_client(self: object, service: str, **kwargs: object) -> _Oidc:
        assert service == "sso-oidc"
        return _Oidc()

    monkeypatch.setattr("botocore.session.Session.create_client", fake_create_client)
    monkeypatch.setattr(
        "lupaxa.aws_authenticate.sso._authorization_code",
        lambda **kwargs: "auth-code",
    )
    login_sso(start_url=START, sso_region="us-east-1", session_name="aws-authenticate")
    cached = json.loads(
        _cache_file(tmp_path, "aws-authenticate").read_text(encoding="utf-8")
    )
    assert cached["accessToken"] == "fresh-token"
    assert cached["startUrl"] == START
    expected_expiry = datetime.fromtimestamp(4102444800, UTC).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    assert cached["registrationExpiresAt"] == expected_expiry


def test_browser_cannot_open() -> None:
    with pytest.raises(LoginError):
        _authorization_code(
            authorize_url="https://oidc.us-east-1.amazonaws.com/authorize",
            redirect_uri="http://127.0.0.1:9/oauth/callback",
            state="state",
            opener=lambda url: False,
        )


def test_expired_sso_token_logs_in_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    name = _session_name(START)
    _seed(
        tmp_path,
        name,
        access_token="expired-token",
        expires_at="2000-01-01T00:00:00Z",
    )
    calls = {"n": 0}

    def fake_login(**kwargs: object) -> None:
        calls["n"] += 1
        assert kwargs.get("session_name") == name
        _seed(tmp_path, name)

    monkeypatch.setattr("lupaxa.aws_authenticate.session.login_sso", fake_login)
    _patch_role(monkeypatch, _role_payload())
    session = AuthenticatedSession.from_sso(START, "us-east-1", ACCOUNT, ROLE)
    assert calls["n"] == 1
    assert session.credentials.access_key_id == "ASIA_SSO"


def test_register_client_sends_authorization_code_grant(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    seen: dict[str, object] = {}

    def fake_make_api_call(
        self: object,
        operation_name: str,
        params: dict[str, object],
    ) -> object:
        if operation_name == "RegisterClient":
            seen.update(params)
            return {
                "clientId": "cid",
                "clientSecret": "csec",
                "clientSecretExpiresAt": 4102444800,
            }
        if operation_name == "CreateToken":
            return {"accessToken": "fresh-token", "expiresIn": 3600}
        raise AssertionError(operation_name)

    monkeypatch.setattr("botocore.client.BaseClient._make_api_call", fake_make_api_call)
    monkeypatch.setattr(
        "lupaxa.aws_authenticate.sso._authorization_code",
        lambda **kwargs: "auth-code",
    )
    login_sso(start_url=START, sso_region="us-east-1", session_name="aws-authenticate")
    assert seen["clientName"] == "aws-authenticate"
    assert seen["clientType"] == "public"
    assert seen["grantTypes"] == ["authorization_code", "refresh_token"]
    assert seen["issuerUrl"] == START
    assert seen["scopes"] == ["sso:account:access"]
    redirect_uris = seen["redirectUris"]
    assert isinstance(redirect_uris, list)
    assert len(redirect_uris) == 1
    assert str(redirect_uris[0]).startswith("http://127.0.0.1:")
    assert str(redirect_uris[0]).endswith("/oauth/callback")


def test_missing_registration_expiry_is_omitted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))

    class _Oidc:
        def register_client(self, **kwargs: object) -> dict[str, object]:
            return {
                "clientId": "cid",
                "clientSecret": "csec",
                "clientSecretExpiresAt": "soon",
            }

        def create_token(self, **kwargs: object) -> dict[str, object]:
            return {"accessToken": "fresh-token", "expiresIn": 3600}

    def fake_create_client(self: object, service: str, **kwargs: object) -> _Oidc:
        return _Oidc()

    monkeypatch.setattr("botocore.session.Session.create_client", fake_create_client)
    monkeypatch.setattr(
        "lupaxa.aws_authenticate.sso._authorization_code",
        lambda **kwargs: "auth-code",
    )
    login_sso(start_url=START, sso_region="us-east-1", session_name="named")
    cached = json.loads(_cache_file(tmp_path, "named").read_text(encoding="utf-8"))
    assert "registrationExpiresAt" not in cached
    assert "None" not in json.dumps(cached)


def _raise_token_error(
    raw: object,
    method: str | None = None,
) -> AuthenticatedSession:
    raise AuthenticationError("missing token") from SSOTokenLoadError(
        error_msg="missing",
    )


def _config_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, body: str) -> None:
    config = tmp_path / "config"
    credentials = tmp_path / "credentials"
    config.write_text(body, encoding="utf-8")
    credentials.write_text("", encoding="utf-8")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(config))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(credentials))
    monkeypatch.setenv("HOME", str(tmp_path))


def test_empty_sso_target_does_not_log_in(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _config_files(
        tmp_path,
        monkeypatch,
        "\n".join(
            (
                "[profile app]",
                "source_profile = base",
                "",
                "[profile base]",
                "region = us-east-1",
                "",
            )
        ),
    )
    calls = {"n": 0}

    def fake_login(**kwargs: object) -> None:
        calls["n"] += 1

    monkeypatch.setattr("lupaxa.aws_authenticate.session.login_sso", fake_login)
    monkeypatch.setattr(
        "lupaxa.aws_authenticate.session.open_session",
        _raise_token_error,
    )
    with pytest.raises(LoginError, match="start URL"):
        AuthenticatedSession.from_chain(profile="app")
    assert calls["n"] == 0


def test_sso_login_walks_to_source_profile(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _config_files(
        tmp_path,
        monkeypatch,
        "\n".join(
            (
                "[profile app]",
                "role_arn = arn:aws:iam::123456789012:role/App",
                "source_profile = portal",
                "",
                "[profile portal]",
                "sso_session = portal",
                "sso_account_id = 123456789012",
                "sso_role_name = Admin",
                "",
                "[sso-session portal]",
                f"sso_start_url = {START}",
                "sso_region = eu-west-1",
                "",
            )
        ),
    )
    seen: dict[str, object] = {}

    def fake_login(**kwargs: object) -> None:
        seen.update(kwargs)

    monkeypatch.setattr("lupaxa.aws_authenticate.session.login_sso", fake_login)
    monkeypatch.setattr(
        "lupaxa.aws_authenticate.session.open_session",
        _raise_token_error,
    )
    with pytest.raises(LoginError, match="usable token"):
        AuthenticatedSession.from_chain(profile="app")
    assert seen["start_url"] == START
    assert seen["sso_region"] == "eu-west-1"
    assert seen["session_name"] == "portal"


def test_two_start_urls_use_distinct_cache_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    names: list[str] = []

    def fake_login(**kwargs: object) -> None:
        name = kwargs.get("session_name")
        assert isinstance(name, str)
        names.append(name)
        _seed(tmp_path, name, access_token=f"token-{len(names)}")

    monkeypatch.setattr("lupaxa.aws_authenticate.session.login_sso", fake_login)
    _patch_role(monkeypatch, _role_payload())
    AuthenticatedSession.from_sso(START, "us-east-1", ACCOUNT, ROLE)
    AuthenticatedSession.from_sso(OTHER, "us-east-1", ACCOUNT, ROLE)
    assert names == [_session_name(START), _session_name(OTHER)]
    first = _cache_file(tmp_path, names[0])
    second = _cache_file(tmp_path, names[1])
    assert first != second
    assert json.loads(first.read_text(encoding="utf-8"))["accessToken"] == "token-1"
    assert json.loads(second.read_text(encoding="utf-8"))["accessToken"] == "token-2"
