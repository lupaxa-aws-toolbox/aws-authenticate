"""boto3 session that remembers which credential source won."""

from __future__ import annotations

import hashlib
import os
import subprocess
import tempfile
from pathlib import Path

import boto3.session
import botocore.config
import botocore.session
from botocore.credentials import (
    AssumeRoleCredentialFetcher,
    AssumeRoleWithWebIdentityCredentialFetcher,
    ContainerMetadataFetcher,
    ContainerProvider,
    CredentialResolver,
    Credentials,
    DeferredRefreshableCredentials,
    EnvProvider,
    InstanceMetadataFetcher,
    InstanceMetadataProvider,
    ProcessProvider,
    SSOProvider,
)
from botocore.exceptions import (
    ClientError,
    CredentialRetrievalError,
    InvalidConfigError,
    ProfileNotFound,
    SSOTokenLoadError,
    TokenRetrievalError,
    UnauthorizedSSOTokenError,
)
from botocore.tokens import SSOTokenProvider
from botocore.utils import FileWebIdentityTokenLoader, JSONFileCache

from .credentials import AwsCredentials
from .errors import (
    AuthenticationError,
    CredentialsNotFoundError,
    LoginError,
    MfaRequiredError,
    RoleAssumptionError,
)
from .mfa import read_mfa_code
from .sso import login_sso


def require_text(value: str | None, name: str) -> str:
    """Return a stripped string or raise ValueError."""
    if value is None or not value.strip():
        raise ValueError(f"{name} is required")
    return value.strip()


def _install(
    provider: object,
    region: str | None,
) -> botocore.session.Session:
    raw = botocore.session.Session()
    raw.register_component("credential_provider", CredentialResolver([provider]))
    if region is not None:
        raw.set_config_variable("region", region)
    return raw


class _HoldingProvider:
    """Provider whose load() returns one Credentials object."""

    METHOD = "explicit"

    def __init__(self, creds: Credentials) -> None:
        self._creds = creds

    def load(self) -> Credentials:
        """Return the stored credentials."""
        return self._creds


class AuthenticatedSession(boto3.session.Session):  # type: ignore[misc]
    """boto3 session plus ``method`` and ``credentials``."""

    def __init__(
        self,
        botocore_session: botocore.session.Session,
        method: str,
    ) -> None:
        """Keep the botocore session that owns the credential provider."""
        super().__init__(botocore_session=botocore_session)
        self.method = method

    @property
    def credentials(self) -> AwsCredentials:
        """Return the current keys. A later read sees a refresh."""
        resolved = self.get_credentials()
        if resolved is None:
            raise CredentialsNotFoundError("No credentials resolved")
        frozen = resolved.get_frozen_credentials()
        return AwsCredentials(frozen.access_key, frozen.secret_key, frozen.token)

    @classmethod
    def from_keys(
        cls,
        access_key: str,
        secret_key: str,
        session_token: str | None = None,
        region: str | None = None,
    ) -> AuthenticatedSession:
        """Return a session for the access key and secret passed in."""
        key = require_text(access_key, "access_key")
        secret = require_text(secret_key, "secret_key")
        token = (session_token.strip() or None) if session_token else None
        creds = Credentials(key, secret, token, method="explicit")
        provider = _HoldingProvider(creds)
        return open_session(_install(provider, region), method="explicit")

    @classmethod
    def from_environment(cls, region: str | None = None) -> AuthenticatedSession:
        """Return a session for AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY."""
        return open_session(
            _install(EnvProvider(environ=os.environ), region),
            method="env",
        )

    @classmethod
    def from_chain(
        cls,
        profile: str | None = None,
        region: str | None = None,
    ) -> AuthenticatedSession:
        """Resolve botocore's standard chain, optionally for one profile."""
        raw = botocore.session.Session(profile=profile)
        if region is not None:
            raw.set_config_variable("region", region)
        return _open_sso(raw)

    @classmethod
    def from_sso(
        cls,
        start_url: str,
        sso_region: str,
        account_id: str,
        role_name: str,
        *,
        region: str | None = None,
    ) -> AuthenticatedSession:
        """Return a session for an IAM Identity Center account role."""
        start = require_text(start_url, "start_url")
        portal_region = require_text(sso_region, "sso_region")
        account = require_text(account_id, "account_id")
        role = require_text(role_name, "role_name")
        session_name = _sso_session_name(start)
        with tempfile.TemporaryDirectory(prefix="aws-authenticate-") as directory:
            config_path, credentials_path = _write_sso_files(
                Path(directory),
                session_name,
                start,
                portal_region,
                account,
                role,
            )
            raw = botocore.session.Session(profile=session_name)
            raw.set_config_variable("config_file", str(config_path))
            raw.set_config_variable("credentials_file", str(credentials_path))
            if region is not None:
                raw.set_config_variable("region", region)
            cache = JSONFileCache(os.path.expanduser("~/.aws/sso/cache"))
            token_provider = SSOTokenProvider(
                raw,
                cache=cache,
                profile_name=session_name,
            )
            provider = SSOProvider(
                load_config=lambda: raw.full_config,
                client_creator=raw.create_client,
                profile_name=session_name,
                token_provider=token_provider,
                token_cache=cache,
            )
            raw.register_component(
                "credential_provider",
                CredentialResolver([provider]),
            )
            return _open_sso(raw, method="sso")

    @classmethod
    def from_profile(
        cls,
        name: str,
        region: str | None = None,
    ) -> AuthenticatedSession:
        """Resolve one named profile through the standard chain."""
        name = require_text(name, "name")
        return cls.from_chain(profile=name, region=region)

    @classmethod
    def from_assume_role(
        cls,
        source: AuthenticatedSession,
        role_arn: str,
        *,
        external_id: str | None = None,
        mfa_serial: str | None = None,
        mfa_code: str | None = None,
        duration_seconds: int | None = None,
        role_session_name: str | None = None,
        region: str | None = None,
    ) -> AuthenticatedSession:
        """Return a session with STS credentials for ``role_arn``."""
        if not isinstance(source, AuthenticatedSession):
            raise ValueError("source is required")
        arn = require_text(role_arn, "role_arn")
        if mfa_code and not mfa_serial:
            raise ValueError("mfa_serial is required")

        extra_args: dict[str, object] = {
            "RoleSessionName": role_session_name or "aws-authenticate",
        }
        if external_id is not None:
            extra_args["ExternalId"] = external_id
        if duration_seconds is not None:
            extra_args["DurationSeconds"] = duration_seconds
        if mfa_serial is not None:
            extra_args["SerialNumber"] = mfa_serial

        mfa_prompter = None
        if mfa_serial is not None:

            def prompter(prompt: str) -> str:
                if mfa_code:
                    return require_text(mfa_code, "mfa_code")
                return read_mfa_code(prompt)

            mfa_prompter = prompter

        fetcher = AssumeRoleCredentialFetcher(
            client_creator=source._session.create_client,
            source_credentials=source.get_credentials(),
            role_arn=arn,
            extra_args=extra_args,
            mfa_prompter=mfa_prompter,
        )
        creds = DeferredRefreshableCredentials(
            refresh_using=fetcher.fetch_credentials,
            method="assume-role",
        )
        provider = _HoldingProvider(creds)
        return open_session(_install(provider, region), method="assume-role")

    @classmethod
    def from_web_identity(
        cls,
        role_arn: str,
        *,
        token: str | None = None,
        token_file: str | None = None,
        role_session_name: str | None = None,
        duration_seconds: int | None = None,
        region: str | None = None,
    ) -> AuthenticatedSession:
        """Return a session that assumes a role with a web identity token."""
        arn = require_text(role_arn, "role_arn")
        if (token is None) == (token_file is None):
            raise ValueError("exactly one of token or token_file is required")

        if token_file is not None:
            try:
                token_value = Path(token_file).read_text(encoding="utf-8")
            except OSError as exc:
                raise CredentialsNotFoundError(
                    f"Web identity token file not found: {token_file}",
                ) from exc
            token_value = token_value.strip()
            if not token_value:
                raise CredentialsNotFoundError("Web identity token is required")
            web_identity_token_loader = FileWebIdentityTokenLoader(token_file)
        else:
            token_value = (token or "").strip()
            if not token_value:
                raise CredentialsNotFoundError("Web identity token is required")

            def web_identity_token_loader() -> str:
                return token_value

        extra_args: dict[str, object] = {
            "RoleSessionName": role_session_name or "aws-authenticate",
        }
        if duration_seconds is not None:
            extra_args["DurationSeconds"] = duration_seconds

        raw = botocore.session.Session()
        fetcher = AssumeRoleWithWebIdentityCredentialFetcher(
            client_creator=raw.create_client,
            web_identity_token_loader=web_identity_token_loader,
            role_arn=arn,
            extra_args=extra_args,
        )
        creds = DeferredRefreshableCredentials(
            refresh_using=fetcher.fetch_credentials,
            method="assume-role-with-web-identity",
        )
        provider = _HoldingProvider(creds)
        return open_session(
            _install(provider, region),
            method="assume-role-with-web-identity",
        )

    @classmethod
    def from_saml(
        cls,
        role_arn: str,
        principal_arn: str,
        assertion: str,
        *,
        duration_seconds: int | None = None,
        region: str | None = None,
    ) -> AuthenticatedSession:
        """Return a session with STS credentials from a SAML assertion."""
        arn = require_text(role_arn, "role_arn")
        principal = require_text(principal_arn, "principal_arn")
        if not assertion.strip():
            raise CredentialsNotFoundError("SAML assertion is required")

        params: dict[str, object] = {
            "RoleArn": arn,
            "PrincipalArn": principal,
            "SAMLAssertion": assertion,
        }
        if duration_seconds is not None:
            params["DurationSeconds"] = duration_seconds

        raw = botocore.session.Session()
        try:
            sts = raw.create_client(
                "sts",
                region_name=region,
                config=botocore.config.Config(
                    signature_version=botocore.UNSIGNED,
                ),
            )
            response = sts.assume_role_with_saml(**params)
        except AuthenticationError:
            raise
        except ValueError:
            raise
        except Exception as exc:
            raise map_aws_error(exc) from exc

        keys = response["Credentials"]
        creds = Credentials(
            keys["AccessKeyId"],
            keys["SecretAccessKey"],
            keys.get("SessionToken"),
            method="saml",
        )
        provider = _HoldingProvider(creds)
        return open_session(_install(provider, region), method="saml")

    @classmethod
    def from_process(
        cls,
        command: str,
        region: str | None = None,
    ) -> AuthenticatedSession:
        """Return a session whose keys come from an external credential process."""
        cred_process = require_text(command, "command")
        profile_name = "aws-authenticate"

        def load_config() -> dict[str, object]:
            return {"profiles": {profile_name: {"credential_process": cred_process}}}

        provider = ProcessProvider(
            profile_name=profile_name,
            load_config=load_config,
            popen=subprocess.Popen,
        )
        return open_session(
            _install(provider, region),
            method="custom-process",
        )

    @classmethod
    def from_instance_metadata(
        cls,
        region: str | None = None,
    ) -> AuthenticatedSession:
        """Return a session for the EC2 instance IAM role."""
        provider = InstanceMetadataProvider(InstanceMetadataFetcher())
        return open_session(_install(provider, region), method="iam-role")

    @classmethod
    def from_container(cls, region: str | None = None) -> AuthenticatedSession:
        """Return a session for ECS or EKS container credentials."""
        provider = ContainerProvider(
            environ=os.environ,
            fetcher=ContainerMetadataFetcher(),
        )
        return open_session(_install(provider, region), method="container-role")


def map_aws_error(exc: BaseException) -> AuthenticationError:
    """Turn a botocore or STS failure into a lupaxa.aws_authenticate error."""
    if isinstance(exc, CredentialRetrievalError | InvalidConfigError | ProfileNotFound):
        return CredentialsNotFoundError(str(exc))
    if isinstance(exc, ClientError):
        error = exc.response.get("Error", {})
        code = str(error.get("Code", ""))
        message = str(error.get("Message", code))
        if "MultiFactorAuthentication" in message and "is required" in message:
            return MfaRequiredError(message)
        return RoleAssumptionError(message)
    return AuthenticationError(str(exc))


def open_session(
    botocore_session: botocore.session.Session,
    method: str | None,
) -> AuthenticatedSession:
    """Resolve once and return the session. ``method`` overrides the provider label."""
    try:
        resolved = botocore_session.get_credentials()
        if resolved is None or not resolved.access_key:
            raise CredentialsNotFoundError("No credentials found")
        frozen = resolved.get_frozen_credentials()
        if not frozen.access_key or not frozen.secret_key:
            raise CredentialsNotFoundError("No credentials found")
    except AuthenticationError:
        raise
    except ValueError:
        raise
    except Exception as exc:
        raise map_aws_error(exc) from exc
    label = method if method is not None else resolved.method
    return AuthenticatedSession(botocore_session, label)


def _open_sso(
    raw: botocore.session.Session,
    method: str | None = None,
) -> AuthenticatedSession:
    """Resolve a session, logging in once when the SSO token is unusable."""
    try:
        return open_session(raw, method=method)
    except AuthenticationError as exc:
        if not _is_token_error(exc):
            raise
        start_url, sso_region, session_name = _sso_login_target(raw)
        login_sso(
            start_url=start_url,
            sso_region=sso_region,
            session_name=session_name,
        )
    try:
        return open_session(raw, method=method)
    except AuthenticationError as exc:
        if _is_token_error(exc):
            raise LoginError("SSO login did not produce a usable token") from exc
        raise


def _is_token_error(exc: BaseException) -> bool:
    current: BaseException | None = exc
    seen: set[int] = set()
    while current is not None and id(current) not in seen:
        if isinstance(
            current,
            UnauthorizedSSOTokenError | SSOTokenLoadError | TokenRetrievalError,
        ):
            return True
        seen.add(id(current))
        current = current.__cause__
    return False


def _sso_session_name(start_url: str) -> str:
    digest = hashlib.sha1(
        start_url.encode("utf-8"),
        usedforsecurity=False,
    ).hexdigest()
    return f"aws-authenticate-{digest[:12]}"


def _sso_login_target(
    raw: botocore.session.Session,
) -> tuple[str, str, str | None]:
    loaded = raw.full_config
    profiles = loaded.get("profiles", {})
    if not isinstance(profiles, dict):
        profiles = {}
    profile_name = str(raw.profile or "default")
    seen: set[str] = set()
    while profile_name and profile_name not in seen:
        seen.add(profile_name)
        profile = profiles.get(profile_name, {})
        if not isinstance(profile, dict):
            break
        start_url, sso_region, session_name = _profile_sso_target(loaded, profile)
        if start_url and sso_region:
            return start_url, sso_region, session_name
        source = profile.get("source_profile")
        if not isinstance(source, str) or not source.strip():
            break
        profile_name = source.strip()
    raise LoginError("SSO login needs a start URL and region")


def _profile_sso_target(
    loaded: object,
    profile: dict[str, object],
) -> tuple[str, str, str | None]:
    session_name = profile.get("sso_session")
    if isinstance(session_name, str) and session_name.strip():
        name = session_name.strip()
        sessions: object = {}
        if isinstance(loaded, dict):
            sessions = loaded.get("sso_sessions", {})
        sso_session: object = {}
        if isinstance(sessions, dict):
            sso_session = sessions.get(name, {})
        if not isinstance(sso_session, dict):
            sso_session = {}
        start_url = sso_session.get(
            "sso_start_url",
            profile.get("sso_start_url", ""),
        )
        sso_region = sso_session.get("sso_region", profile.get("sso_region", ""))
        return _sso_text(start_url), _sso_text(sso_region), name
    return (
        _sso_text(profile.get("sso_start_url", "")),
        _sso_text(profile.get("sso_region", "")),
        None,
    )


def _sso_text(value: object) -> str:
    if isinstance(value, str):
        return value.strip()
    return ""


def _write_sso_files(
    directory: Path,
    session_name: str,
    start_url: str,
    sso_region: str,
    account_id: str,
    role_name: str,
) -> tuple[Path, Path]:
    config_path = directory / "config"
    credentials_path = directory / "credentials"
    config_path.write_text(
        "\n".join(
            (
                f"[sso-session {session_name}]",
                f"sso_start_url = {start_url}",
                f"sso_region = {sso_region}",
                "",
                f"[profile {session_name}]",
                f"sso_session = {session_name}",
                f"sso_account_id = {account_id}",
                f"sso_role_name = {role_name}",
                "",
            ),
        ),
        encoding="utf-8",
    )
    credentials_path.write_text("", encoding="utf-8")
    return config_path, credentials_path
