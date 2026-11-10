"""IAM Identity Center browser login and token cache."""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
import time
import webbrowser
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Protocol, cast
from urllib.parse import parse_qs, urlencode, urlparse

import botocore.config
import botocore.session
from botocore.exceptions import BotoCoreError, ClientError
from botocore.utils import JSONFileCache, SSOTokenLoader

from .errors import LoginError

_LOGIN_TIMEOUT_SECONDS = 600
_OIDC_ERRORS = (ClientError, BotoCoreError, OSError)


class _OidcClient(Protocol):
    """Unsigned SSO OIDC client methods this login flow calls."""

    def register_client(
        self,
        *,
        clientName: str,
        clientType: str,
        grantTypes: list[str],
        redirectUris: list[str],
        issuerUrl: str,
        scopes: list[str],
    ) -> Mapping[str, object]:
        """Register a public OIDC client."""

    def create_token(
        self,
        *,
        grantType: str,
        clientId: str,
        clientSecret: str,
        code: str,
        codeVerifier: str,
        redirectUri: str,
    ) -> Mapping[str, object]:
        """Exchange an authorization code for an access token."""


class _CallbackServer(ThreadingHTTPServer):
    """Localhost server that stores the OAuth redirect query."""

    callback_path: str
    query: str | None

    def __init__(
        self,
        server_address: tuple[str, int],
        request_handler_class: type[BaseHTTPRequestHandler],
    ) -> None:
        """Bind the callback server and start with an empty query."""
        self.callback_path = "/oauth/callback"
        self.query = None
        super().__init__(server_address, request_handler_class)


class _CallbackHandler(BaseHTTPRequestHandler):
    """Record one OAuth callback and tell the browser it can close."""

    def do_GET(self) -> None:
        """Store the callback query when the path matches."""
        server = cast("_CallbackServer", self.server)
        parsed = urlparse(self.path)
        if parsed.path != server.callback_path:
            self.send_response(404)
            self.end_headers()
            return
        server.query = parsed.query
        body = b"Authentication complete. You can close this window."
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        """Drop the default stderr access log."""
        return


def login_sso(
    *,
    start_url: str,
    sso_region: str,
    session_name: str | None = None,
) -> None:
    """Log in through IAM Identity Center and cache the access token."""
    verifier = secrets.token_urlsafe(64)
    challenge = _code_challenge(verifier)
    state = secrets.token_urlsafe(16)
    server = _CallbackServer(("127.0.0.1", 0), _CallbackHandler)
    try:
        port = int(server.server_address[1])
        redirect_uri = f"http://127.0.0.1:{port}/oauth/callback"
        try:
            client = _oidc_client(sso_region)
            registration = client.register_client(
                clientName="aws-authenticate",
                clientType="public",
                grantTypes=["authorization_code", "refresh_token"],
                redirectUris=[redirect_uri],
                issuerUrl=start_url,
                scopes=["sso:account:access"],
            )
        except _OIDC_ERRORS as exc:
            raise LoginError(str(exc)) from exc
        client_id = _text(registration.get("clientId"), "client id")
        client_secret = _text(registration.get("clientSecret"), "client secret")
        code = _authorization_code(
            authorize_url=_authorize_url(
                sso_region=sso_region,
                client_id=client_id,
                redirect_uri=redirect_uri,
                state=state,
                code_challenge=challenge,
            ),
            redirect_uri=redirect_uri,
            state=state,
            server=server,
        )
        try:
            created = client.create_token(
                grantType="authorization_code",
                clientId=client_id,
                clientSecret=client_secret,
                code=code,
                codeVerifier=verifier,
                redirectUri=redirect_uri,
            )
        except _OIDC_ERRORS as exc:
            raise LoginError(str(exc)) from exc
    finally:
        server.server_close()

    _save_token(
        start_url=start_url,
        sso_region=sso_region,
        session_name=session_name,
        client_id=client_id,
        client_secret=client_secret,
        registration_expires_at=_registration_expires_at(
            registration.get("clientSecretExpiresAt"),
        ),
        created=created,
    )


def _authorization_code(
    *,
    authorize_url: str,
    redirect_uri: str,
    state: str,
    opener: Callable[[str], bool] | None = None,
    server: _CallbackServer | None = None,
) -> str:
    """Open the authorize URL and return the callback code."""
    if server is not None:
        path = urlparse(redirect_uri).path
        server.callback_path = path or "/oauth/callback"
    browser = webbrowser.open if opener is None else opener
    if not browser(authorize_url):
        raise LoginError("Could not open a browser")
    if server is None:
        raise LoginError("SSO login could not listen for the browser callback")

    deadline = time.monotonic() + _LOGIN_TIMEOUT_SECONDS
    while server.query is None:
        if time.monotonic() >= deadline:
            raise LoginError("Timed out waiting for IAM Identity Center login")
        server.timeout = max(0.1, min(1.0, deadline - time.monotonic()))
        server.handle_request()

    return _code_from_query(server.query, state)


def _oidc_client(sso_region: str) -> _OidcClient:
    raw = botocore.session.Session()
    config = botocore.config.Config(
        signature_version=botocore.UNSIGNED,
        region_name=sso_region,
    )
    client = raw.create_client("sso-oidc", config=config)
    return cast("_OidcClient", client)


def _authorize_url(
    *,
    sso_region: str,
    client_id: str,
    redirect_uri: str,
    state: str,
    code_challenge: str,
) -> str:
    query = urlencode(
        {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "scopes": "sso:account:access",
        },
    )
    return f"https://oidc.{sso_region}.amazonaws.com/authorize?{query}"


def _code_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    encoded = base64.urlsafe_b64encode(digest).rstrip(b"=")
    return encoded.decode("ascii")


def _code_from_query(query: str, state: str) -> str:
    fields = parse_qs(query, keep_blank_values=True)
    error = _first(fields, "error")
    if error is not None:
        detail = _first(fields, "error_description") or error
        raise LoginError(detail)
    if _first(fields, "state") != state:
        raise LoginError("SSO login state did not match")
    code = _first(fields, "code")
    if code is None:
        raise LoginError("SSO login did not return an authorization code")
    return code


def _first(fields: dict[str, list[str]], name: str) -> str | None:
    values = fields.get(name)
    if not values or not values[0]:
        return None
    return values[0]


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise LoginError(f"SSO login did not return {label}")
    return value


def _registration_expires_at(value: object) -> str | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return datetime.fromtimestamp(value, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _save_token(
    *,
    start_url: str,
    sso_region: str,
    session_name: str | None,
    client_id: str,
    client_secret: str,
    registration_expires_at: str | None,
    created: Mapping[str, object],
) -> None:
    expires_in = created.get("expiresIn")
    if isinstance(expires_in, bool) or not isinstance(expires_in, int | float):
        raise LoginError("SSO login did not return a token expiry")
    expires_at = datetime.now(UTC) + timedelta(seconds=int(expires_in))
    token: dict[str, object] = {
        "startUrl": start_url,
        "region": sso_region,
        "accessToken": _text(created.get("accessToken"), "access token"),
        "expiresAt": expires_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "clientId": client_id,
        "clientSecret": client_secret,
    }
    if registration_expires_at is not None:
        token["registrationExpiresAt"] = registration_expires_at
    refresh_token = created.get("refreshToken")
    if isinstance(refresh_token, str) and refresh_token:
        token["refreshToken"] = refresh_token
    cache = JSONFileCache(os.path.expanduser("~/.aws/sso/cache"))
    SSOTokenLoader(cache=cache).save_token(
        start_url,
        token,
        session_name=session_name,
    )
