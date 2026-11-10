"""Frozen view of resolved AWS keys."""

from dataclasses import dataclass


@dataclass(frozen=True)
class AwsCredentials:
    """Access key, secret, and optional session token."""

    access_key_id: str
    secret_access_key: str
    token: str | None
