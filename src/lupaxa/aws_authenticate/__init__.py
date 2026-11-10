"""Authenticate to AWS and return one session type."""

from .credentials import AwsCredentials
from .errors import (
    AuthenticationError,
    CredentialsNotFoundError,
    LoginError,
    MfaRequiredError,
    RoleAssumptionError,
)
from .session import AuthenticatedSession
from .version import __version__, get_version

__all__ = [
    "AuthenticatedSession",
    "AuthenticationError",
    "AwsCredentials",
    "CredentialsNotFoundError",
    "LoginError",
    "MfaRequiredError",
    "RoleAssumptionError",
    "__version__",
    "get_version",
]
