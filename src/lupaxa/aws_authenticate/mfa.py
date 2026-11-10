"""Terminal prompt for an assume-role MFA code."""

import sys

from .errors import MfaRequiredError


def read_mfa_code(prompt: str) -> str:
    """Read one MFA code from the terminal."""
    if not sys.stdin.isatty():
        raise MfaRequiredError("MFA code required")
    code = input(prompt).strip()
    if not code:
        raise MfaRequiredError("MFA code required")
    return code
