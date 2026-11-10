"""Authentication failures raised by lupaxa.aws_authenticate."""


class AuthenticationError(Exception):
    """A credential source failed. The original error is ``__cause__``."""


class CredentialsNotFoundError(AuthenticationError):
    """The chosen source had no keys."""


class LoginError(AuthenticationError):
    """IAM Identity Center login did not produce a token."""


class MfaRequiredError(AuthenticationError):
    """Assume-role needs an MFA code and none was supplied."""


class RoleAssumptionError(AuthenticationError):
    """STS or IAM Identity Center rejected the role request."""
