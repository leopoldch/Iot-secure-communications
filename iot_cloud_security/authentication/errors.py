# errors


class AuthenticationError(Exception):
    """Base error for the authentication protocol."""


class ReplayAttackError(AuthenticationError):
    """Raised when a nonce is reused or a challenge is too old."""


class InvalidResponseError(AuthenticationError):
    """Raised when a response does not match the expected HMAC."""
