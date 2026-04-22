"""
PERMYT Protocol Exceptions
"""


class PermytError(Exception):
    """Base exception for all PERMYT-related errors."""

    code = "permyt_error"
    default_message = "An error occurred in the PERMYT protocol."

    def __init__(self, message: str | None = None, extra_info: str | None = None):
        super().__init__(message or self.default_message)
        self.extra_info = extra_info


class UnexpectedError(PermytError):
    """Raised when an unexpected error occurs that doesn't fit other categories."""

    code = "unexpected_error"
    default_message = "An unexpected error occurred."


# -----------------------------------------------------------------
# Security-related exceptions
# -----------------------------------------------------------------


class SecurityError(PermytError):
    """
    Raised when cryptographic validation fails.

    This includes:
    - Invalid JWT signatures
    - Proof of possession validation failures
    - Token tampering detection
    - Replay attack detection (nonce reuse)
    - Timestamp outside valid window
    - JWE decryption failures
    """

    code = "security_error"
    default_message = "Security error: cryptographic validation failed."


class InvalidTokenError(SecurityError):
    """Raised when a token is invalid for any reason."""

    code = "invalid_token"
    default_message = "Invalid token: the provided token is malformed or otherwise invalid."


class TokenExpiredError(SecurityError):
    """Raised when a token has expired."""

    code = "token_expired"
    default_message = "Token expired: the token is no longer valid due to expiration."


class TokenAlreadyUsedError(SecurityError):
    """Raised when a single-use token is used more than once."""

    code = "token_already_used"
    default_message = "Token already used: a single-use token was replayed or reused."


class InvalidScopeError(SecurityError):
    """Raised when a requester tries to access an endpoint outside their approved scope."""

    code = "invalid_scope"
    default_message = "Invalid scope: the requester does not have permission for this endpoint."


class InvalidUserError(SecurityError):
    """Raised when a token references a user that does not exist in the service."""

    code = "invalid_user"
    default_message = "Invalid user: the referenced user does not exist in this service."


class InvalidPublicKeyError(SecurityError):
    """Raised when a provided public key is invalid or cannot be parsed."""

    code = "invalid_public_key"
    default_message = (
        "Invalid public key: the provided public key is missing, malformed or unsupported."
    )


class InvalidProofError(SecurityError):
    """Raised when proof of possession validation fails."""

    code = "invalid_proof"
    default_message = (
        "Invalid proof: the proof of possession is invalid or does not match the payload."
    )


class InvalidPayloadError(SecurityError):
    """Raised when a payload cannot be decrypted or is malformed."""

    code = "invalid_payload"
    default_message = "Invalid payload: the payload is malformed or decryption failed."


class ExpiredRequestError(SecurityError):
    """Raised when a request is rejected due to an expired nonce or timestamp."""

    code = "expired_request"
    default_message = "Expired request: nonce or timestamp is outside the valid window."


# -----------------------------------------------------------------
# Data validation exceptions
# -----------------------------------------------------------------


class InvalidInputError(SecurityError):
    """Raised when input data is invalid or missing required fields."""

    code = "invalid_input"
    default_message = "Invalid input: the provided data is invalid or incomplete."


# -----------------------------------------------------------------
# Transport exceptions
# -----------------------------------------------------------------


class TransportError(PermytError):
    """Raised when an outbound HTTP request fails (non-2xx status, timeout, network error)."""

    code = "transport_error"
    default_message = "Transport error: outbound HTTP request failed."

    def __init__(
        self,
        message: str | None = None,
        extra_info: str | None = None,
        status_code: int | None = None,
    ):
        super().__init__(message, extra_info)
        self.status_code = status_code
