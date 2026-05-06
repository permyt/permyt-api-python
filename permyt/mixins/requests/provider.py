import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from permyt.exceptions import PermytError, UnexpectedError
from permyt.typing import (
    EncryptedRequest,
    ScopeGrant,
    ServiceCallEndpoint,
    ServiceCallRequest,
    TokenMetadata,
    TokenRequestData,
)

__all__ = ("ProviderMixin",)


class ProviderMixin:  # pylint: disable=too-few-public-methods
    """
    Mixin for the provider role: a service that holds user data and responds
    to access requests from requesters.
    """

    # -------------------------------------------------------------------------
    # Handle PERMYT token issuance requests
    # -------------------------------------------------------------------------

    def handle_token_request(self, request: EncryptedRequest) -> dict[str, Any]:
        """
        Handle a token issuance request from PERMYT.

        This is the entry point called by PERMYT when a user approves a
        requester's access request. PERMYT provides the user ID, requester
        identity, requester's public key, and the approved scope.

        The provider:
            1. Validates PERMYT's proof and decrypts request
            2. Resolves the user (validates they exist)
            3. Issues a signed token
            4. Returns encrypted token + endpoints + metadata to PERMYT

        PERMYT will forward this data to the requester.

        Args:
            request (EncryptedRequest): Token request data from PERMYT.

        Returns:
            dict[str, Any]: Response to send back to PERMYT:
                - encrypted_token (str): JWE token encrypted with requester's public key
                - endpoints (list[ServiceCallEndpoint]): Endpoints the requester can access
                - expires_at (str): ISO timestamp when token expires

        Raises:
            PermytError: For any expected errors during processing (invalid user, scope, etc.).
        """
        try:
            # Extract and validate the token request data
            data: TokenRequestData = self._extract_request_data(request)

            # Resolve user (validates they exist in this service)
            user = self.resolve_user(data.get("permyt_user_id"))

            # Set token expiry
            ttl_minutes = data.get("ttl_minutes", 5)
            expires_at = datetime.now(timezone.utc) + timedelta(minutes=ttl_minutes)

            # Issue token and encrypt it for the requester
            token = self._issue_token(data, expires_at)
            encrypted_token = self._encrypt_jwe({"token": token}, data.get("service_public_key"))

            # Store token metadata for later validation
            self.store_token(token, user, data, expires_at)

            return {
                "request_id": data["request_id"],
                "encrypted_token": encrypted_token,
                "endpoints": self.get_endpoints_for_scope(data["scope"]),
                "expires_at": expires_at.isoformat(),
            }

        except PermytError as exc:
            return self.handle_permyt_error(exc)

        except Exception as exc:  # pylint: disable=broad-except
            logging.error(f"Unexpected error in handle_token_request: {exc}", exc_info=True)
            return self.handle_permyt_error(UnexpectedError(extra_info=str(exc)))

    def _issue_token(self, data: TokenRequestData, expires_at: datetime) -> str:
        """
        Generate a signed single-use token for a requester.

        The token payload contains minimal information (JTI, request ID, issued_to).
        User and scope are NOT included — they're stored internally and retrieved
        when the requester presents the token.

        Args:
            data (TokenRequestData): Token request data from PERMYT.
            expires_at (datetime): Token expiry timestamp.

        Returns:
            str: Signed JWT token.
        """
        token_payload = {
            "jti": secrets.token_hex(32),
            "request_id": data["request_id"],
            "service_id": data["service_id"],
            "issued_to": data["service_public_key"],
            "iat": int(datetime.now(timezone.utc).timestamp()),
            "exp": int(expires_at.timestamp()),
        }

        return self._sign_jwt(token_payload)

    # -------------------------------------------------------------------------
    # Handle incoming requester calls using issued tokens
    # -------------------------------------------------------------------------

    def handle_service_call(self, request: ServiceCallRequest) -> dict[str, Any]:
        """
        Handle an incoming request from a requester using a PERMYT-issued token.

        The provider:
            1. Extracts and validates the requester's request
            2. Verifies the token and retrieves metadata (user, scope, service_public_key)
            3. Verifies proof of possession
            4. Processes the request

        Args:
            request (ServiceCallRequest): Complete request with token, payload, proof.

        Returns:
            dict[str, Any]: Response from process_request.

        Raises:
            PermytError: For any expected errors during processing.
        """
        try:
            # Extract and validate the requester call data
            metadata, data = self._extract_service_call_data(request)

            # Process the request
            return self.process_request(metadata, data) or {}

        except PermytError as exc:
            return self.handle_permyt_error(exc)

        except Exception as exc:  # pylint: disable=broad-except
            logging.error(f"Unexpected error in handle_service_call: {exc}", exc_info=True)
            return self.handle_permyt_error(UnexpectedError(extra_info=str(exc)))

    def _extract_service_call_data(
        self, request: ServiceCallRequest
    ) -> tuple[TokenMetadata, dict[str, Any]]:
        """
        Extract and validate requester call data.

        Verifies requester's proof and decrypts payload. Replay protection is
        handled by get_token_metadata(), which marks the single-use token as
        consumed on first use.

        Args:
            request (ServiceCallRequest): Incoming request from requester.

        Returns:
            tuple[TokenMetadata, dict[str, Any]]: Token metadata and decrypted request data.

        Raises:
            PermytError: If proof is invalid or token is invalid/used/expired.
        """
        metadata = self.get_token_metadata(request["token"])

        self._verify_proof(request["proof"], request["payload"], metadata["service_public_key"])

        return metadata, self._decrypt_data(request["payload"]["data"])

    # -------------------------------------------------------------------------
    # Store, validate and retrieve tokens
    # -------------------------------------------------------------------------

    def store_token(
        self, token: str, user: Any, data: TokenRequestData, expires_at: datetime
    ) -> None:
        """
        Store a token with its associated metadata for later retrieval.

        ``data`` is the full :class:`~permyt.typing.TokenRequestData` from
        PERMYT's token-issuance request. It carries everything needed to
        validate incoming service calls later:

        - ``data["scope"]`` — a :data:`~permyt.typing.ScopeGrant` mapping
          scope reference to locked **force-input** values. The provider
          **must persist the full structure** (not just the keys) because the
          inner dicts are the constraints ``process_request`` will enforce.
        - ``data["service_public_key"]`` — the requester's public key, needed
          by ``get_token_metadata`` to verify the requester's proof of
          possession on incoming calls.
        - ``data["request_id"]``, ``data["service_id"]`` — useful for
          auditing and debugging.

        Example scope within ``data``::

            {
                "payments.send": {
                    "amount": 1000,
                    "currency": "USD",
                    "receiver": "alice@example.com",
                },
                "identity.basic": {},
            }

        This metadata is never sent to the requester — only used server-side
        when validating incoming service calls.

        Implement using whatever storage your service uses (SQL database,
        Redis, MongoDB, etc.).

        Args:
            token (str): The signed JWT token string.
            user (Any): Internal user object from resolve_user.
            data (TokenRequestData): Full token request data from PERMYT,
                including scope (with locked force inputs),
                service_public_key, request_id, and service_id.
            expires_at (datetime): Token expiry timestamp.
        """
        raise NotImplementedError("Provider role: implement store_token()")

    def get_token_metadata(self, token: str) -> TokenMetadata:
        """
        Validate a token against the database and return its metadata.

        This method is the single point of token validation. It must:
            1. Verify the token signature and expiry (use jwt.decode — exp is a
               standard NumericDate so joserfc validates it automatically)
            2. Extract the JTI from token claims
            3. Look up the token record by JTI
            4. Verify the token record exists
            5. Verify the token has not been used (single-use enforcement)
            6. Mark the token as used (atomically if possible)
            7. Return the stored metadata (user, scope with force inputs,
               service_public_key, expires_at)

        Steps 5–6 together provide replay protection for service calls: once a
        token is marked as used, any duplicate request with the same token is
        rejected by step 5.

        Args:
            token (str): The signed JWT token string.

        Returns:
            TokenMetadata: Contains user, scope, and service_public_key.

        Raises:
            InvalidTokenError: If token is invalid, does not exist, or signature is wrong.
            TokenAlreadyUsedError: If token was already marked as used.
            TokenExpiredError: If token has expired.
        """
        raise NotImplementedError("Provider role: implement get_token_metadata()")

    # -------------------------------------------------------------------------
    # Provider integration methods
    # -------------------------------------------------------------------------

    def resolve_user(self, permyt_user_id: str | None = None) -> Any:
        """
        Resolve a PERMYT user ID to an internal user.

        This method bridges PERMYT's user identity system with your service's
        internal user model. Validate that the user exists and return whatever
        internal representation your service uses (user object, ID, etc.).

        Args:
            permyt_user_id (str | None): The user ID as known by PERMYT.

        Returns:
            Any: Internal user object or ID as used by this service.

        Raises:
            InvalidUserError: If the user does not exist in this service.
        """
        raise NotImplementedError("Provider role: implement resolve_user()")

    def get_endpoints_for_scope(self, scope: ScopeGrant) -> list[ServiceCallEndpoint]:
        """
        Resolve approved scope to concrete service endpoints.

        ``scope`` is a :data:`~permyt.typing.ScopeGrant` whose **keys** are the
        scope references that endpoint resolution should be based on (e.g.
        ``"professional"``, ``"employment"``). The dict values carry the
        locked force inputs and are typically irrelevant to endpoint
        selection — most implementations can simply iterate ``scope.keys()``
        or use ``in`` membership tests against the dict.

        Your service must translate the approved scope references into
        concrete endpoints with usage instructions.

        Args:
            scope (ScopeGrant): Approved scopes (with their locked force
                inputs) from PERMYT.

        Returns:
            list[ServiceCallEndpoint]: List of endpoints corresponding to the approved scope.
                Each endpoint includes the URL and optional input field descriptions.

        Raises:
            InvalidScopeError: If scope contains invalid or unknown permissions.
        """
        raise NotImplementedError("Provider role: implement get_endpoints_for_scope()")

    def process_request(
        self, metadata: TokenMetadata, data: dict[str, Any]
    ) -> dict[str, Any] | None:
        """
        Process an incoming request from a requester.

        Apply service-specific business rules to the incoming request.
        At this point, all cryptographic validation has passed and the token
        has been marked as used.

        **Force-input enforcement.** ``metadata["scope"]`` is the
        :data:`~permyt.typing.ScopeGrant` originally approved by the user,
        including the locked input values for each scope. Implementations
        **must** validate ``data`` against those locked values for any scope
        that declares them, and raise :class:`InvalidInputError` on mismatch.
        This is the security boundary that prevents an agent from changing
        parameters between approval and execution — for example, a payment
        token approved for ``amount=1000, receiver="alice@example.com"`` must
        not be honoured for a call that tries to send a different amount or
        to a different receiver.

        The exact comparison semantics (exact match, max cap, range, etc.)
        are scope-specific and known only to the provider, so the SDK
        deliberately does not auto-enforce them.

        Args:
            metadata (TokenMetadata): Token metadata (user, scope with force
                inputs, service_public_key, expires_at).
            data (dict[str, Any]): Input data from the requester.

        Returns:
            Response data to send back to the requester.

        Raises:
            InvalidInputError: If the input data is invalid, missing required
                fields, or does not match the locked force inputs in
                ``metadata["scope"]``.
        """
        raise NotImplementedError("Provider role: implement process_request()")
