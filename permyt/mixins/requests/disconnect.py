from typing import Any

import logging

from permyt.exceptions import PermytError, UnexpectedError
from permyt.typing import DisconnectRequest, EncryptedRequest

__all__ = ("UserDisconnectMixin",)


class UserDisconnectMixin:  # pylint: disable=too-few-public-methods
    """
    Mixin for the user-disconnect role: a service that previously linked a
    user via the connect flow needs to be told when the user revokes that
    link from their PERMYT app, so it can revoke local credentials and
    detach the PERMYT identity from the local account.

    Flow:
        1. User triggers disconnect on their PERMYT mobile app.
        2. PERMYT calls the service's handle_user_disconnect() endpoint with
           the user's PERMYT user_id.
        3. Service calls process_user_disconnect() to clear local sessions,
           revoke any stored OAuth/refresh tokens for that user, and unlink
           the permyt_user_id from the local account.

    Disconnect is best-effort from PERMYT's perspective — the broker still
    tears down its side regardless of the service response, so a 5xx here
    will not block the user. Services should be idempotent: a repeat
    disconnect for an already-disconnected user is a no-op.
    """

    def handle_user_disconnect(self, request: EncryptedRequest) -> dict[str, Any]:
        """
        Handle a user disconnect notification forwarded by PERMYT.

        Called by PERMYT after a user disconnects this service from their
        profile via the mobile app. PERMYT encrypts and signs the request
        before calling this endpoint.

        The service:
            1. Verifies PERMYT's proof and validates the request signature.
            2. Validates the timestamp and nonce (replay protection).
            3. Decrypts the disconnect payload.
            4. Dispatches to process_user_disconnect() to revoke local state.

        Args:
            request (EncryptedRequest): Encrypted and signed disconnect request from PERMYT.

        Returns:
            dict[str, Any]: Response forwarded back to PERMYT (typically empty).
        """
        try:
            permyt_public_key = self.get_permyt_public_key()
            payload = request["payload"]

            self._verify_proof(request["proof"], payload, permyt_public_key)
            self._validate_nonce_and_timestamp(payload["nonce"], payload["timestamp"])

            data: DisconnectRequest = self._decrypt_data(payload["data"])

            return self.process_user_disconnect(data) or {}

        except PermytError as exc:
            return self.handle_permyt_error(exc)

        except Exception as exc:  # pylint: disable=broad-except
            logging.error(f"Unexpected error in handle_user_disconnect: {exc}", exc_info=True)
            return self.handle_permyt_error(UnexpectedError(extra_info=str(exc)))

    def process_user_disconnect(self, data: DisconnectRequest) -> dict[str, Any] | None:
        """
        Process a user disconnect notification, applying service-specific cleanup.

        All cryptographic validation has passed at this point. The
        ``data["permyt_user_id"]`` identifies the PERMYT user who disconnected.

        Implementations should:
            - Revoke any stored OAuth refresh tokens / API keys held for the user.
            - Clear any cached session state keyed by ``permyt_user_id``.
            - Detach the ``permyt_user_id`` from the local account record (or
              tombstone it for audit purposes).
            - Be idempotent: repeat calls for an already-disconnected user
              should not raise.

        Args:
            data (DisconnectRequest): Validated disconnect payload containing
                the caller's PERMYT ``permyt_user_id``.

        Returns:
            dict[str, Any] | None: Optional response payload sent back to PERMYT.
        """
        raise NotImplementedError("Disconnect capability: implement process_user_disconnect()")
