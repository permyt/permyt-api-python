from datetime import datetime, timedelta, timezone
from typing import Any

import logging
import secrets

from permyt.exceptions import PermytError, UnexpectedError
from permyt.typing import ConnectPayload, ConnectRequest, EncryptedPayload, EncryptedRequest

__all__ = ("UserConnectMixin",)


class UserConnectMixin:  # pylint: disable=too-few-public-methods
    """
    Mixin for the user-connect role: a service that allows users to link their
    account to PERMYT via a QR code, NFC, or OAuth button flow.

    Flow:
        1. Service calls generate_connect_token() to produce a short-lived signed
           token and the connect payload to deliver to the user.
        2. User triggers the connect flow (scans a QR code, taps an NFC tag, or
           clicks a button). Their PERMYT app reads the payload and sends it to
           PERMYT together with the user's PERMYT identity.
        3. PERMYT calls the service's handle_user_connect() endpoint with the
           original token and the user's PERMYT user_id.
        4. Service validates the token and calls process_user_connect() to create,
           log in, or link the user account.
    """

    # -------------------------------------------------------------------------
    # Generate token and connect payload for QR code / NFC / button flows
    # -------------------------------------------------------------------------

    def generate_connect_token(self, system_user_id: str | None = None) -> dict[str, Any]:
        """
        Generate a short-lived signed token and the corresponding connect payload
        for a user connect or login flow.

        Store the returned ``token`` server-side (keyed by JTI) so it can be
        validated when PERMYT calls handle_user_connect(). Deliver the returned
        ``data`` to the user via QR code, NFC tag, or OAuth redirect button.

        The returned ``data`` is a fully-formed signed service-request envelope
        — the same shape every other service-to-PERMYT call uses. PERMYT's
        ``ServiceRequestSerializer`` consumes it unchanged: it verifies the
        outer proof against this service's public key, validates the
        nonce/timestamp window, and decrypts the inner JWE with PERMYT's
        per-service private key. The QR's 5-minute validity comes from the
        envelope's nonce + timestamp window — there is no separate ``expires_at``.

        Args:
            system_user_id (str | None): Internal user ID if the connect flow is
                initiated by an already-authenticated user (account-linking flow).
                Pass ``None`` for anonymous login or sign-up flows.

        Returns:
            dict: A mapping with three keys:
                - ``system_user_id`` (str | None): Echoed back for convenience.
                - ``token`` (str): Plain signed JWT — store this server-side (keyed
                  by JTI) for signature validation when PERMYT calls back.
                - ``data`` (ConnectPayload): The standard envelope to deliver to
                  the user via QR code, NFC, or button deep-link.
        """
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
        token_payload = {
            "jti": secrets.token_hex(32),
            "system_user_id": system_user_id,
            "iat": int(datetime.now(timezone.utc).timestamp()),
            "exp": int(expires_at.timestamp()),
        }
        signed_token = self._sign_jwt(token_payload)

        # Encrypt the signed JWT for PERMYT so the raw token is never exposed in
        # the connect payload. PERMYT decrypts it, extracts the JWT, and passes
        # it back to handle_user_connect() inside an EncryptedRequest.
        encrypted_token = self._encrypt_jwe({"token": signed_token}, self.get_permyt_public_key())

        # Wrap in the standard signed-envelope shape so PERMYT's existing
        # ServiceRequestSerializer can consume the QR contents directly.
        payload: EncryptedPayload = {
            "data": encrypted_token,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "nonce": secrets.token_hex(32),
        }
        proof = self._create_proof(payload)

        connect_payload: ConnectPayload = {
            "service_id": self.get_service_id(),
            "payload": payload,
            "proof": proof,
        }

        return {
            "system_user_id": system_user_id,
            "token": signed_token,
            "data": connect_payload,
        }

    # -------------------------------------------------------------------------
    # Handle user connect/login requests from PERMYT
    # -------------------------------------------------------------------------

    def handle_user_connect(self, request: EncryptedRequest) -> dict[str, Any]:
        """
        Handle a user connect or login request forwarded by PERMYT.

        Called by PERMYT after a user completes a connect flow (QR code scan,
        NFC tap, or button redirect) and their app sends the connect payload to
        PERMYT. PERMYT encrypts and signs the request before calling this endpoint.

        The service:
            1. Verifies PERMYT's proof and validates the request signature.
            2. Validates the timestamp and nonce (replay protection).
            3. Decrypts the connect payload.
            4. Dispatches to process_user_connect() for account creation, login,
               or account linking.

        Args:
            request (EncryptedRequest): Encrypted and signed connect request from PERMYT.

        Returns:
            dict[str, Any]: Response forwarded back to the user's app via PERMYT,
                or a formatted error dict if processing fails.

        Raises:
            PermytError: Caught internally; returned as a formatted error response.
        """
        try:
            permyt_public_key = self.get_permyt_public_key()
            payload = request["payload"]

            # Step 1 — Verify PERMYT's proof
            self._verify_proof(request["proof"], payload, permyt_public_key)

            # Step 2 — Validate timestamp and nonce
            self._validate_nonce_and_timestamp(payload["nonce"], payload["timestamp"])

            # Step 3 — Decrypt the connect request data
            data: ConnectRequest = self._decrypt_data(payload["data"])

            # Dispatch to the service-specific connect handler
            return self.process_user_connect(data) or {}

        except PermytError as exc:
            return self.handle_permyt_error(exc)

        except Exception as exc:  # pylint: disable=broad-except
            logging.error(f"Unexpected error in handle_user_connect: {exc}", exc_info=True)
            return self.handle_permyt_error(UnexpectedError(extra_info=str(exc)))

    def process_user_connect(self, data: ConnectRequest) -> dict[str, Any] | None:
        """
        Process a user connect or login request, applying service-specific business rules.

        All cryptographic validation has passed at this point. Validate ``data["token"]``
        by verifying its signature against this service's public key and checking its JTI
        against the server-side record created by generate_connect_token(). The
        ``data["permyt_user_id"]`` is the caller's PERMYT identity.

        Three scenarios apply depending on the token and user state:

        1. **New user** — Token is not linked to any account and ``permyt_user_id`` is
           unrecognized: create a new account and associate it with this PERMYT user.
        2. **Returning user** — Token is not linked to any account but ``permyt_user_id``
           is already known: log the user into their existing account.
        3. **First-time account linking** — Token is linked to an existing account
           (``system_user_id`` was passed to generate_connect_token) but ``permyt_user_id``
           has never been seen before: associate the existing account with this
           PERMYT user for future logins.

        Args:
            data (ConnectRequest): Validated connect payload containing the service's
                token and the caller's PERMYT ``permyt_user_id``.

        Returns:
            dict[str, Any] | None: Response payload sent back to the user's app via PERMYT.

        Raises:
            InvalidTokenError: If the token signature is invalid, the JTI is not found,
                or the token has already been used.
            InvalidInputError: If the request payload is invalid or missing required fields.
        """
        raise NotImplementedError("Connect capability: implement process_user_connect()")
