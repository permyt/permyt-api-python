from abc import abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import hashlib
import hmac
import json

from joserfc import jwt, jwe
from joserfc.jwk import ECKey

from permyt.exceptions import InvalidPublicKeyError, InvalidProofError, InvalidPayloadError
from permyt.typing import EncryptedRequest


class EncryptionMixin:  # pylint: disable=too-few-public-methods
    """
    Mixin that handles all cryptographic operations in the PERMYT protocol:
    key loading, JWT signing, JWE encryption/decryption, and proof-of-possession
    creation and verification.
    """

    JWT_ALGORITHM = "ES256"
    JWE_ALGORITHMS: dict[str, str] = {
        "alg": "ECDH-ES+A256KW",
        "enc": "A256GCM",
    }  # alg=key exchange, enc=content encryption

    # -------------------------------------------------------------------------
    # Internal methods for key handling, signing & encryption
    # -------------------------------------------------------------------------

    def _load_private_key(self, private_key: str):
        """
        Load private key from a PEM string or file path.

        Args:
            private_key (str): PEM string or path to PEM file.

        Returns:
            Private key object for signing operations.

        Raises:
            ValueError: If the key format is invalid or file does not exist.
        """
        if not private_key:
            raise ValueError("Private key is required for encryption operations")

        if private_key.startswith("-----BEGIN"):
            pem = private_key
        else:
            path = Path(private_key)
            if not path.exists():
                raise ValueError(f"Private key file not found: {private_key}")
            with open(path, "r", encoding="utf-8") as f:
                pem = f.read()

        if not pem.startswith("-----BEGIN"):
            raise ValueError("Invalid private key format.")

        return ECKey.import_key(pem)

    def _create_proof(self, payload: dict[str, Any]) -> str:
        """
        Create a proof of possession by signing a hash of the payload.

        This proves the sender actually created this specific request,
        not just that they hold a valid key.

        Args:
            payload (dict[str, Any]): The payload being sent.

        Returns:
            str: Signed JWT containing the payload hash.
        """
        payload_hash = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()

        proof_claims = {
            "payload_hash": payload_hash,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        return jwt.encode({"alg": self.JWT_ALGORITHM}, proof_claims, self.private_key)

    def _sign_jwt(self, payload: dict[str, Any]) -> str:
        """
        Sign a payload as a JWT using the client's private key (ES256).

        Args:
            payload (dict[str, Any]): Claims to include in the JWT.

        Returns:
            str: Signed JWT string.
        """
        return jwt.encode({"alg": self.JWT_ALGORITHM}, payload, self.private_key)

    def _encrypt_jwe(self, payload: dict[str, Any], public_key: str | None = None) -> str:
        """
        Encrypt a payload using JWE with the recipient's public key.

        Args:
            payload (dict[str, Any]): Data to encrypt.
            public_key (str, optional): Recipient's public key in PEM format.

        Returns:
            str: Compact JWE string.

        Raises:
            InvalidPublicKeyError: If public_key is not provided.
        """
        if not public_key:
            raise InvalidPublicKeyError("Recipient public key is required for encryption")

        recipient_key = ECKey.import_key(public_key)
        return jwe.encrypt_compact(
            self.JWE_ALGORITHMS, json.dumps(payload).encode("utf-8"), recipient_key
        )

    # -------------------------------------------------------------------------
    # Internal methods for token verification and payload decryption
    # -------------------------------------------------------------------------

    def _verify_proof(self, proof: str, payload: dict[str, Any], public_key: str) -> None:
        """
        Verify the proof of possession matches the given payload.

        Confirms the sender holds the private key matching the public key
        AND that they signed this specific payload (not just any data).

        Args:
            proof (str): JWT signed by the sender's private key.
            payload (dict[str, Any]): The payload that should have been signed.
            public_key (str): Public key to verify the signature against.

        Raises:
            InvalidProofError: If proof signature is invalid or doesn't match payload.
        """
        try:
            token_obj = jwt.decode(proof, ECKey.import_key(public_key))

            # Compute expected hash
            expected_hash = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()

        # Intentionally broad: don't leak crypto failure details
        except Exception as exc:  # pylint: disable=broad-except
            raise InvalidProofError() from exc

        # Verify the proof signs this exact payload
        if not hmac.compare_digest(token_obj.claims.get("payload_hash", ""), expected_hash):
            raise InvalidProofError("Proof does not match payload")

    @abstractmethod
    def _validate_nonce_and_timestamp(self, nonce: str, timestamp: str) -> None:
        """
        Validate nonce uniqueness and timestamp freshness to prevent replay attacks.

        Args:
            nonce (str): Unique nonce from the request.
            timestamp (str): ISO 8601 timestamp from the request.

        Raises:
            ExpiredRequestError: If the nonce has already been used or the timestamp
                                 is outside the valid window.
        """
        raise NotImplementedError(
            "Subclasses must implement _validate_nonce_and_timestamp to prevent replay attacks. "
            "See documentation for implementation requirements."
        )

    def _extract_request_data(self, request: EncryptedRequest) -> dict[str, Any]:
        """
        Extract and validate token request data from PERMYT.

        Verifies PERMYT's signature, validates timestamp/nonce, and decrypts payload.

        Args:
            request (EncryptedRequest): Incoming token request from PERMYT.

        Returns:
            dict[str, Any]: Decrypted and validated request data.

        Raises:
            SecurityError: If proof is invalid, timestamp is stale, or nonce was reused.
        """
        permyt_public_key = self.get_permyt_public_key()

        # Step 1 — Verify PERMYT's proof (signs the encrypted payload)
        self._verify_proof(request["proof"], dict(request["payload"]), permyt_public_key)

        # Step 2 — Validate timestamp and nonce from outer payload
        self._validate_nonce_and_timestamp(
            request["payload"]["nonce"], request["payload"]["timestamp"]
        )

        # Step 3 — Decrypt the inner data encrypted by PERMYT
        decrypted_data = self._decrypt_data(request["payload"]["data"])

        return decrypted_data

    def _decrypt_data(self, encrypted_data: str) -> Any:
        """
        Decrypt a JWE payload using this client's private key.

        Args:
            encrypted_data (str): Compact JWE string.

        Returns:
            Any: Decrypted and JSON-parsed data.

        Raises:
            InvalidPayloadError: If decryption fails.
        """
        try:
            decrypted = jwe.decrypt_compact(encrypted_data, self.private_key)
            plaintext = decrypted.plaintext
            if plaintext is None:
                raise InvalidPayloadError("Decryption produced no plaintext")
            return json.loads(plaintext.decode("utf-8"))
        # Intentionally broad: don't leak crypto failure details
        except Exception as exc:  # pylint: disable=broad-except
            raise InvalidPayloadError() from exc

    @abstractmethod
    def get_permyt_public_key(self) -> str:
        """
        Return PERMYT's public key for verifying PERMYT's signatures.
        Obtain this from your PERMYT dashboard.

        Returns:
            str: The PEM-encoded PERMYT public key.
        """
        raise NotImplementedError("Subclasses must implement get_permyt_public_key()")
