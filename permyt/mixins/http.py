import posixpath
import secrets
from datetime import datetime, timezone
from typing import Any

import requests
from requests.exceptions import RequestException

from ..exceptions import TransportError, UnexpectedError

__all__ = ("HTTPClientMixin",)


class HTTPClientMixin:  # pylint: disable=too-few-public-methods
    """
    Mixin that handles low-level signed HTTP communication in the PERMYT protocol.

    Every outgoing request is wrapped in a signed payload: the data is optionally
    JWE-encrypted for the recipient, and a proof-of-possession JWT is attached so
    the recipient can verify the sender's identity and payload integrity.
    """

    def request(
        self,
        url: str,
        action: str,
        data: dict[str, Any],
        *,
        recipient_public_key: str,
        extra_body: dict[str, Any] | None = None,
    ) -> Any:
        """
        Send a signed (and optionally encrypted) POST request.

        The payload is always timestamped and nonced to prevent replay attacks.
        If a recipient public key is provided, the data is JWE-encrypted before
        sending so only the recipient can read it.

        Every request carries an ``action`` discriminator on the outer envelope
        so the recipient's webhook handler can dispatch to the right inner
        handler. This is what allows a service to expose a single
        ``/permyt/webhook`` endpoint instead of one URL per action.

        Args:
            url (str): Target endpoint URL.
            action (str): Required protocol-level action discriminator
                (e.g. ``"access_request"``, ``"token_request"``, ``"service_call"``).
            data (dict[str, Any]): Data to include in the payload.
            recipient_public_key (str): Recipient's PEM public key. The data will be JWE-encrypted
                so only the recipient can decrypt it.
            extra_body (dict[str, Any], optional): Additional top-level fields to merge into
                the request body (e.g. a single-use token for provider calls).

        Returns:
            Any: Parsed JSON response from the recipient.

        Raises:
            TransportError: On network failure or non-2xx HTTP status.
            UnexpectedError: When a 2xx response body is not valid JSON.
        """
        payload = {
            "data": self._encrypt_jwe(data, recipient_public_key),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "nonce": secrets.token_hex(32),
        }

        body = {
            "action": action,
            "service_id": self.service_id,
            "payload": payload,
            "proof": self._create_proof(payload),  # Sign the payload
            **(extra_body or {}),
        }

        try:
            response = requests.post(url, json=body, timeout=30)
        except RequestException as exc:
            raise TransportError(
                f"{action}: HTTP request to {url} failed ({type(exc).__name__})",
                extra_info=str(exc)[:500],
            ) from exc

        if not response.ok:
            raise TransportError(
                f"{action}: {url} returned HTTP {response.status_code}",
                extra_info=(response.text[:500] if response.text else ""),
                status_code=response.status_code,
            )

        try:
            return response.json()
        except ValueError as exc:
            raise UnexpectedError(
                f"{action}: {url} returned non-JSON 2xx body",
                extra_info=response.text[:500],
            ) from exc

    def get_fullpath(self, path: str) -> str:
        """
        Join the base host URL with a path.

        Args:
            path (str): The path to join with the host.

        Returns:
            str: The full URL.
        """
        return posixpath.join(self.host, "rest", path)
