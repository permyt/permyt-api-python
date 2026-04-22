from typing import Any

import logging

from requests.exceptions import RequestException

from permyt.exceptions import PermytError, UnexpectedError
from permyt.typing import (
    AccessRequest,
    AccessResponse,
    AccessStatus,
    EncryptedRequest,
    ExchangeToken,
    RedeemedToken,
    RequestStatus,
    ServiceCredential,
    ServiceCallEndpoint,
)

__all__ = ("RequesterMixin",)


class RequesterMixin:  # pylint: disable=too-few-public-methods
    """
    Mixin for the requester role: a service asking for access to user data
    held by other services.

    Flow:
        1. Requester calls request_access() to ask PERMYT for access to user data.
           PERMYT notifies the user and returns a pending request_id.

        2. User approves or denies the request on their device.
           Requester is notified via callback_url or polls check_access().

        3. On approval, PERMYT returns a list of providers with single-use tokens.
           Requester calls each provider directly via call_services().

    Note:
        Requesters never see which permission level the user approved.
        PERMYT returns only the list of providers and their tokens.
        The requester has no knowledge of the user's privacy structure.
    """

    DEFAULT_CALLBACK_URL: str | None = None

    # -------------------------------------------------------------------------
    # Request, check and process access
    # -------------------------------------------------------------------------

    def request_access(self, request: AccessRequest) -> AccessStatus:
        """
        Request access to user data through PERMYT.
        Returns immediately with a pending request_id.
        Requester is notified via callback_url when user approves or denies.
        If no callback_url, requester must poll check_access() for status.

        Args:
            request (AccessRequest): The access request details.

        Returns:
            AccessStatus: Immediate response with request_id and "pending" status.
        """
        return self.request(
            url=self.get_fullpath("request/access/"),
            action="access_request",
            data={
                "user_id": request["user_id"],
                "description": request["description"],
                "request_id": request.get("request_id"),
                "callback_url": request.get("callback_url", self.DEFAULT_CALLBACK_URL),
            },
            recipient_public_key=self.get_permyt_public_key(),
        )

    def check_access(self, request_id: str) -> AccessStatus:
        """
        Poll PERMYT for the status of a pending access request.
        Use this if no callback_url was provided in request_access.

        Args:
            request_id (str): The request ID returned by request_access.

        Returns:
            AccessStatus: Current status and approved providers/tokens if approved.
        """
        return self.request(
            url=self.get_fullpath("request/access/status/"),
            action="access_check",
            data={"request_id": request_id},
            recipient_public_key=self.get_permyt_public_key(),
        )

    def request_token(self, user_id: str, restricted_to: str | None = None) -> ExchangeToken:
        """
        Request a temporary token to pass user details to another service.

        Args:
            user_id (str): The ID of the user for whom to request the token.
            restricted_to (str, optional): If provided, the token will be
                restricted to this service.

        Returns:
            ExchangeToken: The issued token and its metadata.
        """
        return self.request(
            url=self.get_fullpath("request/token/"),
            action="token_exchange",
            data={"user_id": user_id, "restricted_to": restricted_to},
            recipient_public_key=self.get_permyt_public_key(),
        )

    def redeem_token(self, user_id: str, token: str) -> RedeemedToken:
        """
        Redeem a temporary token to retrieve user details.

        Args:
            user_id (str): The ID of the user for whom to redeem the token.
            token (str): The token to redeem.

        Returns:
            RedeemedToken: The user details associated with the token.
        """
        return self.request(
            url=self.get_fullpath("request/token/redeem/"),
            action="token_redeem",
            data={"token": token, "user_id": user_id},
            recipient_public_key=self.get_permyt_public_key(),
        )

    # -------------------------------------------------------------------------
    # Handle approved access and call providers
    # -------------------------------------------------------------------------

    def handle_approved_access(self, response: AccessResponse) -> list[Any]:
        """
        Verify and decrypt PERMYT's response containing approved provider tokens.

        Args:
            response: Signed response from PERMYT with provider list.

        Returns:
            List of responses from all provider endpoint calls.
        """
        try:
            permyt_public_key = self.get_permyt_public_key()
            payload = response["payload"]

            # Step 1 — Verify PERMYT's proof
            self._verify_proof(response["proof"], payload, permyt_public_key)

            # Step 2 — Validate timestamp and nonce
            self._validate_nonce_and_timestamp(payload["nonce"], payload["timestamp"])

            # Step 3 — Decrypt the provider access list
            services: list[ServiceCredential] = self._decrypt_data(payload["data"])

            return self.call_services(services)

        except PermytError as exc:
            return self.handle_permyt_error(exc)

        except Exception as exc:  # pylint: disable=broad-except
            logging.error(f"Unexpected error in handle_approved_access: {exc}", exc_info=True)
            return self.handle_permyt_error(UnexpectedError(extra_info=str(exc)))

    # -------------------------------------------------------------------------
    # Handle status callbacks PERMYT pushes back
    # -------------------------------------------------------------------------

    def handle_request_status(self, request: EncryptedRequest) -> dict[str, Any]:
        """
        Handle a status callback from PERMYT for a previously submitted access
        request.

        PERMYT pushes one of these whenever an access request transitions
        through its lifecycle (queued → analyzing → awaiting → processing →
        completed / rejected / incomplete / unavailable). The COMPLETED case
        carries the encrypted token bundle in ``data["services"]``; failure
        cases carry a human-readable ``reason``.

        This is the inbound counterpart to ``request_access`` /
        ``check_access``: services that registered a callback URL with PERMYT
        receive these callbacks instead of (or in addition to) polling.

        Args:
            request (EncryptedRequest): Encrypted and signed status callback from PERMYT.

        Returns:
            dict[str, Any]: Whatever ``process_request_status`` returns, or a
                formatted error dict if processing fails.
        """
        try:
            data: RequestStatus = self._extract_request_data(request)
            return self.process_request_status(data) or {"received": True}

        except PermytError as exc:
            return self.handle_permyt_error(exc)

        except Exception as exc:  # pylint: disable=broad-except
            logging.error(f"Unexpected error in handle_request_status: {exc}", exc_info=True)
            return self.handle_permyt_error(UnexpectedError(extra_info=str(exc)))

    def process_request_status(
        self, data: RequestStatus
    ) -> dict[str, Any] | None:  # pylint: disable=unused-argument
        """
        Hook for services to react to access-request status changes pushed by PERMYT.

        Default implementation is a no-op so services that only act as
        providers (and never as requesters) can mix in ``WebhookMixin``
        without supplying a handler. Override this in your client subclass to
        react to ``COMPLETED`` (carrying ``data["services"]``) or to terminal
        failure states (carrying ``data["reason"]``).

        Args:
            data (RequestStatus): Decrypted status payload from PERMYT.

        Returns:
            dict | None: Optional response sent back to PERMYT (typically just
                an acknowledgement). Returning ``None`` is fine — the wrapper
                substitutes ``{"received": True}``.
        """
        return None

    def call_services(self, services: list[ServiceCredential]) -> list[Any]:
        """
        Call all provider endpoints granted by PERMYT with the provided access tokens.

        Args:
            services (list[ServiceCredential]): List of approved provider accesses.

        Returns:
            List of responses from all provider endpoint calls.
        """
        responses: list[Any] = []

        for service in services:
            # Decrypt the token for this provider
            token_data = self._decrypt_data(service["encrypted_token"])
            token = token_data["token"]

            # Call each endpoint this token grants access to
            for endpoint in service["endpoints"]:
                data = self._prepare_data_for_endpoint(service["request_id"], endpoint)

                try:
                    response = self.request(
                        url=endpoint["url"],
                        action="service_call",
                        data=data or {},
                        extra_body={"token": token},
                        recipient_public_key=service["public_key"],
                    )
                    responses.append(response)
                except (PermytError, RequestException) as exc:
                    logging.error(f"Error calling provider {endpoint['url']}: {exc}", exc_info=True)

        return responses

    def _prepare_data_for_endpoint(
        self, request_id: str, endpoint: ServiceCallEndpoint
    ) -> dict[str, Any]:
        """
        Prepare the data inputs to send to a specific provider endpoint.

        Args:
            request_id (str): The request ID for this access request.
            endpoint (ServiceCallEndpoint): The provider endpoint for which to prepare data.

        Returns:
            dict[str, Any]: The data inputs to send to the provider endpoint.
        """
        raise NotImplementedError("Requester role: implement _prepare_data_for_endpoint()")
