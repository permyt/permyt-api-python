from typing import Any

import logging

from permyt.exceptions import InvalidPayloadError, PermytError, UnexpectedError

__all__ = ("InboundMixin",)


class InboundMixin:  # pylint: disable=too-few-public-methods
    """
    Mixin that provides a single dispatcher entry point for every inbound
    PERMYT-related request a service may receive.

    Without this mixin, a service would need to expose one HTTP route per
    action (``/permyt/token-request``, ``/permyt/service-call``, ...). With
    it, a service registers exactly one inbound URL — typically
    ``POST /permyt/inbound`` — and forwards the body to ``handle_inbound``,
    which inspects the outer ``action`` field and dispatches to the right
    role-specific handler.

    Recognised actions:

    - ``token_request``    — PERMYT asks the provider to issue a single-use token
    - ``service_call``     — a requester calls a provider endpoint with a token
    - ``user_connect``     — PERMYT forwards a scanned QR-code login
    - ``user_disconnect``  — PERMYT notifies the service that a user revoked the link
    - ``request_status``   — PERMYT notifies a requester of an access-request status change
    """

    def handle_inbound(self, body: dict[str, Any]) -> dict[str, Any]:
        """
        Dispatch an inbound PERMYT request to the right role-specific handler.

        Args:
            body: The full HTTP request body. Must include an outer ``action``
                field; the rest of the shape depends on the action.

        Returns:
            The result of the dispatched handler, or a formatted error dict
            if the action is missing/unknown or processing fails.
        """
        try:
            action = body.get("action")
            if not action:
                raise InvalidPayloadError(
                    extra_info="Missing 'action' field on inbound request body."
                )

            handler = self._inbound_handler(action)
            if handler is None:
                raise InvalidPayloadError(extra_info=f"Unknown action: {action!r}")
            return handler(body)

        except PermytError as exc:
            return self.handle_permyt_error(exc)

        except Exception as exc:  # pylint: disable=broad-except
            logging.error(f"Unexpected error in handle_inbound: {exc}", exc_info=True)
            return self.handle_permyt_error(UnexpectedError(extra_info=str(exc)))

    def _inbound_handler(self, action: str):
        """Return the handler bound to ``action`` or ``None`` if unknown."""
        return {
            "token_request": self.handle_token_request,
            "service_call": self.handle_service_call,
            "user_connect": self.handle_user_connect,
            "user_disconnect": self.handle_user_disconnect,
            "request_status": self.handle_request_status,
        }.get(action)
