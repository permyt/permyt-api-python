from typing import Any

from ..exceptions import PermytError

__all__ = ("ErrorsMixin",)


class ErrorsMixin:  # pylint: disable=too-few-public-methods
    """
    Mixin that converts PERMYT exceptions into structured error response dicts.

    Used by handler methods (handle_token_request, handle_service_call) to
    catch PermytError exceptions and return a consistent error format instead
    of letting the exception propagate to the caller.
    """

    def handle_permyt_error(self, exc: PermytError) -> dict[str, Any]:
        """
        Convert a PermytError into a structured error response dict.

        Args:
            exc (PermytError): The exception to convert.

        Returns:
            dict[str, Any]: A dict with ``error`` (code), ``message``, and
                optionally ``extra_info`` if the exception carries additional detail.
        """
        error = {"error": exc.code, "message": str(exc)}
        if exc.extra_info:
            error["extra_info"] = exc.extra_info
        return error
