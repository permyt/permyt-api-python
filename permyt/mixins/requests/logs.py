from __future__ import annotations

from permyt.typing import FetchLogsResponse, LogType

__all__ = ("LogsMixin",)


class LogsMixin:  # pylint: disable=too-few-public-methods
    """
    Mixin for fetching the calling service's audit logs from PERMYT.

    The broker exposes a paginated audit log of every action visible to a
    service as either requester or provider — request lifecycle events,
    token issuance, consent changes, connection lifecycle, scope-catalog
    syncs, exchange tokens, etc. This mixin wraps that endpoint with the
    standard signed-request envelope.

    Per-row visibility is enforced on the broker side: a service only sees
    rows it appears on, and ``meta`` is stripped from ``request`` rows when
    the viewer is the provider (since request descriptions are the user's
    intent to the *requester*, not data the provider has any business
    seeing).
    """

    def fetch_logs(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        user_id: str | None = None,
        log_type: LogType | None = None,
        request_id: str | None = None,
        days_back: int | None = None,
    ) -> FetchLogsResponse:
        """
        Fetch a paginated slice of this service's audit log from PERMYT.

        Args:
            limit: Page size, 1-200. Defaults to 50.
            offset: Zero-based offset into the result set. Defaults to 0.
            user_id: Restrict to a single profile, identified by the
                **calling service's** ``permyt_user_id`` for that user (i.e.
                the same id surfaced on each row as ``permyt_user_id``). The
                broker resolves it back to the underlying profile.
            log_type: Restrict to a single :data:`LogType` value.
            request_id: Restrict to a single access-request lifecycle.
            days_back: Restrict to entries within the last N days (1-365).

        Returns:
            FetchLogsResponse: ``{logs, total, limit, offset}``. ``total`` is
            the unsliced count for the same filter combination, suitable for
            driving a pager.
        """
        data: dict = {"limit": limit, "offset": offset}
        if user_id is not None:
            data["user_id"] = user_id
        if log_type is not None:
            data["log_type"] = log_type
        if request_id is not None:
            data["request_id"] = request_id
        if days_back is not None:
            data["days_back"] = days_back

        return self.request(
            url=self.get_fullpath("request/logs/"),
            action="fetch_logs",
            data=data,
            recipient_public_key=self.get_permyt_public_key(),
        )
