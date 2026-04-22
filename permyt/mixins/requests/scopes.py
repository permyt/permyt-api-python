from __future__ import annotations

from permyt.typing import ScopeDefinition, UpdateScopesResponse

__all__ = ("ScopeManagementMixin",)


class ScopeManagementMixin:
    """
    Mixin for programmatic scope management: allows a service to push
    its scope definitions to PERMYT.
    """

    def update_scopes(self, scopes: list[ScopeDefinition]) -> UpdateScopesResponse:
        """
        Push the complete list of scopes for this service to PERMYT.

        PERMYT diffs the submitted list against the current state by
        ``reference`` and creates, updates, or deletes scopes as needed.
        The submitted list is treated as the desired final state.

        Args:
            scopes: Complete list of scope definitions. Each must include
                at least ``reference`` and ``name``.

        Returns:
            UpdateScopesResponse: Counts of created, updated, and deleted scopes.
        """
        return self.request(
            url=self.get_fullpath("request/scopes/update/"),
            action="update_scopes",
            data={"scopes": scopes},
            recipient_public_key=self.get_permyt_public_key(),
        )
