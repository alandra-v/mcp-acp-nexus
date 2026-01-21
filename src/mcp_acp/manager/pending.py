"""Pending approval request handling with async wait capability.

This module provides the internal class for managing pending HITL approvals.
The PendingApprovalRequest wraps a PendingApprovalInfo with async machinery
for waiting on and receiving decisions from the UI.
"""

from __future__ import annotations

__all__ = [
    "PendingApprovalRequest",
]

import asyncio

from mcp_acp.manager.models import PendingApprovalInfo


class PendingApprovalRequest:
    """Internal pending approval with async wait capability.

    Wraps PendingApprovalInfo with the async machinery needed to
    wait for and receive a decision from the UI.

    The typical lifecycle is:
    1. Create PendingApprovalRequest with PendingApprovalInfo
    2. Call wait() to block until decision or timeout
    3. UI calls resolve() to provide the decision
    4. wait() returns with the decision

    Attributes:
        info: The immutable approval information.
    """

    def __init__(self, info: PendingApprovalInfo) -> None:
        """Initialize with approval info.

        Args:
            info: The immutable approval information.
        """
        self.info = info
        self._decision_event = asyncio.Event()
        self._decision: str | None = None
        self._approver_id: str | None = None

    @property
    def id(self) -> str:
        """Get the approval ID."""
        return self.info.id

    @property
    def approver_id(self) -> str | None:
        """Get the approver ID (set when resolved)."""
        return self._approver_id

    def resolve(self, decision: str, approver_id: str | None = None) -> None:
        """Resolve this pending approval with a decision.

        Args:
            decision: "allow", "allow_once", or "deny".
            approver_id: OIDC subject ID of the user who approved/denied.
        """
        self._decision = decision
        self._approver_id = approver_id
        self._decision_event.set()

    async def wait(self, timeout: float) -> tuple[str | None, str | None]:
        """Wait for a decision with timeout.

        Args:
            timeout: Maximum seconds to wait.

        Returns:
            Tuple of (decision, approver_id). Decision is "allow", "allow_once",
            or "deny" if decided, None if timeout. Approver_id is the OIDC subject
            ID of whoever approved/denied, None if timeout.
        """
        try:
            await asyncio.wait_for(self._decision_event.wait(), timeout=timeout)
            return self._decision, self._approver_id
        except asyncio.TimeoutError:
            return None, None
