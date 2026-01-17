"""Cached approvals API endpoints.

Provides visibility into the HITL approval cache for debugging and management.
These are CACHED approvals (previously approved HITL decisions), not pending
HITL requests waiting for user decision.

Routes mounted at: /api/approvals/cached
"""

from __future__ import annotations

__all__ = ["router"]

import time

from fastapi import APIRouter

from mcp_acp.api.deps import ApprovalStoreDep, ProxyStateDep
from mcp_acp.api.errors import APIError, ErrorCode
from mcp_acp.api.schemas import (
    ApprovalCacheResponse,
    CachedApprovalResponse,
    ClearApprovalsResponse,
    DeleteApprovalResponse,
)
from mcp_acp.manager.state import SSEEventType

router = APIRouter()


@router.get("")
async def get_approvals(store: ApprovalStoreDep) -> ApprovalCacheResponse:
    """Get all cached approvals.

    Returns the current state of the approval cache for debugging.
    Note: May include expired entries (lazy expiration on lookup).
    """
    now = time.monotonic()
    ttl = store.ttl_seconds

    approvals = []
    for _key, approval in store.iter_all():
        age = now - approval.stored_at
        approvals.append(
            CachedApprovalResponse(
                subject_id=approval.subject_id,
                tool_name=approval.tool_name,
                path=approval.path,
                request_id=approval.request_id,
                age_seconds=round(age, 1),
                ttl_seconds=ttl,
                expires_in_seconds=round(max(0, ttl - age), 1),
            )
        )

    return ApprovalCacheResponse(
        count=len(approvals),
        ttl_seconds=ttl,
        approvals=approvals,
    )


@router.delete("")
async def clear_approvals(state: ProxyStateDep) -> ClearApprovalsResponse:
    """Clear all cached approvals."""
    count = state.clear_all_cached_approvals()  # Emits cache_cleared SSE event
    return ClearApprovalsResponse(cleared=count, status="ok")


@router.delete("/entry")
async def delete_approval(
    store: ApprovalStoreDep,
    state: ProxyStateDep,
    subject_id: str,
    tool_name: str,
    path: str | None = None,
) -> DeleteApprovalResponse:
    """Delete a specific cached approval.

    Args:
        store: Approval store (injected).
        state: Proxy state for SSE events (injected).
        subject_id: The user who approved.
        tool_name: The tool that was approved.
        path: The path that was approved (optional).

    Raises:
        APIError: 404 CACHED_APPROVAL_NOT_FOUND if approval not found.
    """
    deleted = store.delete(subject_id, tool_name, path)
    if not deleted:
        raise APIError(
            status_code=404,
            code=ErrorCode.CACHED_APPROVAL_NOT_FOUND,
            message=f"Cached approval not found for {subject_id}/{tool_name}/{path}",
            details={"subject_id": subject_id, "tool_name": tool_name, "path": path},
        )

    # Emit SSE event for UI notification
    state.emit_system_event(
        SSEEventType.CACHE_ENTRY_DELETED,
        severity="success",
        message=f"Cached approval deleted: {tool_name}",
        tool_name=tool_name,
        subject_id=subject_id,
        path=path,
    )

    # Emit updated cache snapshot
    state.emit_cached_snapshot()

    return DeleteApprovalResponse(deleted=True, status="ok")
