"""Pending HITL approval API endpoints.

Provides real-time streaming and management of pending HITL approval requests.
These are requests currently waiting for user decision, not cached approvals.

Routes mounted at: /api/approvals/pending

Security:
- All approval actions (approve/deny) require OIDC authentication
- Approver identity is logged in audit trail
- Approver must match the original requester (session binding)
"""

from __future__ import annotations

__all__ = ["router"]

import asyncio
import json
from typing import TYPE_CHECKING, AsyncIterator

from fastapi import APIRouter
from fastapi.responses import StreamingResponse

from mcp_acp.api.deps import IdentityProviderDep, ProxyStateDep
from mcp_acp.api.errors import APIError, ErrorCode
from mcp_acp.api.schemas import ApprovalActionResponse, PendingApprovalResponse
from mcp_acp.manager.events import SSEEventType
from mcp_acp.telemetry.system.system_logger import get_system_logger

if TYPE_CHECKING:
    from mcp_acp.pips.auth.oidc_provider import OIDCIdentityProvider

logger = get_system_logger()

router = APIRouter()


@router.get("")
async def pending_approvals_stream(state: ProxyStateDep) -> StreamingResponse:
    """SSE stream of pending approvals.

    Streams events for:
    - Current pending approvals (on connect)
    - New pending approvals
    - Resolution events (approve/deny)
    - Timeout events

    Event format:
        data: {"type": "...", ...}

    Types:
        - pending_created: New pending approval
        - pending_resolved: Approval was resolved
        - pending_timeout: Approval timed out
        - snapshot: Initial list of pending approvals
    """

    async def event_generator() -> AsyncIterator[str]:
        queue = state.subscribe()
        try:
            # Send current pending approvals first (snapshot)
            pending = state.get_pending_approvals()
            snapshot = {
                "type": "snapshot",
                "approvals": [p.to_dict() for p in pending],
            }
            yield f"data: {json.dumps(snapshot)}\n\n"

            # Send current cached approvals
            cached_approvals = state.get_cached_approvals_for_sse()
            cached_snapshot = {
                "type": SSEEventType.CACHED_SNAPSHOT.value,
                "approvals": cached_approvals,
                "ttl_seconds": state._approval_store.ttl_seconds,
                "count": len(cached_approvals),
            }
            yield f"data: {json.dumps(cached_snapshot)}\n\n"

            # Send current stats
            stats_event = {
                "type": SSEEventType.STATS_UPDATED.value,
                "stats": state.get_stats().to_dict(),
            }
            yield f"data: {json.dumps(stats_event)}\n\n"

            # Stream new events
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=30)
                    try:
                        yield f"data: {json.dumps(event)}\n\n"
                    except (TypeError, ValueError) as e:
                        # Skip non-serializable events rather than crash stream
                        logger.error(
                            {
                                "event": "sse_event_serialization_failed",
                                "message": f"Failed to serialize SSE event: {e}",
                                "component": "api_pending",
                                "error_type": type(e).__name__,
                                "error_message": str(e),
                                "details": {
                                    "event_type": event.get("type") if isinstance(event, dict) else None
                                },
                            }
                        )
                except asyncio.TimeoutError:
                    # Send keepalive comment to prevent connection timeout
                    yield ": keepalive\n\n"
        finally:
            state.unsubscribe(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # Disable nginx buffering
        },
    )


@router.get("/list", response_model=list[PendingApprovalResponse])
async def list_pending_approvals(state: ProxyStateDep) -> list[PendingApprovalResponse]:
    """List pending approvals (non-SSE).

    Alternative to SSE stream for clients that don't support SSE.
    Returns current pending approvals without streaming.
    """
    pending = state.get_pending_approvals()

    return [
        PendingApprovalResponse(
            id=p.id,
            proxy_id=p.proxy_id,
            tool_name=p.tool_name,
            path=p.path,
            subject_id=p.subject_id,
            created_at=p.created_at,
            timeout_seconds=p.timeout_seconds,
            request_id=p.request_id,
            can_cache=p.can_cache,
            cache_ttl_seconds=p.cache_ttl_seconds,
        )
        for p in pending
    ]


async def _get_approver_identity(
    identity_provider: "OIDCIdentityProvider",
) -> str:
    """Get the approver's OIDC identity.

    Args:
        identity_provider: OIDC identity provider.

    Returns:
        Approver's subject ID.

    Raises:
        APIError: 401 AUTH_REQUIRED if not authenticated.
    """
    from mcp_acp.exceptions import AuthenticationError

    try:
        identity = await identity_provider.get_identity()
        return identity.subject_id
    except AuthenticationError as e:
        raise APIError(
            status_code=401,
            code=ErrorCode.AUTH_REQUIRED,
            message=f"Authentication required to approve requests. {e}",
        ) from e


def _verify_approver_is_requester(
    approval_id: str,
    approver_id: str,
    state: "ProxyStateDep",
) -> None:
    """Verify the approver is the same as the original requester.

    Args:
        approval_id: The pending approval ID.
        approver_id: The approver's subject ID.
        state: Proxy state.

    Raises:
        APIError: 404 APPROVAL_NOT_FOUND if approval not found.
        APIError: 403 APPROVAL_UNAUTHORIZED if approver doesn't match requester.
    """
    pending = state.get_pending_approval(approval_id)
    if pending is None:
        raise APIError(
            status_code=404,
            code=ErrorCode.APPROVAL_NOT_FOUND,
            message=f"Pending approval '{approval_id}' not found",
            details={"approval_id": approval_id},
        )

    if pending.subject_id != approver_id:
        logger.warning(
            {
                "event": "approval_authorization_denied",
                "message": "Approver identity doesn't match requester",
                "approval_id": approval_id,
                "requester_id": pending.subject_id,
                "approver_id": approver_id,
            }
        )
        raise APIError(
            status_code=403,
            code=ErrorCode.APPROVAL_UNAUTHORIZED,
            message="You can only approve your own requests",
            details={"approval_id": approval_id, "requester_id": pending.subject_id},
        )


def _resolve_approval(
    approval_id: str,
    action: str,
    response_status: str,
    state: "ProxyStateDep",
    approver_id: str,
) -> ApprovalActionResponse:
    """Resolve a pending approval with the given action.

    Args:
        approval_id: The pending approval ID.
        action: Resolution action ("allow", "allow_once", "deny").
        response_status: Status string for the response.
        state: Proxy state (injected).
        approver_id: OIDC subject ID of the approver.

    Returns:
        ApprovalActionResponse with status confirmation.

    Raises:
        APIError: 404 APPROVAL_NOT_FOUND if approval not found or already resolved.
    """
    if not state.resolve_pending(approval_id, action, approver_id):
        state.emit_system_event(
            SSEEventType.PENDING_NOT_FOUND,
            severity="error",
            message="Approval not found (may have timed out)",
            approval_id=approval_id,
        )
        raise APIError(
            status_code=404,
            code=ErrorCode.APPROVAL_NOT_FOUND,
            message=f"Pending approval '{approval_id}' not found or already resolved",
            details={"approval_id": approval_id},
        )

    return ApprovalActionResponse(status=response_status, approval_id=approval_id)


@router.post("/{approval_id}/approve", response_model=ApprovalActionResponse)
async def approve_pending(
    approval_id: str,
    state: ProxyStateDep,
    identity_provider: IdentityProviderDep,
) -> ApprovalActionResponse:
    """Approve a pending request (caches the approval).

    Requires OIDC authentication. Approver must be the original requester.
    """
    approver_id = await _get_approver_identity(identity_provider)
    _verify_approver_is_requester(approval_id, approver_id, state)
    return _resolve_approval(approval_id, "allow", "approved", state, approver_id)


@router.post("/{approval_id}/allow-once", response_model=ApprovalActionResponse)
async def allow_once_pending(
    approval_id: str,
    state: ProxyStateDep,
    identity_provider: IdentityProviderDep,
) -> ApprovalActionResponse:
    """Allow a pending request without caching.

    Requires OIDC authentication. Approver must be the original requester.
    """
    approver_id = await _get_approver_identity(identity_provider)
    _verify_approver_is_requester(approval_id, approver_id, state)
    return _resolve_approval(approval_id, "allow_once", "allowed_once", state, approver_id)


@router.post("/{approval_id}/deny", response_model=ApprovalActionResponse)
async def deny_pending(
    approval_id: str,
    state: ProxyStateDep,
    identity_provider: IdentityProviderDep,
) -> ApprovalActionResponse:
    """Deny a pending request.

    Requires OIDC authentication. Approver must be the original requester.
    """
    approver_id = await _get_approver_identity(identity_provider)
    _verify_approver_is_requester(approval_id, approver_id, state)
    return _resolve_approval(approval_id, "deny", "denied", state, approver_id)
