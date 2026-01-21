"""Proxy state aggregation for API exposure.

ProxyState wraps existing state stores (ApprovalStore, SessionManager) and provides
a unified interface for the management API. The proxy is the source of truth for
all state - this class provides read access and coordination for UI features.

Pending approvals are managed here for SSE broadcasting to the web UI.
When no UI is connected, HITL falls back to osascript dialogs.
"""

from __future__ import annotations

__all__ = [
    # Re-exported from other modules (for backward compatibility)
    "CachedApprovalSummary",
    "EventSeverity",
    "PendingApprovalInfo",
    "PendingApprovalRequest",
    "ProxyInfo",
    "ProxyStats",
    "SSEEventType",
    # Defined in this module
    "ProxyState",
    "get_global_proxy_state",
    "set_global_proxy_state",
]

import asyncio
import os
import time
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from mcp_acp.telemetry.system.system_logger import get_system_logger

# Re-export from new modules for backward compatibility
# This allows existing code to import from manager.state
from mcp_acp.manager.events import EventSeverity, SSEEventType
from mcp_acp.manager.models import (
    CachedApprovalSummary,
    PendingApprovalInfo,
    ProxyInfo,
    ProxyStats,
)
from mcp_acp.manager.pending import PendingApprovalRequest

# Global proxy state for SSE event emission from non-middleware code paths
# (e.g., LoggingProxyClient connection failures that bypass middleware)
_global_proxy_state: "ProxyState | None" = None


def set_global_proxy_state(state: "ProxyState") -> None:
    """Set the global proxy state for SSE event emission."""
    global _global_proxy_state
    _global_proxy_state = state


def get_global_proxy_state() -> "ProxyState | None":
    """Get the global proxy state for SSE event emission."""
    return _global_proxy_state


logger = get_system_logger()


if TYPE_CHECKING:
    from mcp_acp.manager.client import ManagerClient
    from mcp_acp.pdp import Decision
    from mcp_acp.pep.approval_store import ApprovalStore
    from mcp_acp.pips.auth.session import BoundSession, SessionManager


class ProxyState:
    """Aggregates all proxy state for API exposure.

    This class is the main integration point between the proxy internals
    and the management API. It wraps:
    - ApprovalStore: Cached HITL approvals
    - SessionManager: User-bound sessions
    - Pending approvals: Requests waiting for UI decision

    SSE broadcasting:
    - Subscribers receive new pending approvals and resolutions
    - Used by web UI for real-time approval notifications
    - is_ui_connected property used by HITL to choose UI vs osascript

    Attributes:
        proxy_id: Unique identifier for this proxy instance.
    """

    def __init__(
        self,
        backend_id: str,
        api_port: int,
        approval_store: "ApprovalStore",
        session_manager: "SessionManager",
        command: str | None = None,
        args: list[str] | None = None,
        url: str | None = None,
        backend_transport: str = "stdio",
        mtls_enabled: bool = False,
    ) -> None:
        """Initialize proxy state.

        Args:
            backend_id: The backend server name from config.
            api_port: Port the management API is listening on.
            approval_store: Existing approval cache store.
            session_manager: Existing session manager.
            command: Backend command (for STDIO transport).
            args: Backend command arguments (for STDIO transport).
            url: Backend URL (for HTTP transport).
            backend_transport: Transport type for proxy-to-backend ("stdio" or "streamablehttp").
            mtls_enabled: Whether mTLS is enabled for backend connection.
        """
        # Generate unique proxy ID: 8-char UUID prefix + backend ID
        self._id = f"{uuid.uuid4().hex[:8]}:{backend_id}"
        self._backend_id = backend_id
        self._api_port = api_port
        self._approval_store = approval_store
        self._session_manager = session_manager
        self._started_at = datetime.now(UTC)
        self._command = command
        self._args = args
        self._url = url
        self._backend_transport = backend_transport
        self._mtls_enabled = mtls_enabled
        self._client_id: str | None = None  # Set by middleware on first initialize

        # Pending approvals (for SSE)
        self._pending: dict[str, PendingApprovalRequest] = {}

        # SSE subscribers - each gets its own queue for events
        self._sse_subscribers: set[asyncio.Queue[dict[str, Any]]] = set()

        # Request counters (for live stats)
        self._requests_total = 0
        self._requests_allowed = 0
        self._requests_denied = 0
        self._requests_hitl = 0

        # Backend connection state tracking (for reconnect detection)
        self._backend_disconnected = False

        # Manager client for event forwarding (set after connection)
        self._manager_client: "ManagerClient | None" = None

    def set_manager_client(self, client: "ManagerClient | None") -> None:
        """Set the manager client for event forwarding.

        Called by proxy lifespan after connecting to manager.
        Events will be forwarded to manager for browser aggregation.

        Args:
            client: ManagerClient instance or None to disable forwarding.
        """
        self._manager_client = client

    @property
    def proxy_id(self) -> str:
        """Get the unique proxy ID."""
        return self._id

    def set_client_id(self, client_id: str) -> None:
        """Set MCP client ID from initialize request.

        Called by middleware when client first connects. Only sets once
        (first client wins for the session).

        Args:
            client_id: Client application name (e.g., "claude-desktop").
        """
        if self._client_id is None:
            self._client_id = client_id

    def get_proxy_info(self) -> ProxyInfo:
        """Get current proxy information.

        Returns:
            ProxyInfo with current status and metrics.
        """
        now = datetime.now(UTC)
        return ProxyInfo(
            id=self._id,
            backend_id=self._backend_id,
            status="running",
            started_at=self._started_at,
            pid=os.getpid(),
            api_port=self._api_port,
            uptime_seconds=(now - self._started_at).total_seconds(),
            command=self._command,
            args=self._args,
            url=self._url,
            client_transport="stdio",  # Always stdio for now (Claude Desktop)
            backend_transport=self._backend_transport,
            mtls_enabled=self._mtls_enabled,
            client_id=self._client_id,
        )

    # =========================================================================
    # Request Statistics
    # =========================================================================

    def record_request(self) -> None:
        """Record a policy-evaluated request for stats tracking.

        Called by middleware for policy-evaluated requests only (not discovery).
        Must be followed by record_decision() which emits the SSE event.
        """
        self._requests_total += 1
        # No SSE emit here - record_decision() is always called immediately after
        # and will emit the complete updated stats

    def record_decision(self, decision: "Decision") -> None:
        """Record a policy decision for stats tracking.

        Called by middleware after policy-evaluated requests.
        Does NOT increment total (already counted by record_request).
        Emits stats_updated SSE event if UI is connected.

        Args:
            decision: The policy decision (ALLOW, DENY, or HITL).
        """
        from mcp_acp.pdp import Decision

        if decision == Decision.ALLOW:
            self._requests_allowed += 1
        elif decision == Decision.DENY:
            self._requests_denied += 1
        elif decision == Decision.HITL:
            self._requests_hitl += 1

        # Emit live updates to connected UI clients
        if self.is_ui_connected:
            self.emit_system_event(
                SSEEventType.STATS_UPDATED,
                stats=self.get_stats().to_dict(),
            )
            # Notify about new log entries (for ActivitySection live updates)
            self.emit_system_event(SSEEventType.NEW_LOG_ENTRIES, count=1)

    def get_stats(self) -> ProxyStats:
        """Get current request statistics.

        Returns:
            ProxyStats with current counters.
        """
        return ProxyStats(
            requests_total=self._requests_total,
            requests_allowed=self._requests_allowed,
            requests_denied=self._requests_denied,
            requests_hitl=self._requests_hitl,
        )

    # =========================================================================
    # Backend Connection State (for reconnect detection)
    # =========================================================================

    def mark_backend_disconnected(self) -> None:
        """Mark backend as disconnected.

        Called by middleware when a backend transport error occurs.
        Sets flag to enable reconnection detection on next successful request.
        """
        self._backend_disconnected = True

    def mark_backend_success(self) -> None:
        """Mark backend request as successful.

        Called by middleware after a successful backend request.
        If backend was previously disconnected, emits BACKEND_RECONNECTED event.
        """
        if self._backend_disconnected:
            self._backend_disconnected = False
            self.emit_system_event(
                SSEEventType.BACKEND_RECONNECTED,
                severity="success",
                message="Backend reconnected",
            )

    # =========================================================================
    # Approval Cache (delegates to ApprovalStore)
    # =========================================================================

    def get_cached_approvals(self) -> list[CachedApprovalSummary]:
        """Get all cached approvals.

        Returns:
            List of CachedApprovalSummary with approval details.
        """
        ttl = self._approval_store.ttl_seconds
        now = time.monotonic()
        result = []

        for (subject_id, tool_name, path), approval in self._approval_store.iter_all():
            age = now - approval.stored_at
            expires_in = max(0.0, ttl - age)
            result.append(
                CachedApprovalSummary(
                    subject_id=subject_id,
                    tool_name=tool_name,
                    path=path,
                    age_seconds=age,
                    expires_in_seconds=expires_in,
                )
            )

        return result

    def get_cached_approvals_for_sse(self) -> list[dict[str, Any]]:
        """Get cached approvals in SSE-ready format.

        Returns:
            List of dicts with approval details for SSE transmission.
        """
        ttl = self._approval_store.ttl_seconds
        now = time.monotonic()
        result = []

        for (subject_id, tool_name, path), approval in self._approval_store.iter_all():
            age = now - approval.stored_at
            expires_in = max(0.0, ttl - age)
            result.append(
                {
                    "subject_id": subject_id,
                    "tool_name": tool_name,
                    "path": path,
                    "request_id": approval.request_id,
                    "age_seconds": round(age, 1),
                    "ttl_seconds": ttl,
                    "expires_in_seconds": round(expires_in, 1),
                }
            )

        return result

    def emit_cached_snapshot(self) -> None:
        """Emit current cached approvals to all SSE subscribers.

        Called after cache modifications to keep UI in sync.
        """
        if not self.is_ui_connected:
            return

        approvals = self.get_cached_approvals_for_sse()
        self._broadcast_event(
            {
                "type": SSEEventType.CACHED_SNAPSHOT.value,
                "approvals": approvals,
                "ttl_seconds": self._approval_store.ttl_seconds,
                "count": len(approvals),
            }
        )

    def clear_all_cached_approvals(self) -> int:
        """Clear all cached approvals.

        Returns:
            Number of approvals cleared.
        """
        count = self._approval_store.clear()
        self.emit_system_event(
            SSEEventType.CACHE_CLEARED,
            severity="success",
            message="Approval cache cleared",
            count=count,
        )
        # Emit updated (empty) cache snapshot
        self.emit_cached_snapshot()
        return count

    # =========================================================================
    # Sessions (delegates to SessionManager)
    # =========================================================================

    def get_sessions(self) -> list["BoundSession"]:
        """Get all active sessions.

        Returns:
            List of BoundSession objects.
        """
        return self._session_manager.get_all_sessions()

    # =========================================================================
    # Pending Approvals (for HITL)
    # =========================================================================

    def create_pending(
        self,
        tool_name: str,
        path: str | None,
        subject_id: str,
        timeout_seconds: int,
        request_id: str,
        can_cache: bool = True,
        cache_ttl_seconds: int | None = None,
    ) -> PendingApprovalRequest:
        """Create a pending approval request.

        Called by HITL handler when UI is connected. The request waits
        until resolved via resolve_pending() or timeout.

        Args:
            tool_name: The tool being invoked.
            path: The path being accessed (if applicable).
            subject_id: The user making the request.
            timeout_seconds: How long to wait for decision.
            request_id: Original MCP request ID for correlation.
            can_cache: Whether this approval can be cached.
            cache_ttl_seconds: How long cached approval will last (for UI display).

        Returns:
            PendingApprovalRequest that can be waited on.
        """
        approval_id = uuid.uuid4().hex[:16]
        info = PendingApprovalInfo(
            id=approval_id,
            proxy_id=self._id,
            tool_name=tool_name,
            path=path,
            subject_id=subject_id,
            created_at=datetime.now(UTC),
            timeout_seconds=timeout_seconds,
            request_id=request_id,
            can_cache=can_cache,
            cache_ttl_seconds=cache_ttl_seconds,
        )
        request = PendingApprovalRequest(info)

        self._pending[approval_id] = request

        # Broadcast to SSE subscribers
        self._broadcast_event(
            {
                "type": "pending_created",
                "approval": info.to_dict(),
            }
        )

        return request

    def resolve_pending(self, approval_id: str, decision: str, approver_id: str | None = None) -> bool:
        """Resolve a pending approval.

        Args:
            approval_id: The pending approval ID.
            decision: "allow", "allow_once", or "deny".
            approver_id: OIDC subject ID of the user who approved/denied.

        Returns:
            True if the approval was found and resolved, False otherwise.
        """
        request = self._pending.get(approval_id)
        if request is None:
            return False

        request.resolve(decision, approver_id)

        # Remove from pending dict
        del self._pending[approval_id]

        # Broadcast resolution to SSE subscribers
        self._broadcast_event(
            {
                "type": "pending_resolved",
                "approval_id": approval_id,
                "decision": decision,
            }
        )

        return True

    async def wait_for_decision(self, approval_id: str, timeout: float) -> tuple[str | None, str | None]:
        """Wait for a pending approval decision.

        Args:
            approval_id: The pending approval ID.
            timeout: Maximum seconds to wait.

        Returns:
            Tuple of (decision, approver_id). Decision is "allow", "allow_once",
            or "deny" if decided, None if timeout or not found.
        """
        request = self._pending.get(approval_id)
        if request is None:
            return None, None

        decision, approver_id = await request.wait(timeout)
        if decision is None:
            # Atomic check-and-remove: only broadcast timeout if WE removed it
            # This prevents race where resolve_pending() removes + broadcasts
            # pending_resolved, then we also broadcast pending_timeout
            removed = self._pending.pop(approval_id, None)
            if removed is not None:
                self._broadcast_event(
                    {
                        "type": "pending_timeout",
                        "approval_id": approval_id,
                    }
                )

        return decision, approver_id

    def get_pending_approvals(self) -> list[PendingApprovalInfo]:
        """Get all pending approvals.

        Returns:
            List of pending approval info waiting for decision.
        """
        return [request.info for request in self._pending.values()]

    def get_pending_approval(self, approval_id: str) -> PendingApprovalInfo | None:
        """Get a single pending approval by ID.

        Args:
            approval_id: The pending approval ID.

        Returns:
            PendingApprovalInfo if found, None otherwise.
        """
        request = self._pending.get(approval_id)
        return request.info if request else None

    # =========================================================================
    # SSE Broadcasting
    # =========================================================================

    def subscribe(self) -> asyncio.Queue[dict[str, Any]]:
        """Subscribe to SSE events.

        Returns:
            Queue that will receive events. Call unsubscribe() when done.
        """
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=100)
        self._sse_subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[dict[str, Any]]) -> None:
        """Unsubscribe from SSE events.

        Args:
            queue: The queue returned by subscribe().
        """
        self._sse_subscribers.discard(queue)

    @property
    def is_ui_connected(self) -> bool:
        """Check if any UI clients are connected via SSE.

        Used by HITL handler to decide between web UI and osascript.

        Returns True if:
        - Local SSE subscribers exist (UI connected directly to proxy), OR
        - Proxy is registered with manager (UI connects via manager's /api/events)
        """
        # Direct connection to proxy
        if len(self._sse_subscribers) > 0:
            return True

        # Connected via manager - assume UI could be watching
        if self._manager_client is not None and self._manager_client.registered:
            return True

        return False

    def _broadcast_event(self, event: dict[str, Any]) -> None:
        """Broadcast an event to all SSE subscribers and manager.

        Args:
            event: Event dict to broadcast.
        """
        # Broadcast to local SSE subscribers (web UI connected directly)
        for queue in self._sse_subscribers:
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                # Queue full - subscriber is slow, skip this event
                logger.warning(
                    "SSE queue full, dropping event: type=%s",
                    event.get("type", "unknown"),
                )

        # Forward to manager for aggregation (if connected)
        if self._manager_client is not None and self._manager_client.registered:
            event_type = event.get("type", "unknown")
            task = asyncio.create_task(self._manager_client.push_event(event_type, event))
            # Log any exceptions from the fire-and-forget task
            task.add_done_callback(self._handle_push_event_result)

    def _handle_push_event_result(self, task: asyncio.Task[None]) -> None:
        """Handle result of fire-and-forget push_event task.

        Logs any exceptions that occurred during event forwarding to manager.
        This prevents exceptions from being silently swallowed.

        Args:
            task: Completed asyncio Task from push_event.
        """
        if task.cancelled():
            return
        exc = task.exception()
        if exc is not None:
            logger.debug("Failed to push event to manager: %s", exc)

    def emit_system_event(
        self,
        event_type: SSEEventType,
        severity: "EventSeverity" = "info",
        message: str | None = None,
        details: str | None = None,
        **extra: Any,
    ) -> None:
        """Emit a system event to all connected SSE clients.

        This is the main method for emitting UI notifications from
        anywhere in the proxy. Events are broadcast to all connected
        web UI clients for toast display.

        Args:
            event_type: The type of event (from SSEEventType enum).
            severity: Toast severity level for styling.
            message: Custom message override (optional).
            details: Additional details for expandable toast (optional).
            **extra: Additional event-specific fields.

        Example:
            state.emit_system_event(
                SSEEventType.POLICY_RELOADED,
                severity="success",
                message="Policy reloaded successfully",
            )
        """
        event: dict[str, Any] = {
            "type": event_type.value,
            "severity": severity,
            "timestamp": datetime.now(UTC).isoformat(),
            "proxy_id": self._id,
        }
        if message is not None:
            event["message"] = message
        if details is not None:
            event["details"] = details
        event.update(extra)

        self._broadcast_event(event)
