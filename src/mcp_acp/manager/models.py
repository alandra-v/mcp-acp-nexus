"""Pydantic models for manager daemon.

This module contains two categories of models:

API Response Models (FrozenModel-based):
- FrozenModel: Base class for immutable models
- ManagerStatusResponse: Manager health status
- RegisteredProxyInfo: Manager's view of a registered proxy
- CachedApprovalSummary: Cached approval for API responses
- ProxyInfo: Full proxy runtime information
- ProxyStats: Request statistics
- PendingApprovalInfo: Pending approval for API/SSE

Logging Models:
- ManagerSystemEvent: System log entries for manager daemon
"""

from __future__ import annotations

__all__ = [
    # API Response Models
    "AuthActionResponse",
    "CachedApprovalSummary",
    "FrozenModel",
    "ManagerStatusResponse",
    "PendingApprovalInfo",
    "ProxyInfo",
    "ProxyStats",
    "RegisteredProxyInfo",
    # Logging Models
    "ManagerSystemEvent",
]

from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel, ConfigDict, Field


# =============================================================================
# API Response Models
# =============================================================================


class FrozenModel(BaseModel):
    """Base class for immutable Pydantic models.

    All models in this module inherit from this class to ensure
    immutability after creation.
    """

    model_config = ConfigDict(frozen=True)


class AuthActionResponse(FrozenModel):
    """Response model for auth action endpoints (reload, clear).

    Attributes:
        ok: Whether the action succeeded.
        message: Human-readable result message.
    """

    ok: bool
    message: str


class ManagerStatusResponse(FrozenModel):
    """Response model for manager status endpoint.

    Attributes:
        running: Whether the manager is running.
        pid: Process ID of the manager.
        proxies_connected: Number of proxies currently connected.
    """

    running: bool
    pid: int
    proxies_connected: int


class RegisteredProxyInfo(FrozenModel):
    """API response model for a registered proxy.

    This is the manager's view of a proxy - minimal registration info.
    For full proxy details (transport, stats), use ProxyInfo which
    is returned by the proxy itself.

    Attributes:
        name: Proxy name (e.g., "default").
        instance_id: Unique instance ID for this proxy run.
        connected: Whether the proxy is currently connected.
    """

    name: str
    instance_id: str
    connected: bool


class CachedApprovalSummary(FrozenModel):
    """Summary of a cached approval for API responses.

    Used by get_cached_approvals() to return structured data
    instead of an opaque tuple.

    Attributes:
        subject_id: The user who was granted the approval.
        tool_name: The tool that was approved.
        path: The path that was approved (if applicable).
        age_seconds: How long ago the approval was granted.
        expires_in_seconds: Time until the approval expires.
    """

    subject_id: str
    tool_name: str
    path: str | None
    age_seconds: float
    expires_in_seconds: float


class ProxyInfo(FrozenModel):
    """Information about a running proxy.

    Contains full runtime information about a proxy instance,
    including transport configuration, status, and timing.

    Attributes:
        id: Unique proxy ID in format {uuid}:{backend_id}.
        backend_id: The backend server name from config.
        status: Current status (always "running" for now).
        started_at: When the proxy was started.
        pid: Process ID of the proxy.
        api_port: Port the management API is listening on.
        uptime_seconds: Seconds since proxy started.
        command: Backend command (for STDIO transport).
        args: Backend command arguments (for STDIO transport).
        url: Backend URL (for HTTP transport).
        client_transport: Transport type for client-to-proxy connection.
        backend_transport: Transport type for proxy-to-backend connection.
        mtls_enabled: Whether mTLS is enabled for backend connection.
        client_id: MCP client application name (from initialize request).
    """

    id: str
    backend_id: str
    status: str
    started_at: datetime
    pid: int
    api_port: int
    uptime_seconds: float
    command: str | None = None
    args: list[str] | None = None
    url: str | None = None
    client_transport: str = "stdio"
    backend_transport: str = "stdio"
    mtls_enabled: bool = False
    client_id: str | None = None


class ProxyStats(FrozenModel):
    """Request statistics for a proxy.

    Only counts policy-evaluated requests (tools/call). Discovery requests
    (tools/list, resources/list, etc.) are not included in these counts.

    Attributes:
        requests_total: Total policy-evaluated requests (= allowed + denied + hitl).
        requests_allowed: Requests allowed by policy.
        requests_denied: Requests denied by policy.
        requests_hitl: Requests that triggered HITL approval dialog.
    """

    requests_total: int
    requests_allowed: int
    requests_denied: int
    requests_hitl: int

    def to_dict(self) -> dict[str, Any]:
        """Convert to JSON-serializable dict for SSE/API."""
        return self.model_dump()


class PendingApprovalInfo(FrozenModel):
    """API-facing pending approval data (immutable, serializable).

    This is the public representation of a pending approval, used
    for API responses and SSE events.

    Attributes:
        id: Unique approval request ID.
        proxy_id: ID of the proxy that created this request.
        tool_name: The tool being invoked.
        path: The path being accessed (if applicable).
        subject_id: The user making the request.
        created_at: When the request was created.
        timeout_seconds: How long to wait for decision.
        request_id: Original MCP request ID for correlation.
        can_cache: Whether this approval can be cached.
        cache_ttl_seconds: How long cached approval will last (for UI display).
    """

    id: str
    proxy_id: str
    tool_name: str
    path: str | None
    subject_id: str
    created_at: datetime
    timeout_seconds: int
    request_id: str
    can_cache: bool = True
    cache_ttl_seconds: int | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to JSON-serializable dict for SSE."""
        return self.model_dump(mode="json")


# =============================================================================
# Logging Models
# =============================================================================


class ManagerSystemEvent(BaseModel):
    """One manager system log entry (<log_dir>/mcp-acp/manager/system.jsonl).

    Inspired by:
      - OCSF Application Lifecycle (6002): service start/stop, resource registration
      - OCSF API Activity (6003): API request tracking, status codes, durations

    Used for INFO, WARNING, ERROR, and CRITICAL events related to manager operations.

    Note: 'time' is None when created, populated by ISO8601Formatter during logging.
    """

    # --- core ---
    time: Optional[str] = Field(
        None,
        description="ISO 8601 timestamp (UTC), added by formatter during serialization",
    )
    event: Optional[str] = Field(
        None,
        description="Machine-friendly event name, e.g. 'manager_started', 'proxy_registered'",
    )
    message: str = Field(description="Human-readable log message")

    # --- proxy context ---
    proxy_name: Optional[str] = Field(
        None,
        description="Name of affected proxy, e.g. 'default'",
    )
    instance_id: Optional[str] = Field(
        None,
        description="Unique proxy instance identifier",
    )
    socket_path: Optional[str] = Field(
        None,
        description="UDS path for proxy communication",
    )

    # --- API context (for routing events) ---
    path: Optional[str] = Field(
        None,
        description="API request path, e.g. '/api/config'",
    )
    status_code: Optional[int] = Field(
        None,
        description="HTTP response status code (for error responses)",
    )
    duration_ms: Optional[float] = Field(
        None,
        description="Request duration in milliseconds",
    )

    # --- SSE context ---
    subscriber_count: Optional[int] = Field(
        None,
        description="Current number of SSE subscribers",
    )

    # --- error details ---
    error_type: Optional[str] = Field(
        None,
        description="Exception class name, e.g. 'ConnectionRefusedError'",
    )
    error_message: Optional[str] = Field(
        None,
        description="Short error text from exception",
    )

    # --- additional structured details ---
    details: Optional[Dict[str, Any]] = Field(
        None,
        description="Additional context as key-value pairs",
    )

    model_config = ConfigDict(extra="allow")
