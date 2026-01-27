"""Pydantic models for manager daemon.

This module contains two categories of models:

API Response Models (FrozenModel-based):
- FrozenModel: Base class for immutable models
- ManagerStatusResponse: Manager health status
- RegisteredProxyInfo: Manager's view of a registered proxy
- CachedApprovalSummary: Cached approval for API responses
- Proxy: Proxy info for manager list endpoint
- ProxyRuntimeInfo: Full proxy runtime information (internal API)
- ProxyStats: Request statistics
- PendingApprovalInfo: Pending approval for API/SSE

Logging Models:
- ManagerSystemEvent: System log entries for manager daemon
"""

from __future__ import annotations

__all__ = [
    # Type Aliases
    "IncidentType",
    "ProxyStatus",
    "TransportType",
    # API Response Models
    "AggregatedIncidentsResponse",
    "AuthActionResponse",
    "AuthStatusResponse",
    "CachedApprovalSummary",
    "ConfigSnippetResponse",
    "CreateProxyRequest",
    "CreateProxyResponse",
    "FrozenModel",
    "ManagerStatusResponse",
    "PendingApprovalInfo",
    "Proxy",
    "ProxyDetailResponse",
    "ProxyRuntimeInfo",
    "ProxyStats",
    "RegisteredProxyInfo",
    # Logging Models
    "ManagerSystemEvent",
]

from datetime import datetime
from typing import Any, Dict, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

# Type aliases for constrained values
TransportType = Literal["stdio", "streamablehttp", "auto"]
ProxyStatus = Literal["running", "inactive"]
IncidentType = Literal["shutdown", "bootstrap", "emergency"]


# =============================================================================
# API Response Models
# =============================================================================


class FrozenModel(BaseModel):
    """Base class for immutable Pydantic models.

    All models in this module inherit from this class to ensure
    immutability after creation.
    """

    model_config = ConfigDict(frozen=True)


class AggregatedIncidentsResponse(FrozenModel):
    """Response model for aggregated incidents endpoint.

    Aggregates incidents from all proxies (shutdowns) plus global
    incidents (bootstrap, emergency) into a single timeline.

    Attributes:
        entries: Incident entries sorted by time (newest first).
            Each entry includes 'incident_type' and 'proxy_name' (for shutdowns).
        total_returned: Number of entries in this response.
        has_more: Whether there are more entries to fetch.
        filters_applied: Active filters (time_range, proxy, incident_type).
    """

    entries: list[dict[str, Any]]
    total_returned: int
    has_more: bool
    filters_applied: dict[str, Any]


class AuthActionResponse(FrozenModel):
    """Response model for auth action endpoints (reload, clear).

    Attributes:
        ok: Whether the action succeeded.
        message: Human-readable result message.
    """

    ok: bool
    message: str


class AuthStatusResponse(FrozenModel):
    """Response model for manager auth status endpoint.

    Mirrors the CLI 'auth status' output. Shows whether OIDC is configured
    and the current authentication state.

    Attributes:
        configured: Whether OIDC authentication is configured.
        authenticated: Whether user is currently authenticated.
        subject_id: User subject ID from token (if authenticated).
        email: User email from ID token (if available).
        name: User name from ID token (if available).
        provider: OIDC provider name (e.g., 'auth0').
        token_expires_in_hours: Hours until token expires (if authenticated).
        has_refresh_token: Whether a refresh token is available.
        storage_backend: Token storage backend ('keyring' or 'file').
    """

    configured: bool
    authenticated: bool
    subject_id: str | None = None
    email: str | None = None
    name: str | None = None
    provider: str | None = None
    token_expires_in_hours: float | None = None
    has_refresh_token: bool | None = None
    storage_backend: str | None = None


class CreateProxyRequest(BaseModel):
    """Request model for creating a new proxy.

    Mirrors the CLI 'mcp-acp proxy add' functionality.

    Attributes:
        name: Proxy name (alphanumeric, hyphens, underscores).
        server_name: Backend server display name.
        transport: Transport type (stdio, streamablehttp, auto).
        command: Command to run (required for stdio/auto).
        args: Command arguments (for stdio/auto).
        attestation_slsa_owner: GitHub owner for SLSA attestation (stdio).
        attestation_sha256: Expected SHA-256 hash of binary (stdio).
        attestation_require_signature: Require code signature (macOS, stdio).
        url: Backend URL (required for streamablehttp/auto).
        timeout: HTTP timeout in seconds (for streamablehttp/auto).
        api_key: API key for HTTP backend (stored in keychain).
        mtls_cert: Path to client certificate for mTLS (PEM format).
        mtls_key: Path to client private key for mTLS (PEM format).
        mtls_ca: Path to CA bundle for server verification (PEM format).
    """

    name: str = Field(min_length=1, max_length=64)
    server_name: str = Field(min_length=1)
    transport: TransportType = "stdio"

    # STDIO options
    command: str | None = None
    args: list[str] = Field(default_factory=list)

    # STDIO attestation options
    attestation_slsa_owner: str | None = None
    attestation_sha256: str | None = None
    attestation_require_signature: bool = False

    # HTTP options
    url: str | None = None
    timeout: int = Field(default=30, ge=1, le=300)
    api_key: str | None = None  # Will be stored in keychain, not config

    # mTLS options (for HTTPS backends)
    mtls_cert: str | None = None
    mtls_key: str | None = None
    mtls_ca: str | None = None


class ConfigSnippetResponse(FrozenModel):
    """Response model for MCP client configuration snippet.

    Mirrors the CLI 'install mcp-json' output format.

    Attributes:
        mcpServers: Dictionary mapping proxy names to their config.
            Each entry contains 'command' and 'args' for MCP client.
        executable_path: Path to mcp-acp executable used in config.
    """

    mcpServers: dict[str, dict[str, Any]]
    executable_path: str


class CreateProxyResponse(FrozenModel):
    """Response model for proxy creation.

    Attributes:
        ok: Whether creation succeeded.
        proxy_name: Created proxy name.
        proxy_id: Generated proxy ID.
        config_path: Path to config.json.
        policy_path: Path to policy.json.
        claude_desktop_snippet: Ready-to-copy JSON for Claude Desktop config.
        message: Human-readable result message.
    """

    ok: bool
    proxy_name: str
    proxy_id: str | None = None
    config_path: str | None = None
    policy_path: str | None = None
    claude_desktop_snippet: dict[str, Any] | None = None
    message: str


class Proxy(FrozenModel):
    """Proxy information combining config and runtime data.

    Used by GET /api/manager/proxies to provide a complete view of each proxy.

    Attributes:
        proxy_name: User-defined proxy name (directory name).
        proxy_id: Stable proxy identifier from config.
        status: Current status ('running' if registered, 'inactive' otherwise).
        instance_id: Unique instance ID (None if not running).
        server_name: Backend server name from config.
        transport: Transport type (stdio, streamablehttp, auto).
        command: Command to run (for stdio/auto transport).
        args: Command arguments (for stdio/auto transport).
        url: Backend URL (for streamablehttp/auto transport).
        created_at: ISO timestamp of proxy creation.
        backend_transport: Actual backend transport in use (stdio or streamablehttp).
        mtls_enabled: Whether mTLS is enabled for backend connection.
        stats: Request statistics (None if not running).
    """

    proxy_name: str
    proxy_id: str
    status: ProxyStatus
    instance_id: str | None = None
    server_name: str
    transport: TransportType
    command: str | None = None
    args: list[str] | None = None
    url: str | None = None
    created_at: str
    backend_transport: str = "stdio"
    mtls_enabled: bool = False
    stats: "ProxyStats | None" = None  # Forward reference - ProxyStats defined later


class ProxyDetailResponse(Proxy):
    """Full proxy detail including config and runtime data.

    Extends Proxy with additional runtime data from proxy UDS.
    Returned by GET /api/manager/proxies/{proxy_id}.

    Attributes:
        client_id: MCP client application name (None if not running).
        pending_approvals: Pending HITL approvals (None if not running).
        cached_approvals: Cached approvals (None if not running).
    """

    client_id: str | None = None
    pending_approvals: list[dict[str, Any]] | None = None
    cached_approvals: list[dict[str, Any]] | None = None


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
    For full proxy details (transport, stats), use ProxyRuntimeInfo which
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


class ProxyRuntimeInfo(FrozenModel):
    """Runtime information about a running proxy (internal API).

    Contains full runtime information about a proxy instance,
    including transport configuration, status, and timing.
    Used by per-proxy /api/proxies endpoint.

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
