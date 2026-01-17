"""Pydantic models for production audit logs (auth, operations).

IMPORTANT: The 'time' field in all models is Optional[str] = None because:
- Model instances are created WITHOUT timestamps (time=None)
- ISO8601Formatter adds the timestamp during log serialization
- This provides a single source of truth for timestamps
- Logged events ALWAYS have a 'time' field in ISO 8601 format (e.g., "2025-12-11T10:30:45.123Z")

This separation means:
- Models define the structured event DATA
- Formatter adds the TIMESTAMP during serialization
- No duplicate timestamp generation across the codebase
"""

from __future__ import annotations

__all__ = [
    "ArgumentsSummary",
    "AuthEvent",
    "DeviceHealthChecks",
    "DurationInfo",
    "OIDCInfo",
    "OperationEvent",
    "ResponseSummary",
    "SubjectIdentity",
]

from datetime import datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


# ============================================================================
# Shared Models
# ============================================================================


class SubjectIdentity(BaseModel):
    """
    Identity of the human user, derived from the OIDC token.
    """

    subject_id: str  # OIDC 'sub'
    subject_claims: dict[str, str] | None = None  # selected safe claims


# ============================================================================
# Authentication & Authorization Events (logs/audit/auth.jsonl)
# ============================================================================


class DeviceHealthChecks(BaseModel):
    """Results of individual device health checks.

    Both checks are hard gates - failure blocks proxy startup.
    - disk_encryption: FileVault (macOS) - reduces impact of device theft/loss
    - device_integrity: SIP enabled (macOS) - ensures system not compromised

    Result meanings:
    - pass: Check succeeded, device is compliant
    - fail: Check succeeded, device is NOT compliant
    - unknown: Could not determine status (treated as unhealthy for Zero Trust)
    """

    disk_encryption: Literal["pass", "fail", "unknown"]
    device_integrity: Literal["pass", "fail", "unknown"]


class OIDCInfo(BaseModel):
    """
    Details about the OIDC/OAuth token and provider, for authentication logs.
    """

    issuer: str  # OIDC 'iss'
    provider: str | None = None  # friendly name, e.g. "google", "auth0"
    client_id: str | None = None  # upstream client_id (if you want to log it)

    audience: list[str] | None = None  # normalized 'aud' as list
    scopes: list[str] | None = None  # token scopes, if available

    token_type: str | None = None  # "access", "id", "proxy", etc.
    token_exp: datetime | None = None  # 'exp' as datetime
    token_iat: datetime | None = None  # 'iat' as datetime
    token_expired: bool | None = None  # whether it was expired at validation time


class AuthEvent(BaseModel):
    """
    One authentication/authorization log entry (logs/audit/auth.jsonl).

    Inspired by:
      - OCSF Authentication (3002): token validation outcome, identity, IdP context
      - OCSF Authorize Session (3003): session lifecycle (start/stop) tied to identity

    Note: 'time' is None when created, populated by ISO8601Formatter during logging.
    """

    # --- core ---
    time: str | None = Field(
        None,
        description="ISO 8601 timestamp, added by formatter during serialization",
    )

    # Two session IDs for different purposes:
    # - bound_session_id: Security format "<user_id>:<session_uuid>" for auth binding
    # - mcp_session_id: Plain UUID for correlation with operations/decisions/wire logs
    bound_session_id: str | None = None  # May not exist during startup validation
    mcp_session_id: str | None = None  # For cross-log correlation

    # For per-request auth checks, this is the MCP JSON-RPC id; may be omitted for pure session events.
    request_id: str | None = None

    event_type: Literal[
        "token_invalid",
        "token_refreshed",
        "token_refresh_failed",
        "session_started",
        "session_ended",
        "device_health_failed",
    ]
    status: Literal["Success", "Failure"]
    message: str | None = None

    # Optional MCP method (useful when event_type is per-request token validation).
    method: str | None = None  # "tools/call", "tools/list", etc.

    # --- identity ---
    # May be None if token could not be parsed at all (e.g. totally invalid or missing)
    subject: SubjectIdentity | None = None

    # --- OIDC/OAuth details ---
    oidc: OIDCInfo | None = None

    # --- device health (for device_health_failed events) ---
    device_checks: DeviceHealthChecks | None = None

    # --- session end details ---
    end_reason: Literal["normal", "timeout", "error", "auth_expired", "session_binding_violation"] | None = (
        None
    )

    # --- errors / extra details ---
    error_type: str | None = None  # e.g. "TokenExpiredError"
    error_message: str | None = None  # human-readable error
    details: dict[str, Any] | None = None  # any extra structured data

    model_config = ConfigDict(extra="forbid")


# ============================================================================
# MCP Operation Events (logs/audit/operations.jsonl)
# ============================================================================


class ArgumentsSummary(BaseModel):
    """
    Summary of MCP request arguments (without logging full sensitive payloads).
    """

    redacted: bool = True
    body_hash: str | None = None  # e.g. sha256 hex string
    payload_length: int | None = None  # request size in bytes


class DurationInfo(BaseModel):
    """
    Duration measurement for this MCP operation.

    Measures total operation time from the proxy's perspective:
    from when the audit middleware receives the request until the
    response (or error) is ready to return to the client.

    This includes:
    - Middleware processing overhead
    - Backend round-trip time (proxy → backend → proxy)
    - Response processing

    Note: We cannot measure client→proxy network time (no client-side timing)
    or backend internal processing time (no backend instrumentation).
    """

    duration_ms: float = Field(..., description="Total operation duration in milliseconds")


class ResponseSummary(BaseModel):
    """
    Summary of MCP response metadata (without logging full payloads).

    Captures response size and hash for forensic analysis without
    storing potentially sensitive response content.
    """

    size_bytes: int = Field(..., description="Response payload size in bytes")
    body_hash: str = Field(..., description="SHA256 hash of response payload")


class OperationEvent(BaseModel):
    """
    One MCP operation log entry (audit/operations.jsonl).

    Captures security-relevant information about each MCP operation
    (who did what, when, with what outcome).

    Note: 'time' is None when created, populated by ISO8601Formatter during logging.
    """

    # --- core ---
    time: str | None = Field(
        None,
        description="ISO 8601 timestamp, added by formatter during serialization",
    )
    session_id: str
    request_id: str
    method: str  # MCP method ("tools/call", ...)

    status: str  # "Success" or "Failure"
    error_code: int | None = None  # MCP/JSON-RPC error code (e.g., -32700, -32603)
    message: str | None = None

    # --- identity ---
    subject: SubjectIdentity

    # --- client/backend info ---
    client_id: str | None = None  # MCP client application name (from clientInfo.name)
    backend_id: str  # internal MCP backend identifier
    transport: str | None = None  # backend transport type ("stdio" or "streamablehttp")

    # --- MCP details ---
    tool_name: Optional[str] = None  # only for tools/call
    file_path: Optional[str] = None
    file_extension: Optional[str] = None
    source_path: Optional[str] = None  # for copy/move operations
    dest_path: Optional[str] = None  # for copy/move operations
    arguments_summary: ArgumentsSummary | None = None

    # --- config ---
    config_version: str | None = None

    # --- duration ---
    duration: DurationInfo

    # --- response metadata ---
    response_summary: ResponseSummary | None = None

    model_config = ConfigDict(extra="forbid")
