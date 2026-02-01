"""Pydantic models for authentication audit logs.

IMPORTANT: The 'time' field is Optional[str] = None because:
- Model instances are created WITHOUT timestamps (time=None)
- ISO8601Formatter/HashChainFormatter adds the timestamp during log serialization
- This provides a single source of truth for timestamps

Hash chain fields (sequence, prev_hash, entry_hash) are also added by
HashChainFormatter during serialization for tamper-evident logging.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


class SubjectIdentity(BaseModel):
    """
    Identity of the human user, derived from the OIDC token.
    """

    subject_id: str  # OIDC 'sub'
    subject_claims: dict[str, str] | None = None  # selected safe claims


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
    sequence: int | None = Field(
        None,
        description="Monotonically increasing entry number, added by HashChainFormatter",
    )
    prev_hash: str | None = Field(
        None,
        description="SHA-256 hash of previous entry, or 'GENESIS' for first entry",
    )
    entry_hash: str | None = Field(
        None,
        description="SHA-256 hash of this entry for chain verification",
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
