"""Pydantic models for MCP operation audit logs.

IMPORTANT: The 'time' field is Optional[str] = None because:
- Model instances are created WITHOUT timestamps (time=None)
- ISO8601Formatter/HashChainFormatter adds the timestamp during log serialization
- This provides a single source of truth for timestamps

Hash chain fields (sequence, prev_hash, entry_hash) are also added by
HashChainFormatter during serialization for tamper-evident logging.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class SubjectIdentity(BaseModel):
    """
    Identity of the human user, derived from the OIDC token.
    """

    subject_id: str  # OIDC 'sub'
    subject_claims: dict[str, str] | None = None  # selected safe claims


class ArgumentsSummary(BaseModel):
    """
    Summary of MCP request arguments (without logging full sensitive payloads).
    """

    redacted: bool = True
    body_hash: str | None = None  # SHA256 hex string
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
