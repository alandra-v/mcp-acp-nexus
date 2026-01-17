"""Pydantic models for wire-level debug logs (client↔proxy and proxy↔backend).

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
    "BackendErrorEvent",
    "BackendResponseEvent",
    "ClientRequestEvent",
    "ProxyErrorEvent",
    "ProxyRequestEvent",
    "ProxyResponseEvent",
]

from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


# ============================================================================
# Client ↔ Proxy Wire Events (logs/debug/client_wire.jsonl)
# ============================================================================


class ClientRequestEvent(BaseModel):
    """
    Ingress event: Client request arriving at proxy.

    Logs when an MCP client (Claude Desktop, etc.) sends a request to the proxy.

    Note: 'time' is None when created, populated by ISO8601Formatter during logging.
    """

    time: Optional[str] = Field(
        None,
        description="ISO 8601 timestamp, added by formatter during serialization",
    )
    event: Literal["client_request"] = "client_request"
    source: Literal["client"] = "client"
    direction: Literal["ingress"] = "ingress"
    transport: str  # "stdio" or "streamablehttp"
    method: str  # MCP method (e.g., "tools/call", "initialize")

    # Correlation IDs
    request_id: Optional[str] = None
    session_id: Optional[str] = None

    # Payload (optional, can be large)
    payload: Optional[str] = None  # Serialized JSON string
    payload_type: Optional[str] = None  # e.g., "InitializeRequest", "CallToolRequest"

    # Client metadata (from initialize)
    client_name: Optional[str] = None
    client_version: Optional[str] = None
    protocol_version: Optional[str] = None

    model_config = ConfigDict(extra="allow")  # Allow dynamic fields for method-specific metadata


class ProxyResponseEvent(BaseModel):
    """
    Egress event: Proxy response leaving to client (success).

    Logs when the proxy successfully responds to a client request.

    Note: 'time' is None when created, populated by ISO8601Formatter during logging.
    """

    time: Optional[str] = Field(
        None,
        description="ISO 8601 timestamp, added by formatter during serialization",
    )
    event: Literal["proxy_response"] = "proxy_response"
    source: Literal["proxy"] = "proxy"
    direction: Literal["egress"] = "egress"
    transport: str
    method: str

    # Duration: time from client request received until response ready to send
    # (full proxy processing including backend round-trip)
    duration_ms: float

    # Correlation IDs
    request_id: Optional[str] = None
    session_id: Optional[str] = None

    model_config = ConfigDict(extra="allow")  # Allow dynamic fields for method-specific metadata


class ProxyErrorEvent(BaseModel):
    """
    Egress event: Proxy error leaving to client.

    Logs when the proxy encounters an error while processing a client request.

    Note: 'time' is None when created, populated by ISO8601Formatter during logging.
    """

    time: Optional[str] = Field(
        None,
        description="ISO 8601 timestamp, added by formatter during serialization",
    )
    event: Literal["proxy_error"] = "proxy_error"
    source: Literal["proxy"] = "proxy"
    direction: Literal["egress"] = "egress"
    transport: str
    method: str

    # Duration: time from client request received until error ready to send
    # (full proxy processing including any backend interaction before error)
    duration_ms: float

    # Error details
    error: str  # Error message
    error_type: str  # Exception class name
    error_traceback: str  # Full traceback
    error_code: Optional[int] = None  # MCP error code if available
    error_category: str  # Categorized error type

    # Correlation IDs
    request_id: Optional[str] = None
    session_id: Optional[str] = None

    model_config = ConfigDict(extra="allow")  # Allow dynamic fields for method-specific metadata


# ============================================================================
# Proxy ↔ Backend Wire Events (logs/debug/backend_wire.jsonl)
# ============================================================================


class ProxyRequestEvent(BaseModel):
    """
    Egress event: Proxy request leaving to backend.

    Logs when the proxy sends a request to a backend MCP server.

    Note: 'time' is None when created, populated by ISO8601Formatter during logging.
    """

    time: Optional[str] = Field(
        None,
        description="ISO 8601 timestamp, added by formatter during serialization",
    )
    event: Literal["proxy_request"] = "proxy_request"
    source: Literal["proxy"] = "proxy"
    direction: Literal["egress"] = "egress"
    transport: str
    method: str

    # Correlation IDs
    request_id: Optional[str] = None
    session_id: Optional[str] = None

    # Security metadata for tool calls
    tool_name: Optional[str] = None
    operation_type: Optional[str] = None  # "read", "write", "delete", "list"
    file_path: Optional[str] = None
    file_extension: Optional[str] = None
    file_name: Optional[str] = None
    file_size_bytes: Optional[int] = None
    mime_type_hint: Optional[str] = None

    # Arguments (redacted/sanitized)
    arguments: Optional[dict[str, Any]] = None

    # Payload metadata (for non-tool calls)
    payload_length: Optional[int] = None

    model_config = ConfigDict(extra="allow")  # Allow dynamic fields for method-specific metadata


class BackendResponseEvent(BaseModel):
    """
    Ingress event: Backend response arriving at proxy (success).

    Logs when a backend MCP server successfully responds to the proxy.

    Note: 'time' is None when created, populated by ISO8601Formatter during logging.
    """

    time: Optional[str] = Field(
        None,
        description="ISO 8601 timestamp, added by formatter during serialization",
    )
    event: Literal["backend_response"] = "backend_response"
    source: Literal["backend"] = "backend"
    direction: Literal["ingress"] = "ingress"
    transport: str
    method: str

    # Duration: time from proxy request sent to backend until response received
    # (backend round-trip only, not full proxy processing)
    duration_ms: float

    # Correlation IDs
    request_id: Optional[str] = None
    session_id: Optional[str] = None

    # Response metadata
    payload_length: Optional[int] = None
    result: Optional[dict[str, Any]] = None  # Summarized result

    # Initialize-specific fields
    protocol_version: Optional[str] = None
    server_name: Optional[str] = None
    server_version: Optional[str] = None
    server_info: Optional[dict[str, Any]] = None
    capabilities: Optional[dict[str, Any]] = None

    model_config = ConfigDict(extra="allow")  # Allow dynamic fields for method-specific metadata


class BackendErrorEvent(BaseModel):
    """
    Ingress event: Backend error arriving at proxy.

    Logs when a backend MCP server returns an error to the proxy.

    Note: 'time' is None when created, populated by ISO8601Formatter during logging.
    """

    time: Optional[str] = Field(
        None,
        description="ISO 8601 timestamp, added by formatter during serialization",
    )
    event: Literal["backend_error"] = "backend_error"
    source: Literal["backend"] = "backend"
    direction: Literal["ingress"] = "ingress"
    transport: str
    method: str

    # Duration: time from proxy request sent to backend until error received
    # (backend round-trip only, not full proxy processing)
    duration_ms: float

    # Error details
    error: str
    error_type: str
    error_traceback: str
    error_code: Optional[int] = None
    error_category: str

    # Correlation IDs
    request_id: Optional[str] = None
    session_id: Optional[str] = None

    model_config = ConfigDict(extra="allow")  # Allow dynamic fields for method-specific metadata
