"""Pydantic models for manager daemon system logs.

IMPORTANT: The 'time' field is Optional[str] = None because:
- Model instances are created WITHOUT timestamps (time=None)
- ISO8601Formatter adds the timestamp during log serialization
- This provides a single source of truth for timestamps

Unlike proxy logs, manager logs do NOT use hash chains - they are
operational logs, not security audit trails.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from pydantic import BaseModel, ConfigDict, Field


class ManagerSystemEvent(BaseModel):
    """
    One manager system log entry (<log_dir>/mcp-acp/manager/system.jsonl).

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
