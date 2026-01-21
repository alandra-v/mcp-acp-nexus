"""Backend logger setup for Proxy↔Backend communication (wire-level debugging).

This module provides setup functions and event logging for wire-level debug logging
of communication between the proxy and backend MCP servers.

Logs are written to <log_dir>/mcp-acp/proxies/default/debug/backend_wire.jsonl.
The log_dir is specified in the user's configuration file.

Event logging functions:
- log_proxy_request: Log egress (proxy → backend request)
- log_backend_response: Log ingress success (backend → proxy response)
- log_backend_error: Log ingress error (backend → proxy error)
"""

from __future__ import annotations

__all__ = [
    "log_backend_error",
    "log_backend_response",
    "log_proxy_request",
    "setup_backend_wire_logger",
]

import logging
import time
from pathlib import Path
from typing import Any, Optional

from mcp_acp.constants import APP_NAME
from mcp_acp.telemetry.models.wire import (
    BackendErrorEvent,
    BackendResponseEvent,
    ProxyRequestEvent,
)
from mcp_acp.utils.logging.extractors import extract_tool_metadata
from mcp_acp.utils.logging.logging_helpers import (
    extract_error_metadata,
    serialize_result_summary,
)
from mcp_acp.utils.logging.logger_setup import setup_jsonl_logger
from mcp_acp.utils.logging.logging_context import get_request_id, get_session_id


def setup_backend_wire_logger(log_path: Path) -> logging.Logger:
    """Set up a logger for Proxy↔Backend wire-level debugging.

    Writes JSONL to the specified log path.
    Each log entry includes ISO 8601 timestamp with milliseconds in UTC.

    Args:
        log_path: Path to the backend wire log file (e.g., <log_dir>/mcp-acp/proxies/default/debug/backend_wire.jsonl).

    Returns:
        logging.Logger: Configured logger instance for backend wire logs.
    """
    return setup_jsonl_logger(
        f"{APP_NAME}.debug.backend",
        log_path,
        logging.INFO,
    )


def log_proxy_request(
    logger: logging.Logger,
    transport: str,
    method: str,
    system_logger: Optional[logging.Logger] = None,
    **kwargs: Any,
) -> float:
    """Log egress: proxy request to backend.

    Args:
        logger: Logger instance for writing backend wire logs.
        transport: Transport type ("stdio" or "streamablehttp").
        method: MCP method name.
        system_logger: Logger for system errors (used by extract_tool_metadata).
        **kwargs: Method arguments for metadata extraction.

    Returns:
        float: Start time for duration calculation.
    """
    request_id = get_request_id()
    session_id = get_session_id()

    # Extract metadata for tool calls
    tool_name = None
    operation_type = None
    file_path = None
    file_extension = None
    file_name = None
    file_size_bytes = None
    mime_type_hint = None
    arguments = None

    if method == "tools/call" and "tool_name" in kwargs:
        tool_name_arg = kwargs.get("tool_name")
        arguments_arg = kwargs.get("arguments", {})

        metadata = extract_tool_metadata(tool_name_arg, arguments_arg, system_logger)

        tool_name = metadata.get("tool_name")
        operation_type = metadata.get("operation_type")
        file_path = metadata.get("file_path")
        file_extension = metadata.get("file_extension")
        file_name = metadata.get("file_name")
        file_size_bytes = metadata.get("file_size_bytes")
        mime_type_hint = metadata.get("mime_type_hint")
        arguments = metadata.get("arguments_redacted")

    event = ProxyRequestEvent(
        transport=transport,
        method=method,
        request_id=request_id,
        session_id=session_id,
        tool_name=tool_name,
        operation_type=operation_type,
        file_path=file_path,
        file_extension=file_extension,
        file_name=file_name,
        file_size_bytes=file_size_bytes,
        mime_type_hint=mime_type_hint,
        arguments=arguments,
    )

    logger.info(event.model_dump(exclude_none=True))
    return time.perf_counter()


def log_backend_response(
    logger: logging.Logger,
    transport: str,
    method: str,
    start_time: float,
    result: Any,
) -> None:
    """Log ingress: backend response to proxy (success).

    Args:
        logger: Logger instance for writing backend wire logs.
        transport: Transport type ("stdio" or "streamablehttp").
        method: MCP method name.
        start_time: Start time from request logging.
        result: Response result to log.
    """
    duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

    request_id = get_request_id()
    session_id = get_session_id()

    result_summary = serialize_result_summary(result, max_length=1000)

    event = BackendResponseEvent(
        transport=transport,
        method=method,
        duration_ms=duration_ms,
        request_id=request_id,
        session_id=session_id,
        **result_summary,
    )

    logger.info(event.model_dump(exclude_none=True))


def log_backend_error(
    logger: logging.Logger,
    transport: str,
    method: str,
    start_time: float,
    error: Exception,
) -> None:
    """Log ingress: backend error to proxy.

    Args:
        logger: Logger instance for writing backend wire logs.
        transport: Transport type ("stdio" or "streamablehttp").
        method: MCP method name.
        start_time: Start time from request logging.
        error: Exception that occurred.
    """
    duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

    request_id = get_request_id()
    session_id = get_session_id()

    error_metadata = extract_error_metadata(error)

    event = BackendErrorEvent(
        transport=transport,
        method=method,
        duration_ms=duration_ms,
        request_id=request_id,
        session_id=session_id,
        error=error_metadata["error"],
        error_type=error_metadata["error_type"],
        error_traceback=error_metadata["error_traceback"],
        error_code=error_metadata.get("error_code"),
        error_category=error_metadata["error_category"],
    )

    logger.info(event.model_dump(exclude_none=True))
