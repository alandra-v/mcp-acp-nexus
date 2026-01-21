"""Debug wire logging middleware for Client↔Proxy communication.

This module provides wire-level DEBUG logging for all communication between
MCP clients (like Claude Desktop or MCP Inspector) and the proxy server.

Wire logs include:
- Full message payloads (for debugging)
- Request/response timing
- Protocol-level details

Logs are written to <log_dir>/mcp-acp/proxies/default/debug/client_wire.jsonl using Pydantic models.
The log_dir is specified in the user's configuration file.
"""

from __future__ import annotations

__all__ = [
    "BidirectionalClientLoggingMiddleware",
    "create_client_logging_middleware",
    "setup_client_wire_logger",
]

import logging
import time
import traceback
from pathlib import Path
from typing import Any

from fastmcp.server.middleware.logging import BaseLoggingMiddleware
from fastmcp.server.middleware.middleware import MiddlewareContext

from mcp_acp.constants import APP_NAME
from mcp_acp.telemetry.models.wire import (
    ClientRequestEvent,
    ProxyErrorEvent,
    ProxyResponseEvent,
)
from mcp_acp.telemetry.system.system_logger import get_system_logger
from mcp_acp.utils.logging.extractors import extract_client_info
from mcp_acp.utils.logging.logging_context import (
    get_request_id,
    get_session_id,
)
from mcp_acp.utils.logging.logging_helpers import categorize_error
from mcp_acp.utils.logging.logger_setup import setup_jsonl_logger


class BidirectionalClientLoggingMiddleware(BaseLoggingMiddleware):
    """Wire-level logging middleware for Client↔Proxy communication (debug logs).

    Extends FastMCP's BaseLoggingMiddleware to emit structured Pydantic events
    for wire-level debugging.

    Log events:
    - ClientRequestEvent: Client request arriving at proxy (ingress)
    - ProxyResponseEvent: Proxy response leaving to client (egress, success)
    - ProxyErrorEvent: Proxy error leaving to client (egress, error)
    """

    def __init__(
        self,
        *,
        logger: logging.Logger | None = None,
        log_level: int = logging.INFO,
        include_payloads: bool = True,
        transport: str = "stdio",
    ) -> None:
        """Initialize bidirectional client logging middleware.

        Args:
            logger: Logger instance to use.
            log_level: Log level for messages (default: INFO).
            include_payloads: Whether to include full message payloads.
            transport: Transport type ("stdio" or "http").
        """
        # Debug logger for wire-level logs
        self.logger = logger or logging.getLogger(f"{APP_NAME}.debug.client")
        self.log_level = log_level

        # System logger for operational warnings/errors
        self.system_logger = get_system_logger()

        self.include_payloads = include_payloads
        self.transport = transport

        # FastMCP base class attributes (required but not actively used)
        self.max_payload_length = None
        self.methods = None
        self.payload_serializer = None
        self.structured_logging = True

    def _create_before_message(self, context: MiddlewareContext[Any]) -> dict[str, Any]:
        """Create ClientRequestEvent for ingress (client request arriving at proxy).

        Args:
            context: Middleware context containing request information.

        Returns:
            dict: Pydantic model as dict for logging
        """
        # Get context IDs (set by ContextMiddleware, the outermost middleware)
        request_id = get_request_id()
        session_id = get_session_id()

        # Build event data
        payload_str = None
        payload_type = None

        # Serialize payload if configured
        if self.include_payloads:
            payload_str = self._serialize_payload(context)
            payload_type = type(context.message).__name__

        # Extract client info from initialize request
        client_info = extract_client_info(context)

        # Create Pydantic event
        event = ClientRequestEvent(
            transport=self.transport,
            method=context.method or "unknown",
            request_id=request_id,
            session_id=session_id,
            payload=payload_str,
            payload_type=payload_type,
            client_name=client_info.name,
            client_version=client_info.version,
            protocol_version=client_info.protocol_version,
        )

        return event.model_dump(exclude_none=True)

    def _create_after_message(
        self,
        context: MiddlewareContext[Any],
        start_time: float,
    ) -> dict[str, Any]:
        """Create ProxyResponseEvent for egress (proxy response to client, success).

        Args:
            context: Middleware context containing response information.
            start_time: Start time of the request processing.

        Returns:
            dict: Pydantic model as dict for logging
        """
        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

        # Get context IDs (set by ContextMiddleware, cleared by it in finally)
        request_id = get_request_id()
        session_id = get_session_id()

        # Create Pydantic event
        event = ProxyResponseEvent(
            transport=self.transport,
            method=context.method or "unknown",
            duration_ms=duration_ms,
            request_id=request_id,
            session_id=session_id,
        )

        return event.model_dump(exclude_none=True)

    def _create_error_message(
        self,
        context: MiddlewareContext[Any],
        start_time: float,
        error: Exception,
    ) -> dict[str, Any]:
        """Create ProxyErrorEvent for egress (proxy error to client).

        Args:
            context: Middleware context containing error information.
            start_time: Start time of the request processing.
            error: The exception that occurred.

        Returns:
            dict: Pydantic model as dict for logging
        """
        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

        # Get context IDs (set by ContextMiddleware, cleared by it in finally)
        request_id = get_request_id()
        session_id = get_session_id()

        # Extract error metadata
        error_code = error.code if hasattr(error, "code") else None

        # Create Pydantic event
        event = ProxyErrorEvent(
            transport=self.transport,
            method=context.method or "unknown",
            duration_ms=duration_ms,
            error=str(error),
            error_type=type(error).__name__,
            error_traceback=traceback.format_exc(),
            error_code=error_code,
            error_category=categorize_error(error),
            request_id=request_id,
            session_id=session_id,
        )

        return event.model_dump(exclude_none=True)


def setup_client_wire_logger(log_path: Path) -> logging.Logger:
    """Set up a logger for Client↔Proxy wire-level debugging.

    Writes JSONL to the specified log path.
    Each log entry includes ISO 8601 timestamp with milliseconds in UTC.

    Args:
        log_path: Path to the client wire log file (e.g., <log_dir>/mcp-acp/proxies/default/debug/client_wire.jsonl).

    Returns:
        logging.Logger: Configured logger instance for client wire logs.
    """
    return setup_jsonl_logger(
        f"{APP_NAME}.debug.client",
        log_path,
        logging.INFO,
    )


def create_client_logging_middleware(
    log_path: Path,
    transport: str = "stdio",
    debug_enabled: bool = True,
) -> BidirectionalClientLoggingMiddleware:
    """Create middleware for wire-level logging of Client↔Proxy communication.

    The middleware logs:
    - All MCP methods (tools/call, resources/read, prompts/get, etc.)
    - Request payloads and arguments (ingress from client)
    - Response timing (egress from proxy)
    - Errors and exceptions
    - Explicit direction field ("ingress" for requests, "egress" for responses)
    - Transport type (stdio or streamablehttp)

    Args:
        log_path: Path to the client wire log file (from config via get_client_log_path()).
        transport: Transport type being used ("stdio" or "streamablehttp").
        debug_enabled: Whether debug wire logging is enabled. If False, logs are discarded.

    Returns:
        BidirectionalClientLoggingMiddleware: Configured middleware for the proxy server.
    """
    if debug_enabled:
        logger = setup_client_wire_logger(log_path)
    else:
        # Create a logger that discards all messages
        logger = logging.getLogger(f"{APP_NAME}.debug.client.null")
        logger.handlers.clear()
        logger.addHandler(logging.NullHandler())
        logger.propagate = False

    return BidirectionalClientLoggingMiddleware(
        logger=logger,
        log_level=logging.INFO,
        include_payloads=True,
        transport=transport,
    )
