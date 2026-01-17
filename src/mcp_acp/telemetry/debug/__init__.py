"""Debug wire-level logging for MCP communication.

Provides middleware and clients for wire-level debugging of:
- Client↔Proxy communication (client_wire.jsonl)
- Proxy↔Backend communication (backend_wire.jsonl)
"""

from mcp_acp.telemetry.debug.backend_logger import (
    log_backend_error,
    log_backend_response,
    log_proxy_request,
    setup_backend_wire_logger,
)
from mcp_acp.telemetry.debug.client_logger import (
    BidirectionalClientLoggingMiddleware,
    create_client_logging_middleware,
    setup_client_wire_logger,
)
from mcp_acp.telemetry.debug.logging_proxy_client import (
    LoggingProxyClient,
    create_logging_proxy_client,
)

__all__ = [
    # Client logging
    "BidirectionalClientLoggingMiddleware",
    "create_client_logging_middleware",
    "setup_client_wire_logger",
    # Backend logging
    "LoggingProxyClient",
    "create_logging_proxy_client",
    "log_backend_error",
    "log_backend_response",
    "log_proxy_request",
    "setup_backend_wire_logger",
]
