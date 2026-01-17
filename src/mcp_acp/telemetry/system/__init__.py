"""System operational logging.

Provides system logger for operational events that aren't part of the audit trail
(e.g., metadata extraction failures, backend disconnections, startup events).
"""

from mcp_acp.telemetry.system.system_logger import (
    ConsoleFormatter,
    configure_system_logger_file,
    get_system_logger,
    is_transport_error,
    log_backend_disconnect,
)

__all__ = [
    "ConsoleFormatter",
    "configure_system_logger_file",
    "get_system_logger",
    "is_transport_error",
    "log_backend_disconnect",
]
