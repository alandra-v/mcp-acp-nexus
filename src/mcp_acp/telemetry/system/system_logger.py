"""System logger for operational events.

This module provides a singleton system logger for logging all operational events
that aren't part of the audit trail (e.g., metadata extraction failures, backend
disconnections, initialization logging failures).

Logging strategy:
- Console (stderr): ALL operational messages (INFO, WARNING, ERROR, CRITICAL)
- File (system.jsonl): Only issues (WARNING, ERROR, CRITICAL) - no INFO to save disk space

The file handler is configured separately via configure_system_logger_file() once
the user's log_dir from config is available.
"""

from __future__ import annotations

__all__ = [
    "ConsoleFormatter",
    "configure_system_logger_file",
    "get_system_logger",
    "is_transport_error",
    "log_backend_disconnect",
]

import logging
import sys
from pathlib import Path

from mcp_acp.constants import TRANSPORT_ERRORS
from mcp_acp.utils.logging.iso_formatter import ISO8601Formatter
from mcp_acp.utils.logging.logging_helpers import clean_backend_error

# String indicators for error message matching (fallback detection)
# Based on actual FastMCP, anyio, and httpx error messages
TRANSPORT_ERROR_INDICATORS: tuple[str, ...] = (
    # FastMCP client errors (client.py)
    "server session was closed unexpectedly",
    "failed to initialize server session",
    "client failed to connect",
    # anyio socket errors (_sockets.py)
    "all connection attempts failed",
    # STDIO transport errors
    "broken pipe",
    "eof",
    # httpx transport errors
    "connection refused",
    "connection reset",
    "connection closed",
    "remote disconnected",
)


class ConsoleFormatter(logging.Formatter):
    """Human-readable formatter for console output.

    Extracts 'message' or 'event' field from dict messages for cleaner stderr output.
    """

    def format(self, record: logging.LogRecord) -> str:
        """Format log record for human-readable console output.

        Args:
            record: The log record to format.

        Returns:
            str: Formatted log message with level prefix.
        """
        if isinstance(record.msg, dict):
            # Extract message or event field for human-readable output
            msg = record.msg.get("message") or record.msg.get("event", "")
            return f"{record.levelname}: {msg}"
        return f"{record.levelname}: {record.msg}"


# Module-level singleton logger - initialized once at import
_system_logger: logging.Logger | None = None
_file_handler_configured: bool = False


def get_system_logger() -> logging.Logger:
    """Get the singleton system logger instance.

    Creates the logger on first call with stderr handler only.
    File handler is added later via configure_system_logger_file().

    Logging destinations:
    - stderr (console): INFO, WARNING, ERROR, CRITICAL (operator sees everything)
    - File: Added via configure_system_logger_file() - WARNING, ERROR, CRITICAL only

    Returns:
        logging.Logger: Configured system logger instance.

    Example:
        >>> from mcp_acp.telemetry.system.system_logger import get_system_logger
        >>> logger = get_system_logger()
        >>> logger.warning({"event": "metadata_extraction_failed", "error": "..."})
        # Logged to stderr (and file if configured)
    """
    global _system_logger

    # Return existing logger if already created
    if _system_logger is not None:
        return _system_logger

    # Create base logger at INFO level (accepts INFO and above)
    _system_logger = logging.getLogger("mcp-acp-nexus.system")
    _system_logger.setLevel(logging.INFO)
    _system_logger.propagate = False  # Don't propagate to root logger

    # Remove any existing handlers to avoid duplicates
    _system_logger.handlers.clear()

    # Handler: stderr - INFO and above (operator sees everything)
    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setLevel(logging.INFO)  # Console: INFO, WARNING, ERROR, CRITICAL
    stderr_handler.setFormatter(ConsoleFormatter())
    _system_logger.addHandler(stderr_handler)

    return _system_logger


def configure_system_logger_file(log_path: Path) -> None:
    """Configure the system logger's file handler with the user's log path.

    Should be called once after config is loaded, before creating debug loggers.
    The file handler logs WARNING, ERROR, CRITICAL only (persistent issues).

    Args:
        log_path: Path to the system log file (from config via get_system_log_path()).

    Example:
        >>> from mcp_acp.utils.config import get_system_log_path
        >>> configure_system_logger_file(get_system_log_path(config))
    """
    global _file_handler_configured

    # Only configure once
    if _file_handler_configured:
        return

    logger = get_system_logger()

    # Ensure log directory exists with secure permissions
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        # Set owner-only permissions (0o700) - skip on Windows
        if sys.platform != "win32":
            try:
                log_path.parent.chmod(0o700)
            except OSError:
                pass  # Permission changes might fail on some systems
    except (PermissionError, OSError):
        pass  # If we can't create log dir, stderr will still work

    # Add file handler - WARNING and above (persistent issues only)
    file_handler = logging.FileHandler(log_path, mode="a", encoding="utf-8")
    file_handler.setLevel(logging.WARNING)  # File: only WARNING, ERROR, CRITICAL
    file_handler.setFormatter(ISO8601Formatter())
    logger.addHandler(file_handler)

    _file_handler_configured = True


# ============================================================================
# Backend Disconnect Detection
# ============================================================================


def is_transport_error(exc: Exception) -> bool:
    """Check if exception indicates backend disconnection.

    Args:
        exc: Exception to check.

    Returns:
        True if exception indicates transport/connection failure.
    """
    if isinstance(exc, TRANSPORT_ERRORS):
        return True

    error_msg = str(exc).lower()
    return any(indicator in error_msg for indicator in TRANSPORT_ERROR_INDICATORS)


def log_backend_disconnect(
    transport: str,
    exc: Exception,
    failed_method: str,
    session_id: str | None,
) -> None:
    """Log backend disconnection event to system.jsonl.

    Args:
        transport: Transport type ("stdio" or "streamablehttp").
        exc: Exception that caused the disconnection.
        failed_method: Method that failed due to disconnect.
        session_id: Current session ID if available.
    """
    # Transport-aware message
    if transport == "stdio":
        message = "Backend process terminated unexpectedly - connection lost"
    else:
        message = "Backend server disconnected - HTTP connection lost"

    get_system_logger().critical(
        {
            "event": "backend_disconnected",
            "transport": transport,
            "error": clean_backend_error(str(exc)),
            "error_type": type(exc).__name__,
            "failed_operation": failed_method,
            "session_id": session_id,
            "message": message,
        }
    )
