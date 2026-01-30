"""Daemon logging configuration.

Owns the manager logger configuration (handlers, formatters).
Other daemon modules get their own logger reference via:
    _logger = logging.getLogger(f"{APP_NAME}.manager")

Python loggers are singletons by name, so all modules share the same
logger instance. This module owns the configuration; others just call
log_event().
"""

from __future__ import annotations

__all__ = [
    "configure_manager_logging",
    "log_event",
]

import logging

from mcp_acp.constants import APP_NAME
from mcp_acp.manager.config import ManagerConfig, get_manager_system_log_path
from mcp_acp.manager.models import ManagerSystemEvent
from mcp_acp.utils.logging.iso_formatter import ISO8601Formatter

# Get module logger - initially with stderr only
# File handler added via configure_manager_logging() after config is loaded
_logger = logging.getLogger(f"{APP_NAME}.manager")
_logger.setLevel(logging.INFO)
_logger.propagate = False

# Track if file logging has been configured
_file_handler_configured: bool = False


class _ConsoleFormatter(logging.Formatter):
    """Human-readable formatter for console output."""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record for console output."""
        if isinstance(record.msg, dict):
            msg = record.msg.get("message") or record.msg.get("event", "")
            return f"{record.levelname}: {msg}"
        # Use getMessage() to substitute %s placeholders with args
        return f"{record.levelname}: {record.getMessage()}"


# Initialize with stderr-only until config is loaded
if not _logger.handlers:
    _stderr_handler = logging.StreamHandler()
    _stderr_handler.setFormatter(_ConsoleFormatter())
    _logger.addHandler(_stderr_handler)


def configure_manager_logging(config: ManagerConfig) -> None:
    """Configure manager logging with file handler.

    Sets up:
    - stderr handler: INFO+ for operator visibility (foreground mode)
    - file handler: WARNING+ only (errors and issues worth reviewing)

    Args:
        config: Manager configuration with log directory.
    """
    global _file_handler_configured

    if _file_handler_configured:
        return

    # Close and clear any existing handlers to avoid resource leaks
    for handler in _logger.handlers:
        handler.close()
    _logger.handlers.clear()

    # Add stderr handler (INFO+)
    stderr_handler = logging.StreamHandler()
    stderr_handler.setLevel(logging.INFO)
    stderr_handler.setFormatter(_ConsoleFormatter())
    _logger.addHandler(stderr_handler)

    # Add file handler (WARNING+ only - no operational noise in persistent logs)
    log_path = get_manager_system_log_path(config)
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.parent.chmod(0o700)
    except OSError:
        pass  # stderr will still work

    try:
        file_handler = logging.FileHandler(log_path, mode="a", encoding="utf-8")
        file_handler.setLevel(logging.WARNING)
        file_handler.setFormatter(ISO8601Formatter())
        _logger.addHandler(file_handler)
        _file_handler_configured = True
    except OSError as e:
        log_event(
            logging.WARNING,
            ManagerSystemEvent(
                event="file_logging_failed",
                message="Failed to configure file logging",
                error_type=type(e).__name__,
                error_message=str(e),
            ),
        )


def log_event(level: int, event: ManagerSystemEvent) -> None:
    """Log a ManagerSystemEvent at the specified level.

    Serializes the event to a dict (excluding None values) and logs it.
    The ISO8601Formatter adds the timestamp during serialization.

    Args:
        level: Logging level (e.g., logging.INFO, logging.WARNING).
        event: The event to log.
    """
    _logger.log(level, event.model_dump(exclude_none=True))
