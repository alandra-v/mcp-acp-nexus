"""Logger setup utilities for creating JSONL loggers.

This module provides generic setup functions for creating loggers that write
JSONL with ISO 8601 timestamps to specified file paths.

Provides two types of loggers:
- setup_jsonl_logger: Standard logger for non-critical logs
- setup_failclosed_audit_logger: Security-critical logger that triggers
  shutdown if audit log integrity is compromised

When an IntegrityStateManager is provided, loggers use HashChainFormatter
for tamper-evident logging with hash chains.
"""

from __future__ import annotations

__all__ = [
    "setup_failclosed_audit_logger",
    "setup_jsonl_logger",
]

import logging
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Callable

from mcp_acp.security.integrity.audit_handler import FailClosedAuditHandler
from mcp_acp.utils.logging.iso_formatter import ISO8601Formatter

if TYPE_CHECKING:
    from mcp_acp.security.integrity.integrity_state import IntegrityStateManager


def _ensure_secure_log_directory(log_file: Path) -> None:
    """Create log directory with secure permissions.

    Args:
        log_file: Path to the log file (parent directory will be created).

    Raises:
        PermissionError: If unable to create log directory due to permissions.
        OSError: If directory creation fails for other reasons.
    """
    try:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        # Set owner-only permissions (0o700) - skip on Windows
        if sys.platform != "win32":
            try:
                log_file.parent.chmod(0o700)
            except OSError:
                pass  # Permission changes might fail on some systems
    except PermissionError as e:
        raise PermissionError(f"Cannot create log directory {log_file.parent}: {e}") from e
    except OSError as e:
        raise OSError(f"Failed to create log directory {log_file.parent}: {e}") from e


def setup_jsonl_logger(
    logger_name: str,
    log_file: Path,
    log_level: int = logging.INFO,
) -> logging.Logger:
    """Set up a logger that writes JSONL with ISO 8601 timestamps.

    Creates log directory if it doesn't exist with secure permissions (owner-only: 700).

    Args:
        logger_name: Name for the logger (e.g., "mcp-acp.audit.client")
        log_file: Path to the log file
        log_level: Logging level (default: INFO)

    Returns:
        logging.Logger: Configured logger instance

    Raises:
        PermissionError: If unable to create log directory due to permissions
        OSError: If directory creation fails for other reasons
    """
    _ensure_secure_log_directory(log_file)

    # Create logger
    logger = logging.getLogger(logger_name)
    logger.setLevel(log_level)
    logger.propagate = False  # Don't propagate to root logger

    # Close and remove any existing handlers to avoid duplicates and resource leaks
    for handler in logger.handlers:
        handler.close()
    logger.handlers.clear()

    # Create file handler that writes to the log file
    file_handler = logging.FileHandler(log_file, mode="a", encoding="utf-8")
    file_handler.setLevel(log_level)

    # Add ISO 8601 formatter
    formatter = ISO8601Formatter()
    file_handler.setFormatter(formatter)

    logger.addHandler(file_handler)

    return logger


def setup_failclosed_audit_logger(
    logger_name: str,
    log_file: Path,
    shutdown_callback: Callable[[str], None],
    log_level: int = logging.INFO,
    state_manager: "IntegrityStateManager | None" = None,
    log_dir: Path | None = None,
) -> logging.Logger:
    """Set up an audit logger that triggers shutdown if log integrity is compromised.

    Unlike setup_jsonl_logger which uses a standard FileHandler, this function
    uses FailClosedAuditHandler which verifies file integrity before each write.
    If the audit log is deleted, replaced, or becomes unwritable, the callback
    is invoked to initiate shutdown.

    When state_manager is provided, uses HashChainFormatter for tamper-evident
    logging. Each entry includes sequence number, previous entry hash, and
    current entry hash for chain verification.

    Args:
        logger_name: Name for the logger (e.g., "mcp-acp.audit.operations")
        log_file: Path to the log file
        shutdown_callback: Called with reason string if integrity check fails.
                           This callback must handle the sync-to-async transition.
        log_level: Logging level (default: INFO)
        state_manager: Optional IntegrityStateManager for hash chain support.
                       When provided, log_dir must also be provided.
        log_dir: Base log directory for computing relative file keys.
                 Required when state_manager is provided.

    Returns:
        Configured logger instance with fail-closed handler

    Raises:
        PermissionError: If unable to create log directory due to permissions
        OSError: If directory creation or file open fails
        ValueError: If state_manager is provided without log_dir
    """
    _ensure_secure_log_directory(log_file)

    # Validate state_manager requires log_dir
    if state_manager is not None and log_dir is None:
        raise ValueError("log_dir is required when state_manager is provided")

    # Create logger
    logger = logging.getLogger(logger_name)
    logger.setLevel(log_level)
    logger.propagate = False
    # Close existing handlers before clearing to avoid resource leaks
    for handler in logger.handlers:
        handler.close()
    logger.handlers.clear()

    # Create fail-closed file handler
    file_handler = FailClosedAuditHandler(
        str(log_file),
        shutdown_callback=shutdown_callback,
        mode="a",
        encoding="utf-8",
    )
    file_handler.setLevel(log_level)

    # Use HashChainFormatter when state_manager is provided
    formatter: logging.Formatter
    if state_manager is not None and log_dir is not None:
        from mcp_acp.security.integrity.hash_chain import HashChainFormatter

        # Compute relative file key
        try:
            file_key = str(log_file.relative_to(log_dir))
        except ValueError:
            # Path is not under log_dir - use filename
            file_key = log_file.name

        formatter = HashChainFormatter(
            state_manager=state_manager,
            log_file_key=file_key,
            log_path=log_file,
        )
    else:
        formatter = ISO8601Formatter()

    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    # Set secure file permissions (owner read/write only)
    # This is critical for audit logs containing sensitive auth data
    if sys.platform != "win32":
        try:
            log_file.chmod(0o600)
        except OSError:
            pass  # Permission changes might fail on some systems

    return logger
