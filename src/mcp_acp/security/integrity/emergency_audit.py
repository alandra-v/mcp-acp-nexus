"""Emergency audit logging for critical failures.

This module provides a fallback logging mechanism when primary audit logs
are compromised.

Files using this fallback chain:
- operations.jsonl (operation audit)
- decisions.jsonl (decision audit)
- auth.jsonl (auth events)
- config_history.jsonl (config changes)
- policy_history.jsonl (policy changes)

Fallback chain:
1. Primary audit log (the file being written to)
2. system.jsonl (same log_dir)
3. emergency_audit.jsonl (config directory - survives log_dir deletion)

After logging to any fallback, the proxy MUST shutdown because the primary
audit trail is compromised.
"""

from __future__ import annotations

__all__ = [
    "get_emergency_audit_path",
    "log_with_fallback",
    "write_emergency_audit",
]

import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def get_emergency_audit_path() -> Path:
    """Get path to emergency audit log in config directory.

    This file lives in the config directory (not log_dir) so it survives
    deletion of the log directory.

    Returns:
        Path to emergency_audit.jsonl in config directory.
    """
    # Lazy import to avoid circular dependency
    from mcp_acp.utils.config import get_config_dir

    return get_config_dir() / "emergency_audit.jsonl"


def write_emergency_audit(
    event_type: str,
    operation: dict[str, Any],
    failure_reason: str,
    source_file: str,
) -> bool:
    """Write an audit event to the emergency audit log.

    This is the last resort when both primary audit and system.jsonl fail.
    Uses direct file I/O to minimize dependencies.

    Args:
        event_type: Type of event ("operation" or "decision").
        operation: The operation/decision data that couldn't be logged.
        failure_reason: Why primary logging failed.
        source_file: Which audit file failed (e.g., "operations.jsonl").

    Returns:
        True if write succeeded, False otherwise.
    """
    try:
        path = get_emergency_audit_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        # Set owner-only permissions (0o700) - skip on Windows
        if sys.platform != "win32":
            try:
                path.parent.chmod(0o700)
            except OSError:
                pass  # Permission changes might fail on some systems

        entry: dict[str, Any] = {
            "time": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "event": "emergency_audit",
            "event_type": event_type,
            "failure_reason": failure_reason,
            "source_file": source_file,
            "operation": operation,
        }

        # Extract proxy info from operation for attribution (top-level for easy access)
        # proxy_id: stable identifier for correlation/logic
        # proxy_name: human-readable name for display
        if operation.get("proxy_id"):
            entry["proxy_id"] = operation["proxy_id"]
        if operation.get("proxy_name"):
            entry["proxy_name"] = operation["proxy_name"]

        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, default=str) + "\n")
            f.flush()
            os.fsync(f.fileno())

        return True
    except Exception:
        return False


def log_with_fallback(
    primary_logger: logging.Logger,
    system_logger: logging.Logger,
    event_data: dict[str, Any],
    event_type: str,
    source_file: str,
    proxy_id: str | None = None,
    proxy_name: str | None = None,
) -> tuple[bool, str | None]:
    """Log an event with fallback chain.

    Tries primary logger first, then system.jsonl, then emergency_audit.jsonl.

    Args:
        primary_logger: The primary audit logger (for operations/decisions).
        system_logger: The system logger (system.jsonl).
        event_data: The event data to log.
        event_type: Type of event ("operation" or "decision").
        source_file: Name of the primary log file.
        proxy_id: Stable proxy identifier (for emergency audit attribution).
        proxy_name: Human-readable proxy name (for emergency audit attribution).

    Returns:
        Tuple of (success, failure_reason).
        - success: True if logged to primary, False if fallback was used.
        - failure_reason: None if primary succeeded, otherwise describes failure.
    """
    failure_reason: str | None = None

    # Try primary logger
    try:
        primary_logger.info(event_data)

        # Check if handler detected compromise (for FailClosedAuditHandler)
        # Note: handlers may not exist on mock loggers in tests
        handlers = getattr(primary_logger, "handlers", [])
        for handler in handlers:
            if getattr(handler, "is_compromised", False):
                raise RuntimeError("Audit log compromised")

        return True, None  # Primary succeeded
    except Exception as e:
        failure_reason = str(e)

    # Primary failed - try system.jsonl
    # Note: Standard FileHandler doesn't raise on missing file, so verify it exists
    try:
        # Find system log file path from handler
        system_log_path = None
        for handler in getattr(system_logger, "handlers", []):
            if hasattr(handler, "baseFilename"):
                system_log_path = Path(handler.baseFilename)
                break

        # If file doesn't exist, skip to emergency fallback
        if system_log_path is None or not system_log_path.exists():
            raise RuntimeError("System log file not available")

        system_logger.critical(
            {
                "event": "audit_fallback",
                "message": f"Primary audit log failed: {failure_reason}",
                "source_file": source_file,
                "operation": event_data,
            }
        )
        return False, failure_reason  # Fallback succeeded
    except Exception:
        pass  # system.jsonl also failed

    # Both failed - try emergency_audit.jsonl
    # Add proxy attribution for the emergency audit entry
    operation_with_proxy = {**event_data}
    if proxy_id:
        operation_with_proxy["proxy_id"] = proxy_id
    if proxy_name:
        operation_with_proxy["proxy_name"] = proxy_name
    write_emergency_audit(
        event_type=event_type,
        operation=operation_with_proxy,
        failure_reason=failure_reason or "Unknown error",
        source_file=source_file,
    )

    return False, failure_reason
