"""Fail-closed audit log handler and verification utilities.

This module provides:
- A logging handler that detects audit log compromise and triggers shutdown
- Startup verification to ensure audit logs are writable

The Problem:
  On Unix, when a file is deleted while open, the file descriptor remains
  valid. Writes succeed but go to a "ghost" inode with no directory entry.
  When the process exits, those writes are permanently lost.

The Solution:
  Before each write, compare the current file's device ID and inode number
  to the original values. If they differ, the file was deleted or replaced.
"""

from __future__ import annotations

__all__ = [
    "FailClosedAuditHandler",
    "verify_audit_writable",
]

import json
import logging
import os
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from mcp_acp.exceptions import AuditFailure


class FailClosedAuditHandler(logging.FileHandler):
    """Audit handler that detects file deletion and fails closed.

    Detection covers:
    - File deletion (FileNotFoundError on stat)
    - File replacement (inode change)
    - File moved and recreated (inode change)
    - Permission changes (OSError)
    - Write failures (disk full, etc.)

    When integrity is compromised, calls the shutdown callback with a
    reason string. The handler will not attempt further writes after
    shutdown is triggered.
    """

    def __init__(
        self,
        filename: str,
        shutdown_callback: Callable[[str], None],
        mode: str = "a",
        encoding: str = "utf-8",
    ) -> None:
        """Initialize the fail-closed handler.

        Args:
            filename: Path to the audit log file
            shutdown_callback: Called with reason string when integrity fails.
                               Must handle sync-to-async transition if needed.
            mode: File open mode (should be "a" for append)
            encoding: File encoding
        """
        super().__init__(filename, mode=mode, encoding=encoding)
        self._shutdown_callback = shutdown_callback
        self._shutdown_triggered = False

        # Record original file identity (device + inode)
        # This is how we detect if the file was replaced
        stat = os.fstat(self.stream.fileno())
        self._original_dev = stat.st_dev
        self._original_ino = stat.st_ino

    @property
    def is_compromised(self) -> bool:
        """Check if audit log integrity has been compromised."""
        return self._shutdown_triggered

    def emit(self, record: logging.LogRecord) -> None:
        """Emit a record after verifying file integrity.

        Before each write:
        1. Check file still exists at original path
        2. Verify it's the same file (same device + inode)
        3. If checks pass, write the record
        4. If any check fails, trigger shutdown

        Args:
            record: The log record to write
        """
        if self._shutdown_triggered:
            # Already shutting down - skip logging
            print("[AUDIT] Skipping log - shutdown in progress", file=sys.stderr, flush=True)
            return

        # Verify file still exists and is the same file
        try:
            stat = os.stat(self.baseFilename)
            if stat.st_dev != self._original_dev or stat.st_ino != self._original_ino:
                self._trigger_shutdown(f"Audit log file replaced or moved: {self.baseFilename}")
                return
        except FileNotFoundError:
            # Build comprehensive report of what's missing (all critical logs, not debug)
            missing = []
            file_path = Path(self.baseFilename)
            log_root = file_path.parent.parent  # e.g., mcp-acp/proxies/default/

            # Critical directories and their files
            critical_paths = {
                "audit": ["operations.jsonl", "decisions.jsonl"],
                "system": ["system.jsonl", "config_history.jsonl", "policy_history.jsonl"],
            }

            for dir_name, files in critical_paths.items():
                dir_path = log_root / dir_name
                if not dir_path.exists():
                    missing.append(f"{dir_name}/")
                else:
                    for filename in files:
                        if not (dir_path / filename).exists():
                            missing.append(f"{dir_name}/{filename}")

            if missing:
                self._trigger_shutdown(f"Audit log compromised - missing: {', '.join(missing)}")
            else:
                self._trigger_shutdown(f"Audit log file deleted: {self.baseFilename}")
            return
        except OSError as e:
            self._trigger_shutdown(f"Audit log file inaccessible: {e}")
            return

        # File integrity verified, proceed with write
        try:
            super().emit(record)
        except Exception as e:
            self._trigger_shutdown(f"Audit log write failed: {e}")

    def _trigger_shutdown(self, reason: str) -> None:
        """Trigger shutdown via callback and delayed exit.

        Uses a background thread to delay exit by 500ms, allowing the
        current request's response to be sent to the client before
        the process terminates.

        Args:
            reason: Human-readable reason for shutdown
        """
        if not self._shutdown_triggered:
            self._shutdown_triggered = True

            # Call callback for logging/breadcrumb (best effort)
            try:
                self._shutdown_callback(reason)
            except Exception:
                pass

            # Schedule exit in background thread (allows response to be sent first)
            def delayed_exit() -> None:
                time.sleep(0.5)  # 500ms for response to flush
                os._exit(10)

            thread = threading.Thread(target=delayed_exit, daemon=False)
            thread.start()


def verify_audit_writable(audit_path: Path) -> None:
    """Verify audit log is writable at startup.

    Called before starting the proxy to ensure we can write audit logs.
    If this fails, the proxy should not start.

    Args:
        audit_path: Path to the audit log file (e.g., operations.jsonl)

    Raises:
        AuditFailure: If audit log cannot be written
    """
    # Ensure directory exists with secure permissions
    try:
        audit_path.parent.mkdir(parents=True, exist_ok=True)
        audit_path.parent.chmod(0o700)
    except PermissionError as e:
        raise AuditFailure(f"Cannot create audit log directory: {e}") from e
    except OSError as e:
        raise AuditFailure(f"Failed to create audit log directory: {e}") from e

    # Verify we can write to the file (empty write to test permissions)
    try:
        with audit_path.open("a", encoding="utf-8") as f:
            f.write("")  # Empty write to verify access
            f.flush()
            os.fsync(f.fileno())  # Ensure we can persist to disk
    except PermissionError as e:
        raise AuditFailure(f"Audit log not writable (permission denied): {e}") from e
    except OSError as e:
        raise AuditFailure(f"Audit log not writable: {e}") from e

    # Always set secure file permissions (owner read/write only)
    # This fixes permissions on existing files and sets them on new files
    try:
        audit_path.chmod(0o600)
    except OSError as e:
        raise AuditFailure(f"Cannot set secure permissions on audit log: {e}") from e
