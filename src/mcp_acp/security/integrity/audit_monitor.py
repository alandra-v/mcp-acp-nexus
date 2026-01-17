"""Background audit health monitoring.

This module provides defense in depth by periodically checking audit log
integrity even when no requests are being processed. This catches issues
like file deletion that happen between requests.

The handler (FailClosedAuditHandler) catches issues at write time.
The monitor catches issues during idle periods.
Together they provide comprehensive detection.
"""

from __future__ import annotations

__all__ = ["AuditHealthMonitor"]

import asyncio
import os
import traceback
from pathlib import Path
from typing import TYPE_CHECKING

from mcp_acp.constants import AUDIT_HEALTH_CHECK_INTERVAL_SECONDS
from mcp_acp.exceptions import AuditFailure
from mcp_acp.telemetry.system.system_logger import get_system_logger

if TYPE_CHECKING:
    from mcp_acp.security.shutdown import ShutdownCoordinator

_system_logger = get_system_logger()


class AuditHealthMonitor:
    """Background monitor for audit log integrity.

    Periodically checks that audit log files:
    - Still exist at original path
    - Have the same device ID and inode (not replaced)
    - Are still writable

    Triggers shutdown via ShutdownCoordinator if any check fails.

    Monitors multiple audit log paths (e.g., operations.jsonl and decisions.jsonl).
    """

    def __init__(
        self,
        audit_paths: list[Path],
        shutdown_coordinator: "ShutdownCoordinator",
        check_interval_seconds: float = AUDIT_HEALTH_CHECK_INTERVAL_SECONDS,
    ) -> None:
        """Initialize the health monitor.

        Args:
            audit_paths: Paths to audit log files to monitor
            shutdown_coordinator: Coordinator to call on failure
            check_interval_seconds: How often to check (default from constants)
        """
        self.audit_paths = audit_paths
        self.shutdown_coordinator = shutdown_coordinator
        self.check_interval = check_interval_seconds

        # Original file identities: {path: (dev, ino)}
        self._original_identities: dict[Path, tuple[int, int]] = {}
        self._running = False
        self._task: asyncio.Task[None] | None = None
        self._crashed = False

    async def start(self) -> None:
        """Start the health monitor background task.

        Records initial file identities and begins periodic checking.
        """
        if self._running:
            return

        # Record initial file identities for all monitored paths
        for path in self.audit_paths:
            stat = path.stat()
            self._original_identities[path] = (stat.st_dev, stat.st_ino)

        self._running = True
        self._task = asyncio.create_task(
            self._monitor_loop(),
            name="audit_health_monitor",
        )

    @property
    def is_healthy(self) -> bool:
        """Check if the monitor is running and hasn't crashed."""
        return self._running and not self._crashed and self._task is not None

    async def stop(self) -> None:
        """Stop the health monitor.

        Cancels the background task and waits for cleanup.
        """
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _monitor_loop(self) -> None:
        """Periodic health check loop.

        Runs until stopped or a failure is detected.
        """
        try:
            while self._running:
                await asyncio.sleep(self.check_interval)

                if not self._running:
                    break

                # Check all monitored paths
                for path in self.audit_paths:
                    failure_reason = self._check_integrity(path)
                    if failure_reason:
                        await self.shutdown_coordinator.initiate_shutdown(
                            failure_type=AuditFailure.failure_type,
                            reason=failure_reason,
                            exit_code=AuditFailure.exit_code,
                            context={"source": "health_monitor", "path": str(path)},
                        )
                        return  # Stop monitoring after initiating shutdown
        except asyncio.CancelledError:
            raise  # Normal shutdown, re-raise
        except Exception as e:
            self._crashed = True
            _system_logger.error(
                {
                    "event": "audit_health_monitor_crashed",
                    "error": str(e),
                    "traceback": traceback.format_exc(),
                }
            )
        finally:
            self._running = False  # Allow restart via start()

    def _check_integrity(self, path: Path) -> str | None:
        """Check audit log integrity for a single path.

        Args:
            path: Path to the audit log file

        Returns:
            Failure reason string, or None if all checks pass.
        """
        original = self._original_identities.get(path)
        if original is None:
            return f"Audit log not registered: {path}"

        original_dev, original_ino = original

        try:
            # Same file (not replaced)? Also catches deleted (FileNotFoundError)
            stat = path.stat()
            if stat.st_dev != original_dev or stat.st_ino != original_ino:
                return f"Audit log file replaced: {path}"

            # Actually verify we can write (catches disk full, permission changes)
            with path.open("a") as f:
                f.write("")  # Empty write to verify access
                f.flush()
                os.fsync(f.fileno())  # Ensure we can persist to disk

            return None  # All checks passed

        except FileNotFoundError:
            return f"Audit log file missing: {path}"
        except PermissionError as e:
            return f"Audit log permission denied: {e}"
        except OSError as e:
            return f"Audit log inaccessible: {e}"
