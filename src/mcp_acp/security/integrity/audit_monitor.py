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

# Health check constants
_CHAIN_VERIFY_TAIL_COUNT = 10  # Number of recent entries to verify in health check
_READ_CHUNK_SIZE = 4096  # Bytes to read when tailing log files

if TYPE_CHECKING:
    from mcp_acp.security.integrity.integrity_state import IntegrityStateManager
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
        integrity_state_manager: "IntegrityStateManager | None" = None,
        log_dir: Path | None = None,
    ) -> None:
        """Initialize the health monitor.

        Args:
            audit_paths: Paths to audit log files to monitor
            shutdown_coordinator: Coordinator to call on failure
            check_interval_seconds: How often to check (default from constants)
            integrity_state_manager: Optional IntegrityStateManager for chain verification
            log_dir: Base log directory for computing relative file keys
        """
        self.audit_paths = audit_paths
        self.shutdown_coordinator = shutdown_coordinator
        self.check_interval = check_interval_seconds
        self._integrity_manager = integrity_state_manager
        self._log_dir = log_dir

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

            # Verify hash chain integrity of recent entries (if enabled)
            chain_error = self._verify_recent_chain(path, tail_count=_CHAIN_VERIFY_TAIL_COUNT)
            if chain_error:
                return chain_error

            return None  # All checks passed

        except FileNotFoundError:
            return f"Audit log file missing: {path}"
        except PermissionError as e:
            return f"Audit log permission denied: {e}"
        except OSError as e:
            return f"Audit log inaccessible: {e}"

    def _verify_recent_chain(self, path: Path, tail_count: int = _CHAIN_VERIFY_TAIL_COUNT) -> str | None:
        """Verify hash chain integrity of the most recent entries.

        Only checks the last N entries for performance (full verification
        is done at startup and via CLI command).

        Args:
            path: Path to the audit log file
            tail_count: Number of recent entries to verify (default: 10)

        Returns:
            Error message if chain verification fails, None if OK or not enabled.
        """
        # Skip if hash chain not enabled
        if self._integrity_manager is None or self._log_dir is None:
            return None

        # Import here to avoid circular import
        from mcp_acp.security.integrity.hash_chain import verify_chain_from_lines

        # Read last N lines efficiently
        try:
            with path.open("rb") as f:
                # Seek to end
                f.seek(0, 2)
                file_size = f.tell()

                if file_size == 0:
                    return None  # Empty file, nothing to verify

                # Read chunks from end to find last N lines
                # Start with configured chunk size, expand if needed
                chunk_size = min(_READ_CHUNK_SIZE, file_size)
                lines: list[str] = []

                while len(lines) < tail_count:
                    # Calculate position to read from
                    pos = max(0, file_size - chunk_size)
                    f.seek(pos)
                    data = f.read()

                    try:
                        text = data.decode("utf-8")
                    except UnicodeDecodeError:
                        # Skip partial UTF-8 at start of chunk
                        text = data.decode("utf-8", errors="ignore")

                    # Split into lines, handle partial first line
                    if pos > 0:
                        # Discard partial first line
                        parts = text.split("\n", 1)
                        if len(parts) > 1:
                            text = parts[1]

                    lines = [line for line in text.strip().split("\n") if line]

                    # If we've read the whole file, stop
                    if pos == 0:
                        break
                    # Otherwise, double chunk size for next iteration
                    chunk_size = min(chunk_size * 2, file_size)

                # Take only the last tail_count lines
                lines = lines[-tail_count:]

                if not lines:
                    return None  # No entries to verify

                # Verify chain integrity (partial_chain=True since we're only checking tail)
                result = verify_chain_from_lines(lines, partial_chain=True)
                if not result.success:
                    # Return first error
                    error_details = result.errors[0] if result.errors else "unknown error"
                    return f"Hash chain verification failed for {path.name}: {error_details}"

        except (OSError, ValueError) as e:
            # Log but don't fail on verification errors
            _system_logger.warning(
                {
                    "event": "chain_verification_error",
                    "path": str(path),
                    "error": str(e),
                }
            )

        return None  # Verification passed or skipped
