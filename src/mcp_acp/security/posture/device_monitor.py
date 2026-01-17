"""Periodic device health monitoring for Zero Trust compliance.

Device posture can change during proxy operation (e.g., user disables SIP).
This monitor periodically re-checks device health and triggers shutdown
if the device becomes non-compliant.

Complements startup checks:
- Startup: Hard gate, proxy won't start if unhealthy
- Monitor: Periodic re-verification, proxy shuts down if device becomes unhealthy

Design decisions:
- Check interval: 5 minutes (balance between responsiveness and overhead)
- Zero Trust: First failure triggers shutdown (device posture is stable)
- Logging: Results logged to auth.jsonl for audit trail
"""

from __future__ import annotations

__all__ = ["DeviceHealthMonitor"]

import asyncio
import traceback
from typing import TYPE_CHECKING

from mcp_acp.constants import (
    DEFAULT_DEVICE_FAILURE_THRESHOLD,
    DEVICE_HEALTH_CHECK_INTERVAL_SECONDS,
)
from mcp_acp.exceptions import DeviceHealthError
from mcp_acp.security.posture.device import DeviceHealthReport, check_device_health
from mcp_acp.telemetry.models.audit import DeviceHealthChecks
from mcp_acp.telemetry.system.system_logger import get_system_logger

if TYPE_CHECKING:
    from mcp_acp.security.shutdown import ShutdownCoordinator
    from mcp_acp.telemetry.audit.auth_logger import AuthLogger

_system_logger = get_system_logger()


class DeviceHealthMonitor:
    """Background monitor for device health.

    Periodically runs device health checks and triggers shutdown
    if the device becomes non-compliant.

    Zero Trust behavior: Fails fast on first health check failure.
    Device posture (FileVault, SIP) is stable - transient failures are rare.
    """

    def __init__(
        self,
        shutdown_coordinator: "ShutdownCoordinator",
        auth_logger: "AuthLogger | None" = None,
        check_interval_seconds: float = DEVICE_HEALTH_CHECK_INTERVAL_SECONDS,
        failure_threshold: int = DEFAULT_DEVICE_FAILURE_THRESHOLD,
    ) -> None:
        """Initialize the device health monitor.

        Args:
            shutdown_coordinator: Coordinator to call on failure.
            auth_logger: Optional logger for auth.jsonl audit trail.
            check_interval_seconds: How often to check (default 5 min).
            failure_threshold: Consecutive failures before shutdown (default 1).
        """
        self.shutdown_coordinator = shutdown_coordinator
        self.auth_logger = auth_logger
        self.check_interval = check_interval_seconds
        self.failure_threshold = failure_threshold

        self._running = False
        self._task: asyncio.Task[None] | None = None
        self._crashed = False
        self._consecutive_failures = 0
        self._last_report: DeviceHealthReport | None = None

    async def start(self) -> None:
        """Start the device health monitor background task."""
        if self._running:
            return

        self._running = True
        self._consecutive_failures = 0
        self._task = asyncio.create_task(
            self._monitor_loop(),
            name="device_health_monitor",
        )

    @property
    def is_healthy(self) -> bool:
        """Check if the monitor is running and hasn't crashed."""
        return self._running and not self._crashed and self._task is not None

    @property
    def last_report(self) -> DeviceHealthReport | None:
        """Most recent health check result."""
        return self._last_report

    async def stop(self) -> None:
        """Stop the device health monitor."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _monitor_loop(self) -> None:
        """Periodic health check loop."""
        try:
            while self._running:
                await asyncio.sleep(self.check_interval)

                if not self._running:
                    break

                # Run check in thread pool (subprocess is blocking)
                report = await asyncio.to_thread(check_device_health)
                self._last_report = report

                if report.is_healthy:
                    # Reset failure counter on success
                    self._consecutive_failures = 0
                else:
                    self._consecutive_failures += 1
                    self._log_check_failed(report)

                    if self._consecutive_failures >= self.failure_threshold:
                        await self._trigger_shutdown(report)
                        return

        except asyncio.CancelledError:
            raise  # Normal shutdown
        except Exception as e:
            self._crashed = True
            _system_logger.error(
                {
                    "event": "device_health_monitor_crashed",
                    "error": str(e),
                    "traceback": traceback.format_exc(),
                }
            )
        finally:
            self._running = False

    def _log_check_failed(self, report: DeviceHealthReport) -> None:
        """Log failed health check."""
        _system_logger.warning(
            {
                "event": "device_health_check_failed",
                "report": report.to_dict(),
                "consecutive_failures": self._consecutive_failures,
                "threshold": self.failure_threshold,
            }
        )
        if self.auth_logger:
            self.auth_logger.log_device_health_failed(
                device_checks=DeviceHealthChecks(
                    disk_encryption=report.disk_encryption,
                    device_integrity=report.device_integrity,
                ),
                error_message="; ".join(report.errors) if report.errors else None,
            )

    async def _trigger_shutdown(self, report: DeviceHealthReport) -> None:
        """Trigger proxy shutdown due to device health failure."""
        reason = f"Device health check failed {self.failure_threshold} times: {report.errors}"
        _system_logger.error(
            {
                "event": "device_health_shutdown",
                "reason": reason,
                "report": report.to_dict(),
            }
        )
        await self.shutdown_coordinator.initiate_shutdown(
            failure_type=DeviceHealthError.failure_type,
            reason=reason,
            exit_code=DeviceHealthError.exit_code,
            context={"source": "device_health_monitor", "report": report.to_dict()},
        )
