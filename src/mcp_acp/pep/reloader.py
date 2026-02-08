"""Policy hot reload support.

Provides PolicyReloader for reloading policy without proxy restart.
Handles validation, atomic swap, logging, and version tracking.

Triggers:
- SIGHUP signal (Unix)
- API endpoint POST /api/control/reload-policy
- CLI command: mcp-acp policy reload
"""

from __future__ import annotations

__all__ = [
    "PolicyReloader",
    "ReloadResult",
]

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from mcp_acp.utils.policy import load_policy

if TYPE_CHECKING:
    import logging

    from mcp_acp.manager.state import ProxyState
    from mcp_acp.pdp.policy import PolicyConfig
    from mcp_acp.pep.middleware import PolicyEnforcementMiddleware


@dataclass(frozen=True, slots=True)
class ReloadResult:
    """Result of a policy reload attempt.

    Attributes:
        status: "success", "validation_error", or "file_error".
        old_rules_count: Number of rules before reload.
        new_rules_count: Number of rules after reload.
        approvals_cleared: Number of cached approvals that were cleared.
        error: Error message if status is not "success".
        policy_version: New policy version after reload (e.g., "v3").
    """

    status: Literal["success", "validation_error", "file_error"]
    old_rules_count: int = 0
    new_rules_count: int = 0
    approvals_cleared: int = 0
    error: str | None = None
    policy_version: str | None = None


class PolicyReloader:
    """Handles policy hot reload with validation, logging, and state tracking.

    Orchestrates the reload process:
    1. Load and validate new policy from disk
    2. Swap in middleware (atomic)
    3. Log reload event
    4. Track state for status endpoint

    Thread-safe: Uses asyncio for I/O, atomic reference swap for policy.
    """

    def __init__(
        self,
        middleware: "PolicyEnforcementMiddleware",
        system_logger: "logging.Logger",
        policy_path: Path,
        policy_history_path: Path | None = None,
        initial_version: str | None = None,
    ) -> None:
        """Initialize policy reloader.

        Args:
            middleware: The enforcement middleware to reload policy into.
            system_logger: Logger for reload events.
            policy_path: Path to policy.json.
            policy_history_path: Path to policy_history.jsonl for versioning.
            initial_version: Initial policy version (from startup).
        """
        self._middleware = middleware
        self._logger = system_logger
        self._policy_path = policy_path
        self._policy_history_path = policy_history_path

        # State for status endpoint
        self._current_version = initial_version
        self._last_reload_at: datetime | None = None
        self._started_at = datetime.now(timezone.utc)
        self._reload_count = 0

        # Mutex to prevent concurrent reloads from racing
        self._reload_lock = asyncio.Lock()

        # ProxyState for SSE event emission (set via set_proxy_state)
        self._proxy_state: "ProxyState | None" = None

    def set_proxy_state(self, proxy_state: "ProxyState") -> None:
        """Set ProxyState for SSE event emission.

        Args:
            proxy_state: ProxyState instance for broadcasting UI events.
        """
        self._proxy_state = proxy_state

    @property
    def current_version(self) -> str | None:
        """Get current policy version."""
        return self._current_version

    @property
    def current_rules_count(self) -> int:
        """Get current number of policy rules."""
        return self._middleware._engine.rule_count

    @property
    def last_reload_at(self) -> str | None:
        """Get ISO 8601 timestamp of last reload, or None if never reloaded."""
        return self._last_reload_at.isoformat() if self._last_reload_at else None

    @property
    def uptime_seconds(self) -> float:
        """Get seconds since reloader was created (proxy startup)."""
        return (datetime.now(timezone.utc) - self._started_at).total_seconds()

    @property
    def reload_count(self) -> int:
        """Get number of successful reloads since startup."""
        return self._reload_count

    async def reload(self) -> ReloadResult:
        """Reload policy from disk.

        Process:
        1. Load and validate new policy (in thread pool for file I/O)
        2. Swap into middleware (atomic)
        3. Update version and log event
        4. Return result

        On validation failure, the old policy remains active (LKG pattern).
        Uses mutex to prevent concurrent reloads from racing.

        Returns:
            ReloadResult with status, counts, and version info.
        """
        async with self._reload_lock:
            old_count = self.current_rules_count

            # Load policy in thread pool (file I/O)
            try:
                new_policy = await asyncio.to_thread(load_policy, self._policy_path)
            except FileNotFoundError as e:
                error_msg = f"Policy file not found: {self._policy_path}"
                self._log_reload_failed("file_not_found", error_msg)
                self._emit_reload_failed("file_not_found", error_msg)
                return ReloadResult(
                    status="file_error",
                    old_rules_count=old_count,
                    error=error_msg,
                )
            except ValueError as e:
                error_msg = str(e)
                self._log_reload_failed("validation_error", error_msg)
                self._emit_reload_failed("validation_error", error_msg)
                return ReloadResult(
                    status="validation_error",
                    old_rules_count=old_count,
                    error=error_msg,
                )
            except Exception as e:
                error_msg = f"{type(e).__name__}: {e}"
                self._log_reload_failed("unexpected_error", error_msg)
                self._emit_reload_failed("unexpected_error", error_msg)
                return ReloadResult(
                    status="file_error",
                    old_rules_count=old_count,
                    error=error_msg,
                )

            # Get new version (log the reload to history)
            policy_version = await self._get_new_version(new_policy)

            # Perform swap in middleware (pass version for audit logs)
            swap_result = self._middleware.reload_policy(new_policy, policy_version)

            # Update internal state
            self._current_version = policy_version
            self._last_reload_at = datetime.now(timezone.utc)
            self._reload_count += 1

            # Build result
            result = ReloadResult(
                status="success",
                old_rules_count=swap_result["old_rules_count"],
                new_rules_count=swap_result["new_rules_count"],
                approvals_cleared=swap_result["approvals_cleared"],
                policy_version=policy_version,
            )

            # Emit SSE event for UI notification
            self._emit_reload_success(result)

            return result

    async def _get_new_version(self, new_policy: "PolicyConfig") -> str | None:
        """Get new policy version by logging reload to history.

        If policy_history_path is configured, logs the reload event
        and returns the new version. Otherwise returns None.

        Args:
            new_policy: The newly loaded PolicyConfig.

        Returns:
            New version string (e.g., "v3") or None.
        """
        if self._policy_history_path is None:
            return None

        try:
            from mcp_acp.utils.history_logging.policy_logger import log_policy_loaded

            version, _ = await asyncio.to_thread(
                log_policy_loaded,
                self._policy_history_path,
                self._policy_path,
                new_policy.model_dump(),
                component="proxy",
                source="hot_reload",
            )
            return version
        except Exception as e:
            # Non-fatal: version tracking failed but reload can continue
            self._logger.warning(
                {
                    "event": "policy_version_tracking_failed",
                    "error": str(e),
                    "error_type": type(e).__name__,
                }
            )
            return None

    def _log_reload_failed(self, error_type: str, error: str) -> None:
        """Log failed reload to system.jsonl."""
        self._logger.error(
            {
                "event": "policy_reload_failed",
                "error_type": error_type,
                "error": error,
                "policy_path": str(self._policy_path),
            }
        )

    def _emit_reload_success(self, result: ReloadResult) -> None:
        """Emit SSE event for successful reload."""
        if self._proxy_state is None:
            return

        from mcp_acp.manager.events import SSEEventType

        self._proxy_state.emit_system_event(
            SSEEventType.POLICY_RELOADED,
            severity="success",
            message=f"Policy reloaded ({result.new_rules_count} rules)",
            old_rules_count=result.old_rules_count,
            new_rules_count=result.new_rules_count,
            approvals_cleared=result.approvals_cleared,
            policy_version=result.policy_version,
        )

    def _emit_reload_failed(self, error_type: str, error: str) -> None:
        """Emit SSE event for failed reload."""
        if self._proxy_state is None:
            return

        from mcp_acp.manager.events import SSEEventType

        if error_type == "file_not_found":
            event_type = SSEEventType.POLICY_FILE_NOT_FOUND
            message = "Policy file not found - using last known good"
        else:
            event_type = SSEEventType.POLICY_RELOAD_FAILED
            message = "Policy reload failed - using last known good"

        self._proxy_state.emit_system_event(
            event_type,
            severity="error",
            message=message,
            details=error,
            error_type=error_type,
        )
