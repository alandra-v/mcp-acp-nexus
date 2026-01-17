"""Graceful shutdown coordinator for critical security failures.

This module provides coordinated shutdown when security invariants are violated.
It ensures:
- Client receives clean error before disconnect
- Failure is logged to multiple destinations (defense in depth)
- Process terminates with correct exit code
- New requests are rejected during shutdown window
"""

from __future__ import annotations

__all__ = [
    "ShutdownCoordinator",
    "sync_emergency_shutdown",
]

import asyncio
import json
import os
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import logging

    from mcp_acp.manager.state import ProxyState
    from mcp_acp.telemetry.audit.auth_logger import AuthLogger

# Secure file permissions (defined inline to avoid circular imports)
_DIR_PERMISSIONS = 0o700  # Owner rwx only
_FILE_PERMISSIONS = 0o600  # Owner rw only


def _set_secure_permissions(path: Path, *, is_directory: bool = False) -> None:
    """Set secure permissions on file or directory.

    Inline version to avoid circular imports with file_helpers.
    Does nothing on Windows. Silently ignores permission errors.

    Args:
        path: Path to file or directory.
        is_directory: If True, use directory permissions (0o700).
    """
    if sys.platform == "win32":
        return
    try:
        mode = _DIR_PERMISSIONS if is_directory else _FILE_PERMISSIONS
        path.chmod(mode)
    except OSError:
        pass  # Permission changes might fail on some systems


def _write_shutdown_log(
    log_dir: Path,
    failure_type: str,
    reason: str,
    exit_code: int,
    context: dict[str, Any] | None = None,
) -> bool:
    """Write shutdown event to shutdowns.jsonl.

    Uses direct file I/O (not logging module) because:
    1. Shutdown happens when logging might be compromised
    2. Minimal dependencies for reliability
    3. One-time write, not continuous logging

    Note: Uses broad exception handling intentionally - this is best-effort
    logging during shutdown where we must not raise exceptions.

    Args:
        log_dir: Log directory containing shutdowns.jsonl.
        failure_type: Category of failure (e.g., "audit_failure").
        reason: Human-readable description of the failure.
        exit_code: Process exit code (10=audit, 11=policy, 12=identity).
        context: Additional context for the failure.

    Returns:
        True if write succeeded, False otherwise.
    """
    try:
        shutdowns_path = log_dir / "shutdowns.jsonl"
        shutdowns_path.parent.mkdir(parents=True, exist_ok=True)
        _set_secure_permissions(shutdowns_path.parent, is_directory=True)

        entry = {
            "time": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "event": "security_shutdown",
            "failure_type": failure_type,
            "reason": reason,
            "exit_code": exit_code,
            "context": context or {},
        }

        with shutdowns_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, default=str) + "\n")
            f.flush()
            os.fsync(f.fileno())

        _set_secure_permissions(shutdowns_path)
        return True
    except Exception:
        # Best-effort logging during shutdown - must not raise
        return False


def _show_shutdown_popup(failure_type: str, log_dir: Path) -> None:
    """Show a popup alerting the user that the proxy shut down.

    Best effort - fails silently if osascript unavailable.
    No backoff needed since we're already shutting down.

    Args:
        failure_type: Category of failure (e.g., "audit_failure").
        log_dir: Directory containing .last_crash file.
    """
    if platform.system() != "Darwin":
        return

    crash_file = log_dir / ".last_crash"

    script = f"""
    display alert "MCP ACP" message "Proxy shut down due to {failure_type}.

Restart your MCP client.

Details: {crash_file}" as critical buttons {{"OK"}} default button "OK"
    """

    try:
        result = subprocess.run(
            ["osascript", "-e", script],
            capture_output=True,
            timeout=30,
        )
        if result.returncode != 0:
            print(f"[SHUTDOWN] osascript failed: {result.stderr.decode()}", file=sys.stderr, flush=True)
    except (subprocess.SubprocessError, OSError) as e:
        print(f"[SHUTDOWN] osascript exception: {e}", file=sys.stderr, flush=True)


def _write_crash_breadcrumb(
    log_dir: Path,
    failure_type: str,
    reason: str,
    exit_code: int,
    context: dict[str, Any] | None = None,
) -> None:
    """Write breadcrumb file with failure details.

    Location: <log_dir>/.last_crash
    Format:
        <timestamp>
        failure_type: <type>
        exit_code: <code>
        reason: <reason>
        context: <json>

    This format is:
    - Easy to parse programmatically (labeled fields)
    - Human-readable for operators
    - Minimal dependencies (simple text with one JSON field)

    Args:
        log_dir: Directory for breadcrumb file.
        failure_type: Category of failure (e.g., "audit_failure").
        reason: Human-readable description of the failure.
        exit_code: Process exit code (10=audit, 11=policy, 12=identity).
        context: Additional context for the failure.
    """
    import json

    try:
        log_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass  # If we can't create dir, try writing anyway

    crash_file = log_dir / ".last_crash"
    timestamp = datetime.now(timezone.utc).isoformat()
    context_json = json.dumps(context) if context else "{}"
    crash_file.write_text(
        f"{timestamp}\n"
        f"failure_type: {failure_type}\n"
        f"exit_code: {exit_code}\n"
        f"reason: {reason}\n"
        f"context: {context_json}\n"
    )


class ShutdownCoordinator:
    """Coordinates graceful shutdown on critical security failures.

    Three audiences receive failure information:
    - Client (Claude Desktop): Clean MCP error before disconnect
    - Operator: Breadcrumb file + exit code + stderr
    - Auditor: Audit trail up to failure + system.jsonl

    Shutdown sequence:
    1. Set _shutdown_in_progress = True (reject new requests)
    2. Log to shutdowns.jsonl (best effort, for incidents page)
    3. Log to system.jsonl (best effort)
    4. Write breadcrumb file (best effort)
    5. Log session_ended to auth.jsonl (best effort, if auth_logger set)
    6. Print to stderr (best effort)
    7. Show popup to user (best effort, macOS only)
    8. Emit SSE event to UI (best effort)
    9. Schedule delayed exit (100ms for response to flush)
    10. Return control (caller raises MCP error to client)
    11. Background task calls os._exit() after delay
    """

    def __init__(self, log_dir: Path, system_logger: "logging.Logger") -> None:
        """Initialize the shutdown coordinator.

        Args:
            log_dir: Directory for breadcrumb file (e.g., ~/.../mcp_acp_logs/)
            system_logger: System logger for critical events
        """
        self.log_dir = log_dir
        self.system_logger = system_logger
        self._shutdown_in_progress = False
        self._shutdown_reason: str | None = None
        self._shutdown_exit_code: int = 1
        self._auth_logger: "AuthLogger | None" = None
        self._proxy_state: "ProxyState | None" = None
        self._bound_session_id: str | None = None
        self._session_identity: Any = None  # SubjectIdentity

    def set_proxy_state(self, proxy_state: "ProxyState") -> None:
        """Set the proxy state for SSE event emission on shutdown.

        Args:
            proxy_state: The ProxyState instance for broadcasting events.
        """
        self._proxy_state = proxy_state

    def set_auth_logger(self, auth_logger: "AuthLogger") -> None:
        """Set the auth logger for session_ended logging on shutdown.

        This must be called after the auth logger is created in the lifespan,
        so that session_ended can be logged before os._exit().

        Args:
            auth_logger: The auth logger instance.
        """
        self._auth_logger = auth_logger

    def set_session_info(self, bound_session_id: str, session_identity: Any) -> None:
        """Set session info for session_ended logging on shutdown.

        This must be called after the session is created in the lifespan.
        Stored directly on the coordinator (not ContextVars) to work across
        async tasks and threads.

        Args:
            bound_session_id: The bound session ID (format: <user_id>:<session_uuid>).
            session_identity: The user identity (SubjectIdentity).
        """
        self._bound_session_id = bound_session_id
        self._session_identity = session_identity

    @property
    def is_shutting_down(self) -> bool:
        """Check if shutdown is in progress.

        Middleware should check this and reject new requests during shutdown.
        """
        return self._shutdown_in_progress

    @property
    def shutdown_reason(self) -> str | None:
        """Get the reason for shutdown, if shutting down."""
        return self._shutdown_reason

    async def initiate_shutdown(
        self,
        failure_type: str,
        reason: str,
        exit_code: int,
        context: dict[str, Any] | None = None,
    ) -> None:
        """Initiate graceful shutdown sequence.

        This method:
        1. Sets shutdown flag to reject new requests
        2. Logs to system.jsonl and breadcrumb file
        3. Logs session_ended to auth.jsonl (if auth_logger is set)
        4. Shows popup to user (macOS only)
        5. Schedules delayed exit (100ms)
        6. Returns immediately so caller can raise MCP error

        Args:
            failure_type: Category of failure (e.g., "audit_failure")
            reason: Human-readable description
            exit_code: Process exit code (10=audit, 11=policy, 12=identity)
            context: Additional context for logging
        """
        if self._shutdown_in_progress:
            return  # Already shutting down, don't duplicate

        self._shutdown_in_progress = True
        self._shutdown_reason = reason
        self._shutdown_exit_code = exit_code
        print(f"[SHUTDOWN] Initiating shutdown: {reason}", file=sys.stderr, flush=True)

        # 1. Log to shutdowns.jsonl (best effort - dedicated shutdown log for incidents page)
        try:
            _write_shutdown_log(self.log_dir, failure_type, reason, exit_code, context)
        except Exception:
            pass  # Best effort

        # 2. Log to system.jsonl (best effort - may fail for same reason as audit)
        try:
            self.system_logger.critical(
                {
                    "event": "critical_security_failure",
                    "failure_type": failure_type,
                    "reason": reason,
                    "exit_code": exit_code,
                    "context": context,
                    "action": "shutdown_initiated",
                    "message": f"Proxy shutting down: {reason}",
                }
            )
        except Exception:
            pass  # Best effort - continue with other fallbacks

        # 3. Write breadcrumb file (best effort - simple text, likely to succeed)
        try:
            _write_crash_breadcrumb(self.log_dir, failure_type, reason, exit_code, context)
        except Exception:
            pass  # Best effort

        # 4. Log session_ended to auth.jsonl (best effort)
        # This ensures the session end is logged even when os._exit() bypasses finally blocks
        if self._auth_logger and self._bound_session_id:
            try:
                # Map failure_type to appropriate end_reason
                # session_binding_violation is a specific security event with its own end_reason
                end_reason: str
                if failure_type == "session_binding_violation":
                    end_reason = "session_binding_violation"
                else:
                    end_reason = "error"

                self._auth_logger.log_session_ended(
                    bound_session_id=self._bound_session_id,
                    subject=self._session_identity,
                    end_reason=end_reason,  # type: ignore[arg-type]
                    error_type=failure_type,
                    error_message=reason,
                )
            except Exception:
                pass  # Best effort - don't let this block shutdown

        # 5. Print to stderr (best effort - may not be visible to operator)
        try:
            print(
                f"CRITICAL: Proxy shutting down - {failure_type}\n"
                f"  Reason: {reason}\n"
                f"  Exit code: {exit_code}",
                file=sys.stderr,
            )
        except Exception:
            pass  # Best effort

        # 6. Show popup to user (best effort - macOS only)
        try:
            _show_shutdown_popup(failure_type, self.log_dir)
        except Exception:
            pass  # Best effort

        # 7. Emit SSE event to UI (best effort - may not arrive before exit)
        if self._proxy_state is not None:
            try:
                from mcp_acp.manager.state import SSEEventType

                self._proxy_state.emit_system_event(
                    SSEEventType.CRITICAL_SHUTDOWN,
                    severity="critical",
                    message=f"Proxy shutting down: {failure_type}",
                    details=reason,
                    failure_type=failure_type,
                    exit_code=exit_code,
                )
            except Exception:
                pass  # Best effort

        # 8. Schedule delayed exit (allows MCP error response to flush)
        asyncio.create_task(self._delayed_exit())

    async def _delayed_exit(self) -> None:
        """Exit after delay to allow MCP error response to flush.

        100ms is conservative for a small JSON error response.
        Uses os._exit() which cannot be caught by exception handlers.
        """
        print("[SHUTDOWN] Waiting 100ms before exit...", file=sys.stderr, flush=True)
        await asyncio.sleep(0.1)  # 100ms
        print(f"[SHUTDOWN] Calling os._exit({self._shutdown_exit_code})", file=sys.stderr, flush=True)
        os._exit(self._shutdown_exit_code)


def sync_emergency_shutdown(
    log_dir: Path,
    failure_type: str,
    reason: str,
    exit_code: int,
) -> None:
    """Synchronous emergency shutdown when no event loop is available.

    This is a fallback for when the audit handler callback fires
    before the event loop is running or from a non-async context.

    Args:
        log_dir: Directory for breadcrumb file
        failure_type: Category of failure
        reason: Human-readable description
        exit_code: Process exit code
    """
    print(f"[SHUTDOWN-SYNC] Emergency shutdown: {reason}", file=sys.stderr, flush=True)

    # 1. Write to shutdowns.jsonl (for incidents page)
    try:
        _write_shutdown_log(log_dir, failure_type, reason, exit_code)
    except Exception:
        pass

    # 2. Write breadcrumb file
    try:
        _write_crash_breadcrumb(log_dir, failure_type, reason, exit_code)
    except Exception:
        pass

    # 3. Print to stderr
    try:
        print(
            f"CRITICAL: Proxy shutting down - {failure_type}\n"
            f"  Reason: {reason}\n"
            f"  Exit code: {exit_code}",
            file=sys.stderr,
            flush=True,
        )
    except Exception:
        pass

    # 4. Exit immediately (no delay since we can't wait for response flush)
    print(f"[SHUTDOWN-SYNC] Calling os._exit({exit_code})", file=sys.stderr, flush=True)
    os._exit(exit_code)
