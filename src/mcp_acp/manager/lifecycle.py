"""Manager daemon lifecycle utilities.

Synchronous helpers for checking manager availability and auto-starting
the manager daemon. Used during proxy startup.
"""

from __future__ import annotations

__all__ = ["ensure_manager_running", "is_manager_available"]

import fcntl
import shutil
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from mcp_acp.constants import (
    APP_NAME,
    MANAGER_LOCK_PATH,
    MANAGER_SOCKET_PATH,
    RUNTIME_DIR,
)
from mcp_acp.telemetry.system.system_logger import get_system_logger

_logger = get_system_logger()

# Auto-start timeout constants
MANAGER_STARTUP_TIMEOUT_SECONDS = 5.0
MANAGER_POLL_INTERVAL_SECONDS = 0.2


def is_manager_available() -> bool:
    """Quick check if manager socket exists and accepts connections.

    Returns:
        True if manager is likely running, False otherwise.
    """
    from mcp_acp.manager.utils import test_socket_connection

    return test_socket_connection(MANAGER_SOCKET_PATH)


@contextmanager
def _file_lock(lock_path: Path) -> Iterator[None]:
    """Context manager for exclusive file locking.

    Acquires an exclusive lock on the specified file, creating it if needed.
    The lock is automatically released when exiting the context.

    Args:
        lock_path: Path to the lock file.

    Yields:
        None when lock is acquired.

    Raises:
        OSError: If lock acquisition fails.
    """
    lock_file = open(lock_path, "w")
    try:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        lock_file.close()


def ensure_manager_running() -> bool:
    """Ensure manager daemon is running, starting it if needed.

    Uses file locking to prevent race conditions when multiple proxies
    start simultaneously.

    Returns:
        True if manager is running (was already running or successfully started).
        False if manager could not be started.
    """
    # Quick check - if already running, no need for lock
    if is_manager_available():
        return True

    # Ensure runtime directory exists
    RUNTIME_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)

    # Acquire file lock to prevent race conditions
    try:
        with _file_lock(MANAGER_LOCK_PATH):
            # Double-check after acquiring lock (another proxy may have started it)
            if is_manager_available():
                return True

            # Start manager daemon
            if not _spawn_manager_daemon():
                _logger.warning(
                    {
                        "event": "manager_spawn_failed",
                        "message": "Failed to spawn manager daemon",
                    }
                )
                return False

            # Wait for manager to become ready
            if _wait_for_manager_ready():
                return True
            else:
                _logger.warning(
                    {
                        "event": "manager_not_ready",
                        "message": "Manager daemon did not become ready in time",
                    }
                )
                return False

    except OSError as e:
        _logger.warning(
            {
                "event": "manager_lock_failed",
                "message": f"Failed to acquire manager lock: {e}",
                "error_type": type(e).__name__,
                "error_message": str(e),
            }
        )
        return False


def _spawn_manager_daemon() -> bool:
    """Spawn manager as a detached daemon process.

    Returns:
        True if process was spawned successfully.
    """
    # Find the mcp-acp executable
    mcp_acp_path = shutil.which(APP_NAME)
    if mcp_acp_path is None:
        # Fall back to python -m mcp_acp.cli
        mcp_acp_cmd = [sys.executable, "-m", "mcp_acp.cli"]
    else:
        mcp_acp_cmd = [mcp_acp_path]

    try:
        # Use _run command to avoid recursive daemonization
        subprocess.Popen(
            mcp_acp_cmd + ["manager", "_run"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        return True
    except OSError as e:
        _logger.warning(
            {
                "event": "manager_spawn_error",
                "message": f"Failed to spawn manager: {e}",
                "error_type": type(e).__name__,
                "error_message": str(e),
            }
        )
        return False


def _wait_for_manager_ready() -> bool:
    """Wait for manager socket to accept connections.

    Returns:
        True if manager became ready within timeout.
    """
    from mcp_acp.manager.utils import wait_for_condition

    return wait_for_condition(
        is_manager_available,
        timeout_seconds=MANAGER_STARTUP_TIMEOUT_SECONDS,
        poll_interval=MANAGER_POLL_INTERVAL_SECONDS,
    )
