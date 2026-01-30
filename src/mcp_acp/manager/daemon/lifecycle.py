"""PID file and socket management for the manager daemon.

Handles:
- PID file read/write/cleanup
- Socket staleness detection
- Port availability checks
- Manager running/stopped queries
"""

from __future__ import annotations

__all__ = [
    "cleanup_stale_pid",
    "cleanup_stale_socket",
    "get_manager_pid",
    "is_manager_running",
    "is_port_in_use",
    "remove_pid_file",
    "stop_manager",
    "write_pid_file",
]

import errno
import logging
import os
import signal
import socket

from mcp_acp.constants import MANAGER_PID_PATH, MANAGER_SOCKET_PATH
from mcp_acp.manager.models import ManagerSystemEvent
from mcp_acp.manager.utils import test_socket_connection

from .log_config import log_event


def _read_pid_file() -> int | None:
    """Read PID from PID file if it exists and process is running.

    Returns:
        PID if file exists and process is running, None otherwise.
    """
    if not MANAGER_PID_PATH.exists():
        return None

    try:
        pid = int(MANAGER_PID_PATH.read_text().strip())
        # Verify process exists (signal 0 = check existence)
        os.kill(pid, 0)
        return pid
    except (ValueError, ProcessLookupError):
        return None
    except OSError as e:
        if e.errno == errno.ESRCH:  # No such process
            return None
        raise


def is_manager_running() -> bool:
    """Check if manager daemon is running.

    Checks both PID file validity and socket connectivity.

    Returns:
        True if manager is running and accepting connections.
    """
    pid = _read_pid_file()
    if pid is None:
        return False

    return test_socket_connection(MANAGER_SOCKET_PATH)


def get_manager_pid() -> int | None:
    """Get the PID of the running manager daemon.

    Returns:
        PID if manager is running, None otherwise.
    """
    return _read_pid_file()


def stop_manager() -> bool:
    """Stop the manager daemon.

    Sends SIGTERM to the manager process.

    Returns:
        True if signal was sent successfully, False if not running.
    """
    pid = _read_pid_file()
    if pid is None:
        return False

    try:
        os.kill(pid, signal.SIGTERM)
        return True
    except OSError:
        return False


def cleanup_stale_socket() -> None:
    """Remove stale manager socket file if exists and not connectable.

    Raises:
        RuntimeError: If socket is connectable (manager already running).
    """
    if not MANAGER_SOCKET_PATH.exists():
        return

    if test_socket_connection(MANAGER_SOCKET_PATH):
        raise RuntimeError(f"Manager is already running (socket: {MANAGER_SOCKET_PATH})")

    # Stale socket, remove it
    MANAGER_SOCKET_PATH.unlink(missing_ok=True)
    log_event(
        logging.INFO,
        ManagerSystemEvent(
            event="stale_socket_removed",
            message=f"Removed stale socket: {MANAGER_SOCKET_PATH}",
            socket_path=str(MANAGER_SOCKET_PATH),
        ),
    )


def cleanup_stale_pid() -> None:
    """Remove stale PID file if process is not running.

    Raises:
        RuntimeError: If process is running (manager already running).
    """
    if not MANAGER_PID_PATH.exists():
        return

    pid = _read_pid_file()
    if pid is not None:
        raise RuntimeError(f"Manager is already running (pid: {pid})")

    # Stale PID file, remove it
    MANAGER_PID_PATH.unlink(missing_ok=True)
    log_event(
        logging.INFO,
        ManagerSystemEvent(
            event="stale_pid_removed",
            message=f"Removed stale PID file: {MANAGER_PID_PATH}",
        ),
    )


def write_pid_file() -> None:
    """Write current process PID to PID file."""
    pid = os.getpid()
    MANAGER_PID_PATH.write_text(str(pid))


def remove_pid_file() -> None:
    """Remove PID file if it exists."""
    MANAGER_PID_PATH.unlink(missing_ok=True)


def is_port_in_use(port: int) -> bool:
    """Check if TCP port is accepting connections.

    Args:
        port: TCP port number to check.

    Returns:
        True if port is in use, False otherwise.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("127.0.0.1", port)) == 0
