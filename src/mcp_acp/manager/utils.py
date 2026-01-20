"""Shared utilities for manager package.

Common helpers used by daemon, client, and CLI:
- Socket connectivity testing
- Polling/waiting utilities
"""

from __future__ import annotations

__all__ = [
    "test_socket_connection",
    "wait_for_condition",
]

import socket
import time
from collections.abc import Callable
from pathlib import Path

from mcp_acp.constants import SOCKET_CONNECT_TIMEOUT_SECONDS

# Default poll interval for condition waiting (seconds)
DEFAULT_POLL_INTERVAL_SECONDS = 0.2


def test_socket_connection(socket_path: Path) -> bool:
    """Test if a Unix socket is accepting connections.

    Args:
        socket_path: Path to the Unix socket.

    Returns:
        True if socket accepts connection, False otherwise.
    """
    if not socket_path.exists():
        return False

    try:
        test_sock = socket.socket(socket.AF_UNIX)
        test_sock.settimeout(SOCKET_CONNECT_TIMEOUT_SECONDS)
        test_sock.connect(str(socket_path))
        test_sock.close()
        return True
    except (ConnectionRefusedError, FileNotFoundError, OSError):
        return False


def wait_for_condition(
    condition_fn: Callable[[], bool],
    timeout_seconds: float,
    poll_interval: float = DEFAULT_POLL_INTERVAL_SECONDS,
) -> bool:
    """Wait for a condition to become true.

    Polls the condition function until it returns True or timeout is reached.

    Args:
        condition_fn: Function that returns True when condition is met.
        timeout_seconds: Maximum time to wait.
        poll_interval: Time between condition checks.

    Returns:
        True if condition was met within timeout, False otherwise.
    """
    start_time = time.monotonic()
    while time.monotonic() - start_time < timeout_seconds:
        if condition_fn():
            return True
        time.sleep(poll_interval)
    return False
