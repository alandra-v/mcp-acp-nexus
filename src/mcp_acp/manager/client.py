"""Manager client for proxy registration.

Handles proxy-to-manager communication over UDS:
- Registration on startup
- Event forwarding (push events to manager)
- Graceful disconnect handling

Protocol (NDJSON over UDS):
- Proxy sends: {"type": "register", "protocol_version": 1, "proxy_name": "...", "instance_id": "...", "config_summary": {...}}
- Manager sends: {"type": "registered", "ok": true}
- Proxy sends: {"type": "event", "event_type": "...", "data": {...}}
- (No response to events - fire and forget)
"""

from __future__ import annotations

__all__ = [
    "ManagerClient",
    "ManagerConnectionError",
    "ensure_manager_running",
    "is_manager_available",
]

import asyncio
import fcntl
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from mcp_acp.constants import (
    APP_NAME,
    MANAGER_LOCK_PATH,
    MANAGER_SOCKET_PATH,
    RUNTIME_DIR,
    SOCKET_CONNECT_TIMEOUT_SECONDS,
)
from mcp_acp.manager.protocol import PROTOCOL_VERSION, decode_ndjson, encode_ndjson
from mcp_acp.telemetry.system.system_logger import get_system_logger

# Timeout for registration handshake (seconds)
REGISTRATION_TIMEOUT_SECONDS = 5.0

# Use proxy's system logger since this code runs in the proxy process
_logger = get_system_logger()


class ManagerConnectionError(Exception):
    """Error connecting to or communicating with manager."""

    pass


class ManagerClient:
    """Client for proxy-to-manager communication.

    Handles:
    - Connection to manager.sock
    - Registration handshake
    - Event pushing
    - Graceful disconnect detection

    The client maintains a persistent connection for event forwarding.
    If the manager disconnects, events are silently dropped (proxy continues working).

    Usage:
        client = ManagerClient(proxy_name="default", instance_id="inst_abc123")
        await client.connect()
        await client.register(config_summary={...})

        # Later, push events
        await client.push_event("pending_created", {...})

        # On shutdown
        await client.disconnect()
    """

    def __init__(
        self,
        proxy_name: str,
        instance_id: str,
        manager_socket_path: Path | None = None,
        proxy_api_socket_path: str | None = None,
    ) -> None:
        """Initialize manager client.

        Args:
            proxy_name: Name of this proxy (e.g., "default").
            instance_id: Unique instance ID for this proxy run.
            manager_socket_path: Path to manager socket. Defaults to MANAGER_SOCKET_PATH.
            proxy_api_socket_path: Path to this proxy's API socket (for manager routing).
        """
        self._proxy_name = proxy_name
        self._instance_id = instance_id
        self._socket_path = manager_socket_path or MANAGER_SOCKET_PATH
        self._proxy_api_socket_path = proxy_api_socket_path or ""
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._connected = False
        self._registered = False
        self._lock = asyncio.Lock()

    @property
    def connected(self) -> bool:
        """Check if connected to manager."""
        return self._connected

    @property
    def registered(self) -> bool:
        """Check if registered with manager."""
        return self._registered

    async def connect(self) -> bool:
        """Connect to manager socket.

        Returns:
            True if connected successfully, False if manager not available.

        Note:
            Does not raise on connection failure - proxy should work without manager.
        """
        if self._connected:
            return True

        if not self._socket_path.exists():
            return False

        try:
            # Create Unix socket connection
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_unix_connection(str(self._socket_path)),
                timeout=SOCKET_CONNECT_TIMEOUT_SECONDS,
            )
            self._connected = True
            _logger.info(
                {
                    "event": "manager_connected",
                    "message": f"Connected to manager at {self._socket_path}",
                    "socket_path": str(self._socket_path),
                }
            )
            return True

        except asyncio.TimeoutError:
            _logger.warning(
                {
                    "event": "manager_connect_timeout",
                    "message": "Timeout connecting to manager",
                    "socket_path": str(self._socket_path),
                }
            )
            return False
        except (ConnectionRefusedError, FileNotFoundError, OSError):
            return False

    async def register(self, config_summary: dict[str, Any] | None = None) -> bool:
        """Register this proxy with the manager.

        Args:
            config_summary: Optional summary of proxy configuration to share.

        Returns:
            True if registered successfully, False otherwise.
        """
        if not self._connected:
            return False

        if self._registered:
            return True

        async with self._lock:
            try:
                # Send registration message
                reg_msg = {
                    "type": "register",
                    "protocol_version": PROTOCOL_VERSION,
                    "proxy_name": self._proxy_name,
                    "instance_id": self._instance_id,
                    "config_summary": config_summary or {},
                    "socket_path": self._proxy_api_socket_path,
                }
                await self._send_message(reg_msg)

                # Wait for acknowledgment
                response = await asyncio.wait_for(
                    self._read_message(),
                    timeout=REGISTRATION_TIMEOUT_SECONDS,
                )

                if response and response.get("type") == "registered":
                    if response.get("ok"):
                        self._registered = True
                        _logger.info(
                            {
                                "event": "manager_registered",
                                "message": f"Registered with manager: {self._proxy_name}",
                                "proxy_name": self._proxy_name,
                                "instance_id": self._instance_id,
                            }
                        )
                        return True
                    else:
                        error = response.get("error", "Unknown error")
                        _logger.warning(
                            {
                                "event": "registration_rejected",
                                "message": f"Registration rejected: {error}",
                                "proxy_name": self._proxy_name,
                                "instance_id": self._instance_id,
                                "error_message": error,
                            }
                        )
                        return False
                else:
                    _logger.warning(
                        {
                            "event": "registration_unexpected_response",
                            "message": f"Unexpected registration response: {response}",
                            "proxy_name": self._proxy_name,
                            "instance_id": self._instance_id,
                        }
                    )
                    return False

            except asyncio.TimeoutError:
                _logger.warning(
                    {
                        "event": "registration_timeout",
                        "message": "Registration timed out",
                        "proxy_name": self._proxy_name,
                        "instance_id": self._instance_id,
                    }
                )
                await self._handle_disconnect()
                return False
            except (ConnectionResetError, BrokenPipeError, OSError) as e:
                _logger.warning(
                    {
                        "event": "registration_connection_lost",
                        "message": f"Connection lost during registration: {e}",
                        "proxy_name": self._proxy_name,
                        "instance_id": self._instance_id,
                        "error_type": type(e).__name__,
                        "error_message": str(e),
                    }
                )
                await self._handle_disconnect()
                return False

    async def push_event(self, event_type: str, data: dict[str, Any]) -> None:
        """Push an SSE event to the manager for browser broadcast.

        Fire-and-forget: no response expected, failures are logged but not raised.

        Args:
            event_type: Type of event (e.g., "pending_created", "approval_resolved").
            data: Event payload.
        """
        if not self._connected or not self._registered:
            return

        try:
            event_msg = {
                "type": "event",
                "event_type": event_type,
                "data": data,
            }
            await self._send_message(event_msg)
        except (ConnectionResetError, BrokenPipeError, OSError):
            await self._handle_disconnect()

    async def disconnect(self) -> None:
        """Gracefully disconnect from manager.

        Note: Does not log - callers log if needed. Unexpected disconnects
        are logged in _handle_disconnect() before calling this method.
        """
        if self._writer:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except OSError:
                pass  # Already closed
        self._reader = None
        self._writer = None
        self._connected = False
        self._registered = False

    async def _send_message(self, msg: dict[str, Any]) -> None:
        """Send a JSON message over the connection (NDJSON format)."""
        if not self._writer:
            raise ManagerConnectionError("Not connected")
        self._writer.write(encode_ndjson(msg))
        await self._writer.drain()

    async def _read_message(self) -> dict[str, Any] | None:
        """Read a JSON message from the connection."""
        if not self._reader:
            return None
        line = await self._reader.readline()
        if not line:
            return None
        msg = decode_ndjson(line)
        if msg is None:
            _logger.warning(
                {
                    "event": "invalid_json_from_manager",
                    "message": "Invalid JSON from manager",
                    "proxy_name": self._proxy_name,
                    "instance_id": self._instance_id,
                }
            )
        return msg

    async def _handle_disconnect(self) -> None:
        """Handle unexpected disconnect from manager."""
        if self._connected:
            _logger.warning(
                {
                    "event": "manager_connection_lost",
                    "message": "Manager connection lost. UI may be unavailable. Run 'mcp-acp manager start' to restore.",
                    "proxy_name": self._proxy_name,
                    "instance_id": self._instance_id,
                }
            )
            # TODO: Show osascript popup notification
        await self.disconnect()


def is_manager_available() -> bool:
    """Quick check if manager socket exists and accepts connections.

    Returns:
        True if manager is likely running, False otherwise.
    """
    from mcp_acp.manager.utils import test_socket_connection

    return test_socket_connection(MANAGER_SOCKET_PATH)


# Auto-start timeout constants
MANAGER_STARTUP_TIMEOUT_SECONDS = 5.0
MANAGER_POLL_INTERVAL_SECONDS = 0.2


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
    lock_file = None
    try:
        lock_file = open(MANAGER_LOCK_PATH, "w")
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)

        # Double-check after acquiring lock (another proxy may have started it)
        if is_manager_available():
            return True

        # Start manager daemon
        _logger.info(
            {
                "event": "manager_starting",
                "message": "Starting manager daemon...",
            }
        )
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
            _logger.info(
                {
                    "event": "manager_started",
                    "message": "Manager daemon started successfully",
                }
            )
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
    finally:
        if lock_file is not None:
            try:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
                lock_file.close()
            except OSError:
                pass


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
