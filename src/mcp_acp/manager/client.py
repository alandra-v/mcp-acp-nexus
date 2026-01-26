"""Manager client for proxy registration.

Handles proxy-to-manager communication over UDS:
- Registration on startup
- Event forwarding (push events to manager)
- Graceful disconnect handling

Protocol (NDJSON over UDS):
- Proxy sends: {"type": "register", "proxy_name": "...", "proxy_id": "...", "instance_id": "...", ...}
- Manager sends: {"type": "registered", "ok": true}
- Manager sends: {"type": "ui_status", "browser_connected": true, "subscriber_count": 1}
- Manager sends: {"type": "token_update", "access_token": "...", "expires_at": "ISO8601"}
- Manager sends: {"type": "heartbeat"}
- Proxy sends: {"type": "event", "event_type": "...", "data": {...}}
- Unknown message types are ignored (forward compatibility)
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
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterator

if TYPE_CHECKING:
    from collections.abc import Callable

    from mcp_acp.pep.hitl import HITLHandler
    from mcp_acp.security.auth.token_storage import StoredToken

from mcp_acp.constants import (
    APP_NAME,
    MANAGER_LOCK_PATH,
    MANAGER_SOCKET_PATH,
    RUNTIME_DIR,
    SOCKET_CONNECT_TIMEOUT_SECONDS,
)
from mcp_acp.manager.protocol import decode_ndjson, encode_ndjson
from mcp_acp.telemetry.system.system_logger import get_system_logger

# Timeout for registration handshake (seconds)
REGISTRATION_TIMEOUT_SECONDS = 5.0

# Timeout for manager messages (heartbeat/ui_status) before considering connection lost
HEARTBEAT_TIMEOUT_SECONDS = 45.0

# How often to check for manager availability and attempt reconnection
RECONNECT_CHECK_INTERVAL_SECONDS = 10.0

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
        proxy_id: str | None = None,
    ) -> None:
        """Initialize manager client.

        Args:
            proxy_name: Name of this proxy (e.g., "filesystem").
            instance_id: Unique instance ID for this proxy run.
            manager_socket_path: Path to manager socket. Defaults to MANAGER_SOCKET_PATH.
            proxy_api_socket_path: Path to this proxy's API socket (for manager routing).
            proxy_id: Stable proxy identifier (e.g., "px_a1b2c3d4:filesystem-server").
        """
        self._proxy_name = proxy_name
        self._instance_id = instance_id
        self._proxy_id = proxy_id or ""
        self._socket_path = manager_socket_path or MANAGER_SOCKET_PATH
        self._proxy_api_socket_path = proxy_api_socket_path or ""
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._connected = False
        self._registered = False
        self._lock = asyncio.Lock()

        # Browser connectivity state (from manager ui_status messages)
        self._browser_connected: bool = False

        # Background task for listening to manager messages
        self._message_handler_task: asyncio.Task[None] | None = None

        # Reconnection state
        self._was_registered: bool = False
        self._reconnect_task: asyncio.Task[None] | None = None
        self._last_config_summary: dict[str, Any] | None = None

        # HITL handler for disconnect notifications
        self._hitl_handler: "HITLHandler | None" = None

        # Token callback for manager-distributed tokens
        self._token_callback: "Callable[[StoredToken], None] | None" = None
        # Last token received from manager
        self._manager_token: "StoredToken | None" = None

    @property
    def connected(self) -> bool:
        """Check if connected to manager."""
        return self._connected

    @property
    def registered(self) -> bool:
        """Check if registered with manager."""
        return self._registered

    @property
    def browser_connected(self) -> bool:
        """Check if browser is connected to manager.

        Returns:
            True if connected, registered, AND browser is connected to manager.
            This accurately reflects whether web UI is available for HITL.
        """
        return self._connected and self._registered and self._browser_connected

    def set_hitl_handler(self, handler: "HITLHandler") -> None:
        """Set HITL handler for disconnect notifications.

        Called by proxy during setup to enable HITL fallback when manager
        disconnects mid-wait.

        Args:
            handler: HITLHandler to notify when manager disconnects.
        """
        self._hitl_handler = handler

    def set_token_callback(self, callback: "Callable[[StoredToken], None]") -> None:
        """Set callback for token updates from manager.

        Called by OIDC provider to receive manager-distributed tokens.
        The callback is invoked whenever a new token is received.

        Args:
            callback: Function to call with new StoredToken.
        """
        self._token_callback = callback

    @property
    def manager_token(self) -> "StoredToken | None":
        """Get the last token received from manager.

        Returns:
            StoredToken if received, None if no token from manager.
        """
        return self._manager_token

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

        # Store config for potential reconnection
        self._last_config_summary = config_summary

        async with self._lock:
            try:
                # Send registration message
                reg_msg = {
                    "type": "register",
                    "proxy_name": self._proxy_name,
                    "proxy_id": self._proxy_id,
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
                        self._was_registered = True

                        # Start background message listener for ui_status and heartbeat
                        await self._start_message_listener()

                        # Start periodic reconnection task
                        await self._start_reconnect_task()

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

        Cancels background tasks (message listener, reconnect) and closes connection.
        Note: Does not log - callers log if needed. Unexpected disconnects
        are logged in _handle_disconnect() before calling this method.
        """
        # Cancel message handler task
        if self._message_handler_task is not None:
            self._message_handler_task.cancel()
            try:
                await self._message_handler_task
            except asyncio.CancelledError:
                pass
            self._message_handler_task = None

        # Cancel reconnect task
        if self._reconnect_task is not None:
            self._reconnect_task.cancel()
            try:
                await self._reconnect_task
            except asyncio.CancelledError:
                pass
            self._reconnect_task = None

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
        self._browser_connected = False

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
        """Handle unexpected disconnect from manager.

        Logs the disconnect, notifies HITL handler (so pending approvals can
        fall back to osascript), and cleans up the connection state.
        """
        if self._connected:
            _logger.warning(
                {
                    "event": "manager_connection_lost",
                    "message": "Manager connection lost. UI may be unavailable. Run 'mcp-acp manager start' to restore.",
                    "proxy_name": self._proxy_name,
                    "instance_id": self._instance_id,
                }
            )

        # Notify HITL handler so pending approvals can fall back to osascript
        if self._hitl_handler is not None:
            self._hitl_handler.notify_manager_disconnected()

        # Cancel message handler but keep reconnect task running
        if self._message_handler_task is not None:
            self._message_handler_task.cancel()
            try:
                await self._message_handler_task
            except asyncio.CancelledError:
                pass
            self._message_handler_task = None

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
        self._browser_connected = False

    async def _start_message_listener(self) -> None:
        """Start background task to listen for manager messages.

        Called after successful registration. The listener handles ui_status
        and heartbeat messages from the manager.
        """
        if self._message_handler_task is not None:
            return  # Already running

        self._message_handler_task = asyncio.create_task(self._listen_for_messages())

    async def _listen_for_messages(self) -> None:
        """Listen for messages from manager in background.

        Handles ui_status and heartbeat messages. If no message received within
        HEARTBEAT_TIMEOUT_SECONDS, considers the connection lost.

        This task runs until cancelled or connection is lost.
        """
        try:
            while self._connected and self._reader is not None:
                try:
                    # Wait for message with timeout
                    line = await asyncio.wait_for(
                        self._reader.readline(),
                        timeout=HEARTBEAT_TIMEOUT_SECONDS,
                    )

                    if not line:
                        # EOF - connection closed
                        _logger.warning(
                            {
                                "event": "manager_connection_closed",
                                "message": "Manager closed connection",
                                "proxy_name": self._proxy_name,
                            }
                        )
                        await self._handle_disconnect()
                        return

                    msg = decode_ndjson(line)
                    if msg is not None:
                        await self._handle_manager_message(msg)

                except asyncio.TimeoutError:
                    # No message within timeout - connection may be lost
                    _logger.warning(
                        {
                            "event": "manager_heartbeat_timeout",
                            "message": f"No message from manager in {HEARTBEAT_TIMEOUT_SECONDS}s",
                            "proxy_name": self._proxy_name,
                        }
                    )
                    await self._handle_disconnect()
                    return

                except (ConnectionResetError, BrokenPipeError, OSError) as e:
                    _logger.warning(
                        {
                            "event": "manager_message_read_error",
                            "message": f"Error reading from manager: {e}",
                            "proxy_name": self._proxy_name,
                            "error_type": type(e).__name__,
                        }
                    )
                    await self._handle_disconnect()
                    return

        except asyncio.CancelledError:
            # Normal cancellation during shutdown
            raise

    async def _handle_token_update(self, msg: dict[str, Any]) -> None:
        """Handle token_update message from manager.

        Parses the token, stores it locally, and invokes the callback
        to update the OIDC provider.

        Args:
            msg: Token update message with access_token, expires_at, etc.
        """
        from datetime import datetime

        from mcp_acp.security.auth.token_storage import StoredToken

        try:
            # Parse token from message
            expires_at = datetime.fromisoformat(msg["expires_at"])
            issued_at = datetime.fromisoformat(msg.get("issued_at", msg["expires_at"]))

            token = StoredToken(
                access_token=msg["access_token"],
                refresh_token=msg.get("refresh_token"),
                id_token=msg.get("id_token"),
                expires_at=expires_at,
                issued_at=issued_at,
            )

            self._manager_token = token

            _logger.info(
                {
                    "event": "token_received_from_manager",
                    "message": "Token received from manager",
                    "proxy_name": self._proxy_name,
                    "expires_at": expires_at.isoformat(),
                    "is_expired": token.is_expired,
                }
            )

            # Invoke callback to update OIDC provider
            if self._token_callback is not None:
                self._token_callback(token)

        except (KeyError, ValueError) as e:
            _logger.warning(
                {
                    "event": "token_update_parse_failed",
                    "message": f"Failed to parse token update: {e}",
                    "proxy_name": self._proxy_name,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                }
            )

    async def _handle_manager_message(self, msg: dict[str, Any]) -> None:
        """Handle a message from the manager.

        Args:
            msg: Decoded JSON message from manager.
        """
        msg_type = msg.get("type")

        if msg_type == "ui_status":
            old_status = self._browser_connected
            self._browser_connected = msg.get("browser_connected", False)
            subscriber_count = msg.get("subscriber_count", 0)

            if old_status != self._browser_connected:
                # Log at WARNING so it appears in system log files (not just stderr)
                _logger.warning(
                    {
                        "event": "browser_status_changed",
                        "message": f"Browser connectivity changed: {self._browser_connected}",
                        "browser_connected": self._browser_connected,
                        "subscriber_count": subscriber_count,
                        "proxy_name": self._proxy_name,
                    }
                )

        elif msg_type == "heartbeat":
            # Heartbeat received - connection is alive
            # No logging needed for successful heartbeats
            pass

        elif msg_type == "token_update":
            # Token update from manager (Phase 4 - multi-proxy token distribution)
            await self._handle_token_update(msg)

        elif msg_type == "token_cleared":
            # Token cleared from manager (user logged out)
            self._manager_token = None
            _logger.info(
                {
                    "event": "token_cleared_from_manager",
                    "message": "Token cleared by manager (logout)",
                    "proxy_name": self._proxy_name,
                }
            )

        else:
            # Unknown message type - ignore (forward compatibility)
            _logger.debug(
                {
                    "event": "manager_unknown_message",
                    "message": f"Unknown message type from manager: {msg_type}",
                    "proxy_name": self._proxy_name,
                    "msg_type": msg_type,
                }
            )

    async def _start_reconnect_task(self) -> None:
        """Start background task for periodic reconnection attempts.

        Called after successful registration. The task checks for manager
        availability and reconnects if the connection is lost.
        """
        if self._reconnect_task is not None:
            return  # Already running

        self._reconnect_task = asyncio.create_task(self._periodic_reconnect_check())

    async def _periodic_reconnect_check(self) -> None:
        """Periodically check if manager is available and reconnect.

        Runs as background task after initial registration. Only attempts
        reconnection if previously registered but currently disconnected.
        """
        try:
            while True:
                await asyncio.sleep(RECONNECT_CHECK_INTERVAL_SECONDS)

                # Only try to reconnect if we were previously registered but now disconnected
                if not self._connected and self._was_registered:
                    if await self._try_reconnect():
                        _logger.warning(
                            {
                                "event": "manager_reconnected",
                                "message": f"Reconnected to manager: {self._proxy_name}",
                                "proxy_name": self._proxy_name,
                                "instance_id": self._instance_id,
                            }
                        )
        except asyncio.CancelledError:
            # Normal cancellation during shutdown
            raise

    async def _try_reconnect(self) -> bool:
        """Try to reconnect to manager if it's available again.

        Called periodically when disconnected but was previously registered.

        Returns:
            True if reconnected and re-registered successfully.
        """
        if self._connected:
            return True

        if not self._socket_path.exists():
            return False

        # Try to connect
        if await self.connect():
            # Try to re-register with stored config
            if await self.register(self._last_config_summary):
                return True
            # Registration failed - disconnect
            await self.disconnect()

        return False


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
