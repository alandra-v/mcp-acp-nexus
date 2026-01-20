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
    "PROTOCOL_VERSION",
]

import asyncio
import json
import logging
import socket
from pathlib import Path
from typing import Any

from mcp_acp.constants import (
    MANAGER_SOCKET_PATH,
    SOCKET_CONNECT_TIMEOUT_SECONDS,
)

# Protocol version for manager-proxy communication
PROTOCOL_VERSION = 1

# Timeout for registration handshake (seconds)
REGISTRATION_TIMEOUT_SECONDS = 5.0

# Buffer size for reading responses
READ_BUFFER_SIZE = 4096

_logger = logging.getLogger("mcp-acp.manager.client")


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
        socket_path: Path | None = None,
    ) -> None:
        """Initialize manager client.

        Args:
            proxy_name: Name of this proxy (e.g., "default").
            instance_id: Unique instance ID for this proxy run.
            socket_path: Path to manager socket. Defaults to MANAGER_SOCKET_PATH.
        """
        self._proxy_name = proxy_name
        self._instance_id = instance_id
        self._socket_path = socket_path or MANAGER_SOCKET_PATH
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
            _logger.debug("Manager socket not found: %s", self._socket_path)
            return False

        try:
            # Create Unix socket connection
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_unix_connection(str(self._socket_path)),
                timeout=SOCKET_CONNECT_TIMEOUT_SECONDS,
            )
            self._connected = True
            _logger.info("Connected to manager at %s", self._socket_path)
            return True

        except asyncio.TimeoutError:
            _logger.warning("Timeout connecting to manager")
            return False
        except (ConnectionRefusedError, FileNotFoundError, OSError) as e:
            _logger.debug("Cannot connect to manager: %s", e)
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
                            "Registered with manager: proxy_name=%s, instance_id=%s",
                            self._proxy_name,
                            self._instance_id,
                        )
                        return True
                    else:
                        error = response.get("error", "Unknown error")
                        _logger.warning("Registration rejected: %s", error)
                        return False
                else:
                    _logger.warning("Unexpected registration response: %s", response)
                    return False

            except asyncio.TimeoutError:
                _logger.warning("Registration timed out")
                await self._handle_disconnect()
                return False
            except (ConnectionResetError, BrokenPipeError, OSError) as e:
                _logger.warning("Connection lost during registration: %s", e)
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
        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            _logger.debug("Failed to push event (manager may have disconnected): %s", e)
            await self._handle_disconnect()

    async def disconnect(self) -> None:
        """Gracefully disconnect from manager."""
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
        _logger.debug("Disconnected from manager")

    async def _send_message(self, msg: dict[str, Any]) -> None:
        """Send a JSON message over the connection (NDJSON format)."""
        if not self._writer:
            raise ManagerConnectionError("Not connected")
        line = json.dumps(msg, separators=(",", ":")) + "\n"
        self._writer.write(line.encode("utf-8"))
        await self._writer.drain()

    async def _read_message(self) -> dict[str, Any] | None:
        """Read a JSON message from the connection."""
        if not self._reader:
            return None
        try:
            line = await self._reader.readline()
            if not line:
                return None
            result: dict[str, Any] = json.loads(line.decode("utf-8"))
            return result
        except json.JSONDecodeError as e:
            _logger.warning("Invalid JSON from manager: %s", e)
            return None

    async def _handle_disconnect(self) -> None:
        """Handle unexpected disconnect from manager."""
        if self._connected:
            _logger.warning(
                "Manager connection lost. UI may be unavailable. " "Run 'mcp-acp manager start' to restore."
            )
            # TODO: Show osascript popup notification
        await self.disconnect()


def is_manager_available() -> bool:
    """Quick check if manager socket exists and accepts connections.

    Returns:
        True if manager is likely running, False otherwise.
    """
    if not MANAGER_SOCKET_PATH.exists():
        return False

    try:
        test_sock = socket.socket(socket.AF_UNIX)
        test_sock.settimeout(SOCKET_CONNECT_TIMEOUT_SECONDS)
        test_sock.connect(str(MANAGER_SOCKET_PATH))
        test_sock.close()
        return True
    except (ConnectionRefusedError, FileNotFoundError, OSError):
        return False
