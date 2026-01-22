"""Proxy registry for tracking connected proxies.

Manages the in-memory registry of proxy connections:
- Registration/deregistration
- Connection tracking
- Event broadcasting to SSE subscribers
"""

from __future__ import annotations

__all__ = [
    "ProxyConnection",
    "ProxyRegistry",
    "get_proxy_registry",
]

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from mcp_acp.constants import APP_NAME

_logger = logging.getLogger(f"{APP_NAME}.manager.registry")


@dataclass
class ProxyConnection:
    """Information about a connected proxy.

    Attributes:
        proxy_name: User-facing name (e.g., "default", "filesystem").
        instance_id: Unique ID for this proxy run.
        config_summary: Summary of proxy configuration.
        connected_at: When the proxy connected.
        socket_path: Path to proxy's UDS API socket.
        writer: Async stream writer for sending messages back.
        reader: Async stream reader for receiving messages.
    """

    proxy_name: str
    instance_id: str
    config_summary: dict[str, Any]
    connected_at: datetime
    socket_path: str
    writer: asyncio.StreamWriter
    reader: asyncio.StreamReader
    _event_task: asyncio.Task[None] | None = field(default=None, repr=False)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for API responses."""
        return {
            "name": self.proxy_name,
            "instance_id": self.instance_id,
            "connected": True,
            "connected_at": self.connected_at.isoformat(),
            "config_summary": self.config_summary,
            "socket_path": self.socket_path,
        }


class ProxyRegistry:
    """Registry of connected proxies.

    Thread-safe registry that tracks all proxy connections.
    Also manages SSE event broadcasting to browser subscribers.
    """

    def __init__(self) -> None:
        """Initialize the registry."""
        self._proxies: dict[str, ProxyConnection] = {}
        self._lock = asyncio.Lock()
        # SSE subscribers (queues for each connected browser)
        self._sse_subscribers: list[asyncio.Queue[dict[str, Any]]] = []
        self._sse_lock = asyncio.Lock()

    @property
    def sse_subscriber_count(self) -> int:
        """Return the current number of SSE subscribers."""
        return len(self._sse_subscribers)

    async def register(
        self,
        proxy_name: str,
        instance_id: str,
        config_summary: dict[str, Any],
        socket_path: str,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> bool:
        """Register a proxy connection.

        Args:
            proxy_name: Name of the proxy.
            instance_id: Unique instance ID.
            config_summary: Proxy configuration summary.
            socket_path: Path to proxy's UDS API socket for HTTP routing.
            reader: Stream reader for the connection.
            writer: Stream writer for the connection.

        Returns:
            True if registered successfully, False if name already taken.
        """
        async with self._lock:
            # Check for existing connection with same name
            if proxy_name in self._proxies:
                existing = self._proxies[proxy_name]
                _logger.warning(
                    {
                        "event": "proxy_replaced",
                        "message": f"Proxy '{proxy_name}' already registered. Replacing with new connection",
                        "proxy_name": proxy_name,
                        "instance_id": instance_id,
                        "details": {
                            "old_instance_id": existing.instance_id,
                        },
                    }
                )
                # Close old connection
                await self._close_connection(existing)

            conn = ProxyConnection(
                proxy_name=proxy_name,
                instance_id=instance_id,
                config_summary=config_summary,
                connected_at=datetime.now(timezone.utc),
                socket_path=socket_path,
                writer=writer,
                reader=reader,
            )
            self._proxies[proxy_name] = conn

            _logger.info(
                {
                    "event": "proxy_registered",
                    "message": f"Proxy registered: {proxy_name}",
                    "proxy_name": proxy_name,
                    "instance_id": instance_id,
                    "socket_path": socket_path,
                }
            )

        # Broadcast registration event to browsers
        await self._broadcast_sse_event(
            "proxy_registered",
            {
                "proxy_name": proxy_name,
                "instance_id": instance_id,
            },
        )

        return True

    async def deregister(self, proxy_name: str) -> bool:
        """Deregister a proxy connection.

        Args:
            proxy_name: Name of the proxy to deregister.

        Returns:
            True if deregistered, False if not found.
        """
        async with self._lock:
            if proxy_name not in self._proxies:
                return False

            conn = self._proxies.pop(proxy_name)
            instance_id = conn.instance_id
            await self._close_connection(conn)

            _logger.info(
                {
                    "event": "proxy_disconnected",
                    "message": f"Proxy deregistered: {proxy_name}",
                    "proxy_name": proxy_name,
                    "instance_id": instance_id,
                }
            )

        # Broadcast disconnection event to browsers
        await self._broadcast_sse_event(
            "proxy_disconnected",
            {
                "proxy_name": proxy_name,
                "instance_id": instance_id,
            },
        )

        return True

    async def get_proxy(self, proxy_name: str) -> ProxyConnection | None:
        """Get a proxy connection by name."""
        async with self._lock:
            return self._proxies.get(proxy_name)

    async def list_proxies(self) -> list[dict[str, Any]]:
        """List all connected proxies."""
        async with self._lock:
            return [conn.to_dict() for conn in self._proxies.values()]

    async def proxy_count(self) -> int:
        """Get count of connected proxies."""
        async with self._lock:
            return len(self._proxies)

    async def broadcast_proxy_event(
        self,
        proxy_name: str,
        event_type: str,
        data: dict[str, Any],
    ) -> None:
        """Broadcast an event from a proxy to all SSE subscribers.

        Adds proxy_name to the event data for client-side filtering.

        Args:
            proxy_name: Source proxy name.
            event_type: Type of event (e.g., "pending_created").
            data: Event payload.
        """
        await self._broadcast_sse_event(
            event_type,
            {**data, "proxy_name": proxy_name},
        )

    async def broadcast_snapshot(
        self,
        event_type: str,
        data: dict[str, Any],
    ) -> None:
        """Broadcast a snapshot event to all SSE subscribers.

        Used by manager to send initial state snapshots (pending approvals,
        cached approvals, stats) when a proxy registers.

        Args:
            event_type: Type of snapshot (e.g., "snapshot", "cached_snapshot").
            data: Snapshot payload.
        """
        await self._broadcast_sse_event(event_type, data)

    async def subscribe_sse(self) -> asyncio.Queue[dict[str, Any]]:
        """Subscribe to SSE events.

        Returns:
            Queue that will receive all events.
        """
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        async with self._sse_lock:
            self._sse_subscribers.append(queue)

        # Notify proxies that browser connected
        await self.broadcast_ui_status()

        return queue

    async def unsubscribe_sse(self, queue: asyncio.Queue[dict[str, Any]]) -> None:
        """Unsubscribe from SSE events."""
        async with self._sse_lock:
            if queue in self._sse_subscribers:
                self._sse_subscribers.remove(queue)

        # Notify proxies that browser may have disconnected
        await self.broadcast_ui_status()

    async def broadcast_ui_status(self) -> None:
        """Broadcast current UI connection status to all registered proxies.

        Sends ui_status message to each proxy with current browser connectivity
        and subscriber count. This allows proxies to know whether web UI is
        available for HITL approvals.

        Called when SSE subscribers connect/disconnect.
        """
        from mcp_acp.manager.protocol import encode_ndjson

        browser_connected = len(self._sse_subscribers) > 0
        subscriber_count = len(self._sse_subscribers)

        msg = {
            "type": "ui_status",
            "browser_connected": browser_connected,
            "subscriber_count": subscriber_count,
        }
        msg_bytes = encode_ndjson(msg)

        async with self._lock:
            for conn in self._proxies.values():
                try:
                    conn.writer.write(msg_bytes)
                    await conn.writer.drain()
                except (ConnectionResetError, BrokenPipeError, OSError):
                    # Proxy will be cleaned up by its handler
                    pass

    async def _broadcast_sse_event(
        self,
        event_type: str,
        data: dict[str, Any],
    ) -> None:
        """Broadcast an event to all SSE subscribers."""
        event = {
            "type": event_type,
            "data": data,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        async with self._sse_lock:
            for queue in self._sse_subscribers:
                try:
                    queue.put_nowait(event)
                except asyncio.QueueFull:
                    _logger.warning(
                        {
                            "event": "sse_queue_full",
                            "message": "SSE subscriber queue full, dropping event",
                            "subscriber_count": len(self._sse_subscribers),
                        }
                    )

    async def _close_connection(self, conn: ProxyConnection) -> None:
        """Close a proxy connection."""
        try:
            if conn._event_task:
                conn._event_task.cancel()
            conn.writer.close()
            await conn.writer.wait_closed()
        except OSError:
            pass  # Already closed

    async def close_all(self) -> None:
        """Close all proxy connections."""
        async with self._lock:
            for conn in list(self._proxies.values()):
                await self._close_connection(conn)
            self._proxies.clear()


# Global registry singleton
_registry: ProxyRegistry | None = None


def get_proxy_registry() -> ProxyRegistry:
    """Get the global proxy registry singleton."""
    global _registry
    if _registry is None:
        _registry = ProxyRegistry()
    return _registry
