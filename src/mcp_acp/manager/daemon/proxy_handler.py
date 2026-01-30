"""UDS proxy protocol and heartbeat handling.

Handles:
- Proxy registration over Unix domain socket
- Event forwarding from proxies to browsers
- Heartbeat messages to keep connections alive
- Snapshot broadcasting after registration
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

from mcp_acp.constants import DEFAULT_APPROVAL_TTL_SECONDS
from mcp_acp.manager.models import ManagerSystemEvent
from mcp_acp.manager.protocol import decode_ndjson, encode_ndjson
from mcp_acp.manager.registry import ProxyRegistry
from mcp_acp.manager.routes import PROXY_SNAPSHOT_TIMEOUT_SECONDS, create_uds_client
from mcp_acp.manager.token_service import ManagerTokenService

from .log_config import log_event

__all__ = [
    "handle_proxy_connection",
    "send_heartbeats_to_proxies",
]

# Timeout for proxy registration handshake (seconds)
PROXY_REGISTRATION_TIMEOUT_SECONDS = 10.0

# How often to send heartbeats to proxies (seconds)
PROXY_HEARTBEAT_INTERVAL_SECONDS = 30.0


async def handle_proxy_connection(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    registry: ProxyRegistry,
    token_service: ManagerTokenService | None = None,
) -> None:
    """Handle a proxy connection to the UDS server.

    Protocol:
    1. Proxy sends registration message
    2. Manager validates and acknowledges
    3. Connection stays open for event forwarding

    Args:
        reader: Stream reader for incoming data.
        writer: Stream writer for responses.
        registry: Proxy registry to register with.
        token_service: Token service for sending initial token (optional).
    """
    proxy_name: str | None = None

    try:
        # Read registration message
        line = await asyncio.wait_for(reader.readline(), timeout=PROXY_REGISTRATION_TIMEOUT_SECONDS)
        if not line:
            return

        msg = decode_ndjson(line)
        if msg is None:
            log_event(
                logging.WARNING,
                ManagerSystemEvent(
                    event="registration_invalid_json",
                    message="Invalid JSON in registration",
                ),
            )
            await _send_error(writer, "Invalid JSON")
            return

        # Validate registration message
        if msg.get("type") != "register":
            log_event(
                logging.WARNING,
                ManagerSystemEvent(
                    event="registration_wrong_type",
                    message=f"Expected 'register' message, got: {msg.get('type')}",
                ),
            )
            await _send_error(writer, "Expected 'register' message")
            return

        proxy_name = msg.get("proxy_name")
        proxy_id = msg.get("proxy_id")
        instance_id = msg.get("instance_id")
        config_summary = msg.get("config_summary", {})
        socket_path = msg.get("socket_path", "")

        if not proxy_id or not proxy_name or not instance_id:
            log_event(
                logging.WARNING,
                ManagerSystemEvent(
                    event="registration_missing_fields",
                    message="Missing proxy_id, proxy_name, or instance_id in registration",
                ),
            )
            await _send_error(writer, "Missing proxy_id, proxy_name, or instance_id")
            return

        if not socket_path:
            log_event(
                logging.WARNING,
                ManagerSystemEvent(
                    event="registration_missing_socket",
                    message="Missing socket_path in registration",
                    proxy_name=proxy_name,
                    instance_id=instance_id,
                ),
            )
            await _send_error(writer, "Missing socket_path")
            return

        # Register the proxy
        await registry.register(
            proxy_name=proxy_name,
            proxy_id=proxy_id,
            instance_id=instance_id,
            config_summary=config_summary,
            socket_path=socket_path,
            reader=reader,
            writer=writer,
        )

        # Send acknowledgment
        ack = {"type": "registered", "ok": True}
        await _send_message(writer, ack)

        # Send initial UI status to proxy so it knows browser connectivity
        await _send_ui_status_to_proxy(writer, registry)

        # Send initial token to proxy if available (multi-proxy token distribution)
        if token_service is not None:
            await token_service.send_token_to_proxy(writer)

        # Fetch initial state from proxy and broadcast to browsers
        await _broadcast_proxy_snapshot(socket_path, registry)

        # Now listen for events from proxy
        await _handle_proxy_events(reader, proxy_name, registry)

    except asyncio.TimeoutError:
        log_event(
            logging.WARNING,
            ManagerSystemEvent(
                event="registration_timeout",
                message="Proxy connection timed out during registration",
            ),
        )
    except (ConnectionResetError, BrokenPipeError, OSError) as e:
        log_event(
            logging.WARNING,
            ManagerSystemEvent(
                event="proxy_connection_error",
                message=f"Proxy connection error: {e}",
                error_type=type(e).__name__,
                error_message=str(e),
            ),
        )
    finally:
        # Deregister on disconnect
        if proxy_name:
            await registry.deregister(proxy_name)
        try:
            writer.close()
            await writer.wait_closed()
        except OSError:
            pass


async def _broadcast_proxy_snapshot(
    socket_path: str,
    registry: ProxyRegistry,
) -> None:
    """Fetch proxy state and broadcast to all SSE subscribers.

    Called after proxy registration so browsers get immediate update.

    Args:
        socket_path: Path to proxy's UDS API socket.
        registry: Proxy registry for broadcasting events.
    """
    try:
        async with create_uds_client(
            socket_path,
            timeout=PROXY_SNAPSHOT_TIMEOUT_SECONDS,
        ) as client:
            # Fetch pending approvals
            try:
                pending_resp = await client.get("/api/approvals/pending/list")
                if pending_resp.status_code == 200:
                    pending = pending_resp.json()
                    await registry.broadcast_snapshot(
                        "snapshot",
                        {"approvals": pending},
                    )
            except (httpx.HTTPError, httpx.TimeoutException):
                pass  # Expected during startup race

            # Fetch cached approvals
            try:
                cached_resp = await client.get("/api/approvals/cached")
                if cached_resp.status_code == 200:
                    cached = cached_resp.json()
                    await registry.broadcast_snapshot(
                        "cached_snapshot",
                        {
                            "approvals": cached.get("approvals", []),
                            "ttl_seconds": cached.get("ttl_seconds", DEFAULT_APPROVAL_TTL_SECONDS),
                            "count": cached.get("count", 0),
                        },
                    )
            except (httpx.HTTPError, httpx.TimeoutException):
                pass  # Expected during startup race

            # Fetch stats (from /api/proxies, stats are included in proxy response)
            try:
                proxies_resp = await client.get("/api/proxies")
                if proxies_resp.status_code == 200:
                    proxies = proxies_resp.json()
                    if proxies and len(proxies) > 0:
                        stats = proxies[0].get("stats")
                        if stats:
                            await registry.broadcast_snapshot(
                                "stats_updated",
                                {"stats": stats},
                            )
            except (httpx.HTTPError, httpx.TimeoutException):
                pass  # Expected during startup race

    except (httpx.ConnectError, OSError) as e:
        log_event(
            logging.WARNING,
            ManagerSystemEvent(
                event="snapshot_broadcast_failed",
                message="Failed to broadcast proxy snapshot",
                socket_path=socket_path,
                error_type=type(e).__name__,
                error_message=str(e),
            ),
        )


async def _handle_proxy_events(
    reader: asyncio.StreamReader,
    proxy_name: str,
    registry: ProxyRegistry,
) -> None:
    """Handle event messages from a registered proxy.

    Args:
        reader: Stream reader for incoming data.
        proxy_name: Name of the proxy sending events.
        registry: Proxy registry for event broadcasting.
    """
    while True:
        try:
            line = await reader.readline()
            if not line:
                break

            msg = decode_ndjson(line)
            if msg is None:
                log_event(
                    logging.WARNING,
                    ManagerSystemEvent(
                        event="proxy_invalid_json",
                        message=f"Invalid JSON from proxy '{proxy_name}'",
                        proxy_name=proxy_name,
                    ),
                )
                continue

            if msg.get("type") == "event":
                event_type = msg.get("event_type", "unknown")
                data = msg.get("data", {})
                await registry.broadcast_proxy_event(proxy_name, event_type, data)
            else:
                log_event(
                    logging.WARNING,
                    ManagerSystemEvent(
                        event="proxy_unknown_message",
                        message=f"Unknown message type from proxy '{proxy_name}': {msg.get('type')}",
                        proxy_name=proxy_name,
                    ),
                )

        except (ConnectionResetError, BrokenPipeError, OSError):
            break


async def _send_message(writer: asyncio.StreamWriter, msg: dict[str, Any]) -> None:
    """Send a JSON message over the connection."""
    writer.write(encode_ndjson(msg))
    await writer.drain()


async def _send_error(writer: asyncio.StreamWriter, error: str) -> None:
    """Send an error response."""
    await _send_message(writer, {"type": "registered", "ok": False, "error": error})


async def _send_ui_status_to_proxy(
    writer: asyncio.StreamWriter,
    registry: ProxyRegistry,
) -> None:
    """Send current UI connection status to a proxy.

    Args:
        writer: Stream writer for the proxy connection.
        registry: Proxy registry to get subscriber count from.
    """
    browser_connected = registry.sse_subscriber_count > 0
    msg = {
        "type": "ui_status",
        "browser_connected": browser_connected,
        "subscriber_count": registry.sse_subscriber_count,
    }
    try:
        await _send_message(writer, msg)
    except (ConnectionResetError, BrokenPipeError, OSError):
        pass  # Proxy will be cleaned up by its handler


async def send_heartbeats_to_proxies(registry: ProxyRegistry) -> None:
    """Periodically send heartbeats to all connected proxies.

    Runs as a background task. Sends heartbeat message to each proxy
    every PROXY_HEARTBEAT_INTERVAL_SECONDS.

    Args:
        registry: Proxy registry containing connected proxies.
    """
    heartbeat_msg = encode_ndjson({"type": "heartbeat"})

    while True:
        await asyncio.sleep(PROXY_HEARTBEAT_INTERVAL_SECONDS)

        # Get all proxy connections and send heartbeat
        proxies = await registry.list_proxies()
        for proxy_info in proxies:
            proxy_name = proxy_info.get("name")
            if proxy_name:
                conn = await registry.get_proxy(proxy_name)
                if conn is not None:
                    try:
                        conn.writer.write(heartbeat_msg)
                        await conn.writer.drain()
                    except (ConnectionResetError, BrokenPipeError, OSError):
                        # Proxy disconnected - will be cleaned up by its handler
                        pass
