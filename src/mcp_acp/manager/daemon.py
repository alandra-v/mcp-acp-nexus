"""Manager daemon for serving UI and coordinating proxies.

The manager daemon:
- Serves the web UI (React app) on HTTP port 8765
- Listens on UDS (manager.sock) for proxy registrations (Step 3.2)
- Aggregates SSE events from all proxies (Step 3.3)
- Routes API requests to proxies (Step 3.4)

This module implements Step 3.1: Manager Daemon Skeleton
- HTTP server serving static UI
- UDS server ready for connections
- PID file management
- Graceful shutdown

Lifecycle:
- Started via `mcp-acp manager start` or auto-started by proxy
- Runs as a daemon (survives parent process exit)
- Stopped via `mcp-acp manager stop` or SIGTERM
"""

from __future__ import annotations

__all__ = [
    "run_manager",
    "is_manager_running",
    "get_manager_pid",
    "stop_manager",
]

import asyncio
import errno
import json
import logging
import os
import secrets
import signal
import socket
from pathlib import Path
from typing import Any

import httpx
import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse

from mcp_acp.constants import (
    API_SERVER_SHUTDOWN_TIMEOUT_SECONDS,
    DEFAULT_API_PORT,
    MANAGER_PID_PATH,
    MANAGER_SOCKET_PATH,
    RUNTIME_DIR,
    SOCKET_CONNECT_TIMEOUT_SECONDS,
)
from mcp_acp.manager.config import (
    ManagerConfig,
    get_manager_system_log_path,
    load_manager_config,
)
from mcp_acp.manager.registry import ProxyRegistry, get_proxy_registry
from mcp_acp.utils.logging.iso_formatter import ISO8601Formatter

# Static files directory (built React app) - same as proxy uses
STATIC_DIR = Path(__file__).parent.parent / "web" / "static"

# Token length for API authentication (32 bytes = 64 hex chars)
API_TOKEN_BYTES = 32

# HTTP server backlog (number of pending connections)
HTTP_LISTEN_BACKLOG = 100

# Protocol version for proxy registration
PROTOCOL_VERSION = 1

# Media type mapping for static file serving
STATIC_MEDIA_TYPES: dict[str, str] = {
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".json": "application/json",
    ".js": "application/javascript",
    ".css": "text/css",
    ".woff": "font/woff",
    ".woff2": "font/woff2",
    ".ttf": "font/ttf",
    ".map": "application/json",
}

# Get module logger - initially with stderr only
# File handler added via _configure_manager_logging() after config is loaded
_logger = logging.getLogger("mcp-acp.manager")
_logger.setLevel(logging.INFO)
_logger.propagate = False

# Track if file logging has been configured
_file_handler_configured: bool = False


class _ConsoleFormatter(logging.Formatter):
    """Human-readable formatter for console output."""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record for console output."""
        if isinstance(record.msg, dict):
            msg = record.msg.get("message") or record.msg.get("event", "")
            return f"{record.levelname}: {msg}"
        # Use getMessage() to substitute %s placeholders with args
        return f"{record.levelname}: {record.getMessage()}"


def _configure_manager_logging(config: ManagerConfig) -> None:
    """Configure manager logging with file handler.

    Sets up:
    - stderr handler: INFO+ for operator visibility
    - file handler: WARNING+ for persistent issue tracking

    Args:
        config: Manager configuration with log directory.
    """
    global _file_handler_configured

    if _file_handler_configured:
        return

    # Clear any existing handlers
    _logger.handlers.clear()

    # Add stderr handler (INFO+)
    stderr_handler = logging.StreamHandler()
    stderr_handler.setLevel(logging.INFO)
    stderr_handler.setFormatter(_ConsoleFormatter())
    _logger.addHandler(stderr_handler)

    # Add file handler (WARNING+)
    log_path = get_manager_system_log_path(config)
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.parent.chmod(0o700)
    except OSError:
        pass  # stderr will still work

    try:
        file_handler = logging.FileHandler(log_path, mode="a", encoding="utf-8")
        file_handler.setLevel(logging.WARNING)
        file_handler.setFormatter(ISO8601Formatter())
        _logger.addHandler(file_handler)
        _file_handler_configured = True
    except OSError as e:
        _logger.warning("Failed to configure file logging: %s", e)


# Initialize with stderr-only until config is loaded
if not _logger.handlers:
    _stderr_handler = logging.StreamHandler()
    _stderr_handler.setFormatter(_ConsoleFormatter())
    _logger.addHandler(_stderr_handler)


# =============================================================================
# Response Models (FastAPI best practice)
# =============================================================================


class ManagerStatusResponse(BaseModel):
    """Response model for manager status endpoint."""

    running: bool
    pid: int
    proxies_connected: int


class RegisteredProxyInfo(BaseModel):
    """API response model for a registered proxy.

    Note: This is distinct from manager.state.ProxyInfo which contains
    full proxy runtime information. This model is for manager API responses.
    """

    name: str
    instance_id: str
    connected: bool


# =============================================================================
# PID and Socket Helpers
# =============================================================================


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


def _test_socket_connection(socket_path: Path) -> bool:
    """Test if a Unix socket is accepting connections.

    Args:
        socket_path: Path to the Unix socket.

    Returns:
        True if socket accepts connection, False otherwise.
    """
    from mcp_acp.manager.utils import test_socket_connection

    return test_socket_connection(socket_path)


def is_manager_running() -> bool:
    """Check if manager daemon is running.

    Checks both PID file validity and socket connectivity.

    Returns:
        True if manager is running and accepting connections.
    """
    pid = _read_pid_file()
    if pid is None:
        return False

    return _test_socket_connection(MANAGER_SOCKET_PATH)


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


def _cleanup_stale_socket() -> None:
    """Remove stale manager socket file if exists and not connectable.

    Raises:
        RuntimeError: If socket is connectable (manager already running).
    """
    if not MANAGER_SOCKET_PATH.exists():
        return

    if _test_socket_connection(MANAGER_SOCKET_PATH):
        raise RuntimeError(f"Manager is already running (socket: {MANAGER_SOCKET_PATH})")

    # Stale socket, remove it
    MANAGER_SOCKET_PATH.unlink(missing_ok=True)
    _logger.debug("Removed stale socket: %s", MANAGER_SOCKET_PATH)


def _cleanup_stale_pid() -> None:
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
    _logger.debug("Removed stale PID file: %s", MANAGER_PID_PATH)


def _write_pid_file() -> None:
    """Write current process PID to PID file."""
    MANAGER_PID_PATH.write_text(str(os.getpid()))
    _logger.debug("Wrote PID file: %s (pid=%d)", MANAGER_PID_PATH, os.getpid())


def _remove_pid_file() -> None:
    """Remove PID file if it exists."""
    MANAGER_PID_PATH.unlink(missing_ok=True)


def _is_port_in_use(port: int) -> bool:
    """Check if TCP port is accepting connections.

    Args:
        port: TCP port number to check.

    Returns:
        True if port is in use, False otherwise.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("127.0.0.1", port)) == 0


def _is_safe_path(base_dir: Path, requested_path: Path) -> bool:
    """Check if requested path is safely within base directory.

    Prevents path traversal attacks (e.g., ../../etc/passwd).

    Args:
        base_dir: Base directory that should contain the path.
        requested_path: Path to validate.

    Returns:
        True if path is safely within base_dir.
    """
    try:
        # Resolve both paths to absolute, normalized paths
        base_resolved = base_dir.resolve()
        requested_resolved = requested_path.resolve()
        # Check if requested path starts with base path
        return requested_resolved.is_relative_to(base_resolved)
    except (ValueError, RuntimeError):
        return False


# =============================================================================
# Proxy Registration Protocol
# =============================================================================


async def _handle_proxy_connection(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    registry: ProxyRegistry,
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
    """
    proxy_name: str | None = None
    peername = writer.get_extra_info("peername")
    _logger.debug("New proxy connection from %s", peername)

    try:
        # Read registration message
        line = await asyncio.wait_for(reader.readline(), timeout=10.0)
        if not line:
            _logger.debug("Proxy disconnected before registration")
            return

        try:
            msg = json.loads(line.decode("utf-8"))
        except json.JSONDecodeError as e:
            _logger.warning("Invalid JSON in registration: %s", e)
            await _send_error(writer, "Invalid JSON")
            return

        # Validate registration message
        if msg.get("type") != "register":
            _logger.warning("Expected 'register' message, got: %s", msg.get("type"))
            await _send_error(writer, "Expected 'register' message")
            return

        protocol_version = msg.get("protocol_version")
        if protocol_version != PROTOCOL_VERSION:
            _logger.warning(
                "Incompatible protocol version: %s (expected %s)",
                protocol_version,
                PROTOCOL_VERSION,
            )
            await _send_error(
                writer,
                f"Incompatible protocol version {protocol_version} (expected {PROTOCOL_VERSION})",
            )
            return

        proxy_name = msg.get("proxy_name")
        instance_id = msg.get("instance_id")
        config_summary = msg.get("config_summary", {})
        socket_path = msg.get("socket_path", "")

        if not proxy_name or not instance_id:
            _logger.warning("Missing proxy_name or instance_id in registration")
            await _send_error(writer, "Missing proxy_name or instance_id")
            return

        if not socket_path:
            _logger.warning("Missing socket_path in registration")
            await _send_error(writer, "Missing socket_path")
            return

        # Register the proxy
        await registry.register(
            proxy_name=proxy_name,
            instance_id=instance_id,
            config_summary=config_summary,
            socket_path=socket_path,
            reader=reader,
            writer=writer,
        )

        # Send acknowledgment
        ack = {"type": "registered", "ok": True}
        await _send_message(writer, ack)

        # Fetch initial state from proxy and broadcast to browsers
        await _broadcast_proxy_snapshot(socket_path, registry)

        # Now listen for events from proxy
        await _handle_proxy_events(reader, proxy_name, registry)

    except asyncio.TimeoutError:
        _logger.debug("Proxy connection timed out during registration")
    except (ConnectionResetError, BrokenPipeError, OSError) as e:
        _logger.debug("Proxy connection error: %s", e)
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
        transport = httpx.AsyncHTTPTransport(uds=socket_path)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://localhost",
            timeout=5.0,
        ) as client:
            # Fetch pending approvals
            try:
                pending_resp = await client.get("/api/approvals/pending/list")
                if pending_resp.status_code == 200:
                    pending = pending_resp.json()
                    await registry._broadcast_sse_event(
                        "snapshot",
                        {"approvals": pending},
                    )
            except Exception as e:
                _logger.debug("Failed to fetch pending approvals: %s", e)

            # Fetch cached approvals
            try:
                cached_resp = await client.get("/api/approvals/cached")
                if cached_resp.status_code == 200:
                    cached = cached_resp.json()
                    await registry._broadcast_sse_event(
                        "cached_snapshot",
                        {
                            "approvals": cached.get("approvals", []),
                            "ttl_seconds": cached.get("ttl_seconds", 600),
                            "count": cached.get("count", 0),
                        },
                    )
            except Exception as e:
                _logger.debug("Failed to fetch cached approvals: %s", e)

            # Fetch stats
            try:
                stats_resp = await client.get("/api/debug/stats")
                if stats_resp.status_code == 200:
                    stats = stats_resp.json()
                    await registry._broadcast_sse_event(
                        "stats_updated",
                        {"stats": stats},
                    )
            except Exception as e:
                _logger.debug("Failed to fetch stats: %s", e)

    except Exception as e:
        _logger.warning("Failed to broadcast proxy snapshot: %s", e)


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
                # Connection closed
                _logger.debug("Proxy '%s' connection closed", proxy_name)
                break

            try:
                msg = json.loads(line.decode("utf-8"))
            except json.JSONDecodeError as e:
                _logger.warning("Invalid JSON from proxy '%s': %s", proxy_name, e)
                continue

            if msg.get("type") == "event":
                event_type = msg.get("event_type", "unknown")
                data = msg.get("data", {})
                await registry.broadcast_proxy_event(proxy_name, event_type, data)
            else:
                _logger.debug(
                    "Unknown message type from proxy '%s': %s",
                    proxy_name,
                    msg.get("type"),
                )

        except (ConnectionResetError, BrokenPipeError, OSError):
            break


async def _send_message(writer: asyncio.StreamWriter, msg: dict[str, Any]) -> None:
    """Send a JSON message over the connection."""
    line = json.dumps(msg, separators=(",", ":")) + "\n"
    writer.write(line.encode("utf-8"))
    await writer.drain()


async def _send_error(writer: asyncio.StreamWriter, error: str) -> None:
    """Send an error response."""
    await _send_message(writer, {"type": "registered", "ok": False, "error": error})


# =============================================================================
# FastAPI Application
# =============================================================================


def _create_manager_api_app(
    token: str | None = None,
    registry: ProxyRegistry | None = None,
) -> FastAPI:
    """Create the FastAPI application for manager.

    Serves static UI and manager-level API endpoints.

    Args:
        token: Bearer token for API authentication. None for UDS (OS auth).
        registry: Proxy registry for API endpoints.

    Returns:
        Configured FastAPI application.
    """
    app = FastAPI(
        title="MCP-ACP Manager",
        description="Manager daemon for MCP-ACP proxies",
        version="0.1.0",
    )

    # Store token and registry
    app.state.api_token = token
    app.state.registry = registry or get_proxy_registry()

    # TODO (Phase 4): Add SecurityMiddleware when auth moves to manager

    @app.get("/api/manager/status", response_model=ManagerStatusResponse)
    async def manager_status(request: Request) -> ManagerStatusResponse:
        """Get manager health status."""
        reg: ProxyRegistry = request.app.state.registry
        return ManagerStatusResponse(
            running=True,
            pid=os.getpid(),
            proxies_connected=await reg.proxy_count(),
        )

    @app.get("/api/manager/proxies")
    async def list_registered_proxies(request: Request) -> list[dict[str, Any]]:
        """List all registered proxies (manager's view).

        Returns registration info (name, instance_id, socket_path).
        For full proxy details (transport, stats), use /api/proxies which
        routes to the proxy itself.
        """
        reg: ProxyRegistry = request.app.state.registry
        return await reg.list_proxies()

    @app.get("/api/events")
    async def sse_events(request: Request) -> EventSourceResponse:
        """SSE endpoint for aggregated proxy events.

        Event format matches proxy's format for UI compatibility:
        - `data: {"type": "...", ...}` (type embedded in data JSON)
        - No named SSE events (uses onmessage handler)
        - Events include `proxy_name` for multi-proxy filtering

        On connect, sends initial snapshots by fetching from proxy via UDS.
        """
        reg: ProxyRegistry = request.app.state.registry

        async def event_generator() -> Any:
            # Send initial snapshots from proxy (if connected)
            proxy_conn = await reg.get_proxy("default")
            sent_pending_snapshot = False

            if proxy_conn and proxy_conn.socket_path:
                try:
                    # Fetch initial state from proxy via UDS
                    transport = httpx.AsyncHTTPTransport(uds=proxy_conn.socket_path)
                    async with httpx.AsyncClient(
                        transport=transport,
                        base_url="http://localhost",
                        timeout=5.0,
                    ) as client:
                        # Fetch pending approvals
                        try:
                            pending_resp = await client.get("/api/approvals/pending/list")
                            if pending_resp.status_code == 200:
                                pending = pending_resp.json()
                                yield {"data": json.dumps({"type": "snapshot", "approvals": pending})}
                                sent_pending_snapshot = True
                        except Exception as e:
                            _logger.debug("Failed to fetch pending approvals: %s", e)

                        # Fetch cached approvals
                        try:
                            cached_resp = await client.get("/api/approvals/cached")
                            if cached_resp.status_code == 200:
                                cached = cached_resp.json()
                                yield {
                                    "data": json.dumps(
                                        {
                                            "type": "cached_snapshot",
                                            "approvals": cached.get("approvals", []),
                                            "ttl_seconds": cached.get("ttl_seconds", 600),
                                            "count": cached.get("count", 0),
                                        }
                                    )
                                }
                        except Exception as e:
                            _logger.debug("Failed to fetch cached approvals: %s", e)

                        # Fetch stats
                        try:
                            stats_resp = await client.get("/api/debug/stats")
                            if stats_resp.status_code == 200:
                                stats = stats_resp.json()
                                yield {"data": json.dumps({"type": "stats_updated", "stats": stats})}
                        except Exception as e:
                            _logger.debug("Failed to fetch stats: %s", e)

                except Exception as e:
                    _logger.debug("Failed to connect to proxy: %s", e)

            # Send empty snapshot only if we haven't sent one yet
            if not sent_pending_snapshot:
                yield {"data": json.dumps({"type": "snapshot", "approvals": []})}

            # Subscribe to ongoing events
            queue = await reg.subscribe_sse()
            try:
                while True:
                    # Check if client disconnected
                    if await request.is_disconnected():
                        break
                    try:
                        event = await asyncio.wait_for(queue.get(), timeout=30.0)
                        # Format: {"type": "...", ...data...} - matches proxy format
                        # UI uses event.data.type for routing
                        event_data = {
                            "type": event["type"],
                            **event["data"],
                        }
                        yield {"data": json.dumps(event_data)}
                    except asyncio.TimeoutError:
                        # Send keepalive (no type needed, UI ignores empty data)
                        yield {"data": ""}
            finally:
                await reg.unsubscribe_sse(queue)

        return EventSourceResponse(event_generator())

    # ==========================================================================
    # API Routing: Forward /api/proxy/{name}/* to proxy's UDS socket
    # ==========================================================================

    @app.api_route(
        "/api/proxy/{proxy_name}/{path:path}",
        methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    )
    async def route_to_proxy(
        proxy_name: str,
        path: str,
        request: Request,
    ) -> Response:
        """Route API requests to the appropriate proxy.

        Manager forwards /api/proxy/{name}/* requests to the proxy's UDS socket.
        The path after /api/proxy/{name}/ becomes /api/{path} on the proxy.

        Args:
            proxy_name: Name of the target proxy (e.g., "default").
            path: Remaining path after proxy name (e.g., "approvals/pending").
            request: Incoming FastAPI request.

        Returns:
            Response from the proxy, or error response if proxy unavailable.
        """
        reg: ProxyRegistry = request.app.state.registry

        # Look up proxy in registry
        proxy_conn = await reg.get_proxy(proxy_name)
        if proxy_conn is None:
            return JSONResponse(
                status_code=404,
                content={"error": f"Proxy '{proxy_name}' not found"},
            )

        socket_path = proxy_conn.socket_path
        if not socket_path or not Path(socket_path).exists():
            return JSONResponse(
                status_code=503,
                content={"error": f"Proxy '{proxy_name}' socket not available"},
            )

        # Build target URL (proxy expects /api/... paths)
        target_path = f"/api/{path}"
        if request.url.query:
            target_path = f"{target_path}?{request.url.query}"

        # Forward request to proxy via UDS
        try:
            # Create httpx transport for UDS
            transport = httpx.AsyncHTTPTransport(uds=socket_path)

            async with httpx.AsyncClient(
                transport=transport,
                base_url="http://localhost",  # Required but not used for UDS
                timeout=30.0,
            ) as client:
                # Read body for POST/PUT/PATCH
                body = await request.body() if request.method in ("POST", "PUT", "PATCH") else None

                # Forward headers (filter out hop-by-hop headers)
                forward_headers = {
                    k: v
                    for k, v in request.headers.items()
                    if k.lower() not in ("host", "connection", "transfer-encoding")
                }

                # Make request to proxy
                response = await client.request(
                    method=request.method,
                    url=target_path,
                    content=body,
                    headers=forward_headers,
                )

                # Return proxy response
                return Response(
                    content=response.content,
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    media_type=response.headers.get("content-type"),
                )

        except httpx.ConnectError:
            _logger.warning("Failed to connect to proxy '%s' at %s", proxy_name, socket_path)
            return JSONResponse(
                status_code=503,
                content={"error": f"Proxy '{proxy_name}' connection failed"},
            )
        except httpx.TimeoutException:
            _logger.warning("Timeout connecting to proxy '%s'", proxy_name)
            return JSONResponse(
                status_code=504,
                content={"error": f"Proxy '{proxy_name}' request timed out"},
            )
        except Exception as e:
            _logger.error("Error routing to proxy '%s': %s", proxy_name, e)
            return JSONResponse(
                status_code=500,
                content={"error": f"Internal error routing to proxy: {type(e).__name__}"},
            )

    # ==========================================================================
    # Fallback: Route /api/* (non-manager endpoints) to default proxy
    # ==========================================================================
    # Manager-level endpoints: /api/manager/*, /api/proxies, /api/events
    # Everything else is forwarded to the "default" proxy for backwards compatibility
    # This allows existing UI code to work without changes in Phase 3

    MANAGER_API_PREFIXES = ("/api/manager/", "/api/events", "/api/proxy/")

    @app.api_route(
        "/api/{path:path}",
        methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    )
    async def fallback_to_default_proxy(path: str, request: Request) -> Response:
        """Fallback: route unhandled /api/* requests to default proxy.

        This provides backwards compatibility - existing UI code that uses
        /api/approvals, /api/policy, etc. is automatically routed to the
        default proxy without URL changes.

        Manager-level endpoints (/api/manager/*, /api/proxies, /api/events)
        are handled by explicit routes above and won't hit this fallback.

        Args:
            path: Path after /api/ (e.g., "approvals/pending").
            request: Incoming FastAPI request.

        Returns:
            Response from the default proxy, or 404 if no proxy registered.
        """
        # Check if this should be handled by explicit manager routes
        # (This shouldn't happen due to route ordering, but defensive)
        full_path = f"/api/{path}"
        for prefix in MANAGER_API_PREFIXES:
            if full_path.startswith(prefix):
                return JSONResponse(
                    status_code=404,
                    content={"error": "Not found"},
                )

        # Route to default proxy
        reg: ProxyRegistry = request.app.state.registry
        proxy_conn = await reg.get_proxy("default")
        if proxy_conn is None:
            return JSONResponse(
                status_code=503,
                content={
                    "error": "No proxy connected",
                    "detail": "Proxy 'default' is not registered with the manager. "
                    "Start a proxy to enable API access.",
                },
            )

        socket_path = proxy_conn.socket_path
        if not socket_path or not Path(socket_path).exists():
            return JSONResponse(
                status_code=503,
                content={"error": "Proxy socket not available"},
            )

        # Build target URL (proxy expects /api/... paths)
        target_path = f"/api/{path}"
        if request.url.query:
            target_path = f"{target_path}?{request.url.query}"

        # Forward request to proxy via UDS
        try:
            transport = httpx.AsyncHTTPTransport(uds=socket_path)

            async with httpx.AsyncClient(
                transport=transport,
                base_url="http://localhost",
                timeout=30.0,
            ) as client:
                body = await request.body() if request.method in ("POST", "PUT", "PATCH") else None
                forward_headers = {
                    k: v
                    for k, v in request.headers.items()
                    if k.lower() not in ("host", "connection", "transfer-encoding")
                }

                response = await client.request(
                    method=request.method,
                    url=target_path,
                    content=body,
                    headers=forward_headers,
                )

                return Response(
                    content=response.content,
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    media_type=response.headers.get("content-type"),
                )

        except httpx.ConnectError:
            return JSONResponse(
                status_code=503,
                content={"error": "Proxy connection failed"},
            )
        except httpx.TimeoutException:
            return JSONResponse(
                status_code=504,
                content={"error": "Proxy request timed out"},
            )
        except Exception as e:
            _logger.error("Error routing to default proxy: %s", e)
            return JSONResponse(
                status_code=500,
                content={"error": f"Internal error: {type(e).__name__}"},
            )

    # Serve static files (built React app)
    if STATIC_DIR.exists():
        index_file = STATIC_DIR / "index.html"
        if index_file.exists():

            @app.get("/{path:path}", response_model=None)
            async def serve_spa(path: str, request: Request) -> Response:
                """Serve static files or index.html for SPA routing.

                Args:
                    path: Requested URL path.
                    request: FastAPI request object.

                Returns:
                    Static file or index.html for SPA routes.
                """
                # Check for static files (root-level or in assets/)
                if path:
                    static_file = STATIC_DIR / path
                    # Security: Prevent path traversal attacks
                    if not _is_safe_path(STATIC_DIR, static_file):
                        _logger.warning("Path traversal attempt blocked: %s", path)
                        return HTMLResponse(
                            content="Not Found",
                            status_code=404,
                        )

                    if static_file.exists() and static_file.is_file():
                        suffix = static_file.suffix.lower()
                        media_type = STATIC_MEDIA_TYPES.get(suffix, "application/octet-stream")
                        cache_control = (
                            "public, max-age=31536000, immutable"
                            if path.startswith("assets/")
                            else "public, max-age=3600"
                        )
                        return FileResponse(
                            static_file,
                            media_type=media_type,
                            headers={"Cache-Control": cache_control},
                        )

                # SPA fallback: serve index.html
                html = index_file.read_text()
                api_token = getattr(request.app.state, "api_token", None)

                # TODO (Phase 4): Token injection for dev mode

                response = HTMLResponse(
                    content=html,
                    headers={"Cache-Control": "no-cache, no-store, must-revalidate"},
                )

                # Set HttpOnly cookie for browser authentication
                if api_token:
                    response.set_cookie(
                        key="api_token",
                        value=api_token,
                        httponly=True,
                        samesite="strict",
                        path="/api",
                    )

                return response

    return app


# =============================================================================
# Main Entry Point
# =============================================================================


async def run_manager(port: int | None = None) -> None:
    """Run the manager daemon.

    This is the main entry point for the manager process.
    It sets up HTTP and UDS servers and runs until shutdown.

    Args:
        port: HTTP port for UI. If None, uses config value (default: 8765).

    Raises:
        RuntimeError: If manager is already running or port is in use.
    """
    # Load configuration
    config = load_manager_config()

    # Configure file logging
    _configure_manager_logging(config)

    # Use provided port or config default
    effective_port = port if port is not None else config.ui_port

    # Suppress uvicorn's logging (we use our own)
    for logger_name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logging.getLogger(logger_name).setLevel(logging.CRITICAL)

    # Create runtime directory
    RUNTIME_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)

    # Check for stale files from previous crash
    _cleanup_stale_pid()
    _cleanup_stale_socket()

    # Check if port is in use
    if _is_port_in_use(effective_port):
        raise RuntimeError(
            f"Port {effective_port} is already in use.\n"
            f"Another process is using this port. "
            f"Use --port to specify a different port."
        )

    # Write PID file
    _write_pid_file()

    _logger.info(
        "Manager starting: port=%d, socket=%s, pid=%d",
        effective_port,
        MANAGER_SOCKET_PATH,
        os.getpid(),
    )

    # Track shutdown state
    shutdown_event = asyncio.Event()

    def signal_handler(signum: int, frame: object) -> None:
        """Handle shutdown signals (SIGTERM, SIGINT)."""
        _logger.info("Received signal %d, initiating shutdown", signum)
        shutdown_event.set()

    # Register signal handlers
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    # Create proxy registry
    registry = get_proxy_registry()

    # Generate API token for browser auth
    # TODO (Phase 4): Move to centralized auth
    api_token = secrets.token_hex(API_TOKEN_BYTES)

    # Create FastAPI app for HTTP
    http_app = _create_manager_api_app(token=api_token, registry=registry)

    # Create HTTP server
    http_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    http_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        http_socket.bind(("127.0.0.1", effective_port))
    except OSError as e:
        _remove_pid_file()
        if e.errno == errno.EADDRINUSE:
            raise RuntimeError(
                f"Port {effective_port} is already in use.\n"
                f"Another process is using this port. "
                f"Use --port to specify a different port."
            ) from e
        raise
    http_socket.listen(HTTP_LISTEN_BACKLOG)
    http_socket.setblocking(False)

    http_config = uvicorn.Config(
        http_app,
        fd=http_socket.fileno(),
        log_config=None,
    )
    http_server = uvicorn.Server(http_config)

    # Create UDS server for proxy registration (raw asyncio, not uvicorn)
    # This handles the NDJSON protocol for proxy registration
    uds_server = await asyncio.start_unix_server(
        lambda r, w: _handle_proxy_connection(r, w, registry),
        path=str(MANAGER_SOCKET_PATH),
    )
    # Set secure permissions
    MANAGER_SOCKET_PATH.chmod(0o600)

    async def run_servers() -> None:
        """Run HTTP server and UDS server concurrently."""
        try:
            async with uds_server:
                await asyncio.gather(
                    http_server._serve(),
                    uds_server.serve_forever(),
                )
        except asyncio.CancelledError:
            pass

    server_task = asyncio.create_task(run_servers())

    _logger.info("Manager started successfully")

    # Auto-open browser to management UI
    ui_url = f"http://127.0.0.1:{effective_port}"
    try:
        import webbrowser

        webbrowser.open(ui_url)
        _logger.info("Opened browser to %s", ui_url)
    except Exception as e:
        # Browser didn't open - show macOS notification with URL
        _logger.debug("Failed to open browser: %s", e)
        try:
            import subprocess

            subprocess.run(
                [
                    "osascript",
                    "-e",
                    f'display notification "{ui_url}" with title "MCP-ACP Manager" subtitle "Management UI ready"',
                ],
                check=False,
                capture_output=True,
            )
        except Exception:
            pass  # Non-fatal - UI can be opened manually

    # Wait for shutdown signal
    try:
        await shutdown_event.wait()
    finally:
        _logger.info("Manager shutting down")

        # Close all proxy connections
        await registry.close_all()

        # Graceful shutdown
        http_server.should_exit = True
        uds_server.close()
        await uds_server.wait_closed()

        try:
            await asyncio.wait_for(server_task, timeout=API_SERVER_SHUTDOWN_TIMEOUT_SECONDS)
        except asyncio.TimeoutError:
            _logger.warning("Server shutdown timed out, cancelling")
            server_task.cancel()
        except asyncio.CancelledError:
            pass

        # Cleanup
        try:
            http_socket.close()
        except OSError as e:
            _logger.debug("Error closing HTTP socket: %s", e)

        MANAGER_SOCKET_PATH.unlink(missing_ok=True)
        _remove_pid_file()

        _logger.info("Manager shutdown complete")
