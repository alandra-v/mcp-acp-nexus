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
import logging
import os
import secrets
import signal
import socket
import subprocess
import webbrowser
from pathlib import Path
from typing import Any

import httpx
import uvicorn

from mcp_acp.constants import (
    API_SERVER_SHUTDOWN_TIMEOUT_SECONDS,
    APP_NAME,
    MANAGER_PID_PATH,
    MANAGER_SOCKET_PATH,
    RUNTIME_DIR,
)
from mcp_acp.manager.config import (
    ManagerConfig,
    get_manager_system_log_path,
    load_manager_config,
)
from mcp_acp.manager.protocol import PROTOCOL_VERSION, decode_ndjson, encode_ndjson
from mcp_acp.manager.registry import ProxyRegistry, get_proxy_registry
from mcp_acp.manager.routes import (
    PROXY_SNAPSHOT_TIMEOUT_SECONDS,
    create_manager_api_app,
    create_uds_client,
)
from mcp_acp.utils.logging.iso_formatter import ISO8601Formatter

# Token length for API authentication (32 bytes = 64 hex chars)
API_TOKEN_BYTES = 32

# HTTP server backlog (number of pending connections)
HTTP_LISTEN_BACKLOG = 100

# Get module logger - initially with stderr only
# File handler added via _configure_manager_logging() after config is loaded
_logger = logging.getLogger(f"{APP_NAME}.manager")
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

        msg = decode_ndjson(line)
        if msg is None:
            _logger.warning("Invalid JSON in registration")
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
            except (httpx.HTTPError, httpx.TimeoutException) as e:
                _logger.debug("Failed to fetch pending approvals: %s", e)

            # Fetch cached approvals
            try:
                cached_resp = await client.get("/api/approvals/cached")
                if cached_resp.status_code == 200:
                    cached = cached_resp.json()
                    await registry.broadcast_snapshot(
                        "cached_snapshot",
                        {
                            "approvals": cached.get("approvals", []),
                            "ttl_seconds": cached.get("ttl_seconds", 600),
                            "count": cached.get("count", 0),
                        },
                    )
            except (httpx.HTTPError, httpx.TimeoutException) as e:
                _logger.debug("Failed to fetch cached approvals: %s", e)

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
            except (httpx.HTTPError, httpx.TimeoutException) as e:
                _logger.debug("Failed to fetch stats: %s", e)

    except (httpx.ConnectError, OSError) as e:
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

            msg = decode_ndjson(line)
            if msg is None:
                _logger.warning("Invalid JSON from proxy '%s'", proxy_name)
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
    writer.write(encode_ndjson(msg))
    await writer.drain()


async def _send_error(writer: asyncio.StreamWriter, error: str) -> None:
    """Send an error response."""
    await _send_message(writer, {"type": "registered", "ok": False, "error": error})


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
    http_app = create_manager_api_app(token=api_token, registry=registry)

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
        webbrowser.open(ui_url)
        _logger.info("Opened browser to %s", ui_url)
    except OSError as e:
        # Browser didn't open - show macOS notification with URL
        _logger.debug("Failed to open browser: %s", e)
        try:
            subprocess.run(
                [
                    "osascript",
                    "-e",
                    f'display notification "{ui_url}" with title "MCP-ACP Manager" subtitle "Management UI ready"',
                ],
                check=False,
                capture_output=True,
            )
        except OSError:
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
