"""Manager daemon orchestrator (run_manager entry point).

Sets up and runs the HTTP + UDS servers, signal handlers,
background tasks, and graceful shutdown.
"""

from __future__ import annotations

__all__ = [
    "run_manager",
]

import asyncio
import errno
import logging
import os
import secrets
import signal
import socket
import subprocess
import time
import webbrowser

import uvicorn

from mcp_acp.constants import (
    API_SERVER_SHUTDOWN_TIMEOUT_SECONDS,
    MANAGER_SOCKET_PATH,
    RUNTIME_DIR,
)
from mcp_acp.manager.config import load_manager_config_strict
from mcp_acp.manager.models import ManagerSystemEvent
from mcp_acp.manager.registry import get_proxy_registry
from mcp_acp.manager.routes import create_manager_api_app
from mcp_acp.manager.token_service import ManagerTokenService

from .idle import idle_shutdown_checker
from .lifecycle import (
    cleanup_stale_pid,
    cleanup_stale_socket,
    is_port_in_use,
    remove_pid_file,
    write_pid_file,
)
from .log_config import configure_manager_logging, log_event
from .proxy_handler import handle_proxy_connection, send_heartbeats_to_proxies

# Token length for API authentication (32 bytes = 64 hex chars)
API_TOKEN_BYTES = 32

# HTTP server backlog (number of pending connections)
HTTP_LISTEN_BACKLOG = 100


async def run_manager(port: int | None = None) -> None:
    """Run the manager daemon.

    This is the main entry point for the manager process.
    It sets up HTTP and UDS servers and runs until shutdown.

    Args:
        port: HTTP port for UI. If None, uses config value (default: 8765).

    Raises:
        RuntimeError: If manager is already running or port is in use.
    """
    # Load configuration (strict: fails on missing/invalid config)
    config = load_manager_config_strict()

    # Configure file logging
    configure_manager_logging(config)

    # Use provided port or config default
    effective_port = port if port is not None else config.ui_port

    # Suppress uvicorn's logging (we use our own)
    for logger_name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logging.getLogger(logger_name).setLevel(logging.CRITICAL)

    # Create runtime directory
    RUNTIME_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)

    # Check for stale files from previous crash
    cleanup_stale_pid()
    cleanup_stale_socket()

    # Check if port is in use
    if is_port_in_use(effective_port):
        raise RuntimeError(
            f"Port {effective_port} is already in use.\n"
            f"Another process is using this port. "
            f"Use --port to specify a different port."
        )

    # Write PID file
    write_pid_file()

    log_event(
        logging.INFO,
        ManagerSystemEvent(
            event="manager_starting",
            message=f"Manager starting: port={effective_port}, socket={MANAGER_SOCKET_PATH}, pid={os.getpid()}",
            socket_path=str(MANAGER_SOCKET_PATH),
            details={
                "port": effective_port,
                "pid": os.getpid(),
            },
        ),
    )

    # Track shutdown state
    shutdown_event = asyncio.Event()

    def signal_handler(signum: int, frame: object) -> None:
        """Handle shutdown signals (SIGTERM, SIGINT)."""
        log_event(
            logging.INFO,
            ManagerSystemEvent(
                event="shutdown_signal_received",
                message=f"Received signal {signum}, initiating shutdown",
                details={"signal": signum},
            ),
        )
        shutdown_event.set()

    # Register signal handlers
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    # Create proxy registry
    registry = get_proxy_registry()

    # Initialize token service if OIDC is configured
    token_service: ManagerTokenService | None = None
    if config.auth is not None and config.auth.oidc is not None:
        token_service = ManagerTokenService(config.auth.oidc, registry)
        await token_service.start()
        log_event(
            logging.INFO,
            ManagerSystemEvent(
                event="token_service_started",
                message="Token service started for OIDC authentication",
            ),
        )

    # Generate API token for browser auth
    api_token = secrets.token_hex(API_TOKEN_BYTES)

    # Create FastAPI app for HTTP
    http_app = create_manager_api_app(
        token=api_token,
        registry=registry,
        token_service=token_service,
    )

    # Create HTTP server
    http_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    http_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        http_socket.bind(("127.0.0.1", effective_port))
    except OSError as e:
        remove_pid_file()
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
        ws="none",  # We use SSE, not WebSockets
    )
    http_server = uvicorn.Server(http_config)

    # Create UDS server for proxy registration (raw asyncio, not uvicorn)
    # This handles the NDJSON protocol for proxy registration
    uds_server = await asyncio.start_unix_server(
        lambda r, w: handle_proxy_connection(r, w, registry, token_service),
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

    # Start heartbeat task to keep proxy connections alive
    heartbeat_task = asyncio.create_task(send_heartbeats_to_proxies(registry))

    # Start idle shutdown checker
    startup_time = time.monotonic()
    idle_checker_task = asyncio.create_task(idle_shutdown_checker(registry, shutdown_event, startup_time))

    log_event(
        logging.INFO,
        ManagerSystemEvent(
            event="manager_started",
            message="Manager started successfully",
        ),
    )

    # Auto-open browser to management UI
    ui_url = f"http://127.0.0.1:{effective_port}"
    try:
        webbrowser.open(ui_url)
        log_event(
            logging.INFO,
            ManagerSystemEvent(
                event="browser_opened",
                message=f"Opened browser to {ui_url}",
                details={"url": ui_url},
            ),
        )
    except OSError:
        # Browser didn't open - show macOS notification with URL
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
        log_event(
            logging.INFO,
            ManagerSystemEvent(
                event="manager_shutting_down",
                message="Manager shutting down",
            ),
        )

        # Cancel background tasks
        heartbeat_task.cancel()
        idle_checker_task.cancel()
        try:
            await heartbeat_task
        except asyncio.CancelledError:
            pass
        try:
            await idle_checker_task
        except asyncio.CancelledError:
            pass

        # Stop token service
        if token_service is not None:
            await token_service.stop()

        # Close all proxy connections
        await registry.close_all()

        # Graceful shutdown
        http_server.should_exit = True
        uds_server.close()
        await uds_server.wait_closed()

        try:
            await asyncio.wait_for(server_task, timeout=API_SERVER_SHUTDOWN_TIMEOUT_SECONDS)
        except asyncio.TimeoutError:
            log_event(
                logging.WARNING,
                ManagerSystemEvent(
                    event="shutdown_timeout",
                    message="Server shutdown timed out, cancelling",
                ),
            )
            server_task.cancel()
        except asyncio.CancelledError:
            pass

        # Cleanup
        try:
            http_socket.close()
        except OSError:
            pass  # Non-critical cleanup

        MANAGER_SOCKET_PATH.unlink(missing_ok=True)
        remove_pid_file()

        log_event(
            logging.INFO,
            ManagerSystemEvent(
                event="manager_stopped",
                message="Manager shutdown complete",
            ),
        )
