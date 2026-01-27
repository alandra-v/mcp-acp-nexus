"""Manager command group for mcp-acp CLI.

Provides commands to control the manager daemon:
- start: Start the manager daemon
- stop: Stop the manager daemon
- status: Show manager and proxy status
"""

from __future__ import annotations

__all__ = ["manager"]

import asyncio
import json
import shutil
import subprocess
import sys
from typing import Any

import click

from mcp_acp.constants import (
    APP_NAME,
    DEFAULT_API_PORT,
    MANAGER_SOCKET_PATH,
    RUNTIME_DIR,
)
from mcp_acp.manager import (
    get_manager_pid,
    is_manager_running,
    load_manager_config,
    run_manager,
    stop_manager,
)

from mcp_acp.manager.utils import wait_for_condition

from ..styling import style_error, style_label, style_success, style_warning

# Timeout for manager to become ready after start (seconds)
MANAGER_STARTUP_TIMEOUT_SECONDS = 5.0

# Timeout for manager to stop after SIGTERM (seconds)
MANAGER_STOP_TIMEOUT_SECONDS = 5.0


@click.group()
def manager() -> None:
    """Manager daemon commands.

    The manager daemon serves the web UI and coordinates proxies.
    It can be started explicitly or auto-started by the first proxy.
    """
    pass


@manager.command("start")
@click.option(
    "--port",
    "-p",
    type=int,
    default=None,
    help=f"HTTP port for UI (default: {DEFAULT_API_PORT} or config value)",
)
@click.option(
    "--foreground",
    "-f",
    is_flag=True,
    help="Run in foreground (don't daemonize)",
)
def start(port: int | None, foreground: bool) -> None:
    """Start the manager daemon.

    The manager serves the web UI and coordinates proxy registrations.
    By default, it runs as a background daemon.

    Use --foreground to run in the current terminal (useful for debugging).
    """
    # Load config to get default port
    config = load_manager_config()
    effective_port = port if port is not None else config.ui_port

    # Check if already running
    if is_manager_running():
        pid = get_manager_pid()
        click.echo(style_warning(f"Manager is already running (pid: {pid})"))
        click.echo(f"  Socket: {MANAGER_SOCKET_PATH}")
        click.echo(f"  UI: http://127.0.0.1:{config.ui_port}")
        sys.exit(0)

    if foreground:
        # Run in foreground (blocking)
        click.echo(style_label("Starting manager in foreground..."))
        click.echo(f"  Port: {effective_port}")
        click.echo(f"  Socket: {MANAGER_SOCKET_PATH}")
        click.echo()
        click.echo("Press Ctrl+C to stop")
        click.echo()
        try:
            asyncio.run(run_manager(port=effective_port))
        except KeyboardInterrupt:
            click.echo()
            click.echo("Manager stopped.")
        except RuntimeError as e:
            click.echo(style_error(f"Failed to start: {e}"), err=True)
            sys.exit(1)
    else:
        # Daemonize: spawn as detached subprocess
        click.echo(style_label("Starting manager daemon..."))

        # Ensure runtime directory exists
        RUNTIME_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)

        # Find the mcp-acp executable
        # First try to find it via shutil.which (in PATH)
        # Then fall back to python -m mcp_acp.cli
        mcp_acp_path = shutil.which(APP_NAME)
        if mcp_acp_path is None:
            # Use python -m mcp_acp.cli (works with __main__.py)
            mcp_acp_cmd = [sys.executable, "-m", "mcp_acp.cli"]
        else:
            mcp_acp_cmd = [mcp_acp_path]

        # Spawn manager as detached process
        # We use the internal _run command to avoid recursive daemonization
        # Only pass --port if explicitly specified (let daemon use config otherwise)
        spawn_args = ["manager", "_run"]
        if port is not None:
            spawn_args.extend(["--port", str(port)])

        try:
            process = subprocess.Popen(
                mcp_acp_cmd + spawn_args,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        except OSError as e:
            click.echo(style_error(f"Failed to spawn manager: {e}"), err=True)
            sys.exit(1)

        # Wait for manager to become ready
        if wait_for_condition(is_manager_running, MANAGER_STARTUP_TIMEOUT_SECONDS):
            pid = get_manager_pid()
            click.echo(style_success(f"Manager started (pid: {pid})"))
            click.echo(f"  UI: http://127.0.0.1:{effective_port}")
            click.echo()
            click.echo("To stop: mcp-acp manager stop")
            sys.exit(0)

        # Timeout - check if process died
        if process.poll() is not None:
            click.echo(style_error("Manager process exited unexpectedly"), err=True)
            sys.exit(1)
        else:
            click.echo(style_warning("Manager started but not responding yet"))
            click.echo("  Check logs or try: mcp-acp manager status")
            sys.exit(0)


@manager.command("_run")
@click.option("--port", "-p", type=int, default=None)
@click.pass_context
def _run(ctx: click.Context, port: int | None) -> None:
    """Internal command to run manager (called by daemonized start)."""
    # This is the actual manager process
    try:
        asyncio.run(run_manager(port=port))
    except RuntimeError as e:
        # Log to stderr (will be lost in daemon mode, but helpful for debugging)
        click.echo(f"Manager error: {e}", err=True)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(0)


@manager.command("stop")
def stop() -> None:
    """Stop the manager daemon."""
    if not is_manager_running():
        click.echo(style_warning("Manager is not running"))
        sys.exit(0)

    pid = get_manager_pid()
    click.echo(f"Stopping manager (pid: {pid})...")

    if stop_manager():
        # Wait for process to exit
        if wait_for_condition(
            lambda: not is_manager_running(),
            MANAGER_STOP_TIMEOUT_SECONDS,
        ):
            click.echo(style_success("Manager stopped"))
            sys.exit(0)

        click.echo(style_warning("Manager stop signal sent but process still running"))
        click.echo(f"  You may need to kill it manually: kill {pid}")
        sys.exit(1)
    else:
        click.echo(style_error("Failed to stop manager"), err=True)
        sys.exit(1)


def _fetch_proxies(ui_port: int) -> list[dict[str, Any]]:
    """Fetch registered proxies from manager API.

    Args:
        ui_port: Manager HTTP port.

    Returns:
        List of proxy info dicts, empty list on error.
    """
    import urllib.error
    import urllib.request

    try:
        url = f"http://127.0.0.1:{ui_port}/api/manager/proxies"
        with urllib.request.urlopen(url, timeout=2.0) as response:
            data = response.read().decode("utf-8")
            result: list[dict[str, Any]] = json.loads(data)
            return result
    except (urllib.error.URLError, OSError, json.JSONDecodeError):
        return []


@manager.command("status")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def status(as_json: bool) -> None:
    """Show manager and proxy status."""
    running = is_manager_running()
    pid = get_manager_pid()

    # Load config to get configured port
    config = load_manager_config()
    ui_port = config.ui_port

    # Fetch proxies from manager API if running
    proxies: list[dict] = []
    if running:
        proxies = _fetch_proxies(ui_port)

    result = {
        "manager": {
            "running": running,
            "pid": pid,
            "socket": str(MANAGER_SOCKET_PATH) if running else None,
            "ui_url": f"http://127.0.0.1:{ui_port}" if running else None,
        },
        "proxies": proxies,
    }

    if as_json:
        click.echo(json.dumps(result, indent=2))
    else:
        click.echo()
        if running:
            click.echo(style_success("Manager: Running") + f" (pid: {pid})")
            click.echo(f"  UI: http://127.0.0.1:{ui_port}")
            click.echo(f"  Socket: {MANAGER_SOCKET_PATH}")
        else:
            click.echo(style_warning("Manager: Not running"))
            click.echo()
            click.echo("  Start with: mcp-acp manager start")

        click.echo()
        click.echo(style_label("Proxies"))
        if proxies:
            for proxy in proxies:
                name = proxy.get("proxy_name") or proxy.get("name") or "unknown"
                instance_id = (proxy.get("instance_id") or "")[:8]
                connected_at = proxy.get("connected_at") or ""
                click.echo(f"  {name} ({instance_id}) - connected {connected_at}")
        else:
            click.echo("  No proxies registered")
        click.echo()
