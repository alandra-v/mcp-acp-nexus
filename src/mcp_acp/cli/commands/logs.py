"""Logs command group for mcp-acp CLI.

Provides log viewing commands that read directly from log files.
No API required - works offline.
"""

from __future__ import annotations

__all__ = ["logs"]

import json
import sys
import time
from pathlib import Path

import click

from mcp_acp.manager.config import list_configured_proxies
from mcp_acp.utils.cli import load_manager_config_or_exit, require_proxy_name
from mcp_acp.utils.config import get_log_path
from mcp_acp.utils.file_helpers import format_size, scan_backup_files

from ..styling import style_label

# Log types: CLI name -> (description, internal log_type for get_log_path)
LOG_TYPES: dict[str, tuple[str, str]] = {
    "decisions": ("Policy decisions", "decisions"),
    "operations": ("Operations audit", "operations"),
    "auth": ("Authentication events", "auth"),
    "system": ("System logs", "system"),
    "config-history": ("Config change history", "config_history"),
    "policy-history": ("Policy change history", "policy_history"),
}


def _get_log_path_for_type(proxy_name: str, log_dir: str, log_type: str) -> Path:
    """Get path to a specific log file by CLI log type name."""
    if log_type not in LOG_TYPES:
        raise click.ClickException(f"Unknown log type: {log_type}")
    _, internal_type = LOG_TYPES[log_type]
    return get_log_path(proxy_name, internal_type, log_dir)


@click.group()
def logs() -> None:
    """Log viewing commands.

    View and tail log files directly from disk.
    No running proxy required.

    Use 'logs list' to see available log files.
    """
    pass


@logs.command("list")
@click.option(
    "--proxy",
    "-p",
    "proxy_name",
    help="Proxy name (optional - shows all proxies if not specified)",
)
def logs_list(proxy_name: str | None) -> None:
    """List available log files.

    Without --proxy, shows log paths for ALL proxies.
    With --proxy, shows detailed log info for a specific proxy.

    Also shows backup files (.broken.TIMESTAMP.jsonl) created by 'audit repair'.
    """
    manager_config = load_manager_config_or_exit()
    log_dir_str = manager_config.log_dir

    if proxy_name:
        # Validate specific proxy
        proxy_name = require_proxy_name(proxy_name)
        _show_proxy_logs(proxy_name, log_dir_str)
    else:
        # Show all proxies
        proxies = list_configured_proxies()
        if not proxies:
            click.echo("No proxies configured.")
            click.echo("Run 'mcp-acp proxy add' to create one.")
            return

        click.echo("\n" + style_label("Log Paths") + "\n")

        for name in proxies:
            click.echo(f"  {name}:")
            for cli_type, (description, internal_type) in LOG_TYPES.items():
                log_path = get_log_path(name, internal_type, log_dir_str)
                exists = "✓" if log_path.exists() else "✗"
                # Check for backups
                backups = scan_backup_files(log_path)
                backup_info = f" [{len(backups)} backup(s)]" if backups else ""
                click.echo(f"    {cli_type}: {log_path} {exists}{click.style(backup_info, fg='yellow')}")
            click.echo()


def _show_proxy_logs(proxy_name: str, log_dir_str: str) -> None:
    """Show detailed log info for a specific proxy."""
    click.echo("\n" + style_label(f"Log files: {proxy_name}") + "\n")

    for cli_type, (description, internal_type) in LOG_TYPES.items():
        log_path = get_log_path(proxy_name, internal_type, log_dir_str)
        exists = log_path.exists()

        if exists:
            size = log_path.stat().st_size
            size_str = format_size(size)

            # Count lines (entries)
            try:
                with open(log_path, encoding="utf-8") as f:
                    line_count = sum(1 for line in f if line.strip())
                entries_str = f"{line_count} entries"
            except OSError:
                entries_str = "?"

            status = click.style("exists", fg="green")
            info = f"({size_str}, {entries_str})"
        else:
            status = click.style("not created", fg="yellow")
            info = ""

        click.echo(f"  {cli_type:12} - {description}")
        click.echo(f"               {status} {info}")
        click.echo(f"               {log_path}")

        # Show backup files if any
        backups = scan_backup_files(log_path)
        if backups:
            click.echo(f"               {click.style(f'{len(backups)} backup(s):', fg='yellow')}")
            for backup in backups:
                size_str = format_size(backup.size_bytes)
                click.echo(f"                 - {backup.filename} ({size_str})")

        click.echo()


@logs.command("show")
@click.option(
    "--proxy",
    "-p",
    "proxy_name",
    help="Proxy name (required)",
)
@click.option(
    "--type",
    "-t",
    "log_type",
    type=click.Choice(list(LOG_TYPES.keys())),
    required=True,
    help="Log type to show (required)",
)
@click.option(
    "--limit",
    "-n",
    default=50,
    help="Number of entries to show (default: 50)",
)
def logs_show(proxy_name: str | None, log_type: str, limit: int) -> None:
    """Show recent log entries as JSON.

    Outputs JSONL (one JSON object per line).
    Requires --type to specify which log to show.
    Use 'logs list' to see available log files.
    """
    proxy_name = require_proxy_name(proxy_name)
    manager_config = load_manager_config_or_exit()
    log_path = _get_log_path_for_type(proxy_name, manager_config.log_dir, log_type)

    if not log_path.exists():
        # Output error as JSON
        error = {
            "error": f"Log file not found: {log_path}",
            "hint": "The proxy may not have written any logs yet",
        }
        click.echo(json.dumps(error))
        return

    # Read file and get last N lines
    try:
        with open(log_path, encoding="utf-8") as f:
            lines = f.readlines()
    except OSError as e:
        click.echo(json.dumps({"error": f"Failed to read log file: {e}"}))
        sys.exit(1)

    # Get last N non-empty lines (newest first)
    entries = []
    for line in reversed(lines):
        if line.strip():
            entries.append(line)
            if len(entries) >= limit:
                break

    if not entries:
        click.echo(json.dumps({"entries": [], "count": 0, "file": str(log_path)}))
        return

    # Output JSONL (chronological order)
    for line in reversed(entries):
        click.echo(line.rstrip())


@logs.command("tail")
@click.option(
    "--proxy",
    "-p",
    "proxy_name",
    help="Proxy name (required)",
)
@click.option(
    "--type",
    "-t",
    "log_type",
    type=click.Choice(list(LOG_TYPES.keys())),
    required=True,
    help="Log type to tail (required)",
)
def logs_tail(proxy_name: str | None, log_type: str) -> None:
    """Tail log file in real-time (JSON output).

    Continuously outputs new log entries as JSONL.
    Use 'logs list' to see available log files.
    Press Ctrl+C to stop.
    """
    proxy_name = require_proxy_name(proxy_name)
    manager_config = load_manager_config_or_exit()
    log_path = _get_log_path_for_type(proxy_name, manager_config.log_dir, log_type)

    if not log_path.exists():
        status_msg = {
            "status": "waiting",
            "message": f"Log file not found: {log_path}",
            "hint": "Waiting for file to be created...",
        }
        click.echo(json.dumps(status_msg), err=True)

        # Wait for file to be created
        try:
            while not log_path.exists():
                time.sleep(0.5)
        except KeyboardInterrupt:
            click.echo(json.dumps({"status": "stopped"}), err=True)
            return

    try:
        with open(log_path, encoding="utf-8") as f:
            # Seek to end of file
            f.seek(0, 2)

            while True:
                line = f.readline()
                if line:
                    # Output raw JSONL
                    click.echo(line.rstrip())
                else:
                    # No new content, wait a bit
                    time.sleep(0.1)

    except KeyboardInterrupt:
        pass  # Silent exit on Ctrl+C
    except OSError as e:
        click.echo(json.dumps({"error": f"Failed to read log file: {e}"}), err=True)
        sys.exit(1)
