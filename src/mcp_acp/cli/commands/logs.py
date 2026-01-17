"""Logs command group for mcp-acp-nexus CLI.

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

from mcp_acp.config import AppConfig

from ..styling import style_label
from mcp_acp.utils.config import (
    get_auth_log_path,
    get_config_history_path,
    get_config_path,
    get_decisions_log_path,
    get_audit_log_path,
    get_policy_history_path,
    get_system_log_path,
)

# Log types and their path functions
LOG_TYPES = {
    "decisions": ("Policy decisions", get_decisions_log_path),
    "operations": ("Operations audit", get_audit_log_path),
    "auth": ("Authentication events", get_auth_log_path),
    "system": ("System logs", get_system_log_path),
    "config-history": ("Config change history", get_config_history_path),
    "policy-history": ("Policy change history", get_policy_history_path),
}


def _load_config() -> AppConfig:
    """Load configuration from default path."""
    config_path = get_config_path()

    if not config_path.exists():
        raise click.ClickException(
            f"Configuration not found at {config_path}\n"
            "Run 'mcp-acp-nexus init' to create configuration."
        )

    try:
        return AppConfig.load_from_files(config_path)
    except (OSError, ValueError) as e:
        raise click.ClickException(f"Failed to load configuration: {e}") from e


def _get_log_path(config: AppConfig, log_type: str) -> Path:
    """Get path to a specific log file."""
    if log_type not in LOG_TYPES:
        raise click.ClickException(f"Unknown log type: {log_type}")
    _, path_fn = LOG_TYPES[log_type]
    return path_fn(config)


@click.group()
def logs() -> None:
    """Log viewing commands.

    View and tail log files directly from disk.
    No running proxy required.

    Use 'logs list' to see available log files.
    """
    pass


@logs.command("list")
def logs_list() -> None:
    """List available log files.

    Shows all log types with their file paths and sizes.
    """
    config = _load_config()

    click.echo("\n" + style_label("Available log files") + "\n")

    for log_type, (description, path_fn) in LOG_TYPES.items():
        log_path = path_fn(config)
        exists = log_path.exists()

        if exists:
            size = log_path.stat().st_size
            if size > 1024 * 1024:
                size_str = f"{size / (1024 * 1024):.1f} MB"
            elif size > 1024:
                size_str = f"{size / 1024:.1f} KB"
            else:
                size_str = f"{size} bytes"

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

        click.echo(f"  {log_type:12} - {description}")
        click.echo(f"               {status} {info}")
        click.echo(f"               {log_path}")
        click.echo()


@logs.command("show")
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
def logs_show(log_type: str, limit: int) -> None:
    """Show recent log entries as JSON.

    Outputs JSONL (one JSON object per line).
    Requires --type to specify which log to show.
    Use 'logs list' to see available log files.
    """
    config = _load_config()
    log_path = _get_log_path(config, log_type)

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
    "--type",
    "-t",
    "log_type",
    type=click.Choice(list(LOG_TYPES.keys())),
    required=True,
    help="Log type to tail (required)",
)
def logs_tail(log_type: str) -> None:
    """Tail log file in real-time (JSON output).

    Continuously outputs new log entries as JSONL.
    Use 'logs list' to see available log files.
    Press Ctrl+C to stop.
    """
    config = _load_config()
    log_path = _get_log_path(config, log_type)

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
