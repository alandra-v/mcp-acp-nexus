"""Sessions command group for mcp-acp-nexus CLI.

Shows active sessions. Requires running proxy (uses API).
"""

from __future__ import annotations

__all__ = ["sessions"]

import json
from datetime import datetime

import click

from mcp_acp.cli.api_client import api_request

from ..styling import style_dim, style_label


@click.group()
def sessions() -> None:
    """Session management commands.

    View active authentication sessions.
    Requires the proxy to be running.
    """
    pass


@sessions.command("list")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def sessions_list(as_json: bool) -> None:
    """List active sessions.

    Shows all active authentication sessions with user info and timestamps.
    """
    data = api_request("GET", "/api/auth-sessions")

    if not isinstance(data, list):
        data = []

    if as_json:
        click.echo(json.dumps(data, indent=2))
    else:
        if not data:
            click.echo(style_dim("No active sessions."))
            return

        click.echo("\n" + style_label("Active sessions") + f" {len(data)}\n")

        for session in data:
            session_id = session.get("session_id", "?")
            user_id = session.get("user_id", "?")
            started_at = session.get("started_at", "?")

            # Format timestamp
            if started_at and started_at != "?":
                try:
                    dt = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
                    started_str = dt.strftime("%Y-%m-%d %H:%M:%S")
                except (ValueError, TypeError):
                    started_str = started_at
            else:
                started_str = "?"

            # Truncate session_id for display
            short_id = session_id[:12] + "..." if len(session_id) > 15 else session_id

            click.echo(f"  [{short_id}]")
            click.echo(f"    User: {user_id}")
            click.echo(f"    Started: {started_str}")
            click.echo()
