"""Status command for mcp-acp-nexus CLI.

Shows proxy runtime status. Requires running proxy (uses API).
"""

from __future__ import annotations

__all__ = ["status"]

import json
from typing import Any

import click

from mcp_acp.cli.api_client import APIError, api_request

# Time conversion constants
SECONDS_PER_DAY = 86400
SECONDS_PER_HOUR = 3600
SECONDS_PER_MINUTE = 60


@click.command()
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def status(as_json: bool) -> None:
    """Show proxy runtime status.

    Displays proxy health, uptime, auth status, and session count.
    Requires the proxy to be running.
    """
    # Get status from API
    status_response = api_request("GET", "/api/control/status")
    data = status_response if isinstance(status_response, dict) else {}

    # Get session count (best effort - don't fail if sessions endpoint errors)
    try:
        sessions_response = api_request("GET", "/api/auth-sessions")
        session_count = len(sessions_response) if isinstance(sessions_response, list) else 0
    except APIError:
        session_count = 0

    # Build result
    result = {
        "running": data.get("running", True),
        "uptime_seconds": data.get("uptime_seconds", 0),
        "policy": {
            "version": data.get("policy_version"),
            "rules_count": data.get("policy_rules_count", 0),
            "reload_count": data.get("reload_count", 0),
            "last_reload_at": data.get("last_reload_at"),
        },
        "auth_sessions": {
            "active_count": session_count,
        },
    }

    if as_json:
        click.echo(json.dumps(result, indent=2))
    else:
        _print_status_formatted(result)


def _print_status_formatted(result: dict[str, Any]) -> None:
    """Print status in human-readable format."""
    # Running status
    running = result.get("running", False)
    if running:
        click.echo(click.style("Proxy: Running", fg="green", bold=True))
    else:
        click.echo(click.style("Proxy: Not running", fg="red", bold=True))
        return

    # Uptime
    uptime_secs = result.get("uptime_seconds", 0)
    if uptime_secs >= SECONDS_PER_DAY:
        uptime_str = f"{uptime_secs / SECONDS_PER_DAY:.1f} days"
    elif uptime_secs >= SECONDS_PER_HOUR:
        uptime_str = f"{uptime_secs / SECONDS_PER_HOUR:.1f} hours"
    elif uptime_secs >= SECONDS_PER_MINUTE:
        uptime_str = f"{uptime_secs / SECONDS_PER_MINUTE:.1f} minutes"
    else:
        uptime_str = f"{uptime_secs:.0f} seconds"
    click.echo(f"  Uptime: {uptime_str}")
    click.echo()

    # Policy
    policy = result.get("policy", {})
    click.echo(click.style("Policy", fg="cyan", bold=True))
    click.echo(f"  Rules: {policy.get('rules_count', 0)}")
    if policy.get("version"):
        click.echo(f"  Version: {policy.get('version')}")
    reload_count = policy.get("reload_count", 0)
    if reload_count > 0:
        click.echo(f"  Reloads: {reload_count}")
    click.echo()

    # Auth Sessions (OIDC authenticated users)
    auth_sessions = result.get("auth_sessions", {})
    session_count = auth_sessions.get("active_count", 0)
    click.echo(click.style("Auth Sessions", fg="cyan", bold=True))
    click.echo(f"  Active: {session_count}")
