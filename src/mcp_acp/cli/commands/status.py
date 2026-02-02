"""Status command for mcp-acp CLI.

Shows proxy runtime status. Requires running proxy (uses API).
"""

from __future__ import annotations

__all__ = ["status"]

import json
from typing import Any

import click

from mcp_acp.cli.api_client import ProxyAPIError, api_request
from mcp_acp.manager.config import list_configured_proxies
from mcp_acp.utils.cli import check_proxy_running

# Time conversion constants
SECONDS_PER_DAY = 86400
SECONDS_PER_HOUR = 3600
SECONDS_PER_MINUTE = 60


@click.command()
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@click.option("--proxy", "-p", "proxy_name", help="Proxy name (shows all if not specified)")
def status(as_json: bool, proxy_name: str | None) -> None:
    """Show proxy runtime status.

    Without --proxy: Shows summary of all configured proxies.
    With --proxy: Shows detailed status for specific proxy.

    Examples:
        mcp-acp status                    # All proxies summary
        mcp-acp status --proxy filesystem # Detailed status
    """
    if proxy_name:
        # Detailed status for specific proxy
        _show_single_proxy_status(proxy_name, as_json)
    else:
        # Summary of all proxies
        _show_all_proxies_status(as_json)


def _show_single_proxy_status(proxy_name: str, as_json: bool) -> None:
    """Show detailed status for a single proxy.

    Args:
        proxy_name: Name of the proxy to show status for.
        as_json: If True, output as JSON instead of formatted text.
    """
    # Get status from API
    status_response = api_request("GET", "/api/control/status", proxy_name=proxy_name)
    data = status_response if isinstance(status_response, dict) else {}

    # Get session count (best effort - don't fail if sessions endpoint errors)
    try:
        sessions_response = api_request("GET", "/api/auth-sessions", proxy_name=proxy_name)
        session_count = len(sessions_response) if isinstance(sessions_response, list) else 0
    except ProxyAPIError:
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


def _show_all_proxies_status(as_json: bool) -> None:
    """Show summary status for all configured proxies.

    Args:
        as_json: If True, output as JSON instead of formatted text.
    """
    proxies = list_configured_proxies()

    if not proxies:
        click.echo("No proxies configured. Run 'mcp-acp proxy add' to create one.")
        return

    results = []
    running_count = 0

    for name in proxies:
        is_running = check_proxy_running(name)
        if is_running:
            running_count += 1
        results.append({"name": name, "running": is_running})

    if as_json:
        click.echo(json.dumps({"proxies": results, "running_count": running_count}, indent=2))
    else:
        click.echo(click.style("Proxies:", fg="cyan", bold=True))
        click.echo()
        for proxy_info in results:
            name = str(proxy_info["name"])
            is_running = bool(proxy_info["running"])
            if is_running:
                status_str = click.style("running", fg="green")
            else:
                status_str = click.style("inactive", fg="yellow")
            click.echo(f"  {name:20} {status_str}")
        click.echo()
        click.echo(f"{running_count}/{len(proxies)} proxies running")


def _print_status_formatted(result: dict[str, Any]) -> None:
    """Print status in human-readable format.

    Args:
        result: Status data dictionary with running, uptime, policy, and auth info.
    """
    # Running status
    running = result.get("running", False)
    if running:
        click.echo(click.style("Proxy: Running", fg="green", bold=True))
    else:
        click.echo(click.style("Proxy: Inactive", fg="yellow", bold=True))
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
    if policy.get("last_reload_at"):
        click.echo(f"  Last reload: {policy.get('last_reload_at')}")
    click.echo()

    # Auth Sessions (OIDC authenticated users)
    auth_sessions = result.get("auth_sessions", {})
    session_count = auth_sessions.get("active_count", 0)
    click.echo(click.style("Auth Sessions", fg="cyan", bold=True))
    click.echo(f"  Active: {session_count}")
