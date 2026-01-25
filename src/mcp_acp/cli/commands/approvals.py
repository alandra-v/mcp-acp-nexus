"""Approvals command group for mcp-acp CLI.

Manage cached Human-in-the-Loop (HITL) approvals.
HITL rules require manual user approval before requests proceed.
Requires running proxy (uses API).
"""

from __future__ import annotations

__all__ = ["approvals"]

import json
import sys

import click

from mcp_acp.cli.api_client import api_request

from ..styling import style_dim, style_error, style_label, style_success


@click.group()
def approvals() -> None:
    """Approval cache management.

    View and clear cached Human-in-the-Loop (HITL) approvals.
    HITL rules require manual approval before requests proceed.
    Requires the proxy to be running.
    """
    pass


@approvals.command("cache")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@click.option("--proxy", "-p", "proxy_name", required=True, help="Proxy name")
def approvals_cache(as_json: bool, proxy_name: str) -> None:
    """Show cached approvals.

    Lists approvals that have been cached (user selected "Allow for Xm").
    Use entry numbers with 'approvals clear --entry=N' to clear specific entries.

    Example:
        mcp-acp approvals cache --proxy filesystem
    """
    response = api_request("GET", "/api/approvals/cached", proxy_name=proxy_name)
    data = response if isinstance(response, dict) else {}

    if as_json:
        click.echo(json.dumps(data, indent=2))
    else:
        count = data.get("count", 0)
        ttl = data.get("ttl_seconds", 0)
        approvals_list = data.get("approvals", [])

        if count == 0:
            click.echo(style_dim("No cached approvals."))
            return

        click.echo("\n" + style_label("Cached approvals") + f" {count} (TTL: {ttl}s)\n")

        for i, approval in enumerate(approvals_list, 1):
            tool_name = approval.get("tool_name", "?")
            path = approval.get("path") or "-"
            subject_id = approval.get("subject_id", "?")
            expires_in = approval.get("expires_in_seconds", 0)

            # Format expiry
            if expires_in > 60:
                expires_str = f"{expires_in / 60:.1f}m"
            else:
                expires_str = f"{expires_in:.0f}s"

            click.echo(f"  [{i}] {click.style(tool_name, fg='green', bold=True)}")
            if path != "-":
                click.echo(f"      Path: {path}")
            click.echo(f"      User: {subject_id}")
            click.echo(f"      Expires in: {expires_str}")


@approvals.command("clear")
@click.option("--all", "clear_all", is_flag=True, help="Clear all cached approvals")
@click.option("--entry", "entry_num", type=int, help="Clear entry by number (from 'approvals cache')")
@click.option("--proxy", "-p", "proxy_name", required=True, help="Proxy name")
def approvals_clear(clear_all: bool, entry_num: int | None, proxy_name: str) -> None:
    """Clear cached approvals.

    Use --all to clear entire cache, or --entry=N to clear a specific entry.

    Example:
        mcp-acp approvals clear --proxy filesystem --all
    """
    if not clear_all and entry_num is None:
        click.echo(style_error("Error: Specify --all or --entry=N"), err=True)
        sys.exit(1)

    if clear_all and entry_num is not None:
        click.echo(style_error("Error: Cannot use both --all and --entry"), err=True)
        sys.exit(1)

    # Get current cache
    cache_response = api_request("GET", "/api/approvals/cached", proxy_name=proxy_name)
    cache_data = cache_response if isinstance(cache_response, dict) else {}
    approvals_list = cache_data.get("approvals", [])

    if not approvals_list:
        click.echo(style_dim("No cached approvals to clear."))
        return

    if clear_all:
        if not click.confirm(f"Clear all {len(approvals_list)} cached approval(s)?", default=True):
            click.echo(style_dim("Cancelled."))
            return

        response = api_request("DELETE", "/api/approvals/cached", proxy_name=proxy_name)
        result = response if isinstance(response, dict) else {}
        click.echo(style_success(f"Cleared {result.get('cleared', 0)} cached approval(s)."))

    else:
        if entry_num < 1 or entry_num > len(approvals_list):
            click.echo(style_error(f"Error: Invalid entry. Valid: 1-{len(approvals_list)}"), err=True)
            sys.exit(1)

        approval = approvals_list[entry_num - 1]
        tool = approval.get("tool_name", "?")
        path = approval.get("path") or ""

        desc = f"'{tool}'" + (f" ({path})" if path else "")
        if not click.confirm(f"Clear cached approval for {desc}?", default=True):
            click.echo(style_dim("Cancelled."))
            return

        params = {
            "subject_id": approval.get("subject_id"),
            "tool_name": tool,
            "path": path,
        }
        api_request("DELETE", "/api/approvals/cached/entry", proxy_name=proxy_name, params=params)
        click.echo(style_success(f"Cleared cached approval for '{tool}'."))
