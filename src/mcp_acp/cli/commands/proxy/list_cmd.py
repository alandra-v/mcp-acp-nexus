"""Proxy list command."""

from __future__ import annotations

import json

import click

from mcp_acp.cli.styling import style_dim, style_header
from mcp_acp.manager.config import list_configured_proxies
from mcp_acp.manager.deletion import get_archived_proxy_dir, list_archived_proxies


@click.command()
@click.option("--deleted", is_flag=True, help="Show archived (deleted) proxies")
def proxy_list(deleted: bool) -> None:
    """List proxy configurations.

    Shows all configured proxies, or archived proxies with --deleted.
    """
    if deleted:
        # Show archived proxies
        archives = list_archived_proxies()
        if not archives:
            click.echo(style_dim("No archived proxies."))
            return

        click.echo(style_header("Archived Proxies"))
        click.echo()
        for archive_name in archives:
            archive_dir = get_archived_proxy_dir(archive_name)
            metadata_path = archive_dir / "metadata.json"
            if metadata_path.exists():
                metadata = json.loads(metadata_path.read_text())
                original_name = metadata.get("original_name", "?")
                deleted_at = metadata.get("deleted_at", "?")
                click.echo(f"  {archive_name}")
                click.echo(style_dim(f"    Original name: {original_name}"))
                click.echo(style_dim(f"    Deleted at:    {deleted_at}"))
            else:
                click.echo(f"  {archive_name}")
            click.echo()
    else:
        # Show active proxies
        proxies = list_configured_proxies()
        if not proxies:
            click.echo(style_dim("No proxies configured."))
            click.echo(style_dim("Run 'mcp-acp proxy add' to create one."))
            return

        click.echo(style_header("Configured Proxies"))
        click.echo()
        for name in proxies:
            click.echo(f"  {name}")
        click.echo()
