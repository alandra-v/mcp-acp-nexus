"""Proxy purge command."""

from __future__ import annotations

import click

from mcp_acp.cli.styling import style_dim, style_error, style_success
from mcp_acp.manager.deletion import get_archived_proxy_dir, list_archived_proxies, purge_archived_proxy
from mcp_acp.utils.file_helpers import format_size


@click.command()
@click.argument("name_or_archive")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompt")
def proxy_purge(name_or_archive: str, yes: bool) -> None:
    """Permanently delete archived proxy data.

    Accepts full archive name (e.g., filesystem_2024-01-13T10-30-00)
    or just the proxy name if only one archive exists.
    """
    archives = list_archived_proxies()

    if not archives:
        click.echo(style_dim("No archived proxies."))
        raise SystemExit(1)

    # Resolve archive name
    # Exact match first
    if name_or_archive in archives:
        target = name_or_archive
    else:
        # Prefix match
        matches = [a for a in archives if a.startswith(name_or_archive + "_") or a == name_or_archive]
        if len(matches) == 0:
            click.echo(style_error(f"No archive found matching '{name_or_archive}'."))
            click.echo(style_dim("Available archives:"))
            for a in archives:
                click.echo(style_dim(f"  {a}"))
            raise SystemExit(1)
        elif len(matches) == 1:
            target = matches[0]
        else:
            click.echo(f"Multiple archives found for '{name_or_archive}':")
            click.echo()
            for a in matches:
                click.echo(f"  {a}")
            click.echo()
            click.echo("Specify the full archive name:")
            click.echo(style_dim(f"  mcp-acp proxy purge {matches[0]}"))
            raise SystemExit(1)

    # Confirmation
    if not yes:
        click.echo("This will permanently delete:")
        archive_dir = get_archived_proxy_dir(target)
        if (archive_dir / "config").exists():
            click.echo("  - Archived config and policy")
        if (archive_dir / "logs" / "audit").exists():
            click.echo("  - Archived audit logs (security trail)")
        if (archive_dir / "logs" / "system").exists():
            click.echo("  - Archived system logs")
        click.echo()
        click.echo("This action cannot be undone.")
        if not click.confirm("Continue?"):
            click.echo(style_dim("Cancelled."))
            return

    # Purge
    try:
        result = purge_archived_proxy(target)
    except FileNotFoundError:
        click.echo(style_error(f"Archive '{target}' not found."))
        raise SystemExit(1)

    click.echo(style_success(f"Purged: archive/{target}/"))
    click.echo(style_dim(f"Permanently deleted ({format_size(result.purged_size)})."))
