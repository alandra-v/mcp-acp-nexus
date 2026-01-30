"""Proxy delete command."""

from __future__ import annotations

import click

from mcp_acp.cli.styling import style_dim, style_error, style_label, style_success
from mcp_acp.manager.config import get_proxy_config_path, load_manager_config
from mcp_acp.manager.deletion import delete_proxy
from mcp_acp.utils.file_helpers import format_size

_PROXY_RUNNING_CHECK_TIMEOUT_SECONDS = 5.0


def _is_proxy_running(name: str) -> bool:
    """Check if a proxy is running by querying the manager registry.

    Args:
        name: Proxy name to check.

    Returns:
        True if proxy is registered and running, False otherwise
        (including when the manager is not running).
    """
    from mcp_acp.constants import MANAGER_SOCKET_PATH

    if not MANAGER_SOCKET_PATH.exists():
        return False

    try:
        from mcp_acp.manager.utils import test_socket_connection

        if not test_socket_connection(MANAGER_SOCKET_PATH):
            return False
    except (ImportError, OSError):
        return False

    # Manager is running, query registry via HTTP
    try:
        import httpx

        config = load_manager_config()
        resp = httpx.get(
            f"http://127.0.0.1:{config.ui_port}/api/manager/proxies",
            timeout=_PROXY_RUNNING_CHECK_TIMEOUT_SECONDS,
        )
        if resp.status_code == 200:
            proxies = resp.json()
            return any(p.get("proxy_name") == name and p.get("status") == "running" for p in proxies)
    except (httpx.HTTPError, OSError, ValueError):
        pass

    return False


@click.command()
@click.option("--proxy", "-p", "proxy_name", required=True, help="Proxy name")
@click.option("--purge", is_flag=True, help="Permanently delete (skip archiving)")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompt")
def proxy_delete(proxy_name: str, purge: bool, yes: bool) -> None:
    """Delete a proxy configuration.

    Archives config and audit/system logs by default (soft delete).
    Use --purge to permanently delete everything.
    """
    # Validate proxy exists
    config_path = get_proxy_config_path(proxy_name)
    if not config_path.exists():
        click.echo(style_error(f"Proxy '{proxy_name}' not found."))
        click.echo(style_dim(f"Expected config at: {config_path}"))
        raise SystemExit(1)

    # Check proxy is not running
    if _is_proxy_running(proxy_name):
        click.echo(style_error(f"Proxy '{proxy_name}' is currently running."))
        click.echo(style_dim("Stop the proxy first, then retry deletion."))
        raise SystemExit(1)

    # Confirmation
    if not yes:
        action = "permanently delete" if purge else "delete"
        if not click.confirm(f"{action.title()} proxy '{proxy_name}'?"):
            click.echo(style_dim("Cancelled."))
            return

    # Capture proxy_id before deletion (config will be removed)
    proxy_id = ""
    try:
        from mcp_acp.config import load_proxy_config as _load_proxy_config

        _config = _load_proxy_config(proxy_name)
        proxy_id = _config.proxy_id
    except (FileNotFoundError, ValueError, OSError):
        pass

    # Perform deletion
    click.echo(f"Deleting proxy '{proxy_name}'...")
    click.echo()

    try:
        result = delete_proxy(proxy_name, purge=purge)
    except OSError as e:
        click.echo(style_error(f"Deletion failed: {e}"))
        raise SystemExit(1)

    # Print summary
    if result.archived:
        click.echo(style_label(f"Archived ({format_size(result.archived_size)})"))
        for item in result.archived:
            if result.archive_name:
                click.echo(style_dim(f"  {item}  -> archive/{result.archive_name}/"))
            else:
                click.echo(style_dim(f"  {item}"))
        click.echo()

    if result.deleted:
        click.echo(style_label(f"Deleted permanently ({format_size(result.deleted_size)})"))
        for item in result.deleted:
            click.echo(style_dim(f"  {item}"))
        click.echo()

    click.echo(style_success(f"Proxy '{proxy_name}' deleted."))
    click.echo()

    if result.archive_name:
        click.echo(style_dim(f"To purge:   mcp-acp proxy purge {result.archive_name}"))
        click.echo()

    click.echo(
        style_dim(
            f"Don't forget to remove '{proxy_name}' from your client configuration\n"
            "(e.g., Claude Desktop's claude_desktop_config.json)"
        )
    )

    # Notify manager if running (fire-and-forget)
    _notify_manager_proxy_deleted(proxy_name, proxy_id, result.archive_name)


def _notify_manager_proxy_deleted(proxy_name: str, proxy_id: str, archive_name: str | None) -> None:
    """Send proxy_deleted notification to manager via HTTP (fire-and-forget).

    Args:
        proxy_name: Name of the deleted proxy.
        proxy_id: Stable proxy identifier.
        archive_name: Archive directory name, if archived.
    """
    import httpx

    from mcp_acp.constants import CLI_NOTIFICATION_TIMEOUT_SECONDS
    from mcp_acp.manager.daemon import is_manager_running

    if not is_manager_running():
        return

    try:
        config = load_manager_config()
        url = f"http://127.0.0.1:{config.ui_port}/api/manager/proxies/notify-deleted"
        httpx.post(
            url,
            json={
                "proxy_id": proxy_id,
                "proxy_name": proxy_name,
                "archive_name": archive_name,
            },
            timeout=CLI_NOTIFICATION_TIMEOUT_SECONDS,
        )
    except (httpx.HTTPError, OSError):
        pass  # Fire-and-forget
