"""Proxy authentication commands (API key management)."""

from __future__ import annotations

import click

from mcp_acp.cli.styling import style_dim, style_error, style_success
from mcp_acp.config import save_proxy_config
from mcp_acp.manager.config import get_proxy_config_path


@click.group()
def proxy_auth() -> None:
    """Manage proxy authentication (API keys)."""
    pass


@proxy_auth.command("set-key")
@click.option("--proxy", "-p", "proxy_name", required=True, help="Proxy name")
@click.option("--api-key", "-k", help="API key (will prompt securely if not provided)")
def auth_set_key(proxy_name: str, api_key: str | None) -> None:
    """Set or update API key for a proxy.

    Stores the key securely in the OS keychain. The proxy must use HTTP transport.
    """
    from mcp_acp.config import load_proxy_config
    from mcp_acp.security.credential_storage import BackendCredentialStorage

    # Check proxy exists
    config_path = get_proxy_config_path(proxy_name)
    if not config_path.exists():
        click.echo(style_error(f"Proxy '{proxy_name}' not found"))
        click.echo(style_dim(f"Expected config at: {config_path}"))
        raise SystemExit(1)

    # Load config
    try:
        config = load_proxy_config(proxy_name)
    except (FileNotFoundError, ValueError, OSError) as e:
        click.echo(style_error(f"Failed to load proxy config: {e}"))
        raise SystemExit(1)

    # Check HTTP transport
    if config.backend.http is None:
        click.echo(style_error("Cannot set API key: proxy does not use HTTP transport"))
        click.echo(style_dim(f"Transport type: {config.backend.transport}"))
        raise SystemExit(1)

    # Get API key
    if not api_key:
        api_key = click.prompt(
            "API key (will be stored securely in keychain)",
            hide_input=True,
        )

    if not api_key.strip():
        click.echo(style_error("API key cannot be empty"))
        raise SystemExit(1)

    # Store in keychain
    cred_storage = BackendCredentialStorage(proxy_name)
    try:
        cred_storage.save(api_key.strip())
    except RuntimeError as e:
        click.echo(style_error(f"Failed to store API key in keychain: {e}"))
        raise SystemExit(1)

    # Update config with credential reference
    try:
        updated_http = config.backend.http.model_copy(update={"credential_key": cred_storage.credential_key})
        updated_backend = config.backend.model_copy(update={"http": updated_http})
        updated_config = config.model_copy(update={"backend": updated_backend})
        save_proxy_config(proxy_name, updated_config)
    except (ValueError, OSError) as e:
        # Rollback: delete the stored credential
        try:
            cred_storage.delete()
        except RuntimeError:
            pass
        click.echo(style_error(f"Failed to update config: {e}"))
        raise SystemExit(1)

    click.echo(style_success("API key stored securely in keychain."))


@proxy_auth.command("delete-key")
@click.option("--proxy", "-p", "proxy_name", required=True, help="Proxy name")
@click.option("--force", "-f", is_flag=True, help="Skip confirmation prompt")
def auth_delete_key(proxy_name: str, force: bool) -> None:
    """Remove API key for a proxy.

    Deletes the key from the OS keychain and removes the reference from config.
    """
    from mcp_acp.config import load_proxy_config
    from mcp_acp.security.credential_storage import BackendCredentialStorage

    # Check proxy exists
    config_path = get_proxy_config_path(proxy_name)
    if not config_path.exists():
        click.echo(style_error(f"Proxy '{proxy_name}' not found"))
        click.echo(style_dim(f"Expected config at: {config_path}"))
        raise SystemExit(1)

    # Load config
    try:
        config = load_proxy_config(proxy_name)
    except (FileNotFoundError, ValueError, OSError) as e:
        click.echo(style_error(f"Failed to load proxy config: {e}"))
        raise SystemExit(1)

    # Check if API key exists
    if config.backend.http is None or config.backend.http.credential_key is None:
        click.echo(style_dim("No API key configured for this proxy."))
        return

    # Confirm deletion
    if not force:
        if not click.confirm(f"Remove API key for proxy '{proxy_name}'?"):
            click.echo(style_dim("Cancelled."))
            return

    # Delete from keychain
    cred_storage = BackendCredentialStorage(proxy_name)
    try:
        cred_storage.delete()
    except RuntimeError as e:
        click.echo(style_error(f"Failed to delete API key from keychain: {e}"))
        raise SystemExit(1)

    # Update config to remove credential reference
    try:
        updated_http = config.backend.http.model_copy(update={"credential_key": None})
        updated_backend = config.backend.model_copy(update={"http": updated_http})
        updated_config = config.model_copy(update={"backend": updated_backend})
        save_proxy_config(proxy_name, updated_config)
    except (ValueError, OSError) as e:
        click.echo(style_error(f"Failed to update config: {e}"))
        raise SystemExit(1)

    click.echo(style_success("API key removed from keychain."))
