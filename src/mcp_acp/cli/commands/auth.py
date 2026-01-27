"""Authentication commands for mcp-acp CLI.

Commands:
    auth login    - Authenticate via browser (Device Flow)
    auth logout   - Clear stored credentials
    auth status   - Show authentication status
    auth sessions - Session management (list active sessions)
"""

from __future__ import annotations

__all__ = ["auth"]

import json as json_module
import webbrowser
from datetime import datetime
from typing import TYPE_CHECKING, Any

import click

from mcp_acp.cli.api_client import api_request
from mcp_acp.constants import CLI_NOTIFICATION_TIMEOUT_SECONDS
from mcp_acp.exceptions import AuthenticationError
from mcp_acp.security.auth.device_flow import (
    DeviceFlowDeniedError,
    DeviceFlowError,
    DeviceFlowExpiredError,
    run_device_flow,
)
from mcp_acp.security.auth.token_storage import (
    create_token_storage,
    get_token_storage_info,
)
from mcp_acp.utils.cli import load_manager_config_or_exit

from ..styling import style_dim, style_success

if TYPE_CHECKING:
    from mcp_acp.config import OIDCConfig
    from mcp_acp.manager.config import ManagerConfig


def _notify_manager(action: str) -> bool:
    """Notify running manager of auth change.

    In multi-proxy mode, the manager handles token distribution to all proxies.
    CLI calls manager's HTTP API to trigger reload/clear.

    Args:
        action: "reload" after login, "clear" after logout.

    Returns:
        True if notification succeeded, False otherwise.
    """
    import httpx

    from mcp_acp.manager.config import load_manager_config
    from mcp_acp.manager.daemon import is_manager_running

    if not is_manager_running():
        return False

    try:
        # Use port from manager config (not hardcoded default)
        config = load_manager_config()
        endpoint = f"/api/manager/auth/{action}"
        url = f"http://127.0.0.1:{config.ui_port}{endpoint}"
        response = httpx.post(url, timeout=CLI_NOTIFICATION_TIMEOUT_SECONDS)
        return response.status_code == 200 and response.json().get("ok", False)
    except (httpx.HTTPError, httpx.TimeoutException, OSError):
        return False


@click.group()
def auth() -> None:
    """Authentication commands."""
    pass


@auth.command()
@click.option(
    "--no-browser",
    is_flag=True,
    help="Don't automatically open browser",
)
def login(no_browser: bool) -> None:
    """Authenticate via browser using Device Flow.

    Opens your browser to complete authentication. Tokens are stored
    securely in your OS keychain.

    This is the same pattern as 'gh auth login' or 'aws sso login'.
    """
    # Load manager config to get OIDC settings
    manager_config = load_manager_config_or_exit()

    if manager_config.auth is None or manager_config.auth.oidc is None:
        raise click.ClickException(
            "Authentication not configured.\n" "Run 'mcp-acp init' to configure OIDC authentication."
        )

    oidc_config = manager_config.auth.oidc

    click.echo("Starting authentication...")
    click.echo()

    # Track if we've opened browser
    browser_opened = False

    def display_callback(
        user_code: str,
        verification_uri: str,
        verification_uri_complete: str | None,
    ) -> None:
        """Display authentication instructions to user."""
        nonlocal browser_opened

        # Use the complete URI if available (has code embedded)
        auth_url = verification_uri_complete or verification_uri

        click.echo(click.style("Authentication Required", fg="cyan", bold=True))
        click.echo()

        # Always show the code - user needs to confirm it matches in browser
        click.echo(f"  Your code: {click.style(user_code, fg='green', bold=True)}")
        click.echo()

        if verification_uri_complete:
            click.echo(f"  Open this URL in your browser:")
            click.echo(f"  {click.style(auth_url, fg='blue', underline=True)}")
        else:
            click.echo(f"  1. Open: {click.style(verification_uri, fg='blue', underline=True)}")
            click.echo(f"  2. Enter the code above")

        click.echo()

        # Try to open browser automatically
        if not no_browser:
            try:
                webbrowser.open(auth_url)
                browser_opened = True
                click.echo("  Browser opened automatically.")
            except (OSError, webbrowser.Error) as e:
                click.echo(f"  (Could not open browser automatically: {e})")

        click.echo()
        click.echo("Waiting for authentication", nl=False)

    def poll_callback() -> None:
        """Show progress while polling."""
        click.echo(".", nl=False)

    try:
        # Run the device flow
        token = run_device_flow(
            config=oidc_config,
            display_callback=display_callback,
            poll_callback=poll_callback,
        )

        click.echo()  # Newline after dots
        click.echo()

        # Store token
        storage = create_token_storage(oidc_config)
        storage.save(token)

        # Notify running manager (if any) to reload and broadcast tokens
        manager_notified = _notify_manager("reload")

        # Show success
        click.echo(click.style(style_success("Authentication successful!"), bold=True))
        click.echo()

        # Show storage info
        storage_info = get_token_storage_info()
        click.echo(f"  Token stored in: {storage_info['backend']}")

        # Show expiry
        hours_until_expiry = token.seconds_until_expiry / 3600
        click.echo(f"  Token expires in: {hours_until_expiry:.1f} hours")

        # Show manager sync status
        if manager_notified:
            click.echo("  Running proxies updated with new credentials.")
        else:
            click.echo()
            click.echo("You can now start the proxy with 'mcp-acp start'")

    except DeviceFlowExpiredError:
        click.echo()
        click.echo()
        raise click.ClickException("Authentication timed out. Please run 'mcp-acp auth login' again.")

    except DeviceFlowDeniedError:
        click.echo()
        click.echo()
        raise click.ClickException("Authentication was denied.")

    except DeviceFlowError as e:
        click.echo()
        click.echo()
        raise click.ClickException(f"Authentication failed: {e}")


@auth.command()
@click.option(
    "--federated",
    is_flag=True,
    help="Also log out of the identity provider (Auth0) in your browser",
)
def logout(federated: bool) -> None:
    """Clear stored credentials.

    Removes tokens from your OS keychain. You will need to run
    'auth login' again to use the proxy.

    Use --federated to also log out of Auth0 in your browser. This is
    useful when switching between different users.
    """
    # Load manager config to get OIDC settings (for storage selection)
    manager_config = load_manager_config_or_exit()

    oidc_config = manager_config.auth.oidc if manager_config.auth else None
    storage = create_token_storage(oidc_config)

    if not storage.exists():
        click.echo(style_dim("No stored credentials found."))
        # Still do federated logout if requested (browser session may exist)
        if federated and oidc_config:
            _do_federated_logout(oidc_config)
        return

    try:
        # Notify running manager BEFORE clearing tokens
        manager_notified = _notify_manager("clear")

        storage.delete()
        click.echo(style_success("Local credentials cleared."))

        # Show manager sync status
        if manager_notified:
            click.echo("  Running proxies logged out.")

        # Federated logout if requested
        if federated and oidc_config:
            _do_federated_logout(oidc_config)
        elif oidc_config:
            click.echo()
            click.echo("Tip: Use --federated to also log out of Auth0 in your browser.")

        click.echo()
        click.echo("Run 'mcp-acp auth login' to authenticate again.")
    except AuthenticationError as e:
        raise click.ClickException(f"Failed to clear credentials: {e}")


def _do_federated_logout(oidc_config: OIDCConfig) -> None:
    """Open browser to log out of the identity provider.

    Args:
        oidc_config: OIDC configuration with issuer and client_id.
    """
    # Build Auth0 logout URL
    # Format: https://{issuer}/v2/logout?client_id={client_id}
    issuer = oidc_config.issuer.rstrip("/")
    logout_url = f"{issuer}/v2/logout?client_id={oidc_config.client_id}"

    click.echo()
    click.echo("Opening browser to log out of Auth0...")

    try:
        webbrowser.open(logout_url)
        click.echo(style_success("Browser opened for Auth0 logout."))
    except (OSError, webbrowser.Error) as e:
        click.echo(f"Could not open browser automatically: {e}")
        click.echo(f"Open this URL manually: {logout_url}")


@auth.command()
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def status(as_json: bool) -> None:
    """Show authentication status.

    Displays token validity, user info, and storage backend.
    """
    import json as json_module

    # Load manager config
    manager_config = load_manager_config_or_exit()

    # Build result dict for JSON output
    result: dict[str, Any] = {
        "configured": False,
        "authenticated": False,
        "status": "not_configured",
    }

    if manager_config.auth is None or manager_config.auth.oidc is None:
        result["status"] = "not_configured"
        if as_json:
            click.echo(json_module.dumps(result, indent=2))
        else:
            click.echo(click.style("Authentication not configured", fg="yellow"))
            click.echo()
            click.echo("Run 'mcp-acp init' to configure OIDC authentication.")
        return

    result["configured"] = True
    oidc_config = manager_config.auth.oidc
    storage = create_token_storage(oidc_config)

    # Storage info
    storage_info = get_token_storage_info()
    result["storage"] = storage_info

    # OIDC config (non-sensitive)
    result["oidc"] = {
        "issuer": oidc_config.issuer,
        "client_id": oidc_config.client_id,
        "audience": oidc_config.audience,
    }

    # Check for token
    if not storage.exists():
        result["status"] = "not_authenticated"
        if as_json:
            click.echo(json_module.dumps(result, indent=2))
        else:
            _print_status_formatted(result, storage_info, oidc_config, manager_config)
        return

    # Load and validate token
    try:
        token = storage.load()
    except AuthenticationError as e:
        result["status"] = "token_corrupted"
        result["error"] = str(e)
        if as_json:
            click.echo(json_module.dumps(result, indent=2))
        else:
            click.echo(click.style("Status: Token corrupted", fg="red"))
            click.echo(f"  Error: {e}")
            click.echo()
            click.echo("Run 'mcp-acp auth logout' then 'auth login' to fix.")
        return

    if token is None:
        result["status"] = "not_authenticated"
        if as_json:
            click.echo(json_module.dumps(result, indent=2))
        else:
            _print_status_formatted(result, storage_info, oidc_config, manager_config)
        return

    # Token info
    result["token"] = {
        "expires_in_seconds": token.seconds_until_expiry,
        "has_refresh_token": bool(token.refresh_token),
        "has_id_token": bool(token.id_token),
    }

    # Check expiry
    if token.is_expired:
        result["status"] = "token_expired"
        result["authenticated"] = False
    else:
        result["status"] = "authenticated"
        result["authenticated"] = True

    # Try to extract user info from ID token
    if token.id_token:
        try:
            from mcp_acp.security.auth.jwt_validator import JWTValidator

            validator = JWTValidator(oidc_config)
            claims = validator.decode_without_validation(token.id_token)

            result["user"] = {}
            if "email" in claims:
                result["user"]["email"] = claims["email"]
            if "name" in claims:
                result["user"]["name"] = claims["name"]
            if "sub" in claims:
                result["user"]["subject"] = claims["sub"]

        except (ValueError, KeyError):
            pass  # Can't decode ID token - not critical

    if as_json:
        click.echo(json_module.dumps(result, indent=2))
    else:
        _print_status_formatted(result, storage_info, oidc_config, manager_config)


def _print_status_formatted(
    result: dict[str, Any],
    storage_info: dict[str, Any],
    oidc_config: OIDCConfig,
    manager_config: ManagerConfig,
) -> None:
    """Print auth status in human-readable format."""
    # Show storage info
    click.echo(click.style("Storage", fg="cyan", bold=True))
    click.echo(f"  Backend: {storage_info['backend']}")
    if "keyring_backend" in storage_info:
        click.echo(f"  Keyring: {storage_info['keyring_backend']}")
    if "location" in storage_info:
        click.echo(f"  Location: {storage_info['location']}")
    click.echo()

    # Status
    status_val = result.get("status", "unknown")

    if status_val == "not_authenticated":
        click.echo(click.style("Status: Not authenticated", fg="yellow"))
        click.echo()
        click.echo("Run 'mcp-acp auth login' to authenticate.")
        return

    if status_val == "token_expired":
        click.echo(click.style("Status: Token expired", fg="red"))
        click.echo()
        if result.get("token", {}).get("has_refresh_token"):
            click.echo("Token will be refreshed automatically on next proxy start.")
            click.echo("Or run 'mcp-acp auth login' to re-authenticate now.")
        else:
            click.echo("Run 'mcp-acp auth login' to re-authenticate.")
        return

    # Token is valid
    click.echo(click.style("Status: Authenticated", fg="green", bold=True))
    click.echo()

    # Show token info
    token_info = result.get("token", {})
    if token_info:
        click.echo(click.style("Token", fg="cyan", bold=True))

        expires_in = token_info.get("expires_in_seconds", 0)
        hours_until_expiry = expires_in / 3600
        if hours_until_expiry > 24:
            days = hours_until_expiry / 24
            click.echo(f"  Expires in: {days:.1f} days")
        else:
            click.echo(f"  Expires in: {hours_until_expiry:.1f} hours")

        click.echo(f"  Has refresh token: {'Yes' if token_info.get('has_refresh_token') else 'No'}")
        click.echo(f"  Has ID token: {'Yes' if token_info.get('has_id_token') else 'No'}")

    # User info
    user_info = result.get("user")
    if user_info:
        click.echo()
        click.echo(click.style("User", fg="cyan", bold=True))
        if "email" in user_info:
            click.echo(f"  Email: {user_info['email']}")
        if "name" in user_info:
            click.echo(f"  Name: {user_info['name']}")
        if "subject" in user_info:
            click.echo(f"  Subject: {user_info['subject']}")

    click.echo()
    click.echo(click.style("OIDC Configuration", fg="cyan", bold=True))
    click.echo(f"  Issuer: {oidc_config.issuer}")
    click.echo(f"  Client ID: {oidc_config.client_id}")
    click.echo(f"  Audience: {oidc_config.audience}")

    # Note: mTLS is per-proxy, shown in 'mcp-acp config show --proxy <name>'


# =============================================================================
# auth sessions - Session management subgroup
# =============================================================================


@auth.group()
def sessions() -> None:
    """Session management commands.

    View active authentication sessions.
    Requires the proxy to be running.
    """
    pass


@sessions.command("list")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@click.option("--proxy", "-p", "proxy_name", required=True, help="Proxy name")
def sessions_list(as_json: bool, proxy_name: str) -> None:
    """List active sessions.

    Shows all active authentication sessions with user info and timestamps.

    Example:
        mcp-acp auth sessions list --proxy filesystem
    """
    from ..styling import style_dim, style_label

    data = api_request("GET", "/api/auth-sessions", proxy_name=proxy_name)

    if not isinstance(data, list):
        data = []

    if as_json:
        click.echo(json_module.dumps(data, indent=2))
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
