"""Init command for mcp-acp CLI.

Initializes manager configuration with authentication settings.
Backend configuration is handled per-proxy via 'mcp-acp proxy add'.
"""

from __future__ import annotations

__all__ = ["init"]

import sys

import click

from mcp_acp.config import AuthConfig, OIDCConfig
from mcp_acp.manager.config import (
    ManagerConfig,
    get_manager_config_path,
    save_manager_config,
)
from mcp_acp.security.auth.token_storage import create_token_storage
from mcp_acp.utils.validation import is_valid_oidc_issuer

from ..prompts import prompt_optional, prompt_with_retry
from ..styling import style_dim, style_error, style_header, style_success, style_warning


# =============================================================================
# Validation Helpers
# =============================================================================


def _require_flag(value: str | None, flag_name: str, message: str | None = None) -> str:
    """Validate a required CLI flag, exit with error if missing.

    Args:
        value: The flag value to validate.
        flag_name: Name of the flag (without --) for error message.
        message: Optional custom error message (overrides default).

    Returns:
        The validated non-None value.

    Raises:
        SystemExit: If value is None or empty.
    """
    if not value:
        msg = message or f"--{flag_name} is required"
        click.echo(style_error(f"Error: {msg}"), err=True)
        sys.exit(1)
    return value


def _check_oidc_change_warning(
    old_config: ManagerConfig | None,
    new_auth_config: AuthConfig,
) -> None:
    """Warn if OIDC settings changed and user has stored tokens.

    When OIDC settings change (issuer, client_id, audience), existing tokens
    become invalid. This warns the user to re-authenticate.

    Args:
        old_config: Previous configuration (None if no config existed).
        new_auth_config: New authentication configuration being saved.
    """
    if old_config is None or old_config.auth is None:
        return

    old_oidc = old_config.auth.oidc
    new_oidc = new_auth_config.oidc

    # Check if OIDC settings changed
    oidc_changed = False
    if old_oidc and new_oidc:
        # Both have OIDC - check if settings differ
        if (
            old_oidc.issuer != new_oidc.issuer
            or old_oidc.client_id != new_oidc.client_id
            or old_oidc.audience != new_oidc.audience
        ):
            oidc_changed = True
    elif old_oidc and not new_oidc:
        # Had OIDC, now removed
        oidc_changed = True

    if not oidc_changed:
        return

    # Check if tokens exist
    try:
        storage = create_token_storage(old_oidc)
        if storage.exists():
            click.echo()
            click.echo(style_warning("OIDC settings changed"))
            click.echo("  Your stored authentication token was created with different settings.")
            click.echo("  You will need to run 'mcp-acp auth login' to re-authenticate.")
            click.echo()
    except Exception:
        # Can't check token storage - don't warn, not critical
        pass


# =============================================================================
# Auth Prompting
# =============================================================================


def _prompt_oidc_config() -> OIDCConfig:
    """Prompt for OIDC configuration.

    Returns:
        OIDCConfig with validated settings.
    """
    click.echo()
    click.echo(style_header("OIDC Authentication"))
    click.echo("Configure Auth0/OIDC for user authentication.")
    click.echo()

    # OIDC issuer - validate URL format
    while True:
        issuer = prompt_with_retry("OIDC issuer URL (e.g., https://your-tenant.auth0.com)")
        if is_valid_oidc_issuer(issuer):
            break
        click.echo(style_error(f"\nInvalid issuer URL: {issuer}"))
        click.echo("  OIDC issuer must start with https://\n")

    client_id = prompt_with_retry("Auth0 client ID")
    audience = prompt_with_retry("API audience (e.g., https://your-api.example.com)")

    return OIDCConfig(
        issuer=issuer,
        client_id=client_id,
        audience=audience,
    )


# =============================================================================
# Setup Flows
# =============================================================================


def _run_interactive_init() -> AuthConfig:
    """Run interactive configuration wizard.

    Returns:
        AuthConfig with user-provided values.
    """
    click.echo("\nWelcome to mcp-acp!\n")
    click.echo("This wizard sets up the manager config and OIDC identity provider.")
    click.echo("After init, add your first proxy with 'mcp-acp proxy add'.\n")

    config_path = get_manager_config_path()
    click.echo(f"Config will be saved to: {config_path}\n")

    # OIDC settings (required)
    oidc_config = _prompt_oidc_config()

    return AuthConfig(oidc=oidc_config)


def _run_non_interactive_init(
    oidc_issuer: str | None,
    oidc_client_id: str | None,
    oidc_audience: str | None,
) -> AuthConfig:
    """Run non-interactive configuration setup.

    Args:
        oidc_issuer: OIDC issuer URL.
        oidc_client_id: Auth0 client ID.
        oidc_audience: API audience.

    Returns:
        AuthConfig with validated configuration.

    Raises:
        SystemExit: If required flags are missing or validation fails.
    """
    # Validate required OIDC flags
    oidc_issuer = _require_flag(oidc_issuer, "oidc-issuer")
    oidc_client_id = _require_flag(oidc_client_id, "oidc-client-id")
    oidc_audience = _require_flag(oidc_audience, "oidc-audience")

    # Validate OIDC issuer URL format (must be HTTPS per OpenID Connect spec)
    if not is_valid_oidc_issuer(oidc_issuer):
        click.echo(style_error("Error: --oidc-issuer must start with https://"), err=True)
        sys.exit(1)

    oidc_config = OIDCConfig(
        issuer=oidc_issuer,
        client_id=oidc_client_id,
        audience=oidc_audience,
    )

    return AuthConfig(oidc=oidc_config)


def _display_next_steps() -> None:
    """Display next steps after successful init."""
    click.echo()
    click.echo(style_header("Next Steps"))
    click.echo()
    click.echo("1. Authenticate with your identity provider:")
    click.echo(style_dim("   mcp-acp auth login"))
    click.echo()
    click.echo("2. Add your first proxy or start the manager:")
    click.echo(style_dim("   mcp-acp proxy add"))
    click.echo(style_dim("   mcp-acp manager start"))


# =============================================================================
# CLI Command
# =============================================================================


@click.command()
@click.option(
    "--non-interactive",
    is_flag=True,
    help="Skip prompts, require all options via flags",
)
# OIDC options (required)
@click.option("--oidc-issuer", help="OIDC issuer URL (e.g., https://your-tenant.auth0.com)")
@click.option("--oidc-client-id", help="Auth0 client ID")
@click.option("--oidc-audience", help="API audience for token validation")
@click.option("--force", is_flag=True, help="Overwrite existing config without prompting")
def init(
    non_interactive: bool,
    oidc_issuer: str | None,
    oidc_client_id: str | None,
    oidc_audience: str | None,
    force: bool,
) -> None:
    """Initialize mcp-acp with authentication configuration.

    Creates manager.json with OIDC settings shared across all proxies.

    After init, run:
      1. mcp-acp auth login  - authenticate with your identity provider
      2. mcp-acp proxy add   - add your first proxy configuration

    \b
    OIDC (Required):
    Configure Auth0 or another OIDC provider for user authentication.
    The proxy validates user tokens against this provider.

    \b
    mTLS:
    For HTTPS backends requiring client certificates, configure mTLS
    per-proxy using 'mcp-acp proxy add --mtls-cert --mtls-key --mtls-ca'.

    Use --non-interactive with required flags for scripted setup.
    """
    config_path = get_manager_config_path()
    config_exists = config_path.exists()

    # If config exists, ask to overwrite (unless --force)
    if config_exists and not force:
        if non_interactive:
            click.echo(style_error("Error: Config already exists. Use --force to overwrite."), err=True)
            sys.exit(1)
        if not click.confirm("Config already exists. Overwrite?", default=False):
            click.echo(style_dim("Aborted."))
            sys.exit(0)

    # Load existing config to check for OIDC changes later
    old_config: ManagerConfig | None = None
    if config_exists:
        try:
            from mcp_acp.manager.config import load_manager_config

            old_config = load_manager_config()
        except Exception:
            # Can't load old config - skip the warning
            pass

    # Gather configuration values
    try:
        if non_interactive:
            auth_config = _run_non_interactive_init(
                oidc_issuer,
                oidc_client_id,
                oidc_audience,
            )
        else:
            auth_config = _run_interactive_init()
    except click.Abort:
        click.echo(style_dim("Aborted."))
        sys.exit(0)

    # Warn if OIDC settings changed and user has stored tokens
    _check_oidc_change_warning(old_config, auth_config)

    # Create and save configuration
    manager_config = ManagerConfig(auth=auth_config)

    try:
        save_manager_config(manager_config)
        click.echo("\n" + style_success(f"Configuration saved to {config_path}"))
    except OSError as e:
        click.echo(style_error(f"Error: Failed to save configuration: {e}"), err=True)
        sys.exit(1)

    # Display next steps
    _display_next_steps()
