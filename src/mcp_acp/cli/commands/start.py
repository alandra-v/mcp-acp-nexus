"""Start command for mcp-acp CLI.

Starts the proxy server for manual testing.
"""

from __future__ import annotations

__all__ = [
    "start",
]

import sys
from pathlib import Path
from typing import NoReturn

import click

from mcp_acp import __version__
from ..styling import style_error
from mcp_acp.config import build_app_config_from_per_proxy, load_proxy_config
from mcp_acp.manager.config import (
    get_manager_config_path,
    get_proxy_config_path,
    get_proxy_policy_path,
    list_configured_proxies,
    load_manager_config,
)
from mcp_acp.utils.policy import load_policy
from mcp_acp.utils.history_logging.policy_logger import (
    log_policy_loaded,
    log_policy_validation_failed,
)
from mcp_acp.cli.startup_alerts import show_startup_error_popup
from mcp_acp.exceptions import (
    AuditFailure,
    AuthenticationError,
    DeviceHealthError,
    IdentityVerificationFailure,
)
from mcp_acp.utils.config import (
    ensure_directories,
    get_log_path,
)
from mcp_acp.utils.history_logging import (
    log_config_loaded,
    log_config_validation_failed as log_config_validation_failed_fn,
    log_startup_error,
)

# Bootstrap log filename (used when config is invalid and log_dir unavailable)
BOOTSTRAP_LOG_FILENAME = "bootstrap.jsonl"


def _handle_startup_error(
    bootstrap_log_path: Path,
    *,
    event: str,
    error: Exception,
    popup_message: str,
    popup_detail: str,
    terminal_message: str,
    exit_code: int = 1,
    extra_terminal_lines: list[str] | None = None,
    newline_prefix: bool = True,
    terminal_first: bool = False,
    skip_logging: bool = False,
) -> NoReturn:
    """Handle a startup error with consistent logging, popup, and terminal output.

    This centralizes the error handling pattern used throughout the start command
    while preserving all behavioral details.

    Args:
        bootstrap_log_path: Path to bootstrap.jsonl for logging.
        event: Event name for the log entry.
        error: The exception being handled.
        popup_message: Short message for the macOS popup.
        popup_detail: Detailed message for the popup.
        terminal_message: Error message for terminal output.
        exit_code: Process exit code (default 1).
        extra_terminal_lines: Additional lines to print after the error.
        newline_prefix: Whether to prefix terminal message with newline.
        terminal_first: If True, show terminal output before popup.
        skip_logging: If True, skip log_startup_error (for special cases).

    Raises:
        SystemExit: Always raised with the specified exit_code.
    """
    # Log to bootstrap.jsonl
    if not skip_logging:
        log_startup_error(
            bootstrap_log_path,
            event=event,
            error_message=str(error),
            error_type=type(error).__name__,
            exit_code=exit_code,
        )

    def show_terminal() -> None:
        prefix = "\n" if newline_prefix else ""
        click.echo(prefix + style_error(terminal_message), err=True)
        if extra_terminal_lines:
            for line in extra_terminal_lines:
                click.echo(line, err=True)

    def show_popup() -> None:
        show_startup_error_popup(
            title="MCP ACP",
            message=popup_message,
            detail=popup_detail,
            backoff=True,
        )

    if terminal_first:
        show_terminal()
        show_popup()
    else:
        show_popup()
        show_terminal()

    sys.exit(exit_code)


@click.command()
@click.option("--headless", is_flag=True, help="Run without web UI (no manager auto-start, CLI-only mode)")
@click.option("--proxy", "-p", "proxy_name", help="Proxy name to start (required for multi-proxy mode)")
def start(headless: bool, proxy_name: str | None) -> None:
    """Start the proxy server manually (for testing).

    Loads configuration from the OS-appropriate location.
    No runtime overrides - all settings come from config file.

    Normally the proxy is started by the MCP client (e.g., Claude Desktop).
    This command is useful for manual testing.

    Examples:
        mcp-acp start --proxy filesystem    # Start specific proxy
        mcp-acp start                       # Shows available proxies
    """
    # If no proxy specified, show available proxies and exit
    if not proxy_name:
        proxies = list_configured_proxies()
        if proxies:
            click.echo("Available proxies:", err=True)
            for name in proxies:
                click.echo(f"  - {name}", err=True)
            click.echo(err=True)
            click.echo("Start a specific proxy with: mcp-acp start --proxy <name>", err=True)
            click.echo(err=True)
            click.echo("Note: Each proxy runs in STDIO mode and needs its own terminal.", err=True)
            click.echo("Claude Desktop starts each proxy automatically.", err=True)
        else:
            click.echo("No proxies configured.", err=True)
            click.echo("Run 'mcp-acp proxy add' to create one.", err=True)
        sys.exit(1)

    # Multi-proxy mode: load from proxies/{name}/
    config_path = get_proxy_config_path(proxy_name)
    policy_path = get_proxy_policy_path(proxy_name)
    manager_config_path = get_manager_config_path()

    # Check config existence BEFORE setting up bootstrap log path
    # This avoids creating directories for non-existent proxies
    if not manager_config_path.exists():
        show_startup_error_popup(
            title="MCP ACP",
            message="Manager not initialized.",
            detail="Run in terminal:\n  mcp-acp init\n\nThen restart your MCP client.",
            backoff=True,
        )
        click.echo(err=True)
        click.echo(style_error("Error: Manager config not found."), err=True)
        click.echo("Run 'mcp-acp init' to create a configuration.", err=True)
        sys.exit(1)
    if not config_path.exists():
        available = list_configured_proxies()
        available_hint = f"\n\nAvailable proxies: {', '.join(available)}" if available else ""
        show_startup_error_popup(
            title="MCP ACP",
            message=f"Proxy '{proxy_name}' not found.",
            detail=f"Run in terminal:\n  mcp-acp proxy add\n\nThen restart your MCP client.{available_hint}",
            backoff=True,
        )
        click.echo(err=True)
        click.echo(style_error(f"Error: Proxy '{proxy_name}' not found."), err=True)
        click.echo("Run 'mcp-acp proxy add' to create it.", err=True)
        if available:
            click.echo(f"Available proxies: {', '.join(available)}", err=True)
        sys.exit(1)

    bootstrap_log_path = config_path.parent / BOOTSTRAP_LOG_FILENAME

    try:

        per_proxy_config = load_proxy_config(proxy_name)
        manager_config = load_manager_config()

        # Build AppConfig: OIDC from manager, mTLS/log_level from per-proxy
        oidc_config = manager_config.auth.oidc if manager_config.auth else None
        loaded_config = build_app_config_from_per_proxy(
            proxy_name=proxy_name,
            per_proxy=per_proxy_config,
            oidc=oidc_config,
            log_dir=manager_config.log_dir,
        )

        # Extract log path parameters
        _proxy_name = loaded_config.proxy.name
        _log_dir = loaded_config.logging.log_dir
        _log_level = loaded_config.logging.log_level

        # Ensure directories exist
        ensure_directories(_proxy_name, _log_dir, _log_level)

        # Log config loaded (detects manual changes, updates version)
        config_version, config_manual_changed = log_config_loaded(
            get_log_path(_proxy_name, "config_history", _log_dir),
            config_path,
            loaded_config.model_dump(),
            component="cli",
            source="cli_start",
        )

        # Load policy (policy_path already set based on mode)
        loaded_policy = load_policy(policy_path)

        # Log policy loaded (detects manual changes, updates version)
        policy_version, policy_manual_changed = log_policy_loaded(
            get_log_path(_proxy_name, "policy_history", _log_dir),
            policy_path,
            loaded_policy.model_dump(),
            component="cli",
            source="cli_start",
        )

        # Show startup info (transport shown after detection)
        click.echo(f"mcp-acp v{__version__}", err=True)
        click.echo(f"Config version: {config_version}", err=True)
        click.echo(f"Policy version: {policy_version}", err=True)
        if config_manual_changed:
            click.echo("Note: Manual config changes detected", err=True)
        if policy_manual_changed:
            click.echo("Note: Manual policy changes detected", err=True)
        click.echo(f"Backend: {loaded_config.backend.server_name}", err=True)

        # Create proxy (detects/validates transport)
        # Lazy import to avoid circular import (cli -> proxy -> cli.startup_alerts -> cli)
        from mcp_acp.proxy import create_proxy

        proxy, actual_transport = create_proxy(
            loaded_config,
            config_version=config_version,
            policy_version=policy_version,
            enable_ui=not headless,
        )

        # Display actual transport used (after detection)
        # mTLS only applies to HTTPS URLs with streamablehttp transport
        uses_mtls = (
            actual_transport == "streamablehttp"
            and loaded_config.mtls
            and loaded_config.backend.http
            and loaded_config.backend.http.url.lower().startswith("https://")
        )
        mtls_suffix = " with mTLS" if uses_mtls else ""
        click.echo(f"Backend transport: {actual_transport}{mtls_suffix}", err=True)
        click.echo("-" * 50, err=True)

        click.echo("Proxy server ready - listening on STDIO", err=True)
        click.echo("Press Ctrl+C to stop", err=True)

        # Set up clean shutdown on Ctrl+C and kill
        # Use os._exit(0) for immediate exit - finally blocks don't reliably run
        # in async context with signals. Stale socket cleanup at startup handles this.
        import os
        import signal

        def handle_shutdown(signum: int, frame: object) -> None:
            os._exit(0)

        signal.signal(signal.SIGINT, handle_shutdown)
        signal.signal(signal.SIGTERM, handle_shutdown)

        # proxy server listens for clients via STDIO
        try:
            proxy.run()
        except (KeyboardInterrupt, SystemExit):
            pass  # Clean exit

    except FileNotFoundError as e:
        error_msg = str(e).lower()
        # Distinguish between config not found vs mTLS cert not found
        if "mtls" in error_msg or "certificate" in error_msg or "cert" in error_msg:
            _handle_startup_error(
                bootstrap_log_path,
                event="mtls_cert_not_found",
                error=e,
                popup_message="mTLS certificate not found.",
                popup_detail=f"{e}\n\nCheck the mTLS section in:\n  {config_path}",
                terminal_message=f"Error: mTLS certificate not found: {e}",
            )
        elif "policy" in error_msg:
            # Policy file missing (config exists but policy was deleted)
            _handle_startup_error(
                bootstrap_log_path,
                event="policy_not_found",
                error=e,
                popup_message=f"Policy not found for proxy '{proxy_name}'.",
                popup_detail=f"Policy file missing:\n  {policy_path}\n\nThe file may have been deleted.",
                terminal_message=f"Error: Policy file not found: {e}",
            )
        else:
            # Other configuration file not found
            _handle_startup_error(
                bootstrap_log_path,
                event="config_not_found",
                error=e,
                popup_message=f"Configuration not found for proxy '{proxy_name}'.",
                popup_detail=f"{e}",
                terminal_message=f"Error: File not found: {e}",
            )

    except ValueError as e:
        error_msg = str(e)

        # Determine if this is a config or policy error
        is_policy_error = "policy" in error_msg.lower()

        # Log validation failure to bootstrap log (before user's log_dir is available)
        try:
            if is_policy_error:
                log_policy_validation_failed(
                    bootstrap_log_path,
                    policy_path,
                    error_type="ValidationError",
                    error_message=error_msg,
                    component="cli",
                    source="cli_start",
                )
            else:
                log_config_validation_failed_fn(
                    bootstrap_log_path,
                    config_path,
                    error_type="ValidationError",
                    error_message=error_msg,
                    component="cli",
                    source="cli_start",
                )
        except OSError as log_err:
            # Don't fail startup due to logging errors, but warn for debugging
            click.echo(f"Warning: Could not write to bootstrap log: {log_err}", err=True)

        if is_policy_error:
            show_startup_error_popup(
                title="MCP ACP",
                message=f"Invalid policy for proxy '{proxy_name}'.",
                detail=f"{error_msg}",
                backoff=True,
            )
            click.echo("\n" + style_error(f"Error: Invalid policy: {e}"), err=True)
        else:
            show_startup_error_popup(
                title="MCP ACP",
                message=f"Invalid configuration for proxy '{proxy_name}'.",
                detail=f"{error_msg}",
                backoff=True,
            )
            click.echo("\n" + style_error(f"Error: Invalid configuration: {e}"), err=True)

        # Check for backup if config file is corrupt
        if "Invalid JSON" in error_msg or "Could not read" in error_msg:
            if is_policy_error:
                backup_path = policy_path.with_suffix(".json.bak")
            else:
                backup_path = config_path.with_suffix(".json.bak")
            if backup_path.exists():
                click.echo("\nA backup file exists from a previous edit.", err=True)
                click.echo(f"To restore: cp '{backup_path}' '{backup_path.with_suffix('')}'", err=True)

        sys.exit(1)

    except TimeoutError as e:
        _handle_startup_error(
            bootstrap_log_path,
            event="backend_timeout",
            error=e,
            popup_message="Backend connection timed out.",
            popup_detail=f"{e}\n\nCheck that the backend server is running and responsive.",
            terminal_message=f"Error: Backend connection timed out: {e}",
            newline_prefix=False,
        )

    except ConnectionError as e:
        # Check for SSL-specific errors
        error_msg = str(e).lower()
        if "ssl" in error_msg or "certificate" in error_msg:
            _handle_startup_error(
                bootstrap_log_path,
                event="ssl_error",
                error=e,
                popup_message="SSL/TLS error.",
                popup_detail=f"{e}\n\nCheck your mTLS certificate configuration.",
                terminal_message=f"Error: SSL/TLS error: {e}",
                newline_prefix=False,
            )
        else:
            _handle_startup_error(
                bootstrap_log_path,
                event="backend_connection_failed",
                error=e,
                popup_message="Backend connection failed.",
                popup_detail=f"{e}\n\nCheck that the backend server is running.",
                terminal_message=f"Error: Backend connection failed: {e}",
                newline_prefix=False,
            )

    except AuditFailure as e:
        _handle_startup_error(
            bootstrap_log_path,
            event="audit_failure",
            error=e,
            popup_message="Audit log failure.",
            popup_detail=f"{e}\n\nThe proxy cannot start without a writable audit log.\nCheck file permissions in the log directory.",
            terminal_message=f"Error: Audit log failure: {e}",
            exit_code=AuditFailure.exit_code,
            extra_terminal_lines=["The proxy cannot start without a writable audit log."],
            newline_prefix=False,
        )

    except AuthenticationError as e:
        error_msg = str(e).lower()
        if "not configured" in error_msg:
            # Auth section missing from config - need to run init
            _handle_startup_error(
                bootstrap_log_path,
                event="auth_not_configured",
                error=e,
                popup_message="Authentication not configured.",
                popup_detail="Run in terminal:\n  mcp-acp init\n\nThen restart your MCP client.",
                terminal_message="Error: Authentication not configured.",
                exit_code=AuthenticationError.exit_code,
                extra_terminal_lines=["Run 'mcp-acp init' to configure authentication."],
                terminal_first=True,
            )
        elif "not authenticated" in error_msg or "no token" in error_msg or "token not found" in error_msg:
            # Token not found in keychain - need to login
            _handle_startup_error(
                bootstrap_log_path,
                event="not_authenticated",
                error=e,
                popup_message="Not authenticated.",
                popup_detail="Run in terminal:\n  mcp-acp auth login\n\nThen restart your MCP client.",
                terminal_message="Error: Not authenticated.",
                exit_code=AuthenticationError.exit_code,
                extra_terminal_lines=["Run 'mcp-acp auth login' to authenticate."],
                terminal_first=True,
            )
        elif "expired" in error_msg:
            # Token expired and refresh failed - need to re-login
            _handle_startup_error(
                bootstrap_log_path,
                event="auth_expired",
                error=e,
                popup_message="Auth session expired.",
                popup_detail="Run in terminal:\n  mcp-acp auth login\n\nThen restart your MCP client.",
                terminal_message="Error: Auth session expired.",
                exit_code=AuthenticationError.exit_code,
                extra_terminal_lines=["Run 'mcp-acp auth login' to re-authenticate."],
                terminal_first=True,
            )
        else:
            # Generic auth error
            _handle_startup_error(
                bootstrap_log_path,
                event="auth_failed",
                error=e,
                popup_message="Authentication error.",
                popup_detail=f"{e}\n\nRun 'mcp-acp auth login' to re-authenticate.",
                terminal_message="Error: Authentication failed.",
                exit_code=AuthenticationError.exit_code,
                extra_terminal_lines=[str(e), "", "Run 'mcp-acp auth login' to re-authenticate."],
                terminal_first=True,
            )

    except DeviceHealthError as e:
        _handle_startup_error(
            bootstrap_log_path,
            event="device_health_failed",
            error=e,
            popup_message="Device health check failed.",
            popup_detail=f"{e}\n\nEnsure FileVault is enabled and SIP is not disabled.",
            terminal_message="Error: Device health check failed",
            exit_code=DeviceHealthError.exit_code,
            extra_terminal_lines=[str(e)],
        )

    except IdentityVerificationFailure as e:
        _handle_startup_error(
            bootstrap_log_path,
            event="identity_verification_failed",
            error=e,
            popup_message="Cannot reach identity provider.",
            popup_detail=f"{e}",
            terminal_message="Error: Cannot reach identity provider",
            exit_code=IdentityVerificationFailure.exit_code,
            extra_terminal_lines=[str(e)],
        )

    except (PermissionError, RuntimeError, OSError) as e:
        _handle_startup_error(
            bootstrap_log_path,
            event="startup_failed",
            error=e,
            popup_message="Proxy startup failed.",
            popup_detail=f"{e}",
            terminal_message=f"Error: Proxy startup failed: {e}",
            newline_prefix=False,
        )
