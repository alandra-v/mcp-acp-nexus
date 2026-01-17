"""Start command for mcp-acp-nexus CLI.

Starts the proxy server for manual testing.
"""

import sys

__all__ = [
    "start",
]

import click

from mcp_acp import __version__
from ..styling import style_error
from mcp_acp.config import AppConfig
from mcp_acp.utils.policy import get_policy_path, load_policy
from mcp_acp.utils.history_logging.policy_logger import (
    log_policy_loaded,
    log_policy_validation_failed,
)
from mcp_acp.cli.startup_alerts import show_startup_error_popup
from mcp_acp.exceptions import AuditFailure, AuthenticationError, DeviceHealthError
from mcp_acp.utils.config import (
    ensure_directories,
    get_config_history_path,
    get_config_path,
    get_policy_history_path,
)
from mcp_acp.utils.history_logging import (
    log_config_loaded,
    log_config_validation_failed as log_config_validation_failed_fn,
)

# Bootstrap log filename (used when config is invalid and log_dir unavailable)
BOOTSTRAP_LOG_FILENAME = "bootstrap.jsonl"


@click.command()
@click.option("--no-ui", is_flag=True, help="Disable web UI completely (no HTTP server)")
def start(no_ui: bool) -> None:
    """Start the proxy server manually (for testing).

    Loads configuration from the OS-appropriate location.
    No runtime overrides - all settings come from config file.

    Normally the proxy is started by the MCP client (e.g., Claude Desktop).
    This command is useful for manual testing.
    """
    config_path = get_config_path()

    try:
        # Load configuration
        loaded_config = AppConfig.load_from_files(config_path)

        # Ensure directories exist
        ensure_directories(loaded_config)

        # Log config loaded (detects manual changes, updates version)
        config_version, config_manual_changed = log_config_loaded(
            get_config_history_path(loaded_config),
            config_path,
            loaded_config.model_dump(),
            component="cli",
            source="cli_start",
        )

        # Load policy
        policy_path = get_policy_path()
        loaded_policy = load_policy(policy_path)

        # Log policy loaded (detects manual changes, updates version)
        policy_version, policy_manual_changed = log_policy_loaded(
            get_policy_history_path(loaded_config),
            policy_path,
            loaded_policy.model_dump(),
            component="cli",
            source="cli_start",
        )

        # Show startup info (transport shown after detection)
        click.echo(f"mcp-acp-nexus v{__version__}", err=True)
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
            enable_ui=not no_ui,
        )

        # Display actual transport used (after detection)
        # mTLS only applies to HTTPS URLs with streamablehttp transport
        uses_mtls = (
            actual_transport == "streamablehttp"
            and loaded_config.auth
            and loaded_config.auth.mtls
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
            show_startup_error_popup(
                title="MCP ACP",
                message="mTLS certificate not found.",
                detail=f"{e}\n\nCheck the mTLS section in:\n  {config_path}",
                backoff=True,
            )
            click.echo("\n" + style_error(f"Error: mTLS certificate not found: {e}"), err=True)
        else:
            show_startup_error_popup(
                title="MCP ACP",
                message="Configuration not found.",
                detail="Run in terminal:\n  mcp-acp-nexus init\n\nThen restart your MCP client.",
                backoff=True,
            )
            click.echo("\n" + style_error("Error: Configuration not found."), err=True)
            click.echo("Run 'mcp-acp-nexus init' to create a configuration.", err=True)
        sys.exit(1)

    except ValueError as e:
        error_msg = str(e)

        # Determine if this is a config or policy error
        is_policy_error = "policy" in error_msg.lower()

        # Log validation failure to bootstrap log (before user's log_dir is available)
        try:
            bootstrap_log_path = config_path.parent / BOOTSTRAP_LOG_FILENAME
            if is_policy_error:
                log_policy_validation_failed(
                    bootstrap_log_path,
                    get_policy_path(),
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
                message="Invalid policy.",
                detail=f"{error_msg}",
                backoff=True,
            )
            click.echo("\n" + style_error(f"Error: Invalid policy: {e}"), err=True)
        else:
            show_startup_error_popup(
                title="MCP ACP",
                message="Invalid configuration.",
                detail=f"{error_msg}",
                backoff=True,
            )
            click.echo("\n" + style_error(f"Error: Invalid configuration: {e}"), err=True)

        # Check for backup if config file is corrupt
        if "Invalid JSON" in error_msg or "Could not read" in error_msg:
            if is_policy_error:
                backup_path = get_policy_path().with_suffix(".json.bak")
            else:
                backup_path = config_path.with_suffix(".json.bak")
            if backup_path.exists():
                click.echo("\nA backup file exists from a previous edit.", err=True)
                click.echo(f"To restore: cp '{backup_path}' '{backup_path.with_suffix('')}'", err=True)

        sys.exit(1)

    except TimeoutError as e:
        show_startup_error_popup(
            title="MCP ACP",
            message="Backend connection timed out.",
            detail=f"{e}\n\nCheck that the backend server is running and responsive.",
            backoff=True,
        )
        click.echo(style_error(f"Error: Backend connection timed out: {e}"), err=True)
        sys.exit(1)

    except ConnectionError as e:
        # Check for SSL-specific errors
        error_msg = str(e).lower()
        if "ssl" in error_msg or "certificate" in error_msg:
            show_startup_error_popup(
                title="MCP ACP",
                message="SSL/TLS error.",
                detail=f"{e}\n\nCheck your mTLS certificate configuration.",
                backoff=True,
            )
            click.echo(style_error(f"Error: SSL/TLS error: {e}"), err=True)
        else:
            show_startup_error_popup(
                title="MCP ACP",
                message="Backend connection failed.",
                detail=f"{e}\n\nCheck that the backend server is running.",
                backoff=True,
            )
            click.echo(style_error(f"Error: Backend connection failed: {e}"), err=True)
        sys.exit(1)

    except AuditFailure as e:
        show_startup_error_popup(
            title="MCP ACP",
            message="Audit log failure.",
            detail=f"{e}\n\nThe proxy cannot start without a writable audit log.\nCheck file permissions in the log directory.",
            backoff=True,
        )
        click.echo(style_error(f"Error: Audit log failure: {e}"), err=True)
        click.echo("The proxy cannot start without a writable audit log.", err=True)
        sys.exit(AuditFailure.exit_code)

    except AuthenticationError as e:
        error_msg = str(e).lower()
        if "not configured" in error_msg:
            # Auth section missing from config - need to run init
            # Terminal output FIRST (so user sees it immediately)
            click.echo("\n" + style_error("Error: Authentication not configured."), err=True)
            click.echo("Run 'mcp-acp-nexus init' to configure authentication.", err=True)
            # Popup AFTER (for MCP client users who can't see terminal)
            show_startup_error_popup(
                title="MCP ACP",
                message="Authentication not configured.",
                detail="Run in terminal:\n  mcp-acp-nexus init\n\nThen restart your MCP client.",
                backoff=True,
            )
        elif "not authenticated" in error_msg or "no token" in error_msg or "token not found" in error_msg:
            # Token not found in keychain - need to login
            click.echo("\n" + style_error("Error: Not authenticated."), err=True)
            click.echo("Run 'mcp-acp-nexus auth login' to authenticate.", err=True)
            show_startup_error_popup(
                title="MCP ACP",
                message="Not authenticated.",
                detail="Run in terminal:\n  mcp-acp-nexus auth login\n\nThen restart your MCP client.",
                backoff=True,
            )
        elif "expired" in error_msg:
            # Token expired and refresh failed - need to re-login
            click.echo("\n" + style_error("Error: Auth session expired."), err=True)
            click.echo("Run 'mcp-acp-nexus auth login' to re-authenticate.", err=True)
            show_startup_error_popup(
                title="MCP ACP",
                message="Auth session expired.",
                detail="Run in terminal:\n  mcp-acp-nexus auth login\n\nThen restart your MCP client.",
                backoff=True,
            )
        else:
            # Generic auth error
            click.echo("\n" + style_error("Error: Authentication failed."), err=True)
            click.echo(str(e), err=True)
            click.echo("\nRun 'mcp-acp-nexus auth login' to re-authenticate.", err=True)
            show_startup_error_popup(
                title="MCP ACP",
                message="Authentication error.",
                detail=f"{e}\n\nRun 'mcp-acp-nexus auth login' to re-authenticate.",
                backoff=True,
            )
        sys.exit(AuthenticationError.exit_code)

    except DeviceHealthError as e:
        show_startup_error_popup(
            title="MCP ACP",
            message="Device health check failed.",
            detail=f"{e}\n\nEnsure FileVault is enabled and SIP is not disabled.",
            backoff=True,
        )
        click.echo("\n" + style_error("Error: Device health check failed"), err=True)
        click.echo(str(e), err=True)
        sys.exit(DeviceHealthError.exit_code)

    except (PermissionError, RuntimeError, OSError) as e:
        show_startup_error_popup(
            title="MCP ACP",
            message="Proxy startup failed.",
            detail=f"{e}",
            backoff=True,
        )
        click.echo(style_error(f"Error: Proxy startup failed: {e}"), err=True)
        sys.exit(1)
