"""Shared CLI utility functions.

Provides common helpers for CLI commands to avoid duplication.
"""

from __future__ import annotations

__all__ = [
    "SOCKET_CONNECT_TIMEOUT_SECONDS",
    "check_proxy_running",
    "edit_json_loop",
    "get_editor",
    "load_manager_config_or_exit",
    "require_proxy_name",
    "show_editor_hints",
    "validate_proxy_if_provided",
]

import json
import os
import socket
import sys
from collections.abc import Callable
from typing import Any, TypeVar

import click

from mcp_acp.constants import get_proxy_socket_path
from mcp_acp.manager.config import (
    ManagerConfig,
    get_manager_config_path,
    list_configured_proxies,
    load_manager_config,
)

# Timeout for socket connection test (seconds)
SOCKET_CONNECT_TIMEOUT_SECONDS = 0.5

T = TypeVar("T")


def check_proxy_running(name: str) -> bool:
    """Check if a proxy is running by testing socket connection.

    Attempts to connect to the proxy's Unix domain socket to verify
    the proxy is running and accepting connections.

    Args:
        name: Proxy name (used to determine socket path).

    Returns:
        True if proxy is running and accepting connections, False otherwise.
    """
    socket_path = get_proxy_socket_path(name)
    if not socket_path.exists():
        return False

    test_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        test_sock.settimeout(SOCKET_CONNECT_TIMEOUT_SECONDS)
        test_sock.connect(str(socket_path))
        return True
    except (socket.error, OSError):
        return False
    finally:
        test_sock.close()


def require_proxy_name(proxy_name: str | None) -> str:
    """Require a proxy name, raising an exception if not provided or not found.

    Use this for commands that require a specific proxy to operate on.
    Provides helpful error messages listing available proxies.

    Args:
        proxy_name: Proxy name from CLI option, or None if not provided.

    Returns:
        Validated proxy name.

    Raises:
        click.ClickException: If proxy name not provided or proxy not found.
    """
    if not proxy_name:
        configured = list_configured_proxies()
        if not configured:
            raise click.ClickException(
                "No proxies configured.\nRun 'mcp-acp proxy add <name>' to add a proxy."
            )
        raise click.ClickException(f"--proxy is required. Available: {', '.join(configured)}")

    configured = list_configured_proxies()
    if proxy_name not in configured:
        raise click.ClickException(
            f"Proxy '{proxy_name}' not found.\nAvailable: {', '.join(configured) or '(none)'}"
        )

    return proxy_name


def validate_proxy_if_provided(proxy_name: str | None) -> str | None:
    """Validate proxy name if provided, returning None if not provided.

    Use this for commands where --proxy is optional but should be validated
    if specified.

    Args:
        proxy_name: Proxy name from CLI option, or None if not provided.

    Returns:
        Validated proxy name, or None if not provided.

    Raises:
        click.ClickException: If proxy name provided but not found.
    """
    if not proxy_name:
        return None

    configured = list_configured_proxies()
    if proxy_name not in configured:
        raise click.ClickException(
            f"Proxy '{proxy_name}' not found.\nAvailable: {', '.join(configured) or '(none)'}"
        )

    return proxy_name


def load_manager_config_or_exit() -> ManagerConfig:
    """Load manager configuration from manager.json, exiting on failure.

    Use this for commands that need auth config (OIDC, mTLS) or log_dir.
    These settings are shared across all proxies in multi-proxy mode.

    Returns:
        ManagerConfig instance with auth and logging settings.

    Raises:
        click.ClickException: If config not found or invalid.
    """
    config_path = get_manager_config_path()

    if not config_path.exists():
        raise click.ClickException(
            f"Configuration not found at {config_path}\n" "Run 'mcp-acp init' to create configuration."
        )

    try:
        config = load_manager_config()
        # Verify auth is configured (required for most auth operations)
        if config.auth is None:
            raise click.ClickException(
                "Authentication not configured.\n" "Run 'mcp-acp init' to configure OIDC authentication."
            )
        return config
    except (OSError, ValueError) as e:
        raise click.ClickException(f"Failed to load configuration: {e}") from e


def get_editor() -> str:
    """Get editor from environment with platform-appropriate fallback.

    Checks $EDITOR, then $VISUAL, then falls back to:
    - Windows: notepad
    - macOS/Linux: vi

    Returns:
        Editor command string.
    """
    if sys.platform == "win32":
        default_editor = "notepad"
    else:
        default_editor = "vi"

    return os.environ.get("EDITOR") or os.environ.get("VISUAL") or default_editor


def show_editor_hints(editor: str) -> None:
    """Show save/exit hints for common editors.

    Args:
        editor: Editor command string (may include args like "code --wait").
    """
    # Extract base editor name (handle "code --wait" etc.)
    editor_name = os.path.basename(editor).split()[0]

    if editor_name in ("vim", "vi", "nvim"):
        click.echo("  Esc = normal mode | :wq = save+exit | :q! = exit no save")
    elif editor_name == "nano":
        click.echo("  Ctrl+O Enter = save | Ctrl+X = exit")
    elif editor_name in ("emacs", "emacsclient"):
        click.echo("  Ctrl+X Ctrl+S = save | Ctrl+X Ctrl+C = exit")
    elif editor_name in ("code", "subl", "atom"):
        click.echo("  Cmd/Ctrl+S = save | close tab to finish")


def edit_json_loop(
    initial_content: str,
    validator: Callable[[dict[str, Any]], T],
    item_name: str,
) -> tuple[str, dict[str, Any], T]:
    """Edit JSON content in a loop until valid or cancelled.

    Opens content in editor, validates with provided function, and loops
    on validation failure with option to re-edit.

    Args:
        initial_content: Initial JSON string to edit.
        validator: Function that takes parsed dict and returns validated object.
            Should raise ValueError on validation failure.
        item_name: Name of item being edited (for error messages, e.g., "configuration", "policy").

    Returns:
        Tuple of (edited_content, parsed_dict, validated_object).

    Raises:
        SystemExit: If user cancels edit or aborts on validation failure.
    """
    # Lazy import to avoid circular dependency
    from mcp_acp.cli.styling import style_dim, style_error

    current_content = initial_content

    while True:
        edited_content = click.edit(current_content, extension=".json")

        # User quit without saving
        if edited_content is None:
            click.echo(style_dim("Edit cancelled."))
            sys.exit(0)

        # Check if content changed
        if edited_content.strip() == current_content.strip():
            click.echo(style_dim("No changes made."))
            sys.exit(0)

        # Try to parse and validate
        try:
            new_dict = json.loads(edited_content)
            validated = validator(new_dict)
            return edited_content, new_dict, validated
        except json.JSONDecodeError as e:
            click.echo("\n" + style_error(f"Error: Invalid JSON: {e}"), err=True)
        except ValueError as e:
            click.echo("\n" + style_error(f"Error: Invalid {item_name}: {e}"), err=True)

        # Offer to re-edit
        if not click.confirm(f"Re-edit {item_name}?", default=True):
            click.echo(style_dim("Edit cancelled."))
            sys.exit(1)

        # Keep the edited (invalid) content for re-editing
        current_content = edited_content
