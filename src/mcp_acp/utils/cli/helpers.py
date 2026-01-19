"""Shared CLI utility functions.

Provides common helpers for CLI commands to avoid duplication.
"""

from __future__ import annotations

__all__ = [
    "load_config_or_exit",
    "get_editor",
    "show_editor_hints",
    "edit_json_loop",
]

import json
import os
import sys
from collections.abc import Callable
from typing import Any, TypeVar

import click

from mcp_acp.config import AppConfig
from mcp_acp.utils.config import get_config_path

T = TypeVar("T")


def load_config_or_exit() -> AppConfig:
    """Load configuration from default path, exiting on failure.

    Returns:
        AppConfig instance.

    Raises:
        click.ClickException: If config not found or invalid.
    """
    config_path = get_config_path()

    if not config_path.exists():
        raise click.ClickException(
            f"Configuration not found at {config_path}\n" "Run 'mcp-acp init' to create configuration."
        )

    try:
        return AppConfig.load_from_files(config_path)
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
