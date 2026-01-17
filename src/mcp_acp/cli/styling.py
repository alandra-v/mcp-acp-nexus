"""CLI output styling utilities.

Provides consistent styling helpers for CLI output following the
project's visual language:
- Cyan bold for section headers and labels
- Green for success messages (with checkmark)
- Red for error messages (with cross)
- Dim for neutral/empty state messages
"""

from __future__ import annotations

__all__ = [
    "style_dim",
    "style_error",
    "style_header",
    "style_label",
    "style_success",
    "style_warning",
]

import click


def style_header(title: str) -> str:
    """Style a section header with dashes.

    Args:
        title: The header title text.

    Returns:
        Styled string in format "--- Title ---" with cyan bold.

    Example:
        >>> click.echo(style_header("Authentication"))
        --- Authentication ---
    """
    return click.style(f"--- {title} ---", fg="cyan", bold=True)


def style_label(label: str) -> str:
    """Style a label for list/summary headers.

    Args:
        label: The label text (without colon).

    Returns:
        Styled string with cyan bold and colon suffix.

    Example:
        >>> click.echo(style_label("Active sessions") + f" {count}")
        Active sessions: 5
    """
    return click.style(f"{label}:", fg="cyan", bold=True)


def style_success(message: str) -> str:
    """Style a success message with checkmark.

    Args:
        message: The success message text (without checkmark).

    Returns:
        Styled string with green color and checkmark prefix.

    Example:
        >>> click.echo(style_success("Configuration saved"))
        ✓ Configuration saved
    """
    return click.style(f"✓ {message}", fg="green")


def style_error(message: str) -> str:
    """Style an error message with cross mark.

    Args:
        message: The error message text (without cross).

    Returns:
        Styled string with red color and cross prefix.

    Example:
        >>> click.echo(style_error("File not found"), err=True)
        ✗ File not found
    """
    return click.style(f"✗ {message}", fg="red")


def style_dim(message: str) -> str:
    """Style a neutral/empty state message as dim.

    Args:
        message: The message text.

    Returns:
        Styled string with dim appearance.

    Example:
        >>> click.echo(style_dim("No active sessions."))
        No active sessions.
    """
    return click.style(message, dim=True)


def style_warning(message: str) -> str:
    """Style a warning message with yellow color.

    Args:
        message: The warning message text.

    Returns:
        Styled string with yellow bold color.

    Example:
        >>> click.echo(style_warning("OIDC settings changed"))
        Warning: OIDC settings changed
    """
    return click.style(f"Warning: {message}", fg="yellow", bold=True)
