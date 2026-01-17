"""Startup error alerts for macOS.

Displays native macOS alert dialogs for pre-start failures.
Used by proxy.py and CLI commands when startup fails due to
configuration, authentication, or device health issues.

Non-blocking on other platforms (returns immediately).
"""

from __future__ import annotations

import platform
import subprocess
import sys
import time

from mcp_acp.pep.applescript import escape_applescript_string

__all__ = [
    "show_startup_error_popup",
]

# Timeout for AppleScript dialogs (seconds)
# User has 30 seconds to acknowledge the dialog before it auto-closes
_DIALOG_TIMEOUT_SECONDS = 30

# Delay after showing popup to prevent restart loops (seconds)
_RESTART_BACKOFF_SECONDS = 30


def show_startup_error_popup(
    title: str = "MCP ACP",
    message: str = "Startup failed.",
    detail: str = "Check logs for details.",
    backoff: bool = False,
) -> bool:
    """Show a startup error popup on macOS.

    Displays a native macOS alert dialog when proxy startup fails.
    Used for pre-start failures (auth, config, device health, etc.).
    Non-blocking on other platforms (returns immediately).

    Args:
        title: Alert title (default: "MCP ACP").
        message: Main message text describing the failure.
        detail: Additional detail text (e.g., command to run to fix).
        backoff: If True, sleep after popup to prevent restart loops.
            Only applies when NOT running in interactive terminal (no TTY).
            Use for errors that won't be fixed by automatic restart
            (e.g., auth failures where user must run a command).

    Returns:
        True if popup was shown, False if not on macOS or osascript failed.
    """
    if platform.system() != "Darwin":
        # Not macOS - can't show native popup
        return False

    # Escape strings for AppleScript
    safe_title = escape_applescript_string(title)
    safe_message = escape_applescript_string(message)
    safe_detail = escape_applescript_string(detail)

    # Build AppleScript command
    script = f"""
    display alert "{safe_title}" message "{safe_message}

{safe_detail}" as critical buttons {{"OK"}} default button "OK"
    """

    try:
        subprocess.run(
            ["osascript", "-e", script],
            capture_output=True,
            timeout=_DIALOG_TIMEOUT_SECONDS,
        )
        if backoff and not sys.stdin.isatty():
            # Sleep to prevent rapid restart loops
            # MCP clients auto-restart crashed servers (no TTY)
            # Skip backoff for interactive terminal users
            time.sleep(_RESTART_BACKOFF_SECONDS)
        return True
    except (subprocess.SubprocessError, OSError):
        # osascript failed or not available
        return False
