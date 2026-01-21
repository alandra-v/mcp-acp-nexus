"""Install command group for mcp-acp CLI.

Provides installation helper subcommands for integrating mcp-acp
with MCP clients like Claude Desktop, Cursor, and VS Code.
"""

from __future__ import annotations

__all__ = ["install"]

import json
import shutil
import subprocess
import sys
from pathlib import Path

import click

from mcp_acp.config import AppConfig
from mcp_acp.constants import APP_NAME
from mcp_acp.utils.config import get_config_path

from ..styling import style_error, style_success


def _get_executable_path() -> str:
    """Find absolute path to mcp-acp executable.

    Searches PATH for the mcp-acp executable and returns its
    absolute path for use in MCP client configuration.

    Returns:
        Absolute path to mcp-acp executable.

    Raises:
        click.ClickException: If executable cannot be found in PATH.
    """
    path = shutil.which(APP_NAME)
    if path:
        return str(Path(path).resolve())

    raise click.ClickException(
        "Could not find mcp-acp executable in PATH.\n" "Ensure mcp-acp is installed and accessible."
    )


def _copy_to_clipboard(text: str) -> bool:
    """Copy text to system clipboard using platform-native tools.

    Args:
        text: Text to copy to clipboard.

    Returns:
        True if copy succeeded, False otherwise.
    """
    if sys.platform == "darwin":
        cmd = ["pbcopy"]
    elif sys.platform == "win32":
        cmd = ["clip"]
    else:
        # Linux - try xclip first, then xsel
        if shutil.which("xclip"):
            cmd = ["xclip", "-selection", "clipboard"]
        elif shutil.which("xsel"):
            cmd = ["xsel", "--clipboard", "--input"]
        else:
            return False

    try:
        subprocess.run(
            cmd,
            input=text.encode(),
            check=True,
            timeout=5,
            capture_output=True,
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return False


@click.group()
def install() -> None:
    """Installation helper commands."""
    pass


@install.command("mcp-json")
@click.option("--name", "-n", help="Override server name in output")
@click.option("--copy", "-c", "copy_to_clip", is_flag=True, help="Copy to clipboard")
def install_mcp_json(name: str | None, copy_to_clip: bool) -> None:
    """Generate MCP client configuration JSON.

    Outputs JSON in the standard mcpServers format used by Claude Desktop,
    Cursor, VS Code, and other MCP clients.

    \b
    Example output:
        {
          "mcpServers": {
            "mcp-acp-proxy": {
              "command": "/path/to/mcp-acp",
              "args": ["start"]
            }
          }
        }

    \b
    Usage with MCP clients:
        Claude Desktop: ~/.claude/claude_desktop_config.json
        Cursor:         ~/.cursor/mcp.json
        VS Code:        .vscode/mcp.json
    """
    config_path = get_config_path()

    if not config_path.exists():
        raise click.ClickException(
            f"Config not found at {config_path}\n" "Run 'mcp-acp init' first to create configuration."
        )

    try:
        config = AppConfig.load_from_files(config_path)
    except (FileNotFoundError, ValueError) as e:
        raise click.ClickException(f"Error loading config: {e}") from e

    executable = _get_executable_path()
    server_name = name or config.proxy.name

    output = {
        "mcpServers": {
            server_name: {
                "command": executable,
                "args": ["start"],
            }
        }
    }

    json_output = json.dumps(output, indent=2)

    if copy_to_clip:
        if _copy_to_clipboard(json_output):
            click.echo(style_success("Copied to clipboard!"))
        else:
            click.echo(style_error("Could not copy to clipboard"), err=True)

    click.echo(json_output)
