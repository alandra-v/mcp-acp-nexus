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

from mcp_acp.constants import APP_NAME
from mcp_acp.manager.config import list_configured_proxies

from ..styling import style_dim, style_error, style_success


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
@click.option("--proxy", "-p", "proxy_name", help="Specific proxy (default: all proxies)")
@click.option("--copy", "-c", "copy_to_clip", is_flag=True, help="Copy to clipboard")
def install_mcp_json(proxy_name: str | None, copy_to_clip: bool) -> None:
    """Generate MCP client configuration JSON.

    Without --proxy, generates config for ALL configured proxies.
    With --proxy, generates config for a single proxy.

    Outputs JSON in the standard mcpServers format used by Claude Desktop,
    Cursor, VS Code, and other MCP clients.

    \b
    Example output (all proxies):
        {
          "mcpServers": {
            "filesystem": {
              "command": "/path/to/mcp-acp",
              "args": ["start", "--proxy", "filesystem"]
            },
            "database": {
              "command": "/path/to/mcp-acp",
              "args": ["start", "--proxy", "database"]
            }
          }
        }

    \b
    Usage with MCP clients:
        Claude Desktop: ~/Library/Application Support/Claude/claude_desktop_config.json
        Cursor:         ~/.cursor/mcp.json
        VS Code:        .vscode/mcp.json
    """
    proxies = list_configured_proxies()

    if not proxies:
        click.echo(style_error("No proxies configured."), err=True)
        click.echo(style_dim("Run 'mcp-acp proxy add' to create one."), err=True)
        sys.exit(1)

    if proxy_name:
        # Single proxy
        if proxy_name not in proxies:
            click.echo(style_error(f"Proxy '{proxy_name}' not found."), err=True)
            click.echo(f"Available: {', '.join(proxies)}", err=True)
            sys.exit(1)
        proxies_to_include = [proxy_name]
    else:
        # All proxies
        proxies_to_include = proxies

    executable = _get_executable_path()

    mcp_servers: dict[str, dict[str, object]] = {}
    for name in proxies_to_include:
        mcp_servers[name] = {
            "command": executable,
            "args": ["start", "--proxy", name],
        }

    output = {"mcpServers": mcp_servers}

    json_output = json.dumps(output, indent=2)

    if copy_to_clip:
        if _copy_to_clipboard(json_output):
            click.echo(style_success("Copied to clipboard!"))
        else:
            click.echo(style_error("Could not copy to clipboard"), err=True)

    click.echo(json_output)

    # Show helpful next steps
    click.echo()
    click.echo(style_dim("Add the mcpServers entries to your MCP client config file."))
