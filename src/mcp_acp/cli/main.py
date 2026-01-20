"""Main CLI entry point for mcp-acp.

Defines the CLI group and registers all subcommands.

Commands:
    approvals - Approval cache management (cache, clear)
    audit     - Audit log integrity verification (verify, status)
    auth      - Authentication commands (login, logout, status)
    config    - Configuration management (show, path, edit, validate)
    init      - Initialize proxy configuration
    install   - Installation helpers (mcp-json)
    logs      - Log viewing (show, tail)
    manager   - Manager daemon commands (start, stop, status)
    policy    - Policy management (show, edit, add, validate, reload)
    sessions  - Session management (list)
    start     - Start the proxy server manually
    status    - Show proxy runtime status

Subcommand help:
    mcp-acp COMMAND -h         Show help for a specific command
"""

from __future__ import annotations

__all__ = ["cli"]

import sys

import click

from mcp_acp import __version__

from .commands.approvals import approvals
from .commands.audit import audit
from .commands.auth import auth
from .commands.config import config
from .commands.init import init
from .commands.install import install
from .commands.logs import logs
from .commands.manager import manager
from .commands.policy import policy
from .commands.sessions import sessions
from .commands.start import start
from .commands.status import status


class ReorderedGroup(click.Group):
    """Custom group that shows commands before custom help text."""

    def format_epilog(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        """Add extra help after commands section."""
        formatter.write(
            """
Quick Start:
  mcp-acp init                     Interactive setup wizard
  mcp-acp start                    Test the proxy manually

Non-Interactive Setup (stdio):
  mcp-acp init --non-interactive \\
    --server-name my-server \\
    --connection-type stdio \\
    --command npx \\
    --args "-y,@modelcontextprotocol/server-filesystem,/tmp"

Non-Interactive Setup (both transports):
  mcp-acp init --non-interactive \\
    --server-name my-server \\
    --connection-type both \\
    --command npx \\
    --args "-y,@modelcontextprotocol/server-filesystem,/tmp" \\
    --url http://localhost:3010/mcp

Non-Interactive Setup (HTTPS with mTLS):
  mcp-acp init --non-interactive \\
    --server-name my-server \\
    --connection-type http \\
    --url https://backend.example.com/mcp \\
    --issuer https://auth.example.com/ \\
    --client-id my-client-id \\
    --audience https://api.example.com \\
    --mtls-cert ~/certs/client.pem \\
    --mtls-key ~/certs/client-key.pem \\
    --mtls-ca ~/certs/ca-bundle.pem

Connection Types (--connection-type):
  stdio   Spawn local server process (npx, uvx, python)
  http    Connect to remote HTTP server (requires --url)
  both    Auto-detect: tries HTTP first, falls back to STDIO
"""
        )


@click.group(
    cls=ReorderedGroup,
    invoke_without_command=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)
@click.option("--version", "-v", is_flag=True, help="Show version")
@click.pass_context
def cli(ctx: click.Context, version: bool) -> None:
    """mcp-acp: Zero Trust Access Control Proxy for MCP."""
    if version:
        click.echo(f"mcp-acp {__version__}")
        sys.exit(0)
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


# Register commands
cli.add_command(approvals)
cli.add_command(audit)
cli.add_command(auth)
cli.add_command(config)
cli.add_command(init)
cli.add_command(install)
cli.add_command(logs)
cli.add_command(manager)
cli.add_command(policy)
cli.add_command(sessions)
cli.add_command(start)
cli.add_command(status)


def main() -> None:
    """CLI entry point."""
    cli()
