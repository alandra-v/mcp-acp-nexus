"""Proxy management commands for mcp-acp CLI.

Commands for managing multiple proxy configurations.
"""

from __future__ import annotations

__all__ = ["proxy"]

import click

from .add import proxy_add
from .auth import proxy_auth
from .delete import proxy_delete
from .list_cmd import proxy_list
from .purge import proxy_purge


@click.group()
def proxy() -> None:
    """Manage proxy configurations."""
    pass


proxy.add_command(proxy_add, "add")
proxy.add_command(proxy_auth, "auth")
proxy.add_command(proxy_list, "list")
proxy.add_command(proxy_delete, "delete")
proxy.add_command(proxy_purge, "purge")
