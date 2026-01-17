"""Command-line interface for mcp-acp-nexus.

Provides commands for initializing configuration, starting the proxy server,
and managing configuration.
"""

from .main import cli, main

__all__ = ["cli", "main"]
