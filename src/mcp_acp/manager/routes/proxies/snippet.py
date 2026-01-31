"""Config snippet endpoint."""

from __future__ import annotations

__all__ = ["get_config_snippet", "get_executable_path"]

import shutil
import sys
from pathlib import Path
from typing import Any

from mcp_acp.api.errors import APIError, ErrorCode
from mcp_acp.constants import APP_NAME
from mcp_acp.manager.config import list_configured_proxies
from mcp_acp.manager.models import ConfigSnippetResponse

from . import router


def get_executable_path() -> str:
    """Find absolute path to mcp-acp executable.

    Tries multiple methods to find the executable:
    1. shutil.which (PATH lookup)
    2. sys.argv[0] if it contains 'mcp-acp' or 'mcp_acp'
    3. Falls back to 'mcp-acp' (assumes it's in PATH)

    Returns:
        Absolute path to mcp-acp executable.
    """
    # Try PATH first
    path = shutil.which(APP_NAME)
    if path:
        return str(Path(path).resolve())

    # Try sys.argv[0] - how the current process was invoked
    argv0 = sys.argv[0] if sys.argv else ""
    if "mcp-acp" in argv0 or "mcp_acp" in argv0:
        resolved = Path(argv0).resolve()
        if resolved.exists():
            return str(resolved)

    return APP_NAME  # Fall back to name, assume it's in PATH


@router.get("/config-snippet", response_model=ConfigSnippetResponse)
async def get_config_snippet(proxy: str | None = None) -> ConfigSnippetResponse:
    """Get MCP client configuration snippet for proxies.

    Returns JSON in the standard mcpServers format used by Claude Desktop,
    Cursor, VS Code, and other MCP clients.

    Args:
        proxy: Optional proxy name to get snippet for. If not provided,
               returns snippet for all configured proxies.

    Returns:
        ConfigSnippetResponse with mcpServers dictionary and executable path.

    Raises:
        APIError: If specified proxy not found.
    """
    proxies = list_configured_proxies()

    if proxy:
        # Single proxy requested
        if proxy not in proxies:
            raise APIError(
                status_code=404,
                code=ErrorCode.PROXY_NOT_FOUND,
                message=f"Proxy '{proxy}' not found",
                details={"proxy_name": proxy, "available": proxies},
            )
        proxies_to_include = [proxy]
    else:
        # All proxies
        proxies_to_include = proxies

    executable = get_executable_path()

    mcp_servers: dict[str, dict[str, Any]] = {}
    for name in proxies_to_include:
        mcp_servers[name] = {
            "command": executable,
            "args": ["start", "--proxy", name],
        }

    return ConfigSnippetResponse(
        mcpServers=mcp_servers,
        executable_path=executable,
    )
