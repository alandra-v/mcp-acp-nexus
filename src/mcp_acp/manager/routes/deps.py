"""Shared dependencies and lookup functions for manager routes.

This module contains dependency functions used across multiple route
modules for proxy lookups and registry access.
"""

from __future__ import annotations

__all__ = [
    "find_proxy_by_id",
    "get_proxy_paths",
    "get_proxy_socket",
]

from pathlib import Path

from mcp_acp.api.errors import APIError, ErrorCode
from mcp_acp.config import PerProxyConfig, load_proxy_config
from mcp_acp.manager.config import (
    get_proxy_config_path,
    get_proxy_policy_path,
    list_configured_proxies,
)
from mcp_acp.manager.registry import ProxyRegistry


def find_proxy_by_id(proxy_id: str) -> tuple[str, PerProxyConfig] | None:
    """Find proxy config by proxy_id.

    Args:
        proxy_id: The stable proxy identifier.

    Returns:
        Tuple of (proxy_name, config) if found, None otherwise.
    """
    for proxy_name in list_configured_proxies():
        try:
            config = load_proxy_config(proxy_name)
            if config.proxy_id == proxy_id:
                return (proxy_name, config)
        except (FileNotFoundError, ValueError, OSError):
            continue
    return None


def get_proxy_paths(proxy_id: str) -> tuple[str, Path, Path]:
    """Get proxy name, config path, and policy path from proxy_id.

    Args:
        proxy_id: The stable proxy identifier.

    Returns:
        Tuple of (proxy_name, config_path, policy_path).

    Raises:
        APIError: If proxy_id not found (404).
    """
    result = find_proxy_by_id(proxy_id)
    if result is None:
        raise APIError(
            status_code=404,
            code=ErrorCode.PROXY_NOT_FOUND,
            message=f"Proxy with ID '{proxy_id}' not found",
            details={"proxy_id": proxy_id},
        )
    proxy_name, _ = result
    config_path = get_proxy_config_path(proxy_name)
    policy_path = get_proxy_policy_path(proxy_name)
    return proxy_name, config_path, policy_path


async def get_proxy_socket(proxy_name: str, reg: ProxyRegistry) -> str | None:
    """Get UDS socket path for a proxy if it's running.

    Args:
        proxy_name: Name of the proxy.
        reg: Proxy registry.

    Returns:
        Socket path if proxy is running, None otherwise.
    """
    registered = await reg.list_proxies()
    reg_info = next((p for p in registered if p["name"] == proxy_name), None)
    if reg_info and reg_info.get("socket_path"):
        socket_path: str = reg_info["socket_path"]
        if Path(socket_path).exists():
            return socket_path
    return None
