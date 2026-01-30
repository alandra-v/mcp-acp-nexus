"""Proxy listing and detail endpoints."""

from __future__ import annotations

__all__ = ["list_proxies_enhanced", "get_proxy_detail"]

import asyncio
import json
import logging

import httpx
from fastapi import Request

from mcp_acp.api.errors import APIError, ErrorCode
from mcp_acp.config import PerProxyConfig, load_proxy_config
from mcp_acp.constants import APP_NAME
from mcp_acp.manager.config import list_configured_proxies
from mcp_acp.manager.models import Proxy, ProxyDetailResponse, ProxyStats
from mcp_acp.manager.registry import ProxyRegistry

from . import router
from ..deps import find_proxy_by_id
from ..helpers import (
    PROXY_SNAPSHOT_TIMEOUT_SECONDS,
    create_uds_client,
    fetch_proxy_snapshots,
)

_logger = logging.getLogger(f"{APP_NAME}.manager.routes.proxies")


@router.get("/proxies", response_model=list[Proxy])
async def list_proxies_enhanced(request: Request) -> list[Proxy]:
    """List all configured proxies with config and runtime data.

    Returns enhanced proxy information combining:
    - Config data (server_name, transport, created_at) from config files
    - Runtime data (status, instance_id, stats) from registry and UDS

    Shows all configured proxies, not just running ones.
    """
    reg: ProxyRegistry = request.app.state.registry

    # Get registered (running) proxies for lookup
    registered = await reg.list_proxies()
    registered_by_name = {p["name"]: p for p in registered}

    # Get all configured proxies
    configured_names = list_configured_proxies()

    # Load configs and identify running proxies
    configs: dict[str, PerProxyConfig] = {}
    running_proxies: list[tuple[str, str]] = []  # (proxy_name, socket_path)

    for proxy_name in configured_names:
        try:
            configs[proxy_name] = load_proxy_config(proxy_name)
        except (FileNotFoundError, ValueError, OSError) as e:
            _logger.warning(
                {
                    "event": "proxy_config_load_failed",
                    "message": f"Failed to load config for proxy '{proxy_name}': {e}",
                    "proxy_name": proxy_name,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                }
            )
            continue

        # Check if running
        reg_info = registered_by_name.get(proxy_name)
        if reg_info and reg_info.get("socket_path"):
            running_proxies.append((proxy_name, reg_info["socket_path"]))

    # Fetch stats concurrently for all running proxies
    async def fetch_stats(socket_path: str) -> ProxyStats | None:
        try:
            async with create_uds_client(
                socket_path,
                timeout=PROXY_SNAPSHOT_TIMEOUT_SECONDS,
            ) as client:
                resp = await client.get("/api/stats")
                if resp.status_code == 200:
                    stats_data = resp.json()
                    return ProxyStats(
                        requests_total=stats_data.get("requests_total", 0),
                        requests_allowed=stats_data.get("requests_allowed", 0),
                        requests_denied=stats_data.get("requests_denied", 0),
                        requests_hitl=stats_data.get("requests_hitl", 0),
                    )
        except (httpx.ConnectError, OSError, httpx.TimeoutException, json.JSONDecodeError):
            pass  # Failed to fetch stats
        return None

    # Fetch all stats concurrently
    stats_results = await asyncio.gather(
        *(fetch_stats(socket_path) for _, socket_path in running_proxies),
        return_exceptions=True,
    )
    stats_by_name: dict[str, ProxyStats | None] = {}
    for (proxy_name, _), stats_result in zip(running_proxies, stats_results):
        if isinstance(stats_result, BaseException):
            stats_by_name[proxy_name] = None
        else:
            stats_by_name[proxy_name] = stats_result

    # Build result
    result: list[Proxy] = []
    for proxy_name, config in configs.items():
        reg_info = registered_by_name.get(proxy_name)
        is_running = reg_info is not None

        # Extract command/args from stdio config, url from http config
        command = None
        args = None
        url = None
        if config.backend.stdio:
            command = config.backend.stdio.command
            args = config.backend.stdio.args or []
        if config.backend.http:
            url = config.backend.http.url

        # Determine actual backend transport
        # - "auto" resolves to stdio if command present, else streamablehttp
        # - explicit transport types are used as-is
        backend_transport = config.backend.transport
        if backend_transport == "auto":
            backend_transport = "stdio" if config.backend.stdio else "streamablehttp"

        result.append(
            Proxy(
                proxy_name=proxy_name,
                proxy_id=config.proxy_id,
                status="running" if is_running else "inactive",
                instance_id=reg_info.get("instance_id") if reg_info else None,
                server_name=config.backend.server_name,
                transport=config.backend.transport,
                command=command,
                args=args if args else None,
                url=url,
                created_at=config.created_at,
                backend_transport=backend_transport,
                mtls_enabled=config.mtls is not None,
                stats=stats_by_name.get(proxy_name),
            )
        )

    return result


@router.get("/proxies/{proxy_id}", response_model=ProxyDetailResponse)
async def get_proxy_detail(proxy_id: str, request: Request) -> ProxyDetailResponse:
    """Get full proxy detail by proxy_id.

    Returns config and runtime data for a specific proxy.

    Args:
        proxy_id: Stable proxy identifier from config.
        request: FastAPI request object.

    Returns:
        ProxyDetailResponse with config and runtime data.

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

    proxy_name, config = result
    reg: ProxyRegistry = request.app.state.registry

    # Check if running
    registered = await reg.list_proxies()
    reg_info = next((p for p in registered if p["name"] == proxy_name), None)
    is_running = reg_info is not None

    # Extract command/args from stdio config, url from http config
    command = None
    args = None
    url = None
    if config.backend.stdio:
        command = config.backend.stdio.command
        args = config.backend.stdio.args or []
    if config.backend.http:
        url = config.backend.http.url

    # Determine actual backend transport
    backend_transport = config.backend.transport
    if backend_transport == "auto":
        backend_transport = "stdio" if config.backend.stdio else "streamablehttp"

    # Fetch runtime data if running
    stats = None
    client_id = None
    pending_approvals = None
    cached_approvals = None

    if is_running and reg_info and reg_info.get("socket_path"):
        socket_path = reg_info["socket_path"]
        try:
            async with create_uds_client(
                socket_path,
                timeout=PROXY_SNAPSHOT_TIMEOUT_SECONDS,
            ) as client:
                snapshots = await fetch_proxy_snapshots(client)

                # Extract stats
                if snapshots["stats"]:
                    stats = ProxyStats(
                        requests_total=snapshots["stats"].get("requests_total", 0),
                        requests_allowed=snapshots["stats"].get("requests_allowed", 0),
                        requests_denied=snapshots["stats"].get("requests_denied", 0),
                        requests_hitl=snapshots["stats"].get("requests_hitl", 0),
                    )

                # Extract client_id
                client_id = snapshots.get("client_id")

                # Extract pending approvals
                pending_approvals = snapshots["pending"]

                # Extract cached approvals
                if snapshots["cached"]:
                    cached_approvals = snapshots["cached"].get("approvals", [])

        except (httpx.ConnectError, OSError, httpx.TimeoutException, json.JSONDecodeError) as e:
            _logger.debug("Runtime data fetch failed for proxy '%s': %s", proxy_name, e)

    return ProxyDetailResponse(
        proxy_name=proxy_name,
        proxy_id=config.proxy_id,
        status="running" if is_running else "inactive",
        instance_id=reg_info.get("instance_id") if reg_info else None,
        server_name=config.backend.server_name,
        transport=config.backend.transport,
        command=command,
        args=args if args else None,
        url=url,
        created_at=config.created_at,
        backend_transport=backend_transport,
        mtls_enabled=config.mtls is not None,
        stats=stats,
        client_id=client_id,
        pending_approvals=pending_approvals,
        cached_approvals=cached_approvals,
    )
