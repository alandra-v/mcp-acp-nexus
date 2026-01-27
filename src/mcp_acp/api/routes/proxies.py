"""Proxy information API endpoints.

Provides visibility into running proxy instances.

Routes mounted at: /api/proxies
"""

from __future__ import annotations

__all__ = ["router"]

from fastapi import APIRouter

from mcp_acp.api.deps import ProxyStateDep
from mcp_acp.api.errors import APIError, ErrorCode
from mcp_acp.api.schemas import ProxyResponse, StatsResponse
from mcp_acp.manager.models import ProxyRuntimeInfo, ProxyStats

router = APIRouter()


def _build_proxy_response(info: ProxyRuntimeInfo, stats: ProxyStats) -> ProxyResponse:
    """Build a ProxyResponse from proxy info and stats."""
    return ProxyResponse(
        id=info.id,
        backend_id=info.backend_id,
        status=info.status,
        started_at=info.started_at,
        pid=info.pid,
        api_port=info.api_port,
        uptime_seconds=info.uptime_seconds,
        command=info.command,
        args=info.args,
        url=info.url,
        client_transport=info.client_transport,
        backend_transport=info.backend_transport,
        mtls_enabled=info.mtls_enabled,
        client_id=info.client_id,
        stats=StatsResponse(
            requests_total=stats.requests_total,
            requests_allowed=stats.requests_allowed,
            requests_denied=stats.requests_denied,
            requests_hitl=stats.requests_hitl,
        ),
    )


@router.get("", response_model=list[ProxyResponse])
async def list_proxies(state: ProxyStateDep) -> list[ProxyResponse]:
    """List all proxies.

    Returns array with single entry for this proxy.
    """
    info = state.get_proxy_info()
    stats = state.get_stats()

    return [_build_proxy_response(info, stats)]


@router.get("/{proxy_id}", response_model=ProxyResponse)
async def get_proxy(proxy_id: str, state: ProxyStateDep) -> ProxyResponse:
    """Get details for a specific proxy.

    Args:
        proxy_id: The proxy ID to look up.
        state: Proxy state (injected).

    Returns:
        ProxyResponse with proxy details.

    Raises:
        APIError: 404 PROXY_NOT_FOUND if proxy not found.
    """
    info = state.get_proxy_info()

    if info.id != proxy_id:
        raise APIError(
            status_code=404,
            code=ErrorCode.PROXY_NOT_FOUND,
            message=f"Proxy '{proxy_id}' not found",
            details={"proxy_id": proxy_id},
        )

    stats = state.get_stats()

    return _build_proxy_response(info, stats)
