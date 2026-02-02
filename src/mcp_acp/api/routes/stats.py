"""Proxy statistics API endpoint.

Returns request counters and rolling latency medians.

Routes mounted at: /api/stats
"""

from __future__ import annotations

__all__ = ["router"]

from fastapi import APIRouter

from mcp_acp.api.deps import ProxyStateDep
from mcp_acp.api.schemas import LatencyResponse, StatsWithLatencyResponse

router = APIRouter()


@router.get("", response_model=StatsWithLatencyResponse)
async def get_stats(state: ProxyStateDep) -> StatsWithLatencyResponse:
    """Get proxy request statistics with latency data.

    Returns counters (total, allowed, denied, hitl) and rolling
    latency medians for proxy_latency, policy_eval, and hitl_wait.
    """
    stats = state.get_stats()
    latency = state.get_latency()

    return StatsWithLatencyResponse(
        requests_total=stats.requests_total,
        requests_allowed=stats.requests_allowed,
        requests_denied=stats.requests_denied,
        requests_hitl=stats.requests_hitl,
        latency=LatencyResponse(
            proxy_latency_ms=latency["proxy_latency"]["median_ms"],
            policy_eval_ms=latency["policy_eval"]["median_ms"],
            hitl_wait_ms=latency["hitl_wait"]["median_ms"],
        ),
    )
