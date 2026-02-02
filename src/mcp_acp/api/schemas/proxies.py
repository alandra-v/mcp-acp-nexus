"""Proxy information API schemas."""

from __future__ import annotations

__all__ = [
    "LatencyResponse",
    "ProxyResponse",
    "StatsResponse",
    "StatsWithLatencyResponse",
]

from datetime import datetime

from pydantic import BaseModel


class StatsResponse(BaseModel):
    """Response model for proxy request statistics."""

    requests_total: int
    requests_allowed: int
    requests_denied: int
    requests_hitl: int


class LatencyResponse(BaseModel):
    """Latency medians for the /api/stats endpoint."""

    proxy_latency_ms: float | None = None
    policy_eval_ms: float | None = None
    hitl_wait_ms: float | None = None


class StatsWithLatencyResponse(BaseModel):
    """Combined stats + latency response for /api/stats."""

    requests_total: int
    requests_allowed: int
    requests_denied: int
    requests_hitl: int
    latency: LatencyResponse


class ProxyResponse(BaseModel):
    """Response model for proxy information."""

    id: str
    backend_id: str
    status: str
    started_at: datetime
    pid: int
    api_port: int
    uptime_seconds: float
    command: str | None = None
    args: list[str] | None = None
    url: str | None = None
    client_transport: str = "stdio"
    backend_transport: str = "stdio"
    mtls_enabled: bool = False
    client_id: str | None = None
    stats: StatsResponse
