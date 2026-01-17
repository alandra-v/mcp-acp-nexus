"""Proxy information API schemas."""

from __future__ import annotations

__all__ = [
    "ProxyResponse",
    "StatsResponse",
]

from datetime import datetime

from pydantic import BaseModel


class StatsResponse(BaseModel):
    """Response model for proxy request statistics."""

    requests_total: int
    requests_allowed: int
    requests_denied: int
    requests_hitl: int


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
