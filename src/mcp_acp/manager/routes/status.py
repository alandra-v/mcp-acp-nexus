"""Manager status endpoint."""

from __future__ import annotations

__all__ = ["router"]

import os

from fastapi import APIRouter, Request

from mcp_acp.manager.models import ManagerStatusResponse
from mcp_acp.manager.registry import ProxyRegistry

router = APIRouter(prefix="/api/manager", tags=["manager"])


@router.get("/status", response_model=ManagerStatusResponse)
async def manager_status(request: Request) -> ManagerStatusResponse:
    """Get manager health status."""
    reg: ProxyRegistry = request.app.state.registry
    return ManagerStatusResponse(
        running=True,
        pid=os.getpid(),
        proxies_connected=await reg.proxy_count(),
    )
