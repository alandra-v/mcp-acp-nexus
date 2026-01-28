"""SSE events endpoint."""

from __future__ import annotations

__all__ = ["router"]

import asyncio
import json
import logging
from typing import Any

import httpx
from fastapi import APIRouter, Request
from sse_starlette.sse import EventSourceResponse

from mcp_acp.constants import APP_NAME, DEFAULT_APPROVAL_TTL_SECONDS
from mcp_acp.manager.registry import ProxyRegistry

from .helpers import (
    PROXY_SNAPSHOT_TIMEOUT_SECONDS,
    create_uds_client,
    fetch_proxy_snapshots,
)

_logger = logging.getLogger(f"{APP_NAME}.manager.routes.events")

router = APIRouter(tags=["events"])


@router.get("/api/events")
async def sse_events(request: Request) -> EventSourceResponse:
    """SSE endpoint for aggregated proxy events.

    Event format matches proxy's format for UI compatibility:
    - `data: {"type": "...", ...}` (type embedded in data JSON)
    - No named SSE events (uses onmessage handler)
    - Events include `proxy_name` for multi-proxy filtering

    On connect, sends initial snapshots by fetching from proxy via UDS.
    """
    reg: ProxyRegistry = request.app.state.registry

    async def event_generator() -> Any:
        # Send initial snapshots from all connected proxies
        all_proxies = await reg.get_all_proxies()
        sent_pending_snapshot = False

        for proxy_conn in all_proxies:
            if not proxy_conn.socket_path:
                continue

            try:
                async with create_uds_client(
                    proxy_conn.socket_path,
                    timeout=PROXY_SNAPSHOT_TIMEOUT_SECONDS,
                ) as client:
                    snapshots = await fetch_proxy_snapshots(client)

                    # Send pending approvals (include proxy_name for multi-proxy)
                    if snapshots["pending"] is not None:
                        yield {
                            "data": json.dumps(
                                {
                                    "type": "snapshot",
                                    "approvals": snapshots["pending"],
                                    "proxy_name": proxy_conn.proxy_name,
                                }
                            )
                        }
                        sent_pending_snapshot = True

                    # Send cached approvals
                    if snapshots["cached"] is not None:
                        cached = snapshots["cached"]
                        yield {
                            "data": json.dumps(
                                {
                                    "type": "cached_snapshot",
                                    "approvals": cached.get("approvals", []),
                                    "ttl_seconds": cached.get("ttl_seconds", DEFAULT_APPROVAL_TTL_SECONDS),
                                    "count": cached.get("count", 0),
                                    "proxy_name": proxy_conn.proxy_name,
                                }
                            )
                        }

                    # Send stats
                    if snapshots["stats"] is not None:
                        yield {
                            "data": json.dumps(
                                {
                                    "type": "stats_updated",
                                    "stats": snapshots["stats"],
                                    "proxy_id": proxy_conn.proxy_id,
                                }
                            )
                        }

            except (httpx.ConnectError, OSError):
                pass  # Expected if proxy not ready

        # Send empty snapshot only if we haven't sent one yet
        if not sent_pending_snapshot:
            yield {"data": json.dumps({"type": "snapshot", "approvals": []})}

        # Subscribe to ongoing events
        queue = await reg.subscribe_sse()
        subscriber_count = reg.sse_subscriber_count
        _logger.info(
            {
                "event": "sse_subscriber_connected",
                "message": f"SSE subscriber connected (total: {subscriber_count})",
                "subscriber_count": subscriber_count,
            }
        )
        try:
            while True:
                # Check if client disconnected
                if await request.is_disconnected():
                    break
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=30.0)
                    # Format: {"type": "...", ...data...} - matches proxy format
                    # UI uses event.data.type for routing
                    event_data = {
                        "type": event["type"],
                        **event["data"],
                    }
                    yield {"data": json.dumps(event_data)}
                except asyncio.TimeoutError:
                    # Send SSE comment as keepalive (not data, won't trigger onmessage)
                    yield {"comment": "keepalive"}
        finally:
            await reg.unsubscribe_sse(queue)
            subscriber_count = reg.sse_subscriber_count
            _logger.info(
                {
                    "event": "sse_subscriber_disconnected",
                    "message": f"SSE subscriber disconnected (total: {subscriber_count})",
                    "subscriber_count": subscriber_count,
                }
            )

    return EventSourceResponse(event_generator())
