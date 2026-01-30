"""Proxy deletion and CLI notification endpoints."""

from __future__ import annotations

__all__ = ["delete_proxy_endpoint", "notify_proxy_deleted"]

import logging

from fastapi import Request
from pydantic import BaseModel

from mcp_acp.api.errors import APIError, ErrorCode
from mcp_acp.constants import APP_NAME
from mcp_acp.manager.models import ProxyDeleteResponse
from mcp_acp.manager.registry import ProxyRegistry

from . import router
from ..deps import find_proxy_by_id

_logger = logging.getLogger(f"{APP_NAME}.manager.routes.proxies")


@router.delete("/proxies/{proxy_id}", response_model=ProxyDeleteResponse)
async def delete_proxy_endpoint(
    proxy_id: str,
    request: Request,
    purge: bool = False,
) -> ProxyDeleteResponse:
    """Delete a proxy configuration.

    Soft deletes (archives) by default. Pass ?purge=true to permanently delete.

    Args:
        proxy_id: Stable proxy identifier from config.
        request: FastAPI request object.
        purge: If True, permanently delete instead of archiving.

    Returns:
        ProxyDeleteResponse with deletion summary.

    Raises:
        APIError: If proxy not found (404) or currently running (409).
    """
    from mcp_acp.manager.deletion import delete_proxy
    from mcp_acp.manager.events import SSEEventType

    # Resolve proxy_id -> proxy_name
    result = find_proxy_by_id(proxy_id)
    if result is None:
        raise APIError(
            status_code=404,
            code=ErrorCode.PROXY_NOT_FOUND,
            message=f"Proxy with ID '{proxy_id}' not found",
            details={"proxy_id": proxy_id},
        )

    proxy_name, _config = result
    reg: ProxyRegistry = request.app.state.registry

    # Check if proxy is running
    registered = await reg.list_proxies()
    is_running = any(p["name"] == proxy_name for p in registered)

    if is_running:
        raise APIError(
            status_code=409,
            code=ErrorCode.PROXY_RUNNING,
            message=f"Proxy '{proxy_name}' is currently running. Stop the proxy first.",
            details={"proxy_id": proxy_id, "proxy_name": proxy_name},
        )

    # Perform deletion
    try:
        delete_result = delete_proxy(proxy_name, purge=purge, deleted_by="api")
    except OSError as e:
        raise APIError(
            status_code=500,
            code=ErrorCode.INTERNAL_ERROR,
            message=f"Failed to delete proxy: {e}",
            details={"proxy_id": proxy_id, "proxy_name": proxy_name, "error": str(e)},
        )

    # Broadcast proxy_deleted SSE event (best-effort — deletion already succeeded)
    try:
        await reg.broadcast_snapshot(
            SSEEventType.PROXY_DELETED.value,
            {
                "proxy_id": proxy_id,
                "proxy_name": proxy_name,
                "archive_name": delete_result.archive_name,
            },
        )
    except Exception:
        _logger.debug("SSE broadcast failed after proxy deletion: %s", proxy_name)

    _logger.warning(
        {
            "event": "proxy_deleted",
            "message": f"Proxy deleted: {proxy_name}",
            "proxy_name": proxy_name,
            "proxy_id": proxy_id,
            "details": {
                "purge": purge,
                "deleted_by": "api",
                "archive_name": delete_result.archive_name,
                "archived_count": len(delete_result.archived),
                "deleted_count": len(delete_result.deleted),
            },
        }
    )

    return ProxyDeleteResponse(
        archived=delete_result.archived,
        deleted=delete_result.deleted,
        archive_name=delete_result.archive_name,
        archived_size=delete_result.archived_size,
        deleted_size=delete_result.deleted_size,
    )


class _ProxyDeletedNotification(BaseModel):
    """Request body for CLI proxy deletion notification."""

    proxy_id: str
    proxy_name: str
    archive_name: str | None = None


@router.post("/proxies/notify-deleted")
async def notify_proxy_deleted(
    notification: _ProxyDeletedNotification,
    request: Request,
) -> dict[str, bool]:
    """Receive CLI notification that a proxy was deleted.

    Broadcasts proxy_deleted SSE event so web UI updates instantly.
    Called by CLI after local deletion completes.
    """
    from mcp_acp.manager.events import SSEEventType

    reg: ProxyRegistry = request.app.state.registry
    await reg.broadcast_snapshot(
        SSEEventType.PROXY_DELETED.value,
        {
            "proxy_id": notification.proxy_id,
            "proxy_name": notification.proxy_name,
            "archive_name": notification.archive_name,
        },
    )

    _logger.warning(
        {
            "event": "proxy_deleted",
            "message": f"Proxy deleted (CLI): {notification.proxy_name}",
            "proxy_name": notification.proxy_name,
            "proxy_id": notification.proxy_id,
            "details": {
                "deleted_by": "cli",
                "archive_name": notification.archive_name,
            },
        }
    )

    return {"ok": True}
