"""Shared HTTP/UDS utilities for manager routes.

This module contains constants and helper functions used across
multiple route modules for communication with proxies.
"""

from __future__ import annotations

__all__ = [
    "PROXY_REQUEST_TIMEOUT_SECONDS",
    "PROXY_SNAPSHOT_TIMEOUT_SECONDS",
    "STATIC_DIR",
    "STATIC_MEDIA_TYPES",
    "create_uds_client",
    "error_response",
    "fetch_proxy_snapshots",
    "is_safe_path",
]

import json
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator

import httpx
from fastapi.responses import JSONResponse

from mcp_acp.constants import APP_NAME

# Static files directory (built React app)
STATIC_DIR = Path(__file__).parent.parent.parent / "web" / "static"

# HTTP client timeouts for proxy communication (seconds)
PROXY_SNAPSHOT_TIMEOUT_SECONDS = 5.0
PROXY_REQUEST_TIMEOUT_SECONDS = 30.0

# Media type mapping for static file serving
STATIC_MEDIA_TYPES: dict[str, str] = {
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".json": "application/json",
    ".js": "application/javascript",
    ".css": "text/css",
    ".woff": "font/woff",
    ".woff2": "font/woff2",
    ".ttf": "font/ttf",
    ".map": "application/json",
}

_logger = logging.getLogger(f"{APP_NAME}.manager.routes")


@asynccontextmanager
async def create_uds_client(
    socket_path: str,
    timeout: float = PROXY_REQUEST_TIMEOUT_SECONDS,
) -> AsyncIterator[httpx.AsyncClient]:
    """Create HTTP client for UDS communication with proxy.

    This is an async context manager that properly handles client lifecycle.

    Args:
        socket_path: Path to the Unix Domain Socket.
        timeout: Request timeout in seconds.

    Yields:
        Configured httpx.AsyncClient for UDS communication.

    Example:
        async with create_uds_client("/tmp/proxy.sock") as client:
            response = await client.get("/api/status")
    """
    transport = httpx.AsyncHTTPTransport(uds=socket_path)
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://localhost",  # Required but not used for UDS
        timeout=timeout,
    ) as client:
        yield client


async def fetch_proxy_snapshots(
    client: httpx.AsyncClient,
) -> dict[str, Any]:
    """Fetch all snapshots from proxy API.

    Fetches pending approvals, cached approvals, and stats from a proxy.
    Errors don't propagate - returns None for failed fetches.

    Args:
        client: HTTP client configured for UDS communication.

    Returns:
        Dict with keys: pending, cached, stats, client_id. Each may be None on error.
    """
    result: dict[str, Any] = {"pending": None, "cached": None, "stats": None, "client_id": None}

    # Fetch pending approvals
    try:
        resp = await client.get("/api/approvals/pending/list")
        if resp.status_code == 200:
            result["pending"] = resp.json()
    except (httpx.HTTPError, httpx.TimeoutException, json.JSONDecodeError) as e:
        _logger.debug("Pending approvals fetch failed (expected during startup): %s", e)

    # Fetch cached approvals
    try:
        resp = await client.get("/api/approvals/cached")
        if resp.status_code == 200:
            result["cached"] = resp.json()
    except (httpx.HTTPError, httpx.TimeoutException, json.JSONDecodeError) as e:
        _logger.debug("Cached approvals fetch failed (expected during startup): %s", e)

    # Fetch stats and client_id from /api/proxies
    try:
        resp = await client.get("/api/proxies")
        if resp.status_code == 200:
            proxies = resp.json()
            if proxies and len(proxies) > 0:
                result["stats"] = proxies[0].get("stats")
                result["client_id"] = proxies[0].get("client_id")
    except (httpx.HTTPError, httpx.TimeoutException, json.JSONDecodeError) as e:
        _logger.debug("Proxy info fetch failed (expected during startup): %s", e)

    return result


def error_response(
    status_code: int,
    message: str,
    detail: str | None = None,
) -> JSONResponse:
    """Create standardized error response.

    Args:
        status_code: HTTP status code.
        message: Error message for the "error" field.
        detail: Optional additional detail.

    Returns:
        JSONResponse with error structure.
    """
    content: dict[str, Any] = {"error": message}
    if detail:
        content["detail"] = detail
    return JSONResponse(status_code=status_code, content=content)


def is_safe_path(base_dir: Path, requested_path: Path) -> bool:
    """Check if requested path is safely within base directory.

    Prevents path traversal attacks (e.g., ../../etc/passwd).

    Args:
        base_dir: Base directory that should contain the path.
        requested_path: Path to validate.

    Returns:
        True if path is safely within base_dir.
    """
    try:
        # Resolve both paths to absolute, normalized paths
        base_resolved = base_dir.resolve()
        requested_resolved = requested_path.resolve()
        # Check if requested path starts with base path
        return requested_resolved.is_relative_to(base_resolved)
    except (ValueError, RuntimeError):
        return False
