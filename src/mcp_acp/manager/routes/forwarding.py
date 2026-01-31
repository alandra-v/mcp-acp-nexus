"""Request forwarding and static file serving."""

from __future__ import annotations

__all__ = [
    "router",
    "MANAGER_API_PREFIXES",
    "IDLE_EXEMPT_PATHS",
    "create_static_routes",
]

import logging
import time
from pathlib import Path

import httpx
from typing import Any

from fastapi import APIRouter, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse

from mcp_acp.constants import APP_NAME
from mcp_acp.manager.registry import ProxyConnection, ProxyRegistry

from .helpers import (
    PROXY_REQUEST_TIMEOUT_SECONDS,
    STATIC_DIR,
    STATIC_MEDIA_TYPES,
    is_safe_path,
    create_uds_client,
    error_response,
)

_logger = logging.getLogger(f"{APP_NAME}.manager.routes.forwarding")

# Manager API prefixes (not forwarded to proxy)
MANAGER_API_PREFIXES = ("/api/manager/", "/api/events", "/api/proxy/")

# Paths that should NOT reset the idle shutdown timer
# - /api/manager/status: CLI health checks (should not keep manager alive)
# - /api/events: SSE keepalives (connection itself counts, not keepalives)
IDLE_EXEMPT_PATHS = frozenset({"/api/manager/status", "/api/events"})

# Headers stripped when forwarding to proxy UDS sockets.
# Hop-by-hop headers (RFC 7230 §6.1) must not cross connection boundaries.
# Auth headers belong to the manager session — the proxy UDS connection is
# authenticated by OS file permissions, not by bearer tokens or cookies.
_STRIP_HEADERS = frozenset(
    (
        # Hop-by-hop (RFC 7230)
        "host",
        "connection",
        "keep-alive",
        "transfer-encoding",
        "te",
        "trailer",
        "upgrade",
        "proxy-authenticate",
        "proxy-authorization",
        # Auth (manager-session scoped)
        "authorization",
        "cookie",
    )
)

router = APIRouter(tags=["forwarding"])


# ==========================================================================
# Request Forwarding Helpers
# ==========================================================================


async def _forward_request_to_proxy(
    socket_path: str,
    target_path: str,
    request: Request,
    proxy_name: str = "default",
) -> Response:
    """Forward an HTTP request to a proxy via UDS.

    Common logic for routing requests to proxy sockets.

    Args:
        socket_path: Path to proxy's UDS socket.
        target_path: Target path on the proxy (e.g., "/api/approvals").
        request: Incoming FastAPI request to forward.
        proxy_name: Proxy name for error messages.

    Returns:
        Response from the proxy, or error JSONResponse on failure.
    """
    start_time = time.monotonic()
    try:
        async with create_uds_client(socket_path) as client:
            # Read body for POST/PUT/PATCH
            body = await request.body() if request.method in ("POST", "PUT", "PATCH") else None

            forward_headers = {k: v for k, v in request.headers.items() if k.lower() not in _STRIP_HEADERS}

            # Make request to proxy
            response = await client.request(
                method=request.method,
                url=target_path,
                content=body,
                headers=forward_headers,
            )

            duration_ms = int((time.monotonic() - start_time) * 1000)

            # Log non-200 responses as warnings (persisted to file)
            if response.status_code >= 400:
                _logger.warning(
                    {
                        "event": "proxy_response_error",
                        "message": f"Proxy '{proxy_name}' returned {response.status_code} for {request.method} {target_path}",
                        "proxy_name": proxy_name,
                        "path": target_path,
                        "status_code": response.status_code,
                        "duration_ms": duration_ms,
                    }
                )

            # Return proxy response
            return Response(
                content=response.content,
                status_code=response.status_code,
                headers=dict(response.headers),
                media_type=response.headers.get("content-type"),
            )

    except httpx.ConnectError:
        duration_ms = int((time.monotonic() - start_time) * 1000)
        _logger.warning(
            {
                "event": "proxy_connect_failed",
                "message": f"Failed to connect to proxy '{proxy_name}' at {socket_path}",
                "proxy_name": proxy_name,
                "socket_path": socket_path,
                "duration_ms": duration_ms,
            }
        )
        return error_response(503, f"Proxy '{proxy_name}' connection failed")
    except httpx.TimeoutException:
        duration_ms = int((time.monotonic() - start_time) * 1000)
        _logger.warning(
            {
                "event": "proxy_timeout",
                "message": f"Timeout connecting to proxy '{proxy_name}'",
                "proxy_name": proxy_name,
                "duration_ms": duration_ms,
            }
        )
        return error_response(504, f"Proxy '{proxy_name}' request timed out")
    except OSError as e:
        duration_ms = int((time.monotonic() - start_time) * 1000)
        _logger.error(
            {
                "event": "proxy_os_error",
                "message": f"OS error routing to proxy '{proxy_name}'",
                "proxy_name": proxy_name,
                "error_type": type(e).__name__,
                "error_message": str(e),
                "duration_ms": duration_ms,
            }
        )
        return error_response(500, f"Internal error routing to proxy: {type(e).__name__}")


async def _get_default_proxy(reg: ProxyRegistry) -> ProxyConnection | JSONResponse:
    """Get default proxy for fallback routing.

    Multi-proxy routing logic:
    - If exactly one proxy is registered, return it (convenient default)
    - If no proxies are registered, return 503 error response
    - If multiple proxies are registered, return 400 error with list of names

    Args:
        reg: The proxy registry.

    Returns:
        ProxyConnection if exactly one proxy is registered,
        JSONResponse error if zero or multiple proxies.
    """
    proxies = await reg.get_all_proxies()

    if len(proxies) == 0:
        return error_response(
            503,
            "No proxies connected",
            "Start a proxy to enable API access.",
        )

    if len(proxies) == 1:
        return proxies[0]

    # Multiple proxies - require explicit proxy name
    names = sorted(p.proxy_name for p in proxies)
    return error_response(
        400,
        "Multiple proxies available",
        f"Specify proxy using /api/proxy/{{name}}/... Available: {', '.join(names)}",
    )


# ==========================================================================
# Forwarding Endpoints
# ==========================================================================


@router.api_route(
    "/api/proxy/{proxy_name}/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
)
async def route_to_proxy(
    proxy_name: str,
    path: str,
    request: Request,
) -> Response:
    """Route API requests to the appropriate proxy.

    Manager forwards /api/proxy/{name}/* requests to the proxy's UDS socket.
    The path after /api/proxy/{name}/ becomes /api/{path} on the proxy.

    Args:
        proxy_name: Name of the target proxy (e.g., "default").
        path: Remaining path after proxy name (e.g., "approvals/pending").
        request: Incoming FastAPI request.

    Returns:
        Response from the proxy, or error response if proxy unavailable.
    """
    reg: ProxyRegistry = request.app.state.registry

    # Look up proxy in registry
    proxy_conn = await reg.get_proxy(proxy_name)
    if proxy_conn is None:
        return error_response(404, f"Proxy '{proxy_name}' not found")

    socket_path = proxy_conn.socket_path
    if not socket_path or not Path(socket_path).exists():
        return error_response(503, f"Proxy '{proxy_name}' socket not available")

    # Build target URL (proxy expects /api/... paths)
    target_path = f"/api/{path}"
    if request.url.query:
        target_path = f"{target_path}?{request.url.query}"

    return await _forward_request_to_proxy(socket_path, target_path, request, proxy_name)


@router.api_route(
    "/api/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
)
async def fallback_to_default_proxy(path: str, request: Request) -> Response:
    """Fallback: route unhandled /api/* requests to default proxy.

    When only one proxy is registered, requests to /api/approvals,
    /api/policy, etc. are automatically routed to it.

    Manager-level endpoints (/api/manager/*, /api/proxies, /api/events)
    are handled by explicit routes above and won't hit this fallback.

    Args:
        path: Path after /api/ (e.g., "approvals/pending").
        request: Incoming FastAPI request.

    Returns:
        Response from the default proxy, or 404 if no proxy registered.
    """
    # Check if this should be handled by explicit manager routes
    # (This shouldn't happen due to route ordering, but defensive)
    full_path = f"/api/{path}"
    for prefix in MANAGER_API_PREFIXES:
        if full_path.startswith(prefix):
            return error_response(404, "Not found")

    # Route to default proxy (if exactly one) or return error
    reg: ProxyRegistry = request.app.state.registry
    result = await _get_default_proxy(reg)

    # If error response, return it directly
    if isinstance(result, JSONResponse):
        return result

    proxy_conn = result
    socket_path = proxy_conn.socket_path
    if not socket_path or not Path(socket_path).exists():
        return error_response(503, "Proxy socket not available")

    # Build target URL (proxy expects /api/... paths)
    target_path = f"/api/{path}"
    if request.url.query:
        target_path = f"{target_path}?{request.url.query}"

    return await _forward_request_to_proxy(socket_path, target_path, request, proxy_conn.proxy_name)


def create_static_routes(app_state_getter: Any) -> APIRouter | None:
    """Create static file serving router.

    This is a factory function because static file serving requires
    access to app.state.api_token which isn't available at import time.

    Args:
        app_state_getter: Callable that returns app.state from request.

    Returns:
        APIRouter with static file routes, or None if static dir doesn't exist.
    """
    if not STATIC_DIR.exists():
        return None

    index_file = STATIC_DIR / "index.html"
    if not index_file.exists():
        return None

    static_router = APIRouter(tags=["static"])

    @static_router.get("/{path:path}", response_model=None)
    async def serve_spa(path: str, request: Request) -> Response:
        """Serve static files or index.html for SPA routing.

        Args:
            path: Requested URL path.
            request: FastAPI request object.

        Returns:
            Static file or index.html for SPA routes.
        """
        # Check for static files (root-level or in assets/)
        if path:
            static_file = STATIC_DIR / path
            # Security: Prevent path traversal attacks
            if not is_safe_path(STATIC_DIR, static_file):
                _logger.warning(
                    {
                        "event": "path_traversal_blocked",
                        "message": f"Path traversal attempt blocked: {path}",
                        "path": path,
                    }
                )
                return HTMLResponse(
                    content="Not Found",
                    status_code=404,
                )

            if static_file.exists() and static_file.is_file():
                suffix = static_file.suffix.lower()
                media_type = STATIC_MEDIA_TYPES.get(suffix, "application/octet-stream")
                cache_control = (
                    "public, max-age=31536000, immutable"
                    if path.startswith("assets/")
                    else "public, max-age=3600"
                )
                return FileResponse(
                    static_file,
                    media_type=media_type,
                    headers={"Cache-Control": cache_control},
                )

        # SPA fallback: serve index.html
        html = index_file.read_text()
        api_token = getattr(request.app.state, "api_token", None)

        # Dev mode note: When running React dev server separately (npm run dev),
        # use the built SPA or configure CORS. Token is set via HttpOnly cookie below.

        response = HTMLResponse(
            content=html,
            headers={"Cache-Control": "no-cache, no-store, must-revalidate"},
        )

        # Set HttpOnly cookie for browser authentication
        if api_token:
            response.set_cookie(
                key="api_token",
                value=api_token,
                httponly=True,
                samesite="strict",
                path="/api",
            )

        return response

    return static_router
