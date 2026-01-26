"""FastAPI routes and HTTP helpers for the manager daemon.

This module contains:
- Constants for static file serving and HTTP timeouts
- HTTP client helpers for UDS communication with proxies
- The FastAPI application factory with all manager routes

Routes:
- /api/manager/status: Manager health status
- /api/manager/proxies: List registered proxies
- /api/events: SSE event stream
- /api/proxy/{name}/{path}: Route to specific proxy
- /api/{path}: Fallback to default proxy
- /{path}: Serve SPA static files
"""

from __future__ import annotations

__all__ = [
    "PROXY_REQUEST_TIMEOUT_SECONDS",
    "PROXY_SNAPSHOT_TIMEOUT_SECONDS",
    "STATIC_DIR",
    "STATIC_MEDIA_TYPES",
    "create_manager_api_app",
    "create_uds_client",
    "error_response",
    "fetch_proxy_snapshots",
]

import asyncio
import json
import logging
import os
import time
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any, AsyncIterator

if TYPE_CHECKING:
    from mcp_acp.manager.token_service import ManagerTokenService

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from sse_starlette.sse import EventSourceResponse

from mcp_acp.constants import APP_NAME, DEFAULT_APPROVAL_TTL_SECONDS
from mcp_acp.manager.models import AuthActionResponse, ManagerStatusResponse
from mcp_acp.manager.registry import ProxyConnection, ProxyRegistry, get_proxy_registry

# Static files directory (built React app)
STATIC_DIR = Path(__file__).parent.parent / "web" / "static"

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

# Manager API prefixes (not forwarded to proxy)
MANAGER_API_PREFIXES = ("/api/manager/", "/api/events", "/api/proxy/")

# Paths that should NOT reset the idle shutdown timer
# - /api/manager/status: CLI health checks (should not keep manager alive)
# - /api/events: SSE keepalives (connection itself counts, not keepalives)
IDLE_EXEMPT_PATHS = frozenset({"/api/manager/status", "/api/events"})

_logger = logging.getLogger(f"{APP_NAME}.manager.routes")


# =============================================================================
# HTTP Client Helpers
# =============================================================================


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
        Dict with keys: pending, cached, stats. Each may be None on error.
    """
    result: dict[str, Any] = {"pending": None, "cached": None, "stats": None}

    # Fetch pending approvals
    try:
        resp = await client.get("/api/approvals/pending/list")
        if resp.status_code == 200:
            result["pending"] = resp.json()
    except (httpx.HTTPError, httpx.TimeoutException, json.JSONDecodeError):
        pass  # Expected during startup race

    # Fetch cached approvals
    try:
        resp = await client.get("/api/approvals/cached")
        if resp.status_code == 200:
            result["cached"] = resp.json()
    except (httpx.HTTPError, httpx.TimeoutException, json.JSONDecodeError):
        pass  # Expected during startup race

    # Fetch stats from /api/proxies (stats included in proxy response)
    try:
        resp = await client.get("/api/proxies")
        if resp.status_code == 200:
            proxies = resp.json()
            if proxies and len(proxies) > 0:
                result["stats"] = proxies[0].get("stats")
    except (httpx.HTTPError, httpx.TimeoutException, json.JSONDecodeError):
        pass  # Expected during startup race

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


# =============================================================================
# Path Validation
# =============================================================================


def _is_safe_path(base_dir: Path, requested_path: Path) -> bool:
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


# =============================================================================
# Request Forwarding
# =============================================================================


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

            # Forward headers (filter out hop-by-hop headers)
            forward_headers = {
                k: v
                for k, v in request.headers.items()
                if k.lower() not in ("host", "connection", "transfer-encoding")
            }

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


# =============================================================================
# Default Proxy Resolution
# =============================================================================


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


# =============================================================================
# FastAPI Application Factory
# =============================================================================


def create_manager_api_app(
    token: str | None = None,
    registry: ProxyRegistry | None = None,
    token_service: "ManagerTokenService | None" = None,
) -> FastAPI:
    """Create the FastAPI application for manager.

    Serves static UI and manager-level API endpoints.

    Args:
        token: Bearer token for API authentication. None for UDS (OS auth).
        registry: Proxy registry for API endpoints.
        token_service: ManagerTokenService for auth token distribution.

    Returns:
        Configured FastAPI application.
    """
    app = FastAPI(
        title="MCP-ACP Manager",
        description="Manager daemon for MCP-ACP proxies",
        version="0.1.0",
    )

    # Store token, registry, and token service
    app.state.api_token = token
    app.state.registry = registry or get_proxy_registry()
    app.state.token_service = token_service

    # Note: Manager API auth uses HttpOnly cookie (api_token) set on index.html load.
    # This is adequate for localhost-only UI. No additional SecurityMiddleware needed.

    @app.middleware("http")
    async def track_activity(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        """Track API activity for idle shutdown.

        Records activity timestamp for all requests except those in
        IDLE_EXEMPT_PATHS (status checks and SSE keepalives), which
        should not prevent idle shutdown.
        """
        response = await call_next(request)
        if request.url.path not in IDLE_EXEMPT_PATHS:
            request.app.state.registry.record_activity()
        return response

    @app.get("/api/manager/status", response_model=ManagerStatusResponse)
    async def manager_status(request: Request) -> ManagerStatusResponse:
        """Get manager health status."""
        reg: ProxyRegistry = request.app.state.registry
        return ManagerStatusResponse(
            running=True,
            pid=os.getpid(),
            proxies_connected=await reg.proxy_count(),
        )

    @app.get("/api/manager/proxies")
    async def list_registered_proxies(request: Request) -> list[dict[str, Any]]:
        """List all registered proxies (manager's view).

        Returns registration info (name, instance_id, socket_path).
        For full proxy details (transport, stats), use /api/proxies which
        routes to the proxy itself.
        """
        reg: ProxyRegistry = request.app.state.registry
        return await reg.list_proxies()

    @app.post("/api/manager/auth/reload", response_model=AuthActionResponse)
    async def reload_auth_tokens(request: Request) -> AuthActionResponse:
        """Reload authentication tokens from storage.

        Called by CLI after 'auth login' to notify manager to reload
        tokens and broadcast to all connected proxies.

        Returns:
            AuthActionResponse with 'ok' and message about token distribution.
        """
        ts = request.app.state.token_service
        if ts is None:
            return AuthActionResponse(ok=False, message="Token service not configured (no OIDC)")

        success = await ts.reload_from_storage()
        if success:
            return AuthActionResponse(ok=True, message="Token reloaded and broadcast to proxies")
        return AuthActionResponse(ok=False, message="No token found in storage")

    @app.post("/api/manager/auth/clear", response_model=AuthActionResponse)
    async def clear_auth_tokens(request: Request) -> AuthActionResponse:
        """Clear authentication tokens (logout).

        Called by CLI after 'auth logout' to notify manager to clear
        tokens and notify all connected proxies.

        Returns:
            AuthActionResponse with 'ok' status.
        """
        ts = request.app.state.token_service
        if ts is None:
            return AuthActionResponse(ok=False, message="Token service not configured (no OIDC)")

        await ts.clear_token()
        return AuthActionResponse(ok=True, message="Token cleared, proxies notified")

    @app.get("/api/events")
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
                                        "ttl_seconds": cached.get(
                                            "ttl_seconds", DEFAULT_APPROVAL_TTL_SECONDS
                                        ),
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
                                        "proxy_name": proxy_conn.proxy_name,
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

    # ==========================================================================
    # API Routing: Forward /api/proxy/{name}/* to proxy's UDS socket
    # ==========================================================================

    @app.api_route(
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

    # ==========================================================================
    # Fallback: Route /api/* (non-manager endpoints) to default proxy
    # ==========================================================================
    # Manager-level endpoints: /api/manager/*, /api/proxies, /api/events
    # Everything else is forwarded to the default proxy when only one is registered.

    @app.api_route(
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

    # Serve static files (built React app)
    if STATIC_DIR.exists():
        index_file = STATIC_DIR / "index.html"
        if index_file.exists():

            @app.get("/{path:path}", response_model=None)
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
                    if not _is_safe_path(STATIC_DIR, static_file):
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

    return app
