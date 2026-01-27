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
import shutil
import sys
import time
from datetime import UTC, datetime
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any, AsyncIterator

if TYPE_CHECKING:
    from mcp_acp.manager.token_service import ManagerTokenService

from mcp_acp.exceptions import AuthenticationError
from mcp_acp.security.auth.jwt_validator import JWTValidator
from mcp_acp.security.auth.token_storage import (
    create_token_storage,
    get_token_storage_info,
)

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from sse_starlette.sse import EventSourceResponse

from mcp_acp.constants import APP_NAME, DEFAULT_APPROVAL_TTL_SECONDS
from mcp_acp.manager.config import (
    get_proxy_config_path,
    get_proxy_log_dir,
    get_proxy_policy_path,
    list_configured_proxies,
    load_manager_config,
    validate_proxy_name,
)
from mcp_acp.api.errors import APIError, ErrorCode
from mcp_acp.config import (
    BackendConfig,
    HITLConfig,
    HttpTransportConfig,
    MTLSConfig,
    PerProxyConfig,
    StdioAttestationConfig,
    StdioTransportConfig,
    generate_proxy_id,
    load_proxy_config,
    save_proxy_config,
)
from mcp_acp.manager.models import (
    AggregatedIncidentsResponse,
    AuthActionResponse,
    AuthStatusResponse,
    ConfigSnippetResponse,
    CreateProxyRequest,
    CreateProxyResponse,
    Proxy,
    IncidentType,
    ManagerStatusResponse,
    ProxyDetailResponse,
    ProxyStats,
)
from mcp_acp.api.schemas import IncidentsSummary
from mcp_acp.manager.registry import ProxyConnection, ProxyRegistry, get_proxy_registry
from mcp_acp.pdp import create_default_policy
from mcp_acp.security.integrity.emergency_audit import get_emergency_audit_path
from mcp_acp.utils.api import count_entries_and_latest, get_cutoff_time, parse_timestamp, read_jsonl_filtered
from mcp_acp.utils.config import get_config_dir
from mcp_acp.utils.policy import save_policy
from mcp_acp.utils.validation import SHA256_HEX_LENGTH, validate_sha256_hex

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

# Incidents aggregation: fetch extra entries from each source to allow for proper
# merging and sorting across sources. The final limit is applied after merge.
INCIDENTS_FETCH_MULTIPLIER = 2

# Transport types that require specific configuration
STDIO_TRANSPORTS = frozenset({"stdio", "auto"})
HTTP_TRANSPORTS = frozenset({"streamablehttp", "auto"})

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

    @app.get("/api/manager/proxies", response_model=list[Proxy])
    async def list_proxies_enhanced(request: Request) -> list[Proxy]:
        """List all configured proxies with config and runtime data.

        Returns enhanced proxy information combining:
        - Config data (server_name, transport, created_at) from config files
        - Runtime data (status, instance_id, stats) from registry and UDS

        Shows all configured proxies, not just running ones.
        """
        reg: ProxyRegistry = request.app.state.registry

        # Get registered (running) proxies for lookup
        registered = await reg.list_proxies()
        registered_by_name = {p["name"]: p for p in registered}

        # Get all configured proxies
        configured_names = list_configured_proxies()

        # Load configs and identify running proxies
        configs: dict[str, PerProxyConfig] = {}
        running_proxies: list[tuple[str, str]] = []  # (proxy_name, socket_path)

        for proxy_name in configured_names:
            try:
                configs[proxy_name] = load_proxy_config(proxy_name)
            except (FileNotFoundError, ValueError, OSError) as e:
                _logger.warning(
                    {
                        "event": "proxy_config_load_failed",
                        "message": f"Failed to load config for proxy '{proxy_name}': {e}",
                        "proxy_name": proxy_name,
                        "error_type": type(e).__name__,
                        "error_message": str(e),
                    }
                )
                continue

            # Check if running
            reg_info = registered_by_name.get(proxy_name)
            if reg_info and reg_info.get("socket_path"):
                running_proxies.append((proxy_name, reg_info["socket_path"]))

        # Fetch stats concurrently for all running proxies
        async def fetch_stats(socket_path: str) -> ProxyStats | None:
            try:
                async with create_uds_client(
                    socket_path,
                    timeout=PROXY_SNAPSHOT_TIMEOUT_SECONDS,
                ) as client:
                    resp = await client.get("/api/stats")
                    if resp.status_code == 200:
                        stats_data = resp.json()
                        return ProxyStats(
                            requests_total=stats_data.get("requests_total", 0),
                            requests_allowed=stats_data.get("requests_allowed", 0),
                            requests_denied=stats_data.get("requests_denied", 0),
                            requests_hitl=stats_data.get("requests_hitl", 0),
                        )
            except (httpx.ConnectError, OSError, httpx.TimeoutException):
                pass  # Failed to fetch stats
            return None

        # Fetch all stats concurrently
        stats_results = await asyncio.gather(
            *(fetch_stats(socket_path) for _, socket_path in running_proxies),
            return_exceptions=True,
        )
        stats_by_name: dict[str, ProxyStats | None] = {}
        for (proxy_name, _), stats_result in zip(running_proxies, stats_results):
            if isinstance(stats_result, BaseException):
                stats_by_name[proxy_name] = None
            else:
                stats_by_name[proxy_name] = stats_result

        # Build result
        result: list[Proxy] = []
        for proxy_name, config in configs.items():
            reg_info = registered_by_name.get(proxy_name)
            is_running = reg_info is not None

            # Extract command/args from stdio config, url from http config
            command = None
            args = None
            url = None
            if config.backend.stdio:
                command = config.backend.stdio.command
                args = config.backend.stdio.args or []
            if config.backend.http:
                url = config.backend.http.url

            # Determine actual backend transport
            # - "auto" resolves to stdio if command present, else streamablehttp
            # - explicit transport types are used as-is
            backend_transport = config.backend.transport
            if backend_transport == "auto":
                backend_transport = "stdio" if config.backend.stdio else "streamablehttp"

            result.append(
                Proxy(
                    proxy_name=proxy_name,
                    proxy_id=config.proxy_id,
                    status="running" if is_running else "inactive",
                    instance_id=reg_info.get("instance_id") if reg_info else None,
                    server_name=config.backend.server_name,
                    transport=config.backend.transport,
                    command=command,
                    args=args if args else None,
                    url=url,
                    created_at=config.created_at,
                    backend_transport=backend_transport,
                    mtls_enabled=config.mtls is not None,
                    stats=stats_by_name.get(proxy_name),
                )
            )

        return result

    def _find_proxy_by_id(proxy_id: str) -> tuple[str, PerProxyConfig] | None:
        """Find proxy config by proxy_id.

        Args:
            proxy_id: The stable proxy identifier.

        Returns:
            Tuple of (proxy_name, config) if found, None otherwise.
        """
        for proxy_name in list_configured_proxies():
            try:
                config = load_proxy_config(proxy_name)
                if config.proxy_id == proxy_id:
                    return (proxy_name, config)
            except (FileNotFoundError, ValueError, OSError):
                continue
        return None

    @app.get("/api/manager/proxies/{proxy_id}", response_model=ProxyDetailResponse)
    async def get_proxy_detail(proxy_id: str, request: Request) -> ProxyDetailResponse:
        """Get full proxy detail by proxy_id.

        Returns config and runtime data for a specific proxy.

        Args:
            proxy_id: Stable proxy identifier from config.
            request: FastAPI request object.

        Returns:
            ProxyDetailResponse with config and runtime data.

        Raises:
            APIError: If proxy_id not found (404).
        """
        result = _find_proxy_by_id(proxy_id)
        if result is None:
            raise APIError(
                status_code=404,
                code=ErrorCode.PROXY_NOT_FOUND,
                message=f"Proxy with ID '{proxy_id}' not found",
                details={"proxy_id": proxy_id},
            )

        proxy_name, config = result
        reg: ProxyRegistry = request.app.state.registry

        # Check if running
        registered = await reg.list_proxies()
        reg_info = next((p for p in registered if p["name"] == proxy_name), None)
        is_running = reg_info is not None

        # Extract command/args from stdio config, url from http config
        command = None
        args = None
        url = None
        if config.backend.stdio:
            command = config.backend.stdio.command
            args = config.backend.stdio.args or []
        if config.backend.http:
            url = config.backend.http.url

        # Determine actual backend transport
        backend_transport = config.backend.transport
        if backend_transport == "auto":
            backend_transport = "stdio" if config.backend.stdio else "streamablehttp"

        # Fetch runtime data if running
        stats = None
        client_id = None
        pending_approvals = None
        cached_approvals = None

        if is_running and reg_info and reg_info.get("socket_path"):
            socket_path = reg_info["socket_path"]
            try:
                async with create_uds_client(
                    socket_path,
                    timeout=PROXY_SNAPSHOT_TIMEOUT_SECONDS,
                ) as client:
                    snapshots = await fetch_proxy_snapshots(client)

                    # Extract stats
                    if snapshots["stats"]:
                        stats = ProxyStats(
                            requests_total=snapshots["stats"].get("requests_total", 0),
                            requests_allowed=snapshots["stats"].get("requests_allowed", 0),
                            requests_denied=snapshots["stats"].get("requests_denied", 0),
                            requests_hitl=snapshots["stats"].get("requests_hitl", 0),
                        )

                    # Extract client_id
                    client_id = snapshots.get("client_id")

                    # Extract pending approvals
                    pending_approvals = snapshots["pending"]

                    # Extract cached approvals
                    if snapshots["cached"]:
                        cached_approvals = snapshots["cached"].get("approvals", [])

            except (httpx.ConnectError, OSError, httpx.TimeoutException) as e:
                _logger.debug("Runtime data fetch failed for proxy '%s': %s", proxy_name, e)

        return ProxyDetailResponse(
            proxy_name=proxy_name,
            proxy_id=config.proxy_id,
            status="running" if is_running else "inactive",
            instance_id=reg_info.get("instance_id") if reg_info else None,
            server_name=config.backend.server_name,
            transport=config.backend.transport,
            command=command,
            args=args if args else None,
            url=url,
            created_at=config.created_at,
            backend_transport=backend_transport,
            mtls_enabled=config.mtls is not None,
            stats=stats,
            client_id=client_id,
            pending_approvals=pending_approvals,
            cached_approvals=cached_approvals,
        )

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

    @app.get("/api/manager/auth/status", response_model=AuthStatusResponse)
    async def get_auth_status() -> AuthStatusResponse:
        """Get authentication status.

        Returns the current auth state from manager config and token storage.
        Works without any running proxies since auth is managed at manager level.

        Returns:
            AuthStatusResponse with configured/authenticated state and user info.
        """
        manager_config = load_manager_config()

        # Check if OIDC is configured
        if manager_config.auth is None or manager_config.auth.oidc is None:
            return AuthStatusResponse(
                configured=False,
                authenticated=False,
            )

        oidc_config = manager_config.auth.oidc
        storage = create_token_storage(oidc_config)
        storage_info = get_token_storage_info()

        # Check for token
        if not storage.exists():
            return AuthStatusResponse(
                configured=True,
                authenticated=False,
                provider=oidc_config.issuer,
                storage_backend=storage_info.get("backend"),
            )

        # Load token
        try:
            token = storage.load()
        except (AuthenticationError, OSError):
            return AuthStatusResponse(
                configured=True,
                authenticated=False,
                provider=oidc_config.issuer,
                storage_backend=storage_info.get("backend"),
            )

        if token is None or token.is_expired:
            return AuthStatusResponse(
                configured=True,
                authenticated=False,
                provider=oidc_config.issuer,
                storage_backend=storage_info.get("backend"),
            )

        # Extract user info from ID token
        email = None
        name = None
        subject_id = None
        if token.id_token:
            try:
                validator = JWTValidator(oidc_config)
                claims = validator.decode_without_validation(token.id_token)
                email = claims.get("email")
                name = claims.get("name")
                subject_id = claims.get("sub")
            except (ValueError, KeyError):
                pass

        # Calculate hours until expiry
        hours_until_expiry = None
        if token.seconds_until_expiry > 0:
            hours_until_expiry = round(token.seconds_until_expiry / 3600, 1)

        return AuthStatusResponse(
            configured=True,
            authenticated=True,
            subject_id=subject_id,
            email=email,
            name=name,
            provider=oidc_config.issuer,
            token_expires_in_hours=hours_until_expiry,
            has_refresh_token=bool(token.refresh_token),
            storage_backend=storage_info.get("backend"),
        )

    # ==========================================================================
    # Config Snippet
    # ==========================================================================

    def _get_executable_path() -> str:
        """Find absolute path to mcp-acp executable.

        Tries multiple methods to find the executable:
        1. shutil.which (PATH lookup)
        2. sys.argv[0] if it contains 'mcp-acp' or 'mcp_acp'
        3. Falls back to 'mcp-acp' (assumes it's in PATH)

        Returns:
            Absolute path to mcp-acp executable.
        """
        # Try PATH first
        path = shutil.which(APP_NAME)
        if path:
            return str(Path(path).resolve())

        # Try sys.argv[0] - how the current process was invoked
        argv0 = sys.argv[0] if sys.argv else ""
        if "mcp-acp" in argv0 or "mcp_acp" in argv0:
            resolved = Path(argv0).resolve()
            if resolved.exists():
                return str(resolved)

        return APP_NAME  # Fall back to name, assume it's in PATH

    @app.get("/api/manager/config-snippet", response_model=ConfigSnippetResponse)
    async def get_config_snippet(proxy: str | None = None) -> ConfigSnippetResponse:
        """Get MCP client configuration snippet for proxies.

        Returns JSON in the standard mcpServers format used by Claude Desktop,
        Cursor, VS Code, and other MCP clients.

        Args:
            proxy: Optional proxy name to get snippet for. If not provided,
                   returns snippet for all configured proxies.

        Returns:
            ConfigSnippetResponse with mcpServers dictionary and executable path.

        Raises:
            APIError: If specified proxy not found.
        """
        proxies = list_configured_proxies()

        if proxy:
            # Single proxy requested
            if proxy not in proxies:
                raise APIError(
                    status_code=404,
                    code=ErrorCode.PROXY_NOT_FOUND,
                    message=f"Proxy '{proxy}' not found",
                    details={"proxy_name": proxy, "available": proxies},
                )
            proxies_to_include = [proxy]
        else:
            # All proxies
            proxies_to_include = proxies

        executable = _get_executable_path()

        mcp_servers: dict[str, dict[str, Any]] = {}
        for name in proxies_to_include:
            mcp_servers[name] = {
                "command": executable,
                "args": ["start", "--proxy", name],
            }

        return ConfigSnippetResponse(
            mcpServers=mcp_servers,
            executable_path=executable,
        )

    # ==========================================================================
    # Incidents Aggregation
    # ==========================================================================

    def _fetch_incidents(
        log_path: Path,
        incident_type: str,
        fetch_limit: int,
        cutoff_time: datetime | None,
        before_dt: datetime | None,
        proxy_name: str | None = None,
        proxy_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch incidents from a log file and annotate with type.

        Args:
            log_path: Path to the JSONL log file.
            incident_type: Type to annotate entries with.
            fetch_limit: Maximum entries to fetch.
            cutoff_time: Time cutoff for filtering.
            before_dt: Pagination cursor.
            proxy_name: Proxy name to annotate (for per-proxy logs).
            proxy_id: Proxy ID to annotate (for correlation).

        Returns:
            List of incident entries with incident_type and proxy info.
        """
        entries, _, _ = read_jsonl_filtered(
            log_path,
            limit=fetch_limit,
            cutoff_time=cutoff_time,
            before=before_dt,
        )
        result = []
        for entry in entries:
            # Copy entry to avoid mutating original
            annotated = {**entry, "incident_type": incident_type}
            # Add proxy info if provided (for per-proxy logs)
            # Preserve existing values from entry (for emergency audit which has them embedded)
            if proxy_id is not None and "proxy_id" not in annotated:
                annotated["proxy_id"] = proxy_id
            if proxy_name is not None and "proxy_name" not in annotated:
                annotated["proxy_name"] = proxy_name
            result.append(annotated)
        return result

    @app.get("/api/manager/incidents", response_model=AggregatedIncidentsResponse)
    async def get_aggregated_incidents(
        proxy: str | None = None,
        incident_type: IncidentType | None = None,
        time_range: str = "all",
        limit: int = 100,
        before: str | None = None,
    ) -> AggregatedIncidentsResponse:
        """Get aggregated incidents from all proxies.

        Combines shutdowns (per-proxy) with bootstrap and emergency (global).
        Each entry includes 'incident_type' field and 'proxy_name' for shutdowns.

        Args:
            proxy: Filter by proxy name (only affects shutdowns).
            incident_type: Filter by type ('shutdown', 'bootstrap', 'emergency').
            time_range: Time range filter ('5m', '1h', '24h', 'all').
            limit: Maximum entries to return (default: 100).
            before: Cursor for pagination (ISO timestamp).

        Returns:
            Aggregated incidents sorted by time (newest first).
        """
        manager_config = load_manager_config()
        cutoff_time = get_cutoff_time(time_range)
        before_dt = parse_timestamp(before)
        fetch_limit = limit * INCIDENTS_FETCH_MULTIPLIER

        all_entries: list[dict[str, Any]] = []

        # Build proxy info cache (name -> id) for annotation
        proxy_names_to_fetch = [proxy] if proxy else list_configured_proxies()
        proxy_id_map: dict[str, str] = {}
        for pname in proxy_names_to_fetch:
            try:
                config = load_proxy_config(pname)
                proxy_id_map[pname] = config.proxy_id
            except (FileNotFoundError, ValueError, OSError):
                pass  # Skip if config can't be loaded

        # Collect shutdowns from all proxies (per-proxy log dirs)
        if incident_type is None or incident_type == "shutdown":
            for proxy_name in proxy_names_to_fetch:
                log_dir = get_proxy_log_dir(proxy_name, manager_config)
                shutdowns_path = log_dir / "shutdowns.jsonl"
                all_entries.extend(
                    _fetch_incidents(
                        shutdowns_path,
                        "shutdown",
                        fetch_limit,
                        cutoff_time,
                        before_dt,
                        proxy_name=proxy_name,
                        proxy_id=proxy_id_map.get(proxy_name),
                    )
                )

        # Collect bootstrap errors from all proxies (per-proxy directories)
        if incident_type is None or incident_type == "bootstrap":
            for proxy_name in proxy_names_to_fetch:
                proxy_dir = get_proxy_config_path(proxy_name).parent
                bootstrap_path = proxy_dir / "bootstrap.jsonl"
                all_entries.extend(
                    _fetch_incidents(
                        bootstrap_path,
                        "bootstrap",
                        fetch_limit,
                        cutoff_time,
                        before_dt,
                        proxy_name=proxy_name,
                        proxy_id=proxy_id_map.get(proxy_name),
                    )
                )

        # Collect emergency audit (global - has proxy_id/proxy_name embedded in entries)
        if incident_type is None or incident_type == "emergency":
            emergency_path = get_emergency_audit_path()
            all_entries.extend(
                _fetch_incidents(emergency_path, "emergency", fetch_limit, cutoff_time, before_dt)
            )

        # Sort all entries by time (newest first)
        all_entries.sort(key=lambda e: e.get("time", ""), reverse=True)

        # Apply limit
        has_more = len(all_entries) > limit
        entries_to_return = all_entries[:limit]

        # Build filters applied
        filters_applied: dict[str, Any] = {"time_range": time_range}
        if proxy:
            filters_applied["proxy"] = proxy
        if incident_type:
            filters_applied["incident_type"] = incident_type

        return AggregatedIncidentsResponse(
            entries=entries_to_return,
            total_returned=len(entries_to_return),
            has_more=has_more,
            filters_applied=filters_applied,
        )

    @app.get("/api/manager/incidents/summary", response_model=IncidentsSummary)
    async def get_incidents_summary() -> IncidentsSummary:
        """Get aggregated incidents summary from all proxies.

        Combines shutdown counts from all proxy log directories with
        global bootstrap and emergency counts.

        Returns:
            IncidentsSummary with counts and latest critical timestamp.
        """
        manager_config = load_manager_config()

        # Count shutdowns from all proxies
        shutdowns_count = 0
        shutdowns_latest: str | None = None
        proxy_names = list_configured_proxies()
        for proxy_name in proxy_names:
            log_dir = get_proxy_log_dir(proxy_name, manager_config)
            shutdowns_path = log_dir / "shutdowns.jsonl"
            count, latest = count_entries_and_latest(shutdowns_path)
            shutdowns_count += count
            if latest and (shutdowns_latest is None or latest > shutdowns_latest):
                shutdowns_latest = latest

        # Count bootstrap from all proxies (per-proxy directories)
        bootstrap_count = 0
        for proxy_name in proxy_names:
            proxy_dir = get_proxy_config_path(proxy_name).parent
            bootstrap_path = proxy_dir / "bootstrap.jsonl"
            count, _ = count_entries_and_latest(bootstrap_path)
            bootstrap_count += count

        # Count emergency (global)
        emergency_path = get_emergency_audit_path()
        emergency_count, emergency_latest = count_entries_and_latest(emergency_path)

        # Latest critical timestamp (shutdowns + emergency, not bootstrap)
        critical_timestamps = [t for t in [shutdowns_latest, emergency_latest] if t]
        latest_critical = max(critical_timestamps) if critical_timestamps else None

        return IncidentsSummary(
            shutdowns_count=shutdowns_count,
            emergency_count=emergency_count,
            bootstrap_count=bootstrap_count,
            latest_critical_timestamp=latest_critical,
            # Paths not meaningful for aggregated summary (per-proxy files)
            shutdowns_path=None,
            emergency_path=str(emergency_path) if emergency_path.exists() else None,
            bootstrap_path=None,
        )

    # ==========================================================================
    # Proxy Creation
    # ==========================================================================

    def _build_transport_configs(
        body: CreateProxyRequest,
    ) -> tuple[StdioTransportConfig | None, HttpTransportConfig | None]:
        """Build transport configurations from request.

        Args:
            body: Validated proxy creation request.

        Returns:
            Tuple of (stdio_config, http_config).

        Raises:
            APIError: If attestation_sha256 is invalid format.
        """
        stdio_config = None
        http_config = None

        if body.transport in STDIO_TRANSPORTS and body.command:
            # Build attestation config if any attestation options provided
            attestation = None
            if body.attestation_slsa_owner or body.attestation_sha256 or body.attestation_require_signature:
                # Validate SHA-256 format if provided
                normalized_sha256 = None
                if body.attestation_sha256:
                    is_valid, normalized_sha256 = validate_sha256_hex(body.attestation_sha256)
                    if not is_valid:
                        raise APIError(
                            status_code=400,
                            code=ErrorCode.PROXY_INVALID,
                            message=f"Invalid attestation_sha256: must be {SHA256_HEX_LENGTH} hex characters",
                            details={"proxy_name": body.name, "attestation_sha256": body.attestation_sha256},
                        )
                attestation = StdioAttestationConfig(
                    slsa_owner=body.attestation_slsa_owner,
                    expected_sha256=normalized_sha256,
                    require_signature=body.attestation_require_signature,
                )
            stdio_config = StdioTransportConfig(
                command=body.command,
                args=body.args,
                attestation=attestation,
            )

        if body.transport in HTTP_TRANSPORTS and body.url:
            http_config = HttpTransportConfig(
                url=body.url,
                timeout=body.timeout,
            )

        return stdio_config, http_config

    def _build_mtls_config(body: CreateProxyRequest) -> MTLSConfig | None:
        """Build mTLS configuration from request.

        Args:
            body: Validated proxy creation request.

        Returns:
            MTLSConfig if all mTLS options provided, None otherwise.

        Raises:
            APIError: If partial mTLS options provided or files don't exist.
        """
        # Check if any mTLS options provided
        has_any = body.mtls_cert or body.mtls_key or body.mtls_ca
        if not has_any:
            return None

        # Require all three if any is provided
        if not (body.mtls_cert and body.mtls_key and body.mtls_ca):
            raise APIError(
                status_code=400,
                code=ErrorCode.PROXY_INVALID,
                message="mTLS requires all three: mtls_cert, mtls_key, mtls_ca",
                details={"proxy_name": body.name},
            )

        # Validate paths exist
        for field_name, path_val in [
            ("mtls_cert", body.mtls_cert),
            ("mtls_key", body.mtls_key),
            ("mtls_ca", body.mtls_ca),
        ]:
            if not Path(path_val).expanduser().exists():
                raise APIError(
                    status_code=400,
                    code=ErrorCode.PROXY_INVALID,
                    message=f"mTLS {field_name} file not found: {path_val}",
                    details={"proxy_name": body.name, "field": field_name, "path": path_val},
                )

        return MTLSConfig(
            client_cert_path=body.mtls_cert,
            client_key_path=body.mtls_key,
            ca_bundle_path=body.mtls_ca,
        )

    def _store_api_key(
        proxy_name: str,
        api_key: str,
        http_config: HttpTransportConfig,
    ) -> HttpTransportConfig:
        """Store API key in keychain and return updated config.

        Args:
            proxy_name: Name of the proxy.
            api_key: API key to store.
            http_config: HTTP config to update with credential_key.

        Returns:
            Updated HttpTransportConfig with credential_key.

        Raises:
            APIError: If keychain storage fails.
        """
        try:
            from mcp_acp.security.credential_storage import BackendCredentialStorage

            cred_storage = BackendCredentialStorage(proxy_name)
            cred_storage.save(api_key)
            return http_config.model_copy(update={"credential_key": cred_storage.credential_key})
        except RuntimeError as e:
            _logger.error(
                {
                    "event": "keychain_store_failed",
                    "message": f"Failed to store API key in keychain for proxy '{proxy_name}'",
                    "proxy_name": proxy_name,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                }
            )
            raise APIError(
                status_code=500,
                code=ErrorCode.PROXY_CREATION_FAILED,
                message=f"Failed to store API key in keychain: {e}",
                details={"proxy_name": proxy_name, "error": str(e)},
            )

    def _check_http_health(url: str, timeout: int, mtls_config: MTLSConfig | None) -> None:
        """Check HTTP backend health before creating proxy.

        Args:
            url: Backend URL to check.
            timeout: HTTP timeout in seconds.
            mtls_config: Optional mTLS configuration.

        Raises:
            APIError: If health check fails (backend unreachable or cert error).
        """
        from mcp_acp.constants import HEALTH_CHECK_TIMEOUT_SECONDS
        from mcp_acp.utils.transport import check_http_health

        try:
            check_http_health(
                url, timeout=min(timeout, HEALTH_CHECK_TIMEOUT_SECONDS), mtls_config=mtls_config
            )
        except ValueError as e:
            # Invalid mTLS certificates
            _logger.warning(
                {
                    "event": "health_check_cert_invalid",
                    "message": f"Invalid mTLS certificate for {url}: {e}",
                    "url": url,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                }
            )
            raise APIError(
                status_code=400,
                code=ErrorCode.PROXY_INVALID,
                message=f"Invalid mTLS certificate: {e}",
                details={"url": url, "error": str(e)},
            )
        except (TimeoutError, ConnectionError, OSError) as e:
            error_msg = str(e).lower()
            is_ssl_error = "ssl" in error_msg or "certificate" in error_msg
            _logger.warning(
                {
                    "event": "health_check_failed",
                    "message": f"Health check failed for {url}: {e}",
                    "url": url,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                    "is_ssl_error": is_ssl_error,
                }
            )
            if is_ssl_error:
                raise APIError(
                    status_code=400,
                    code=ErrorCode.PROXY_INVALID,
                    message=f"SSL/TLS error connecting to backend: {e}",
                    details={"url": url, "error": str(e)},
                )
            raise APIError(
                status_code=400,
                code=ErrorCode.PROXY_INVALID,
                message=f"Backend health check failed: could not reach {url}",
                details={"url": url, "error": str(e)},
            )

    @app.post("/api/manager/proxies", response_model=CreateProxyResponse, status_code=201)
    async def create_proxy(body: CreateProxyRequest) -> CreateProxyResponse:
        """Create a new proxy configuration.

        Mirrors CLI 'mcp-acp proxy add' functionality:
        1. Validates proxy name
        2. Creates proxies/{name}/config.json
        3. Creates proxies/{name}/policy.json (default policy)
        4. Stores API key in keychain if provided
        5. Returns Claude Desktop config snippet

        Args:
            body: CreateProxyRequest with proxy configuration.

        Returns:
            CreateProxyResponse with paths and Claude Desktop snippet.

        Raises:
            APIError: If validation fails (400), proxy exists (409), or creation fails (500).
        """
        # Validate proxy name
        try:
            validate_proxy_name(body.name)
        except ValueError as e:
            raise APIError(
                status_code=400,
                code=ErrorCode.PROXY_INVALID,
                message=str(e),
                details={"proxy_name": body.name},
            )

        # Check if proxy already exists
        config_path = get_proxy_config_path(body.name)
        if config_path.exists():
            raise APIError(
                status_code=409,
                code=ErrorCode.PROXY_EXISTS,
                message=f"Proxy '{body.name}' already exists.",
                details={"proxy_name": body.name},
            )

        # Validate transport-specific requirements
        if body.transport in STDIO_TRANSPORTS and not body.command:
            raise APIError(
                status_code=400,
                code=ErrorCode.PROXY_INVALID,
                message="Command is required for stdio/auto transport.",
                details={"proxy_name": body.name, "transport": body.transport},
            )
        if body.transport == "streamablehttp" and not body.url:
            raise APIError(
                status_code=400,
                code=ErrorCode.PROXY_INVALID,
                message="URL is required for HTTP transport.",
                details={"proxy_name": body.name, "transport": body.transport},
            )

        # Build transport configs
        stdio_config, http_config = _build_transport_configs(body)

        # Build mTLS config (validates paths exist)
        mtls_config = _build_mtls_config(body)

        # Check HTTP backend health if configured
        if http_config is not None:
            _check_http_health(http_config.url, http_config.timeout, mtls_config)

        # Generate proxy ID
        proxy_id = generate_proxy_id(body.server_name)

        # Build backend config
        backend_config = BackendConfig(
            server_name=body.server_name,
            transport=body.transport,
            stdio=stdio_config,
            http=http_config,
        )

        # Store API key in keychain if provided (raises APIError on failure)
        if body.api_key and http_config is not None:
            http_config = _store_api_key(body.name, body.api_key, http_config)
            backend_config = backend_config.model_copy(update={"http": http_config})

        # Create proxy config
        proxy_config = PerProxyConfig(
            proxy_id=proxy_id,
            created_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            backend=backend_config,
            hitl=HITLConfig(),
            mtls=mtls_config,
        )

        # Save config
        try:
            save_proxy_config(body.name, proxy_config)
        except OSError as e:
            raise APIError(
                status_code=500,
                code=ErrorCode.PROXY_CREATION_FAILED,
                message=f"Failed to save proxy configuration: {e}",
                details={"proxy_name": body.name, "error": str(e)},
            )

        # Create default policy
        policy_path = get_proxy_policy_path(body.name)
        try:
            default_policy = create_default_policy()
            save_policy(default_policy, policy_path)
        except OSError as e:
            raise APIError(
                status_code=500,
                code=ErrorCode.PROXY_CREATION_FAILED,
                message=f"Config created but policy creation failed: {e}",
                details={"proxy_name": body.name, "config_path": str(config_path), "error": str(e)},
            )

        # Build Claude Desktop snippet
        claude_snippet = {
            body.name: {
                "command": "mcp-acp",
                "args": ["start", "--proxy", body.name],
            }
        }

        return CreateProxyResponse(
            ok=True,
            proxy_name=body.name,
            proxy_id=proxy_id,
            config_path=str(config_path),
            policy_path=str(policy_path),
            claude_desktop_snippet=claude_snippet,
            message=f"Proxy '{body.name}' created successfully.",
        )

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
