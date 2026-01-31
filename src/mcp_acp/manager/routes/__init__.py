"""Manager routes package - modular API routes for the manager daemon.

This package splits the manager routes into focused modules:
- helpers: Shared HTTP/UDS utilities
- deps: Shared dependencies for proxy lookups
- status: Manager health status
- proxies: Proxy CRUD operations
- policy: Policy management
- config: Configuration management
- logs: Log viewing
- audit: Audit integrity
- auth: Authentication management
- incidents: Incidents aggregation
- events: SSE endpoint
- forwarding: Request routing and static files
"""

from __future__ import annotations

__all__ = [
    "create_manager_api_app",
    # Used by daemon.py
    "PROXY_SNAPSHOT_TIMEOUT_SECONDS",
    "create_uds_client",
    # Used by tests
    "IDLE_EXEMPT_PATHS",
    "MANAGER_API_PREFIXES",
    "is_safe_path",
    "error_response",
]

from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING

from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from mcp_acp.api.errors import (
    APIError,
    api_error_handler,
    http_exception_handler,
    validation_error_handler,
)
from mcp_acp.manager.registry import ProxyRegistry, get_proxy_registry

from .forwarding import IDLE_EXEMPT_PATHS, MANAGER_API_PREFIXES
from .helpers import (
    PROXY_SNAPSHOT_TIMEOUT_SECONDS,
    is_safe_path,
    create_uds_client,
    error_response,
)

# Import routers
from . import auth
from . import audit
from . import config
from . import events
from . import forwarding
from . import incidents
from . import logs
from . import policy
from . import proxies
from . import status

if TYPE_CHECKING:
    from mcp_acp.manager.token_service import ManagerTokenService


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
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    # Store token, registry, and token service
    app.state.api_token = token
    app.state.registry = registry or get_proxy_registry()
    app.state.token_service = token_service

    # Exception handlers for structured error responses (matching proxy server)
    app.add_exception_handler(APIError, api_error_handler)
    app.add_exception_handler(RequestValidationError, validation_error_handler)
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)

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

    # Include all routers
    # Order matters: more specific routes should be included before catch-all routes

    # Manager-level endpoints
    app.include_router(status.router)
    app.include_router(proxies.router)
    app.include_router(policy.router)
    app.include_router(config.router)
    app.include_router(logs.router)
    app.include_router(audit.router)
    app.include_router(auth.router)
    app.include_router(incidents.router)
    app.include_router(events.router)

    # Forwarding routes (includes /api/proxy/{name}/* and /api/* fallback)
    app.include_router(forwarding.router)

    # Static file serving (catch-all for SPA)
    static_router = forwarding.create_static_routes(lambda req: req.app.state)
    if static_router:
        app.include_router(static_router)

    return app
