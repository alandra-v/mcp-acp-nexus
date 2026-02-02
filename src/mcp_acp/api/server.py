"""FastAPI server for the management API and static file serving.

Currently implements:
- Cached approvals API (/api/approvals/cached) - previously approved HITL decisions
- Pending approvals API (/api/approvals/pending) - HITL requests waiting for decision
- Proxies API (/api/proxies) - proxy information
- Auth sessions API (/api/auth-sessions) - user authentication bindings
- Control API (/api/control) - policy reload

Security:
- HTTP: HttpOnly cookie (production) or Bearer token (dev) for /api/* endpoints
- HTTP: Host header validation (DNS rebinding protection)
- HTTP: Origin header validation (CSRF protection)
- UDS: OS file permissions provide authentication (no token needed)
- All: Security response headers

Future additions:
- Config management (/api/config)
- Policy management (/api/policy)
- Log viewer (/api/logs)
- Static file serving for React UI

Usage:
    The API server is embedded in the proxy process (see proxy.py) to share
    memory with the approval store. It starts automatically on port 8765
    when the proxy runs.

    For standalone development/testing (without shared memory):
        uv run uvicorn mcp_acp.api.server:create_api_app \\
            --factory --host 127.0.0.1 --port 8765

    Note: Standalone mode won't have access to the approval cache since the
    ApprovalStore is only registered when running inside the proxy process.
    Also, security middleware is disabled in standalone mode (no token).
"""

from __future__ import annotations

__all__ = ["create_api_app"]

import json
import os
from pathlib import Path

from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from .errors import (
    APIError,
    api_error_handler,
    http_exception_handler,
    validation_error_handler,
)
from .routes import (
    approvals,
    auth,
    config,
    control,
    debug,
    incidents,
    logs,
    pending,
    policy,
    proxies,
    sessions,
    stats,
)
from .security import VITE_DEV_PORT, SecurityMiddleware, is_valid_token_format

# Static files directory (built React app)
STATIC_DIR = Path(__file__).parent.parent / "web" / "static"


def _is_dev_mode_request(request: Request) -> bool:
    """Check if request is from Vite dev server (cross-origin).

    Dev mode: Vite on :VITE_DEV_PORT makes requests to API on :8765
    Production: Browser loads page directly from :8765 (same-origin)

    In dev mode, we inject the token into HTML for cross-origin auth.
    In production, we use HttpOnly cookies instead.
    """
    origin = request.headers.get("origin", "")
    referer = request.headers.get("referer", "")
    dev_port_pattern = f":{VITE_DEV_PORT}"
    return dev_port_pattern in origin or dev_port_pattern in referer


def create_api_app(
    token: str | None = None,
    is_uds: bool = False,
    proxy_name: str | None = None,
) -> FastAPI:
    """Create the FastAPI application with all routes.

    Args:
        token: Bearer token for API authentication. If None, security
            middleware is disabled (for standalone dev/testing).
        is_uds: If True, this app serves UDS connections (OS permissions = auth).
            UDS apps skip token/host/origin validation but keep size limits
            and security headers.
        proxy_name: Name of the proxy this API serves. Required for per-proxy
            policy and config paths.

    Returns:
        Configured FastAPI application.
    """
    app = FastAPI(
        title="MCP-ACP Extended API",
        description="Management API for MCP-ACP Extended proxy",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    # Store token for injection into index.html (HTTP only, not UDS)
    app.state.api_token = token

    # Mark if this is a UDS server (CLI uses UDS, browser uses HTTP)
    app.state.is_uds_server = is_uds

    # Store proxy name for per-proxy path resolution
    app.state.proxy_name = proxy_name

    # Security middleware (must be added before CORS)
    # For UDS: skip token/host/origin checks (OS permissions = auth)
    # For HTTP: full validation with token
    # Disabled for standalone dev/testing (no token, not UDS)
    if token or is_uds:
        app.add_middleware(SecurityMiddleware, token=token, is_uds=is_uds)

    # CORS configuration
    # In production, this API runs on localhost only (same-origin with proxy)
    # CORS is disabled by default - only enable for development with separate frontend
    # Set MCP_ACP_CORS_ORIGINS="http://localhost:3000" when running Vite dev server
    cors_origins_env = os.environ.get("MCP_ACP_CORS_ORIGINS", "").strip()
    if cors_origins_env:
        cors_origins = [origin.strip() for origin in cors_origins_env.split(",") if origin.strip()]
        app.add_middleware(
            CORSMiddleware,
            allow_origins=cors_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            allow_headers=["Content-Type", "Authorization"],
            max_age=3600,  # Cache preflight for 1 hour
        )

    # Register exception handlers for structured error responses
    app.add_exception_handler(APIError, api_error_handler)
    app.add_exception_handler(RequestValidationError, validation_error_handler)
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)

    # Mount API routes
    app.include_router(proxies.router, prefix="/api/proxies", tags=["proxies"])
    app.include_router(sessions.router, prefix="/api/auth-sessions", tags=["auth-sessions"])
    app.include_router(approvals.router, prefix="/api/approvals/cached", tags=["cached-approvals"])
    app.include_router(pending.router, prefix="/api/approvals/pending", tags=["pending-approvals"])
    app.include_router(control.router, prefix="/api/control", tags=["control"])
    app.include_router(policy.router, prefix="/api/policy", tags=["policy"])
    app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
    app.include_router(config.router, prefix="/api/config", tags=["config"])
    app.include_router(logs.router, prefix="/api/logs", tags=["logs"])
    app.include_router(incidents.router, prefix="/api/incidents", tags=["incidents"])
    app.include_router(debug.router, prefix="/api/debug", tags=["debug"])
    app.include_router(stats.router, prefix="/api/stats", tags=["stats"])

    # Serve static files (built React app)
    # Note: We use dynamic file serving instead of StaticFiles mount so that
    # rebuilds are picked up without server restart (for development convenience)
    if STATIC_DIR.exists():
        index_file = STATIC_DIR / "index.html"
        if index_file.exists():

            @app.get("/{path:path}", response_model=None)
            async def serve_spa(path: str, request: Request) -> Response:
                """Serve static files or index.html for SPA routing."""
                # Media type mapping for static files
                media_types = {
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

                # Check for static files (root-level or in assets/)
                if path:
                    static_file = STATIC_DIR / path
                    if static_file.exists() and static_file.is_file():
                        suffix = static_file.suffix.lower()
                        media_type = media_types.get(suffix, "application/octet-stream")
                        # Long cache for hashed assets, short cache for root files
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

                # Dev mode only: inject token into HTML for cross-origin auth
                # In production (same-origin), we use HttpOnly cookies instead.
                # Security: Token is validated to be hex-only before injection
                # to prevent XSS. json.dumps provides additional escaping.
                if _is_dev_mode_request(request) and api_token and is_valid_token_format(api_token):
                    token_script = f"<script>window.__API_TOKEN__ = {json.dumps(api_token)};</script>"
                    html = html.replace("</head>", f"{token_script}\n  </head>")

                response = HTMLResponse(
                    content=html,
                    headers={"Cache-Control": "no-cache, no-store, must-revalidate"},
                )

                # Always set HttpOnly cookie for browser authentication
                # Works in production (same-origin), harmless in dev (cross-origin won't send it)
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
