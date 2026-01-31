"""Security middleware and token management for the API.

Implements security controls per docs/design/ui-security.md:
- Host header validation (DNS rebinding protection)
- Origin header validation (CSRF protection)
- Bearer token or HttpOnly cookie authentication (for HTTP browser connections)
- SSE authentication (same-origin with cookie, or query param for dev)
- Security response headers

Token lifecycle:
- Generated on proxy startup (32 bytes, hex encoded)
- Production: Set as HttpOnly cookie (XSS-safe, auto-sent with requests)
- Dev mode: Injected into HTML for cross-origin auth (Vite on :3000)
- CLI uses UDS (Unix Domain Socket) instead - no token needed

Authentication architecture:
- Browser (production): HTTP + HttpOnly cookie (same-origin)
- Browser (dev mode): HTTP + Bearer token (cross-origin to API)
- CLI: UDS + OS file permissions (socket is 0600, owner-only)
"""

from __future__ import annotations

__all__ = [
    "ALLOWED_HOSTS",
    "ALLOWED_ORIGINS",
    "AUTH_BYPASS_ENDPOINTS",
    "MAX_REQUEST_SIZE",
    "VITE_DEV_PORT",
    "SecurityMiddleware",
    "generate_token",
    "is_valid_token_format",
    "validate_token",
]

import hmac
import secrets

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

from mcp_acp.telemetry.system.system_logger import get_system_logger

logger = get_system_logger()

# Security constants
ALLOWED_HOSTS = {"localhost", "127.0.0.1", "[::1]"}

# Vite dev server port - used to detect cross-origin dev mode
VITE_DEV_PORT = "3000"

ALLOWED_ORIGINS = {
    # Production (API served from same origin)
    "http://localhost:8765",
    "http://127.0.0.1:8765",
    # Development (Vite dev server)
    f"http://localhost:{VITE_DEV_PORT}",
    f"http://127.0.0.1:{VITE_DEV_PORT}",
}

# SSE endpoints that allow special auth handling (matched via path.endswith())
# "/events" is loose — also matches forwarded proxy paths like /api/proxy/x/events.
# This is safe since SSE handling only provides *alternative* auth, not a bypass.
SSE_ENDPOINTS = ("/pending", "/stream", "/events")

# Endpoints that bypass auth (dev mode only, protected by endpoint logic)
AUTH_BYPASS_ENDPOINTS = ("/api/auth/dev-token", "/api/manager/auth/dev-token")

# Max request size (1MB)
MAX_REQUEST_SIZE = 1024 * 1024


# =============================================================================
# Token Management
# =============================================================================


def generate_token() -> str:
    """Generate a secure random token.

    Returns:
        64-character hex string (32 bytes of randomness).
    """
    return secrets.token_hex(32)


def is_valid_token_format(token: str) -> bool:
    """Validate token format for safe HTML injection.

    Ensures token only contains hex characters to prevent XSS.
    This is defense-in-depth since json.dumps also escapes,
    but validates at the source.

    Args:
        token: Token to validate.

    Returns:
        True if token is valid hex format, False otherwise.
    """
    if not token or len(token) != 64:
        return False
    return all(c in "0123456789abcdef" for c in token.lower())


def validate_token(provided: str, expected: str) -> bool:
    """Validate token using constant-time comparison.

    Prevents timing attacks by ensuring comparison takes the same
    time regardless of where strings differ.

    Args:
        provided: Token from request.
        expected: Expected token.

    Returns:
        True if tokens match, False otherwise.
    """
    return hmac.compare_digest(provided, expected)


# =============================================================================
# Security Middleware
# =============================================================================


class SecurityMiddleware(BaseHTTPMiddleware):
    """Security middleware implementing all HTTP security controls.

    For HTTP servers:
        1. Request size limit
        2. Host header validation
        3. Origin header validation
        4. Origin required for mutations
        5. Token authentication for /api/* endpoints
        6. Security response headers

    For UDS servers:
        1. Request size limit
        2. Security response headers
        (Skip host/origin/token - OS permissions provide authentication)
    """

    def __init__(self, app: ASGIApp, token: str | None = None, is_uds: bool = False) -> None:
        """Initialize middleware.

        Args:
            app: ASGI application.
            token: Bearer token for authentication (required for HTTP, None for UDS).
            is_uds: If True, this serves UDS connections (OS permissions = auth).
        """
        super().__init__(app)
        self.token = token
        self.is_uds = is_uds

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """Process request through security checks.

        Args:
            request: Incoming request.
            call_next: Next middleware/handler.

        Returns:
            Response (error or from handler).
        """
        # 1. Request size limit (applies to both HTTP and UDS)
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > MAX_REQUEST_SIZE:
                    return JSONResponse(
                        status_code=413,
                        content={"error": "Request too large"},
                    )
            except ValueError:
                return JSONResponse(
                    status_code=400,
                    content={"error": "Invalid content-length header"},
                )

        # UDS connections are pre-authenticated by OS file permissions.
        # Skip host/origin/token validation - just check size and add headers.
        if self.is_uds:
            response = await call_next(request)
            self._add_security_headers(response)
            return response

        # HTTP-specific security checks (2-5)

        # 2. Host header validation (DNS rebinding protection)
        host = request.headers.get("host", "").split(":")[0]
        if host not in ALLOWED_HOSTS:
            logger.warning(
                {
                    "event": "invalid_host_rejected",
                    "message": f"Rejected request with invalid host: {host}",
                    "component": "api_security",
                    "details": {"host": host, "path": str(request.url.path)},
                }
            )
            return JSONResponse(
                status_code=403,
                content={"error": "Invalid host header"},
            )

        # 3. Origin header validation
        origin = request.headers.get("origin")
        if origin and origin not in ALLOWED_ORIGINS:
            logger.warning(
                {
                    "event": "invalid_origin_rejected",
                    "message": f"Rejected request with invalid origin: {origin}",
                    "component": "api_security",
                    "details": {"origin": origin, "path": str(request.url.path)},
                }
            )
            return JSONResponse(
                status_code=403,
                content={"error": "Invalid origin"},
            )

        # 4. Require Origin for mutations (CSRF protection)
        # Exception: CLI requests with valid bearer token don't need Origin
        # (CSRF is a browser vulnerability - CLI tools aren't affected)
        if request.method in ("POST", "PUT", "DELETE"):
            if not origin:
                # Allow if valid bearer token present (CLI access)
                auth_header = request.headers.get("authorization", "")
                if auth_header.startswith("Bearer ") and self.token:
                    token = auth_header[7:]
                    if validate_token(token, self.token):
                        pass  # CLI with valid token - allow without Origin
                    else:
                        return JSONResponse(
                            status_code=401,
                            content={"error": "Invalid token"},
                        )
                else:
                    logger.warning(
                        {
                            "event": "mutation_without_origin_rejected",
                            "message": f"Rejected mutation without origin: {request.method} {request.url.path}",
                            "component": "api_security",
                            "details": {"method": request.method, "path": str(request.url.path)},
                        }
                    )
                    return JSONResponse(
                        status_code=403,
                        content={"error": "Origin header required for mutations"},
                    )

        # 5. Token validation for /api/* endpoints
        # Exception: dev-token endpoint bypasses auth (protected by endpoint logic)
        if request.url.path.startswith("/api/") and request.url.path not in AUTH_BYPASS_ENDPOINTS:
            if not self._check_auth(request):
                logger.warning(
                    {
                        "event": "unauthorized_request_rejected",
                        "message": f"Rejected unauthorized request: {request.method} {request.url.path}",
                        "component": "api_security",
                        "details": {"method": request.method, "path": str(request.url.path)},
                    }
                )
                return JSONResponse(
                    status_code=401,
                    content={"error": "Unauthorized"},
                )

        # 6. Process request
        response = await call_next(request)

        # 7. Add security headers
        self._add_security_headers(response)

        return response

    def _add_security_headers(self, response: Response) -> None:
        """Add security headers to response.

        Args:
            response: Response to add headers to.
        """
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        # CSP: allow Google Fonts and inline styles for UI
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "script-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self'"
        )
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "same-origin"
        # Disable unnecessary browser features
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"

    def _extract_token(self, request: Request) -> str | None:
        """Extract token from Authorization header or HttpOnly cookie.

        Priority:
        1. Authorization header (CLI via HTTP, dev mode browser)
        2. HttpOnly cookie (production browser)

        Args:
            request: Incoming request.

        Returns:
            Token string if found, None otherwise.
        """
        # 1. Try Authorization header
        auth_header: str = request.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            return auth_header[7:]

        # 2. Try HttpOnly cookie (browser production mode)
        cookie_token: str | None = request.cookies.get("api_token")
        if cookie_token:
            return cookie_token

        return None

    def _check_auth(self, request: Request) -> bool:
        """Check if request is authenticated.

        Authentication methods (in order):
        1. Bearer token in Authorization header
        2. HttpOnly cookie (browser production mode)
        3. SSE endpoints: same-origin (no Origin header) is trusted
        4. SSE endpoints: token in query param (dev mode)

        Args:
            request: Incoming request.

        Returns:
            True if authenticated, False otherwise.
        """
        # Check Authorization header or HttpOnly cookie
        token = self._extract_token(request)
        if token and self.token and validate_token(token, self.token):
            return True

        # SSE endpoints have special handling because EventSource API
        # doesn't support custom headers (can't send Authorization).
        # In production, cookies ARE sent with EventSource automatically.
        if request.method == "GET" and self._is_sse_endpoint(request.url.path):
            origin = request.headers.get("origin")

            # Same-origin requests (no Origin header) are trusted.
            # This is secure because:
            # 1. Host header was already validated (DNS rebinding protection)
            # 2. Browsers don't send Origin for same-origin requests
            # 3. Non-browser clients without Origin would need to know the URL
            #    which requires local access (API is localhost-only)
            if not origin:
                # Additional check: if Referer present, validate it
                referer = request.headers.get("referer", "")
                if referer and not self._is_valid_referer(referer):
                    logger.warning(
                        {
                            "event": "invalid_referer_rejected",
                            "message": f"Rejected SSE with invalid referer: {referer}",
                            "component": "api_security",
                            "details": {"referer": referer, "path": str(request.url.path)},
                        }
                    )
                    return False
                return True

            # Cross-origin: accept token in query param (dev mode only)
            # This is for EventSource which can't send custom headers
            query_token = request.query_params.get("token")
            if query_token and self.token and validate_token(query_token, self.token):
                return True

        return False

    def _is_valid_referer(self, referer: str) -> bool:
        """Check if Referer header matches allowed origins.

        Args:
            referer: Referer header value.

        Returns:
            True if referer is valid, False otherwise.
        """
        # Referer includes full URL, extract origin part
        for allowed in ALLOWED_ORIGINS:
            if referer.startswith(allowed):
                return True
        return False

    def _is_sse_endpoint(self, path: str) -> bool:
        """Check if path is an SSE streaming endpoint.

        Args:
            path: URL path.

        Returns:
            True if SSE endpoint, False otherwise.
        """
        return path.endswith(SSE_ENDPOINTS)
