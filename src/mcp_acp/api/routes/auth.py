"""Authentication API endpoints.

Provides authentication management with full CLI parity:
- GET /api/auth/status - Check auth status and get user info
- POST /api/auth/login - Start device flow authentication
- GET /api/auth/login/poll - Poll for device flow completion
- POST /api/auth/logout - Local logout (clear keychain)
- POST /api/auth/logout-federated - Federated logout (Auth0)
- GET /api/auth/dev-token - Get API token (dev mode only)

Routes mounted at: /api/auth
"""

from __future__ import annotations

__all__ = ["router"]

import asyncio
import os
import time
from typing import TYPE_CHECKING, Literal, cast

from fastapi import APIRouter, Query, Request
from pydantic import BaseModel

from mcp_acp.api.deps import OIDCConfigDep
from mcp_acp.api.errors import APIError, ErrorCode
from mcp_acp.api.schemas import (
    AuthStatusResponse,
    DeviceFlowPollResponse,
    DeviceFlowStartResponse,
    FederatedLogoutResponse,
    LogoutResponse,
    NotifyResponse,
)
from mcp_acp.api.security import VITE_DEV_PORT
from mcp_acp.exceptions import AuthenticationError
from mcp_acp.security.auth.device_flow import (
    DeviceCodeResponse,
    DeviceFlow,
    DeviceFlowError,
)
from mcp_acp.security.auth.token_storage import (
    create_token_storage,
    get_token_storage_info,
)

if TYPE_CHECKING:
    from mcp_acp.config import OIDCConfig
    from mcp_acp.pips.auth.oidc_provider import OIDCIdentityProvider
    from mcp_acp.security.auth.device_flow import PollOnceResult

router = APIRouter()


# =============================================================================
# Dev mode token endpoint
# =============================================================================


class DevTokenResponse(BaseModel):
    """Response for dev-token endpoint."""

    token: str


def _is_dev_mode() -> bool:
    """Check if running in development mode.

    Dev mode is detected by MCP_ACP_CORS_ORIGINS containing the Vite dev port.
    """
    cors_origins = os.environ.get("MCP_ACP_CORS_ORIGINS", "")
    return f":{VITE_DEV_PORT}" in cors_origins


@router.get("/dev-token")
async def get_dev_token(request: Request) -> DevTokenResponse:
    """Get API token for development mode.

    This endpoint is ONLY available in dev mode (when MCP_ACP_CORS_ORIGINS
    includes the Vite dev port). In production, returns 404.

    Used by Vite dev server since it serves its own index.html and can't
    get the token from the API server's token injection.

    Security: This endpoint is protected by the same localhost-only
    restrictions as all other endpoints. The token is only exposed
    to local development tools.
    """
    if not _is_dev_mode():
        raise APIError(
            status_code=404,
            code=ErrorCode.INTERNAL_ERROR,
            message="Not found",
        )

    token = getattr(request.app.state, "api_token", None)
    if not token:
        raise APIError(
            status_code=503,
            code=ErrorCode.SERVICE_UNAVAILABLE,
            message="Token not available",
        )

    return DevTokenResponse(token=token)


# =============================================================================
# In-memory device flow state
# =============================================================================


class _DeviceFlowState:
    """Tracks an active device flow."""

    def __init__(self, device_code: DeviceCodeResponse, oidc_config: "OIDCConfig") -> None:
        self.device_code = device_code
        self.oidc_config = oidc_config
        self.created_at = time.monotonic()
        self.completed = False
        self.error: str | None = None
        self.error_type: str | None = None


# Device flow state storage (in-memory, keyed by user_code)
# Cleaned up on completion, expiry, or error
# Max 100 concurrent flows to prevent memory exhaustion
_device_flows: dict[str, _DeviceFlowState] = {}
_MAX_DEVICE_FLOWS = 100


# =============================================================================
# Helpers
# =============================================================================


def _cleanup_expired_flows() -> None:
    """Remove expired device flows from memory."""
    now = time.monotonic()
    expired = [
        code for code, state in _device_flows.items() if now - state.created_at > state.device_code.expires_in
    ]
    for code in expired:
        del _device_flows[code]


# =============================================================================
# Endpoints
# =============================================================================


def _get_provider_name(issuer: str) -> str:
    """Extract provider name from OIDC issuer URL."""
    # Extract domain from issuer URL (e.g., "https://foo.auth0.com" -> "Auth0")
    try:
        from urllib.parse import urlparse

        domain = urlparse(issuer).netloc
        if "auth0.com" in domain:
            return "Auth0"
        return domain
    except Exception:
        return issuer


def _unauthenticated_response(oidc_config: "OIDCConfig") -> AuthStatusResponse:
    """Build standard unauthenticated response with storage info."""
    storage_info = get_token_storage_info()
    return AuthStatusResponse(
        authenticated=False,
        storage_backend=storage_info.get("backend"),
        provider=_get_provider_name(oidc_config.issuer),
    )


def _get_identity_provider_optional(request: Request) -> "OIDCIdentityProvider | None":
    """Get identity provider from app state, or None if not available."""
    provider = getattr(request.app.state, "identity_provider", None)
    return cast("OIDCIdentityProvider | None", provider)


def _require_identity_provider(request: Request) -> "OIDCIdentityProvider":
    """Get identity provider from app state, raising 503 if unavailable."""
    provider = _get_identity_provider_optional(request)
    if provider is None:
        raise APIError(
            status_code=503,
            code=ErrorCode.AUTH_PROVIDER_UNAVAILABLE,
            message="Identity provider not available",
        )
    return provider


def _clear_credentials(
    request: Request,
    oidc_config: "OIDCConfig",
    *,
    best_effort: bool = False,
) -> None:
    """Clear credentials via provider or directly from storage.

    Args:
        request: FastAPI request object.
        oidc_config: OIDC configuration.
        best_effort: If True, suppress exceptions. If False, raise on error.
    """
    provider = _get_identity_provider_optional(request)

    # Try provider logout first (clears memory + storage + emits SSE)
    if provider is not None and hasattr(provider, "logout"):
        try:
            provider.logout()
            return
        except Exception:
            if not best_effort:
                raise

    # Fall back to direct storage deletion
    storage = create_token_storage(oidc_config)
    if storage.exists():
        try:
            storage.delete()
        except Exception:
            if not best_effort:
                raise


@router.get("/status")
async def get_auth_status(request: Request, oidc_config: OIDCConfigDep) -> AuthStatusResponse:
    """Get authentication status and user info.

    Returns current auth state including:
    - Whether user is authenticated
    - User info (subject_id, email, name) if authenticated
    - Token expiry and refresh token status
    - Storage backend info

    Works in two modes:
    1. Full proxy mode: uses identity provider from app.state
    2. Standalone/API mode: reads directly from token storage (keychain)
    """
    storage_info = get_token_storage_info()

    # Try identity provider first (if running in full proxy mode)
    provider = _get_identity_provider_optional(request)
    if provider is not None and provider.is_authenticated:
        try:
            identity = await provider.get_identity()
            token = provider._current_token

            expires_in_hours = None
            has_refresh = None
            email = identity.subject_claims.get("email")
            name = identity.subject_claims.get("name")

            if token:
                expires_in_hours = token.seconds_until_expiry / 3600
                has_refresh = bool(token.refresh_token)

                # If email/name not in access token claims, try ID token
                if (not email or not name) and token.id_token:
                    try:
                        from mcp_acp.security.auth.jwt_validator import JWTValidator

                        validator = JWTValidator(oidc_config)
                        id_claims = validator.decode_without_validation(token.id_token)
                        if not email:
                            email = id_claims.get("email")
                        if not name:
                            name = id_claims.get("name")
                    except (ValueError, KeyError):
                        pass  # Can't decode ID token - not critical

            return AuthStatusResponse(
                authenticated=True,
                subject_id=identity.subject_id,
                email=email,
                name=name,
                token_expires_in_hours=expires_in_hours,
                has_refresh_token=has_refresh,
                storage_backend=storage_info.get("backend"),
                provider=_get_provider_name(oidc_config.issuer),
            )
        except AuthenticationError:
            pass  # Fall through to token storage check

    # Fall back to reading directly from token storage (like CLI does)
    storage = create_token_storage(oidc_config)
    provider_name = _get_provider_name(oidc_config.issuer)

    if not storage.exists():
        return AuthStatusResponse(
            authenticated=False,
            storage_backend=storage_info.get("backend"),
            provider=provider_name,
        )

    try:
        token = storage.load()
    except AuthenticationError:
        return AuthStatusResponse(
            authenticated=False,
            storage_backend=storage_info.get("backend"),
            provider=provider_name,
        )

    if token is None or token.is_expired:
        return AuthStatusResponse(
            authenticated=False,
            storage_backend=storage_info.get("backend"),
            provider=provider_name,
        )

    # Token is valid - extract user info from ID token
    email = None
    name = None
    subject_id = None

    if token.id_token:
        try:
            from mcp_acp.security.auth.jwt_validator import JWTValidator

            validator = JWTValidator(oidc_config)
            claims = validator.decode_without_validation(token.id_token)

            email = claims.get("email")
            name = claims.get("name")
            subject_id = claims.get("sub")
        except (ValueError, KeyError):
            pass  # Can't decode ID token - not critical

    return AuthStatusResponse(
        authenticated=True,
        subject_id=subject_id,
        email=email,
        name=name,
        token_expires_in_hours=token.seconds_until_expiry / 3600,
        has_refresh_token=bool(token.refresh_token),
        storage_backend=storage_info.get("backend"),
        provider=provider_name,
    )


@router.post("/login")
async def start_login(oidc_config: OIDCConfigDep) -> DeviceFlowStartResponse:
    """Start device flow authentication.

    Initiates OAuth device authorization flow:
    1. Returns user_code and verification_uri
    2. User opens URL and enters code in browser
    3. Poll /api/auth/login/poll?code={user_code} for completion

    Returns verification URL and code for user to complete in browser.
    """
    # Cleanup expired flows
    _cleanup_expired_flows()

    # Prevent memory exhaustion from too many concurrent flows
    if len(_device_flows) >= _MAX_DEVICE_FLOWS:
        raise APIError(
            status_code=503,
            code=ErrorCode.AUTH_DEVICE_FLOW_LIMIT,
            message="Too many concurrent login attempts. Please try again later.",
            details={"max_flows": _MAX_DEVICE_FLOWS},
        )

    # Start device flow (synchronous HTTP call, run in thread pool)
    try:
        device_code = await asyncio.to_thread(_request_device_code, oidc_config)
    except DeviceFlowError as e:
        raise APIError(
            status_code=502,
            code=ErrorCode.AUTH_DEVICE_FLOW_FAILED,
            message=str(e),
        )

    # Store flow state for polling
    _device_flows[device_code.user_code] = _DeviceFlowState(device_code, oidc_config)

    return DeviceFlowStartResponse(
        user_code=device_code.user_code,
        verification_uri=device_code.verification_uri,
        verification_uri_complete=device_code.verification_uri_complete,
        expires_in=device_code.expires_in,
        interval=device_code.interval,
        poll_endpoint=f"/api/auth/login/poll?code={device_code.user_code}",
    )


def _request_device_code(oidc_config: "OIDCConfig") -> DeviceCodeResponse:
    """Request device code (sync helper for thread pool)."""
    with DeviceFlow(oidc_config) as flow:
        return flow.request_device_code()


@router.get("/login/poll")
async def poll_login(
    request: Request,
    code: str = Query(..., description="The user_code from /login"),
) -> DeviceFlowPollResponse:
    """Poll for device flow completion.

    Call repeatedly (respecting interval from /login response) until
    status is 'complete', 'expired', 'denied', or 'error'.

    On 'complete', tokens are automatically stored in keychain and
    the running proxy is notified to reload tokens.
    """
    # Cleanup expired flows
    _cleanup_expired_flows()

    # Find flow state
    state = _device_flows.get(code)
    if state is None:
        return DeviceFlowPollResponse(
            status="expired",
            message="Device flow not found or expired. Start a new login.",
        )

    if state.completed:
        return DeviceFlowPollResponse(
            status="complete",
            message="Authentication successful. Tokens stored.",
        )

    if state.error:
        return DeviceFlowPollResponse(
            status=cast(Literal["expired", "denied", "error"], state.error_type or "error"),
            message=state.error,
        )

    # Poll token endpoint (single poll, not blocking loop)
    result = await asyncio.to_thread(_poll_token_once, state)

    if result.status == "pending":
        return DeviceFlowPollResponse(
            status="pending",
            message="Waiting for user to complete authentication...",
        )

    if result.status == "complete":
        # Success - store token and cleanup
        storage = create_token_storage(state.oidc_config)
        storage.save(result.token)

        state.completed = True
        del _device_flows[code]

        # Notify proxy to reload tokens (emits SSE event to UI)
        provider = _get_identity_provider_optional(request)
        if provider is not None and hasattr(provider, "reload_token_from_storage"):
            provider.reload_token_from_storage()

        return DeviceFlowPollResponse(
            status="complete",
            message="Authentication successful. Tokens stored in keychain.",
        )

    # Error states (expired, denied, error)
    state.error = result.error_message
    state.error_type = result.status
    del _device_flows[code]
    return DeviceFlowPollResponse(
        status=cast(Literal["expired", "denied", "error"], result.status),
        message=result.error_message,
    )


def _poll_token_once(state: _DeviceFlowState) -> "PollOnceResult":
    """Poll token endpoint once (sync helper for thread pool).

    Uses DeviceFlow.poll_once to avoid code duplication.

    Args:
        state: Device flow state with config and device code.

    Returns:
        PollOnceResult with status and token (if complete).
    """
    with DeviceFlow(state.oidc_config) as flow:
        return flow.poll_once(state.device_code)


@router.post("/notify-login")
async def notify_login(request: Request) -> NotifyResponse:
    """Notify running proxy that CLI completed login.

    Called by CLI after storing tokens in keychain.
    Triggers proxy to reload tokens and emit SSE event to UI.
    """
    provider = _require_identity_provider(request)

    if not hasattr(provider, "reload_token_from_storage"):
        raise APIError(
            status_code=501,
            code=ErrorCode.NOT_IMPLEMENTED,
            message="Identity provider does not support token reload",
            details={"feature": "reload_token_from_storage"},
        )

    success = provider.reload_token_from_storage()
    if success:
        return NotifyResponse(
            status="ok",
            message="Proxy notified of login",
        )
    else:
        return NotifyResponse(
            status="no_token",
            message="No token found in storage",
        )


@router.post("/notify-logout")
async def notify_logout(request: Request) -> NotifyResponse:
    """Notify running proxy of logout.

    Called by CLI before clearing tokens from keychain.
    Triggers proxy to clear in-memory token and emit SSE event to UI.
    """
    provider = _require_identity_provider(request)

    if not hasattr(provider, "logout"):
        raise APIError(
            status_code=501,
            code=ErrorCode.NOT_IMPLEMENTED,
            message="Identity provider does not support logout",
            details={"feature": "logout"},
        )

    # Clear proxy's in-memory token (emits SSE event)
    provider.logout()

    return NotifyResponse(
        status="ok",
        message="Proxy notified of logout",
    )


@router.post("/logout")
async def logout(request: Request, oidc_config: OIDCConfigDep) -> LogoutResponse:
    """Clear local authentication tokens from keychain.

    Removes tokens from OS keychain and notifies running proxy.
    You will need to run login again to use authenticated features.
    """
    # Check if credentials exist first
    storage = create_token_storage(oidc_config)
    if not storage.exists():
        return LogoutResponse(
            status="not_authenticated",
            message="No stored credentials found.",
        )

    # Clear credentials (raises on error)
    try:
        _clear_credentials(request, oidc_config, best_effort=False)
    except Exception as e:
        raise APIError(
            status_code=500,
            code=ErrorCode.INTERNAL_ERROR,
            message=f"Failed to clear credentials: {e}",
        )

    return LogoutResponse(
        status="logged_out",
        message="Logged out successfully.",
    )


@router.post("/logout-federated")
async def logout_federated(request: Request, oidc_config: OIDCConfigDep) -> FederatedLogoutResponse:
    """Get federated logout URL (Auth0) and clear local credentials.

    Returns URL for browser to complete federated logout.
    Also clears local credentials from keychain and notifies proxy.

    Open the returned logout_url in a browser to complete
    the logout from the identity provider (Auth0).
    """
    # Clear local credentials (best effort - continue even on error)
    _clear_credentials(request, oidc_config, best_effort=True)

    # Build Auth0 logout URL
    issuer = oidc_config.issuer.rstrip("/")
    logout_url = f"{issuer}/v2/logout?client_id={oidc_config.client_id}"

    return FederatedLogoutResponse(
        status="logged_out",
        logout_url=logout_url,
        message="Local credentials cleared. Open logout_url in browser to complete federated logout.",
    )
