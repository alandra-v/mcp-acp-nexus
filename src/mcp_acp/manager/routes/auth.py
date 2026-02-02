"""Auth management endpoints."""

from __future__ import annotations

__all__ = ["router"]

import asyncio
import logging
import os
import time
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from mcp_acp.api.schemas.auth import (
    DeviceFlowStartResponse,
    FederatedLogoutResponse,
    LogoutResponse,
)
from mcp_acp.api.security import VITE_DEV_PORT
from mcp_acp.constants import APP_NAME
from mcp_acp.exceptions import AuthenticationError, DeviceFlowError
from mcp_acp.manager.config import load_manager_config
from mcp_acp.manager.models import AuthActionResponse, AuthStatusResponse
from mcp_acp.security.auth.device_flow import (
    DeviceCodeResponse,
    DeviceFlow,
)
from mcp_acp.security.auth.jwt_validator import JWTValidator
from mcp_acp.security.auth.token_storage import (
    create_token_storage,
    get_token_storage_info,
)

if TYPE_CHECKING:
    from mcp_acp.config import OIDCConfig
    from mcp_acp.security.auth.device_flow import PollOnceResult

_logger = logging.getLogger(f"{APP_NAME}.manager.auth")

router = APIRouter(prefix="/api/manager/auth", tags=["auth"])


# =============================================================================
# Dev mode token endpoint
# =============================================================================


class _DevTokenResponse(BaseModel):
    """Response for dev-token endpoint."""

    token: str


def _is_dev_mode() -> bool:
    """Check if running in development mode.

    Dev mode is detected by MCP_ACP_CORS_ORIGINS containing the Vite dev port.

    Returns:
        True if Vite dev port is present in CORS origins.
    """
    cors_origins = os.environ.get("MCP_ACP_CORS_ORIGINS", "")
    return f":{VITE_DEV_PORT}" in cors_origins


@router.get("/dev-token", response_model=_DevTokenResponse)
async def get_dev_token(request: Request) -> _DevTokenResponse:
    """Get API token for development mode.

    Only available when MCP_ACP_CORS_ORIGINS includes the Vite dev port.
    In production, returns 404.

    Used by Vite dev server since it serves its own index.html and cannot
    get the token from the manager's HttpOnly cookie injection.

    Args:
        request: FastAPI request object.

    Returns:
        _DevTokenResponse with the manager's api_token.

    Raises:
        HTTPException: 404 in production, 503 if token unavailable.
    """
    if not _is_dev_mode():
        raise HTTPException(status_code=404, detail="Not found")

    token = getattr(request.app.state, "api_token", None)
    if not token:
        raise HTTPException(status_code=503, detail="Token not available")

    return _DevTokenResponse(token=token)


# =============================================================================
# In-memory device flow state (for background polling)
# =============================================================================


class _DeviceFlowState:
    """Tracks an active device flow with background polling."""

    def __init__(
        self,
        device_code: DeviceCodeResponse,
        oidc_config: "OIDCConfig",
    ) -> None:
        self.device_code = device_code
        self.oidc_config = oidc_config
        self.created_at = time.monotonic()
        self.task: asyncio.Task | None = None  # background poll task


# Device flow state storage (in-memory, keyed by user_code)
_device_flows: dict[str, _DeviceFlowState] = {}
_MAX_DEVICE_FLOWS = 100


def _cleanup_expired_flows() -> None:
    """Remove expired device flows from memory."""
    now = time.monotonic()
    expired = [
        code for code, state in _device_flows.items() if now - state.created_at > state.device_code.expires_in
    ]
    for code in expired:
        st = _device_flows.pop(code, None)
        if st and st.task and not st.task.done():
            st.task.cancel()


def _get_oidc_config() -> "OIDCConfig":
    """Load OIDC config from manager config.

    Raises:
        HTTPException: If OIDC is not configured.
    """
    manager_config = load_manager_config()
    if manager_config.auth is None or manager_config.auth.oidc is None:
        raise HTTPException(
            status_code=400,
            detail="OIDC not configured. Run 'mcp-acp init' first.",
        )
    return manager_config.auth.oidc


def _request_device_code(oidc_config: "OIDCConfig") -> DeviceCodeResponse:
    """Request device code (sync helper for thread pool)."""
    with DeviceFlow(oidc_config) as flow:
        return flow.request_device_code()


def _poll_token_once(state: _DeviceFlowState) -> "PollOnceResult":
    """Poll token endpoint once (sync helper for thread pool).

    Args:
        state: Active device flow state with config and device code.

    Returns:
        PollOnceResult with status and token (if complete).
    """
    with DeviceFlow(state.oidc_config) as flow:
        return flow.poll_once(state.device_code)


@router.post("/reload", response_model=AuthActionResponse)
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


@router.post("/clear", response_model=AuthActionResponse)
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


@router.get("/status", response_model=AuthStatusResponse)
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

    # Common OIDC config fields for all "configured=True" responses
    oidc_fields = {
        "provider": oidc_config.issuer,
        "client_id": oidc_config.client_id,
        "audience": oidc_config.audience,
        "scopes": list(oidc_config.scopes) if oidc_config.scopes else None,
        "storage_backend": storage_info.get("backend"),
    }

    # Check for token
    if not storage.exists():
        return AuthStatusResponse(
            configured=True,
            authenticated=False,
            **oidc_fields,
        )

    # Load token
    try:
        token = storage.load()
    except (AuthenticationError, OSError):
        return AuthStatusResponse(
            configured=True,
            authenticated=False,
            **oidc_fields,
        )

    if token is None or token.is_expired:
        return AuthStatusResponse(
            configured=True,
            authenticated=False,
            **oidc_fields,
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
        token_expires_in_hours=hours_until_expiry,
        has_refresh_token=bool(token.refresh_token),
        **oidc_fields,
    )


# =============================================================================
# Login / Logout endpoints (web UI device flow)
# =============================================================================


async def _poll_device_flow(app: Any, user_code: str) -> None:
    """Background task that polls Auth0 until login completes or fails.

    On success: saves token, reloads token service, broadcasts SSE auth_login.
    On failure: broadcasts SSE auth_login_failed with reason.
    Always cleans up flow state.

    Args:
        app: FastAPI/Starlette application instance (provides app.state).
        user_code: Device flow user code identifying the flow in _device_flows.
    """
    state = _device_flows.get(user_code)
    if state is None:
        return

    interval = state.device_code.interval
    registry = getattr(app.state, "registry", None)
    token_service = getattr(app.state, "token_service", None)

    try:
        while True:
            await asyncio.sleep(interval)

            # Flow may have been cleaned up by another request or expiry
            if user_code not in _device_flows:
                return

            try:
                result = await asyncio.to_thread(_poll_token_once, state)
            except Exception as exc:
                _logger.warning({"event": "device_flow_poll_error", "error": str(exc)})
                if registry:
                    await registry.broadcast_snapshot(
                        "auth_login_failed",
                        {
                            "severity": "error",
                            "reason": "error",
                            "message": f"Login failed: {exc}",
                        },
                    )
                return

            if result.status == "pending":
                continue

            if result.status == "slow_down":
                interval += 5
                continue

            if result.status == "complete":
                # Save token to storage
                storage = create_token_storage(state.oidc_config)
                storage.save(result.token)

                # Reload token service (broadcasts to proxies)
                if token_service is not None:
                    await token_service.reload_from_storage()

                # Broadcast SSE event to web UI
                if registry:
                    await registry.broadcast_snapshot(
                        "auth_login",
                        {
                            "severity": "success",
                            "message": "Logged in",
                        },
                    )
                return

            # Error states: expired, denied, error
            reason = result.status  # "expired", "denied", or "error"
            error_msg = result.error_message or "Login failed"

            _logger.info(
                {
                    "event": "device_flow_completed",
                    "status": reason,
                    "user_code": user_code,
                    "message": error_msg,
                }
            )

            if reason == "expired":
                notify_msg = "Code expired, please try again"
            elif reason == "denied":
                notify_msg = "Authorization denied"
            else:
                notify_msg = error_msg

            if registry:
                await registry.broadcast_snapshot(
                    "auth_login_failed",
                    {
                        "severity": "error",
                        "reason": reason,
                        "message": notify_msg,
                    },
                )
            return

    except asyncio.CancelledError:
        return
    finally:
        _device_flows.pop(user_code, None)


@router.post("/login", response_model=DeviceFlowStartResponse)
async def start_login(request: Request) -> DeviceFlowStartResponse:
    """Start device flow authentication.

    Initiates OAuth device authorization flow and spawns a background
    task to poll Auth0. The browser is notified via SSE when login
    completes or fails — no poll endpoint needed.

    Returns verification URL and code for user to complete in browser.
    """
    oidc_config = _get_oidc_config()

    # Cleanup expired flows
    _cleanup_expired_flows()

    # Prevent memory exhaustion
    if len(_device_flows) >= _MAX_DEVICE_FLOWS:
        raise HTTPException(
            status_code=503,
            detail="Too many concurrent login attempts. Please try again later.",
        )

    # Start device flow (sync HTTP call, run in thread pool)
    try:
        device_code = await asyncio.to_thread(_request_device_code, oidc_config)
    except DeviceFlowError as e:
        raise HTTPException(status_code=502, detail=str(e))

    # Store flow state
    flow_state = _DeviceFlowState(device_code, oidc_config)
    _device_flows[device_code.user_code] = flow_state

    # Spawn background polling task
    task = asyncio.create_task(_poll_device_flow(request.app, device_code.user_code))
    flow_state.task = task

    return DeviceFlowStartResponse(
        user_code=device_code.user_code,
        verification_uri=device_code.verification_uri,
        verification_uri_complete=device_code.verification_uri_complete,
        expires_in=device_code.expires_in,
        interval=device_code.interval,
        poll_endpoint="",  # Not used — SSE replaces polling
    )


@router.post("/logout", response_model=LogoutResponse)
async def logout(request: Request) -> LogoutResponse:
    """Clear local authentication tokens.

    Removes tokens from storage and notifies connected proxies.
    """
    oidc_config = _get_oidc_config()
    storage = create_token_storage(oidc_config)

    if not storage.exists():
        return LogoutResponse(
            status="not_authenticated",
            message="No stored credentials found.",
        )

    try:
        storage.delete()
    except AuthenticationError as e:
        raise HTTPException(status_code=500, detail=str(e))

    # Clear token service (broadcasts to proxies)
    ts = request.app.state.token_service
    if ts is not None:
        await ts.clear_token()

    # Broadcast SSE event
    registry = getattr(request.app.state, "registry", None)
    if registry:
        await registry.broadcast_snapshot(
            "auth_logout",
            {"severity": "success", "message": "Logged out"},
        )

    return LogoutResponse(
        status="logged_out",
        message="Logged out successfully.",
    )


@router.post("/logout-federated", response_model=FederatedLogoutResponse)
async def logout_federated(request: Request) -> FederatedLogoutResponse:
    """Clear local credentials and return Auth0 federated logout URL.

    Clears tokens (best effort) and returns URL for browser to
    complete federated logout from the identity provider.
    """
    oidc_config = _get_oidc_config()

    # Clear local credentials (best effort)
    try:
        storage = create_token_storage(oidc_config)
        if storage.exists():
            storage.delete()
    except (AuthenticationError, OSError) as e:
        _logger.warning({"event": "federated_logout_storage_error", "error": str(e)})

    # Clear token service (broadcasts to proxies)
    ts = request.app.state.token_service
    if ts is not None:
        try:
            await ts.clear_token()
        except Exception as e:
            _logger.warning({"event": "federated_logout_token_clear_error", "error": str(e)})

    # Broadcast SSE event
    registry = getattr(request.app.state, "registry", None)
    if registry:
        await registry.broadcast_snapshot(
            "auth_logout",
            {"severity": "success", "message": "Logged out"},
        )

    # Build Auth0 logout URL
    issuer = oidc_config.issuer.rstrip("/")
    logout_url = f"{issuer}/v2/logout?client_id={oidc_config.client_id}"

    return FederatedLogoutResponse(
        status="logged_out",
        logout_url=logout_url,
        message="Local credentials cleared. Open logout_url in browser to complete federated logout.",
    )
