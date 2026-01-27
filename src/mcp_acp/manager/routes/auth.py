"""Auth management endpoints."""

from __future__ import annotations

__all__ = ["router"]

from fastapi import APIRouter, Request

from mcp_acp.exceptions import AuthenticationError
from mcp_acp.manager.config import load_manager_config
from mcp_acp.manager.models import AuthActionResponse, AuthStatusResponse
from mcp_acp.security.auth.jwt_validator import JWTValidator
from mcp_acp.security.auth.token_storage import (
    create_token_storage,
    get_token_storage_info,
)

router = APIRouter(prefix="/api/manager/auth", tags=["auth"])


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
