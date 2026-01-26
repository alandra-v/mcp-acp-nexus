"""Auth session API endpoints.

Provides visibility into active authentication sessions.
Auth sessions represent user authentication bindings (JWT token -> session).
These are NOT proxy lifecycle sessions.

Routes mounted at: /api/auth-sessions
"""

from __future__ import annotations

__all__ = ["router"]

from fastapi import APIRouter

from mcp_acp.api.deps import ProxyStateDep
from mcp_acp.api.schemas import AuthSessionResponse

router = APIRouter()


@router.get("", response_model=list[AuthSessionResponse])
async def list_auth_sessions(
    state: ProxyStateDep,
    proxy_id: str | None = None,
) -> list[AuthSessionResponse]:
    """List all active authentication sessions.

    Auth sessions represent user authentication bindings (JWT token -> session).
    These are NOT proxy lifecycle sessions.

    Args:
        state: Proxy state (injected).
        proxy_id: Optional filter by proxy ID (for multi-proxy future).

    Returns:
        List of active auth sessions.
    """

    sessions = state.get_sessions()

    return [
        AuthSessionResponse(
            session_id=s.session_id,
            user_id=s.user_id,
            started_at=s.created_at,
            expires_at=s.expires_at,
        )
        for s in sessions
    ]
