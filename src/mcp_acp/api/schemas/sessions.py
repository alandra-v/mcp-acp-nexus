"""Auth session API schemas."""

from __future__ import annotations

__all__ = [
    "AuthSessionResponse",
]

from datetime import datetime

from pydantic import BaseModel


class AuthSessionResponse(BaseModel):
    """Response model for authentication session information.

    Auth sessions represent user authentication bindings (JWT token -> session).
    These are NOT proxy lifecycle sessions.
    """

    session_id: str
    user_id: str
    started_at: datetime
    expires_at: datetime
