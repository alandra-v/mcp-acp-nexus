"""Session management with user binding per MCP spec.

MCP Security Requirements:
- Sessions MUST NOT be used for authentication (token validation on every request)
- Sessions SHOULD be bound to user ID from validated token
- Session IDs MUST be cryptographically secure and non-deterministic

Session Format: <user_id>:<session_id>
This prevents session hijacking across users - even if an attacker obtains
a session ID, they cannot use it without authenticating as that user.

See docs/design/mcp_security_best_practices.md for full specification.
"""

from __future__ import annotations

__all__ = [
    "BoundSession",
    "SessionManager",
    "parse_bound_session_id",
]

import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcp_acp.security.auth.jwt_validator import ValidatedToken
    from mcp_acp.telemetry.models.audit import SubjectIdentity


@dataclass(frozen=True)
class BoundSession:
    """Session bound to authenticated user.

    Attributes:
        user_id: Subject ID from validated JWT (e.g., "auth0|123").
        session_id: Cryptographically secure random identifier.
        created_at: Session creation timestamp (UTC).
        expires_at: Session expiration timestamp (UTC).
    """

    user_id: str
    session_id: str
    created_at: datetime
    expires_at: datetime

    @property
    def bound_id(self) -> str:
        """Return the bound session ID format per MCP spec.

        Format: <user_id>:<session_id>

        This format ensures sessions cannot be used across users.
        Even if an attacker obtains the session_id, they cannot
        construct a valid bound_id without knowing the user_id.
        """
        return f"{self.user_id}:{self.session_id}"

    def is_expired(self) -> bool:
        """Check if session has expired."""
        return datetime.now(timezone.utc) > self.expires_at


class SessionManager:
    """Manage sessions bound to authenticated users.

    Per MCP spec:
    - Sessions MUST NOT be used for authentication (token validation on every request)
    - Sessions SHOULD be bound to user ID from validated token
    - Session IDs MUST be cryptographically secure and non-deterministic

    Usage:
        manager = SessionManager()

        # Create session from validated token
        session = manager.create_session_from_token(validated_token)

        # Or create from identity
        session = manager.create_session(identity)

        # Validate session belongs to user
        is_valid = manager.validate_session(bound_id, validated_token)
    """

    # Session lifetime (shorter than token lifetime for security)
    DEFAULT_TTL = timedelta(hours=8)

    # Session ID entropy (256 bits via secrets.token_urlsafe)
    SESSION_ID_BYTES = 32

    def __init__(self, ttl: timedelta = DEFAULT_TTL) -> None:
        """Initialize session manager.

        Args:
            ttl: Session time-to-live. Default 8 hours.
        """
        self._ttl = ttl
        self._sessions: dict[str, BoundSession] = {}

    def create_session_from_token(self, validated_token: "ValidatedToken") -> BoundSession:
        """Create a new session bound to the authenticated user from a validated token.

        CRITICAL: User ID comes from the validated token, never from client input.
        This prevents session hijacking across users.

        Args:
            validated_token: JWT that has been validated (signature, expiry, audience).

        Returns:
            BoundSession with cryptographically secure ID bound to user.
        """
        # User ID from token (not client-provided)
        user_id = validated_token.subject_id

        return self._create_bound_session(user_id)

    def create_session(self, identity: "SubjectIdentity") -> BoundSession:
        """Create a new session bound to the user identity.

        Use this when you have a SubjectIdentity rather than a ValidatedToken.
        The identity must come from a validated source (not client input).

        Args:
            identity: Validated user identity.

        Returns:
            BoundSession with cryptographically secure ID bound to user.
        """
        return self._create_bound_session(identity.subject_id)

    def _create_bound_session(self, user_id: str) -> BoundSession:
        """Internal helper to create a bound session for a user ID.

        Args:
            user_id: Validated user identifier.

        Returns:
            BoundSession instance.
        """
        # Cryptographically secure session ID (256 bits)
        session_id = secrets.token_urlsafe(self.SESSION_ID_BYTES)

        now = datetime.now(timezone.utc)
        session = BoundSession(
            user_id=user_id,
            session_id=session_id,
            created_at=now,
            expires_at=now + self._ttl,
        )

        # Store by bound_id for lookup
        self._sessions[session.bound_id] = session

        return session

    def validate_session_with_token(self, bound_id: str, validated_token: "ValidatedToken") -> bool:
        """Validate session belongs to the current authenticated user.

        Per MCP spec: "MCP Servers MUST NOT use sessions for authentication."
        This means we ALWAYS validate the bearer token first, then check
        the session matches.

        Args:
            bound_id: Session ID in format <user_id>:<session_id>.
            validated_token: Already-validated JWT token.

        Returns:
            True if session is valid and belongs to token's user.
        """
        return self._validate_session(bound_id, validated_token.subject_id)

    def validate_session(self, bound_id: str, identity: "SubjectIdentity") -> bool:
        """Validate session belongs to the identity.

        Args:
            bound_id: Session ID in format <user_id>:<session_id>.
            identity: Validated user identity.

        Returns:
            True if session is valid and belongs to identity's user.
        """
        return self._validate_session(bound_id, identity.subject_id)

    def _validate_session(self, bound_id: str, user_id: str) -> bool:
        """Internal helper to validate a session.

        Args:
            bound_id: Session ID in format <user_id>:<session_id>.
            user_id: Validated user identifier.

        Returns:
            True if session is valid and belongs to user.
        """
        session = self._sessions.get(bound_id)
        if session is None:
            return False

        if session.is_expired():
            del self._sessions[bound_id]
            return False

        # Verify session belongs to this user (token/identity is source of truth)
        return session.user_id == user_id

    def get_session(self, bound_id: str) -> BoundSession | None:
        """Get a session by bound ID.

        Args:
            bound_id: Session ID in format <user_id>:<session_id>.

        Returns:
            BoundSession if found and not expired, None otherwise.
        """
        session = self._sessions.get(bound_id)
        if session is None:
            return None

        if session.is_expired():
            del self._sessions[bound_id]
            return None

        return session

    def invalidate_session(self, bound_id: str) -> None:
        """Invalidate a session (logout, expiry, etc.)."""
        self._sessions.pop(bound_id, None)

    def cleanup_expired(self) -> int:
        """Remove expired sessions. Returns count of removed sessions."""
        expired = [bound_id for bound_id, session in self._sessions.items() if session.is_expired()]
        for bound_id in expired:
            del self._sessions[bound_id]
        return len(expired)

    @property
    def active_session_count(self) -> int:
        """Return count of active (non-expired) sessions."""
        # Clean up expired first
        self.cleanup_expired()
        return len(self._sessions)

    def get_all_sessions(self) -> list[BoundSession]:
        """Get all active (non-expired) sessions.

        Returns:
            List of active BoundSession objects.
        """
        self.cleanup_expired()
        return list(self._sessions.values())


def parse_bound_session_id(bound_id: str) -> tuple[str, str] | None:
    """Parse a bound session ID into user_id and session_id.

    Args:
        bound_id: Session ID in format <user_id>:<session_id>.

    Returns:
        Tuple of (user_id, session_id) or None if invalid format.
    """
    if ":" not in bound_id:
        return None

    # Split on first colon only (user_id may contain colons)
    user_id, session_id = bound_id.split(":", 1)
    if not user_id or not session_id:
        return None

    return (user_id, session_id)
