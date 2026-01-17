"""Tests for session binding per MCP security spec."""

from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

import pytest

from mcp_acp.pips.auth.session import (
    BoundSession,
    SessionManager,
    parse_bound_session_id,
)
from mcp_acp.telemetry.models.audit import SubjectIdentity


class TestBoundSession:
    """Tests for BoundSession dataclass."""

    def test_bound_id_format(self):
        """Bound ID follows <user_id>:<session_id> format."""
        session = BoundSession(
            user_id="auth0|123",
            session_id="abc123",
            created_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=8),
        )
        assert session.bound_id == "auth0|123:abc123"

    def test_bound_id_with_special_characters(self):
        """Bound ID handles special characters in user_id."""
        session = BoundSession(
            user_id="google-oauth2|12345@gmail.com",
            session_id="xyz789",
            created_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=8),
        )
        assert session.bound_id == "google-oauth2|12345@gmail.com:xyz789"

    def test_is_expired_returns_false_for_valid_session(self):
        """Session with future expiry is not expired."""
        session = BoundSession(
            user_id="user1",
            session_id="sess1",
            created_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        assert session.is_expired() is False

    def test_is_expired_returns_true_for_expired_session(self):
        """Session with past expiry is expired."""
        session = BoundSession(
            user_id="user1",
            session_id="sess1",
            created_at=datetime.now(timezone.utc) - timedelta(hours=10),
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
        )
        assert session.is_expired() is True


class TestSessionManager:
    """Tests for SessionManager."""

    @pytest.fixture
    def manager(self):
        """Create a session manager with default TTL."""
        return SessionManager()

    @pytest.fixture
    def identity(self):
        """Create a test identity."""
        return SubjectIdentity(
            subject_id="auth0|testuser",
            subject_claims={"auth_type": "oidc"},
        )

    def test_create_session_returns_bound_session(self, manager, identity):
        """Create session returns a BoundSession with correct user_id."""
        session = manager.create_session(identity)
        assert isinstance(session, BoundSession)
        assert session.user_id == "auth0|testuser"
        assert session.session_id  # Not empty
        assert ":" in session.bound_id

    def test_create_session_generates_unique_ids(self, manager, identity):
        """Each session gets a unique session_id."""
        session1 = manager.create_session(identity)
        session2 = manager.create_session(identity)
        assert session1.session_id != session2.session_id
        assert session1.bound_id != session2.bound_id

    def test_create_session_sets_expiry(self, manager, identity):
        """Session expiry is set based on TTL."""
        session = manager.create_session(identity)
        expected_expiry = session.created_at + timedelta(hours=8)
        # Allow 1 second tolerance
        assert abs((session.expires_at - expected_expiry).total_seconds()) < 1

    def test_validate_session_returns_true_for_valid_session(self, manager, identity):
        """Valid session belonging to identity returns True."""
        session = manager.create_session(identity)
        assert manager.validate_session(session.bound_id, identity) is True

    def test_validate_session_returns_false_for_nonexistent_session(self, manager, identity):
        """Nonexistent session returns False."""
        assert manager.validate_session("fake:session", identity) is False

    def test_validate_session_returns_false_for_wrong_user(self, manager, identity):
        """Session belonging to different user returns False."""
        session = manager.create_session(identity)
        other_identity = SubjectIdentity(
            subject_id="auth0|other_user",
            subject_claims={"auth_type": "oidc"},
        )
        # Session exists but belongs to different user
        assert manager.validate_session(session.bound_id, other_identity) is False

    def test_validate_session_removes_expired_session(self, manager, identity):
        """Expired session is removed during validation."""
        # Create manager with very short TTL
        short_ttl_manager = SessionManager(ttl=timedelta(seconds=-1))  # Already expired
        session = short_ttl_manager.create_session(identity)

        # Session should be expired and removed
        assert short_ttl_manager.validate_session(session.bound_id, identity) is False
        assert short_ttl_manager.get_session(session.bound_id) is None

    def test_get_session_returns_session_if_exists(self, manager, identity):
        """Get session returns the session if it exists."""
        session = manager.create_session(identity)
        retrieved = manager.get_session(session.bound_id)
        assert retrieved == session

    def test_get_session_returns_none_if_not_exists(self, manager):
        """Get session returns None for nonexistent session."""
        assert manager.get_session("fake:session") is None

    def test_invalidate_session_removes_session(self, manager, identity):
        """Invalidate session removes it from manager."""
        session = manager.create_session(identity)
        manager.invalidate_session(session.bound_id)
        assert manager.get_session(session.bound_id) is None

    def test_invalidate_nonexistent_session_is_noop(self, manager):
        """Invalidating nonexistent session doesn't raise."""
        manager.invalidate_session("fake:session")  # Should not raise

    def test_cleanup_expired_removes_expired_sessions(self, manager, identity):
        """Cleanup removes expired sessions."""
        # Create manager with very short TTL
        short_ttl_manager = SessionManager(ttl=timedelta(seconds=-1))
        session = short_ttl_manager.create_session(identity)

        # Should have 1 session
        assert session.bound_id in short_ttl_manager._sessions

        # Cleanup should remove the expired session
        count = short_ttl_manager.cleanup_expired()
        assert count == 1
        assert session.bound_id not in short_ttl_manager._sessions

    def test_active_session_count(self, manager, identity):
        """Active session count returns correct count."""
        assert manager.active_session_count == 0
        manager.create_session(identity)
        assert manager.active_session_count == 1
        manager.create_session(identity)
        assert manager.active_session_count == 2


class TestSessionManagerWithToken:
    """Tests for SessionManager with ValidatedToken."""

    @pytest.fixture
    def manager(self):
        """Create a session manager."""
        return SessionManager()

    @pytest.fixture
    def mock_token(self):
        """Create a mock ValidatedToken."""
        token = Mock()
        token.subject_id = "auth0|tokenuser"
        return token

    def test_create_session_from_token(self, manager, mock_token):
        """Create session from validated token uses token's subject_id."""
        session = manager.create_session_from_token(mock_token)
        assert session.user_id == "auth0|tokenuser"

    def test_validate_session_with_token(self, manager, mock_token):
        """Validate session with token checks against token's user."""
        session = manager.create_session_from_token(mock_token)
        assert manager.validate_session_with_token(session.bound_id, mock_token) is True

    def test_validate_session_with_different_token(self, manager, mock_token):
        """Validate fails when token is from different user."""
        session = manager.create_session_from_token(mock_token)

        other_token = Mock()
        other_token.subject_id = "auth0|other_user"

        assert manager.validate_session_with_token(session.bound_id, other_token) is False


class TestParseBoundSessionId:
    """Tests for parse_bound_session_id helper."""

    def test_parses_valid_bound_id(self):
        """Parse valid bound ID returns tuple."""
        result = parse_bound_session_id("auth0|123:abc456")
        assert result == ("auth0|123", "abc456")

    def test_handles_user_id_with_colons(self):
        """Parse handles user_id containing colons (splits on first only)."""
        result = parse_bound_session_id("urn:user:123:abc456")
        assert result == ("urn", "user:123:abc456")

    def test_returns_none_for_invalid_format(self):
        """Parse returns None for ID without colon."""
        assert parse_bound_session_id("no_colon_here") is None

    def test_returns_none_for_empty_user_id(self):
        """Parse returns None for empty user_id."""
        assert parse_bound_session_id(":session123") is None

    def test_returns_none_for_empty_session_id(self):
        """Parse returns None for empty session_id."""
        assert parse_bound_session_id("user123:") is None
