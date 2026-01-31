"""Tests for OIDCIdentityProvider logout and manager token clearing.

Verifies that:
- logout() clears _manager_token (prevents stale token use after logout)
- _on_manager_token_cleared() triggers full logout
- get_identity() raises AuthenticationError after logout
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

from mcp_acp.config import OIDCConfig
from mcp_acp.exceptions import AuthenticationError
from mcp_acp.pips.auth.oidc_provider import OIDCIdentityProvider
from mcp_acp.security.auth.token_storage import StoredToken


@pytest.fixture
def oidc_config() -> OIDCConfig:
    """Minimal OIDC config for provider construction."""
    return OIDCConfig(
        issuer="https://test.auth0.com",
        client_id="test-client-id",
        audience="https://api.test.com",
    )


@pytest.fixture
def mock_storage() -> MagicMock:
    """Mock TokenStorage with no stored token."""
    storage = MagicMock()
    storage.load.return_value = None
    storage.exists.return_value = False
    return storage


@pytest.fixture
def valid_token() -> StoredToken:
    """Non-expired stored token."""
    now = datetime.now(timezone.utc)
    return StoredToken(
        access_token="test-access-token",
        refresh_token="test-refresh-token",
        id_token=None,
        expires_at=now + timedelta(hours=1),
        issued_at=now,
    )


@pytest.fixture
def provider(oidc_config: OIDCConfig, mock_storage: MagicMock) -> OIDCIdentityProvider:
    """OIDCIdentityProvider with mock storage and no JWT validator."""
    return OIDCIdentityProvider(
        config=oidc_config,
        token_storage=mock_storage,
        jwt_validator=MagicMock(),
    )


class TestLogoutClearsManagerToken:
    """Tests that logout() clears _manager_token."""

    def test_logout_clears_manager_token(
        self,
        provider: OIDCIdentityProvider,
        valid_token: StoredToken,
    ) -> None:
        """logout() sets _manager_token to None."""
        provider._manager_token = valid_token
        provider.logout(emit_event=False)
        assert provider._manager_token is None

    def test_logout_clears_current_token(
        self,
        provider: OIDCIdentityProvider,
        valid_token: StoredToken,
    ) -> None:
        """logout() sets _current_token to None."""
        provider._current_token = valid_token
        provider.logout(emit_event=False)
        assert provider._current_token is None

    def test_logout_clears_cache(
        self,
        provider: OIDCIdentityProvider,
    ) -> None:
        """logout() sets _cache to None."""
        provider._cache = MagicMock()
        provider.logout(emit_event=False)
        assert provider._cache is None

    def test_logout_deletes_from_storage(
        self,
        provider: OIDCIdentityProvider,
        mock_storage: MagicMock,
    ) -> None:
        """logout() calls storage.delete()."""
        provider.logout(emit_event=False)
        mock_storage.delete.assert_called_once()

    async def test_get_identity_fails_after_logout_with_manager_token(
        self,
        provider: OIDCIdentityProvider,
        valid_token: StoredToken,
        mock_storage: MagicMock,
    ) -> None:
        """After logout, get_identity() raises even if manager token was previously set."""
        # Simulate manager token being set (login via manager)
        provider._manager_token = valid_token
        provider._current_token = valid_token

        # Logout
        provider.logout(emit_event=False)

        # Storage has no fallback token
        mock_storage.load.return_value = None

        # get_identity() should fail
        with pytest.raises(AuthenticationError, match="Not authenticated"):
            await provider.get_identity()


class TestManagerTokenClearedCallback:
    """Tests that _on_manager_token_cleared() triggers logout."""

    def test_on_manager_token_cleared_calls_logout(
        self,
        provider: OIDCIdentityProvider,
        valid_token: StoredToken,
        mock_storage: MagicMock,
    ) -> None:
        """_on_manager_token_cleared() clears all token state."""
        # Simulate active session with manager token
        provider._manager_token = valid_token
        provider._current_token = valid_token
        provider._cache = MagicMock()

        # Trigger manager clear callback
        provider._on_manager_token_cleared()

        # All state should be cleared
        assert provider._manager_token is None
        assert provider._current_token is None
        assert provider._cache is None
        mock_storage.delete.assert_called_once()

    def test_on_manager_token_cleared_clears_hitl_cache(
        self,
        provider: OIDCIdentityProvider,
    ) -> None:
        """_on_manager_token_cleared() clears HITL approval cache via proxy_state."""
        mock_state = MagicMock()
        provider._proxy_state = mock_state

        provider._on_manager_token_cleared()

        mock_state.clear_all_cached_approvals.assert_called_once()

    async def test_get_identity_fails_after_manager_token_cleared(
        self,
        provider: OIDCIdentityProvider,
        valid_token: StoredToken,
        mock_storage: MagicMock,
    ) -> None:
        """After manager token cleared, get_identity() raises AuthenticationError."""
        provider._manager_token = valid_token

        # Manager signals logout
        provider._on_manager_token_cleared()

        # No fallback
        mock_storage.load.return_value = None

        with pytest.raises(AuthenticationError, match="Not authenticated"):
            await provider.get_identity()


class TestSetManagerClientRegistersCallbacks:
    """Tests that set_manager_client() registers both token and clear callbacks."""

    def test_registers_token_clear_callback(
        self,
        provider: OIDCIdentityProvider,
    ) -> None:
        """set_manager_client() registers clear callback on ManagerClient."""
        mock_client = MagicMock()
        mock_client.manager_token = None

        provider.set_manager_client(mock_client)

        mock_client.set_token_callback.assert_called_once()
        mock_client.set_token_clear_callback.assert_called_once_with(provider._on_manager_token_cleared)
