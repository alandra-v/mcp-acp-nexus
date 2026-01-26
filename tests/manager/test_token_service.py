"""Tests for ManagerTokenService.

Tests token lifecycle management and distribution to proxies.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_acp.manager.token_service import (
    TOKEN_REFRESH_BUFFER_SECONDS,
    ManagerTokenService,
)
from mcp_acp.security.auth.token_storage import StoredToken


@pytest.fixture
def mock_oidc_config() -> MagicMock:
    """Create mock OIDC config."""
    config = MagicMock()
    config.issuer = "https://example.auth0.com/"
    config.client_id = "test-client-id"
    return config


@pytest.fixture
def mock_registry() -> MagicMock:
    """Create mock registry with broadcast capability."""
    registry = MagicMock()
    registry.broadcast_to_all_proxies = AsyncMock()
    return registry


@pytest.fixture
def valid_token() -> StoredToken:
    """Create a valid (not expired) token."""
    return StoredToken(
        access_token="access_123",
        refresh_token="refresh_456",
        id_token="id_789",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        issued_at=datetime.now(timezone.utc),
    )


@pytest.fixture
def expiring_token() -> StoredToken:
    """Create a token expiring within refresh buffer (5 minutes)."""
    return StoredToken(
        access_token="access_expiring",
        refresh_token="refresh_expiring",
        id_token="id_expiring",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=4),
        issued_at=datetime.now(timezone.utc) - timedelta(hours=1),
    )


@pytest.fixture
def mock_writer() -> MagicMock:
    """Create mock stream writer."""
    writer = MagicMock()
    writer.write = MagicMock()
    writer.drain = AsyncMock()
    return writer


class TestTokenServiceStart:
    """Tests for token service startup."""

    async def test_loads_token_from_storage_on_start(
        self,
        mock_oidc_config: MagicMock,
        mock_registry: MagicMock,
        valid_token: StoredToken,
    ) -> None:
        """Service loads existing token from storage on start."""
        service = ManagerTokenService(mock_oidc_config, mock_registry)
        service._storage = MagicMock()
        service._storage.load = MagicMock(return_value=valid_token)

        await service.start()

        try:
            assert service.has_token is True
            assert service.current_token == valid_token
            service._storage.load.assert_called_once()
        finally:
            await service.stop()

    async def test_starts_without_token_when_storage_empty(
        self,
        mock_oidc_config: MagicMock,
        mock_registry: MagicMock,
    ) -> None:
        """Service starts gracefully when no token in storage."""
        service = ManagerTokenService(mock_oidc_config, mock_registry)
        service._storage = MagicMock()
        service._storage.load = MagicMock(return_value=None)

        await service.start()

        try:
            assert service.has_token is False
            assert service.current_token is None
        finally:
            await service.stop()

    async def test_handles_storage_load_failure(
        self,
        mock_oidc_config: MagicMock,
        mock_registry: MagicMock,
    ) -> None:
        """Service handles storage load failure gracefully."""
        service = ManagerTokenService(mock_oidc_config, mock_registry)
        service._storage = MagicMock()
        service._storage.load = MagicMock(side_effect=Exception("Keychain error"))

        # Should not raise
        await service.start()

        try:
            assert service.has_token is False
        finally:
            await service.stop()


class TestSendTokenToProxy:
    """Tests for sending token to individual proxy."""

    async def test_sends_token_to_proxy(
        self,
        mock_oidc_config: MagicMock,
        mock_registry: MagicMock,
        valid_token: StoredToken,
        mock_writer: MagicMock,
    ) -> None:
        """Sends token update message to proxy writer."""
        service = ManagerTokenService(mock_oidc_config, mock_registry)
        service._current_token = valid_token

        result = await service.send_token_to_proxy(mock_writer)

        assert result is True
        mock_writer.write.assert_called_once()
        mock_writer.drain.assert_called_once()

        # Verify message format
        written_data = mock_writer.write.call_args[0][0]
        import json

        msg = json.loads(written_data.decode().strip())
        assert msg["type"] == "token_update"
        assert msg["access_token"] == "access_123"
        assert msg["refresh_token"] == "refresh_456"
        assert "expires_at" in msg

    async def test_returns_false_when_no_token(
        self,
        mock_oidc_config: MagicMock,
        mock_registry: MagicMock,
        mock_writer: MagicMock,
    ) -> None:
        """Returns False when no token available."""
        service = ManagerTokenService(mock_oidc_config, mock_registry)
        service._current_token = None

        result = await service.send_token_to_proxy(mock_writer)

        assert result is False
        mock_writer.write.assert_not_called()

    async def test_handles_broken_pipe(
        self,
        mock_oidc_config: MagicMock,
        mock_registry: MagicMock,
        valid_token: StoredToken,
    ) -> None:
        """Handles broken pipe gracefully."""
        service = ManagerTokenService(mock_oidc_config, mock_registry)
        service._current_token = valid_token

        writer = MagicMock()
        writer.write = MagicMock(side_effect=BrokenPipeError())

        result = await service.send_token_to_proxy(writer)

        assert result is False


class TestReloadFromStorage:
    """Tests for reloading token after CLI login."""

    async def test_reloads_and_broadcasts_token(
        self,
        mock_oidc_config: MagicMock,
        mock_registry: MagicMock,
        valid_token: StoredToken,
    ) -> None:
        """Reloads token from storage and broadcasts to all proxies."""
        service = ManagerTokenService(mock_oidc_config, mock_registry)
        service._storage = MagicMock()
        service._storage.load = MagicMock(return_value=valid_token)

        result = await service.reload_from_storage()

        assert result is True
        assert service.current_token == valid_token
        mock_registry.broadcast_to_all_proxies.assert_called_once()

        # Verify broadcast message
        broadcast_msg = mock_registry.broadcast_to_all_proxies.call_args[0][0]
        assert broadcast_msg["type"] == "token_update"
        assert broadcast_msg["access_token"] == "access_123"

    async def test_returns_false_when_no_token_in_storage(
        self,
        mock_oidc_config: MagicMock,
        mock_registry: MagicMock,
    ) -> None:
        """Returns False when no token in storage."""
        service = ManagerTokenService(mock_oidc_config, mock_registry)
        service._storage = MagicMock()
        service._storage.load = MagicMock(return_value=None)

        result = await service.reload_from_storage()

        assert result is False
        mock_registry.broadcast_to_all_proxies.assert_not_called()

    async def test_handles_reload_failure(
        self,
        mock_oidc_config: MagicMock,
        mock_registry: MagicMock,
    ) -> None:
        """Handles reload failure gracefully."""
        service = ManagerTokenService(mock_oidc_config, mock_registry)
        service._storage = MagicMock()
        service._storage.load = MagicMock(side_effect=Exception("Keychain error"))

        result = await service.reload_from_storage()

        assert result is False
        mock_registry.broadcast_to_all_proxies.assert_not_called()


class TestClearToken:
    """Tests for clearing token on logout."""

    async def test_clears_token_and_broadcasts(
        self,
        mock_oidc_config: MagicMock,
        mock_registry: MagicMock,
        valid_token: StoredToken,
    ) -> None:
        """Clears token and broadcasts token_cleared to all proxies."""
        service = ManagerTokenService(mock_oidc_config, mock_registry)
        service._current_token = valid_token

        await service.clear_token()

        assert service.has_token is False
        assert service.current_token is None
        mock_registry.broadcast_to_all_proxies.assert_called_once()

        # Verify broadcast message
        broadcast_msg = mock_registry.broadcast_to_all_proxies.call_args[0][0]
        assert broadcast_msg["type"] == "token_cleared"


class TestTokenRefresh:
    """Tests for proactive token refresh."""

    async def test_refreshes_token_when_near_expiry(
        self,
        mock_oidc_config: MagicMock,
        mock_registry: MagicMock,
        expiring_token: StoredToken,
    ) -> None:
        """Refreshes token when within 5 minutes of expiry."""
        new_token = StoredToken(
            access_token="access_new",
            refresh_token="refresh_new",
            id_token="id_new",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            issued_at=datetime.now(timezone.utc),
        )

        service = ManagerTokenService(mock_oidc_config, mock_registry)
        service._current_token = expiring_token
        service._storage = MagicMock()
        service._storage.save = MagicMock()

        with patch("mcp_acp.security.auth.refresh_tokens") as mock_refresh:
            mock_refresh.return_value = new_token

            await service._refresh_token()

            mock_refresh.assert_called_once()
            service._storage.save.assert_called_once_with(new_token)
            assert service.current_token == new_token
            mock_registry.broadcast_to_all_proxies.assert_called_once()

    async def test_skips_refresh_without_refresh_token(
        self,
        mock_oidc_config: MagicMock,
        mock_registry: MagicMock,
    ) -> None:
        """Skips refresh when no refresh_token available."""
        token_without_refresh = StoredToken(
            access_token="access_only",
            refresh_token=None,
            id_token=None,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=2),
            issued_at=datetime.now(timezone.utc),
        )

        service = ManagerTokenService(mock_oidc_config, mock_registry)
        service._current_token = token_without_refresh

        with patch("mcp_acp.security.auth.refresh_tokens") as mock_refresh:
            await service._refresh_token()

            mock_refresh.assert_not_called()
            mock_registry.broadcast_to_all_proxies.assert_not_called()

    async def test_handles_refresh_failure(
        self,
        mock_oidc_config: MagicMock,
        mock_registry: MagicMock,
        expiring_token: StoredToken,
    ) -> None:
        """Handles refresh failure gracefully, keeps old token."""
        service = ManagerTokenService(mock_oidc_config, mock_registry)
        service._current_token = expiring_token

        with patch("mcp_acp.security.auth.refresh_tokens") as mock_refresh:
            mock_refresh.side_effect = Exception("Network error")

            # Should not raise
            await service._refresh_token()

            # Old token should be retained
            assert service.current_token == expiring_token
            mock_registry.broadcast_to_all_proxies.assert_not_called()


class TestTokenMessageFormat:
    """Tests for token message format."""

    def test_build_token_message_includes_all_fields(
        self,
        mock_oidc_config: MagicMock,
        mock_registry: MagicMock,
        valid_token: StoredToken,
    ) -> None:
        """Token message includes all required fields."""
        service = ManagerTokenService(mock_oidc_config, mock_registry)

        msg = service._build_token_message(valid_token)

        assert msg["type"] == "token_update"
        assert msg["access_token"] == "access_123"
        assert msg["refresh_token"] == "refresh_456"
        assert msg["id_token"] == "id_789"
        assert "expires_at" in msg
        assert "issued_at" in msg
        # ISO format check
        assert "T" in msg["expires_at"]


class TestConcurrency:
    """Tests for thread-safety of token operations."""

    async def test_concurrent_operations_are_safe(
        self,
        mock_oidc_config: MagicMock,
        mock_registry: MagicMock,
        valid_token: StoredToken,
    ) -> None:
        """Concurrent token operations don't cause race conditions."""
        service = ManagerTokenService(mock_oidc_config, mock_registry)
        service._storage = MagicMock()
        service._storage.load = MagicMock(return_value=valid_token)

        writer = MagicMock()
        writer.write = MagicMock()
        writer.drain = AsyncMock()

        # Run multiple operations concurrently
        results = await asyncio.gather(
            service.reload_from_storage(),
            service.send_token_to_proxy(writer),
            service.clear_token(),
            return_exceptions=True,
        )

        # No exceptions should be raised
        for result in results:
            assert not isinstance(result, Exception)
