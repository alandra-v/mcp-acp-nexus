"""Token distribution service for multi-proxy OIDC authentication.

The ManagerTokenService centralizes token lifecycle management:
- Loads tokens from keychain on startup
- Monitors expiry and proactively refreshes (5 minutes before expiry)
- Broadcasts token updates to all connected proxies
- Sends initial token when proxy registers

This implements Phase 4's token distribution requirement, ensuring all proxies
share the same token state without each independently managing refresh.

Protocol:
    Manager -> Proxy: {"type": "token_update", "access_token": "...", "expires_at": "ISO8601"}
"""

from __future__ import annotations

__all__ = [
    "ManagerTokenService",
]

import asyncio
import logging
from typing import TYPE_CHECKING, Any

from mcp_acp.constants import APP_NAME
from mcp_acp.manager.protocol import encode_ndjson
from mcp_acp.security.auth.token_storage import StoredToken, create_token_storage

if TYPE_CHECKING:
    from mcp_acp.config import OIDCConfig
    from mcp_acp.manager.registry import ProxyRegistry

# Refresh token 5 minutes before expiry
TOKEN_REFRESH_BUFFER_SECONDS = 300

# How often to check token expiry (30 seconds)
TOKEN_CHECK_INTERVAL_SECONDS = 30

_logger = logging.getLogger(f"{APP_NAME}.manager.token_service")


class ManagerTokenService:
    """Centralized token management for multi-proxy deployments.

    The token service runs in the manager daemon and:
    1. Loads existing token from keychain on startup
    2. Monitors expiry and refreshes proactively
    3. Broadcasts token updates to all connected proxies
    4. Provides initial token to newly registered proxies

    Usage:
        service = ManagerTokenService(oidc_config, registry)
        await service.start()

        # When CLI does auth login:
        await service.reload_from_storage()

        # On shutdown:
        await service.stop()
    """

    def __init__(
        self,
        config: "OIDCConfig",
        registry: "ProxyRegistry",
    ) -> None:
        """Initialize token service.

        Args:
            config: OIDC configuration for token refresh.
            registry: Proxy registry for broadcasting updates.
        """
        self._config = config
        self._registry = registry
        self._storage = create_token_storage(config)
        self._current_token: StoredToken | None = None
        self._monitor_task: asyncio.Task[None] | None = None
        self._lock = asyncio.Lock()

    @property
    def has_token(self) -> bool:
        """Check if a valid token is available."""
        return self._current_token is not None

    @property
    def current_token(self) -> StoredToken | None:
        """Get the current token (may be expired)."""
        return self._current_token

    async def start(self) -> None:
        """Start the token service.

        Loads existing token from storage and starts the expiry monitor.
        """
        async with self._lock:
            # Load existing token
            try:
                self._current_token = self._storage.load()
                if self._current_token:
                    _logger.info(
                        {
                            "event": "token_loaded",
                            "message": "Loaded existing token from storage",
                            "expires_at": self._current_token.expires_at.isoformat(),
                            "is_expired": self._current_token.is_expired,
                        }
                    )
            except Exception as e:
                _logger.warning(
                    {
                        "event": "token_load_failed",
                        "message": f"Failed to load token from storage: {e}",
                        "error_type": type(e).__name__,
                        "error_message": str(e),
                    }
                )

            # Start expiry monitor
            self._monitor_task = asyncio.create_task(self._monitor_expiry())

    async def stop(self) -> None:
        """Stop the token service.

        Cancels the expiry monitor task.
        """
        if self._monitor_task is not None:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
            self._monitor_task = None

    async def reload_from_storage(self) -> bool:
        """Reload token from storage (after CLI auth login).

        Called when CLI stores new tokens. Loads the new token and
        broadcasts to all connected proxies.

        Returns:
            True if token was loaded and broadcast, False if no token.
        """
        async with self._lock:
            try:
                self._current_token = self._storage.load()
            except Exception as e:
                _logger.warning(
                    {
                        "event": "token_reload_failed",
                        "message": f"Failed to reload token: {e}",
                        "error_type": type(e).__name__,
                        "error_message": str(e),
                    }
                )
                return False

            if self._current_token is None:
                return False

            _logger.info(
                {
                    "event": "token_reloaded",
                    "message": "Token reloaded from storage, broadcasting to proxies",
                    "expires_at": self._current_token.expires_at.isoformat(),
                }
            )

            await self._broadcast_token()
            return True

    async def clear_token(self) -> None:
        """Clear the current token (on logout).

        Broadcasts a token_cleared message to all proxies.
        """
        async with self._lock:
            self._current_token = None
            await self._broadcast_token_cleared()

    async def send_token_to_proxy(self, writer: asyncio.StreamWriter) -> bool:
        """Send current token to a specific proxy.

        Called when a new proxy registers to give it the current token.
        Thread-safe: acquires lock to prevent race with clear_token().

        Args:
            writer: Stream writer for the proxy connection.

        Returns:
            True if token was sent, False if no token available.
        """
        async with self._lock:
            if self._current_token is None:
                return False

            msg = self._build_token_message(self._current_token)
            try:
                writer.write(encode_ndjson(msg))
                await writer.drain()
                return True
            except (ConnectionResetError, BrokenPipeError, OSError):
                return False

    async def _monitor_expiry(self) -> None:
        """Background task to monitor token expiry and refresh proactively."""
        try:
            while True:
                await asyncio.sleep(TOKEN_CHECK_INTERVAL_SECONDS)

                async with self._lock:
                    if self._current_token is None:
                        continue

                    # Check if token needs refresh
                    seconds_until_expiry = self._current_token.seconds_until_expiry
                    if seconds_until_expiry <= TOKEN_REFRESH_BUFFER_SECONDS:
                        await self._refresh_token()

        except asyncio.CancelledError:
            raise

    async def _refresh_token(self) -> None:
        """Refresh the current token and broadcast update.

        Called when token is within 5 minutes of expiry.
        """
        if self._current_token is None or not self._current_token.refresh_token:
            _logger.warning(
                {
                    "event": "token_refresh_skipped",
                    "message": "Cannot refresh: no token or no refresh_token",
                }
            )
            return

        try:
            from mcp_acp.security.auth import refresh_tokens

            # Run refresh in thread pool (HTTP call)
            refreshed = await asyncio.to_thread(
                refresh_tokens,
                self._config,
                self._current_token.refresh_token,
            )

            # Save to storage
            self._storage.save(refreshed)
            self._current_token = refreshed

            _logger.info(
                {
                    "event": "token_refreshed",
                    "message": "Token refreshed successfully, broadcasting to proxies",
                    "expires_at": refreshed.expires_at.isoformat(),
                }
            )

            # Broadcast to all proxies
            await self._broadcast_token()

        except Exception as e:
            _logger.error(
                {
                    "event": "token_refresh_failed",
                    "message": f"Failed to refresh token: {e}",
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                }
            )

    async def _broadcast_token(self) -> None:
        """Broadcast current token to all connected proxies."""
        if self._current_token is None:
            return

        msg = self._build_token_message(self._current_token)
        await self._registry.broadcast_to_all_proxies(msg)

    async def _broadcast_token_cleared(self) -> None:
        """Broadcast token cleared message to all proxies."""
        msg = {
            "type": "token_cleared",
        }
        await self._registry.broadcast_to_all_proxies(msg)

    def _build_token_message(self, token: StoredToken) -> dict[str, Any]:
        """Build token_update message for broadcast.

        Args:
            token: Token to include in message.

        Returns:
            Dict ready for NDJSON encoding.
        """
        return {
            "type": "token_update",
            "access_token": token.access_token,
            "refresh_token": token.refresh_token,
            "id_token": token.id_token,
            "expires_at": token.expires_at.isoformat(),
            "issued_at": token.issued_at.isoformat(),
        }
