"""OIDC Identity Provider for keychain-based authentication (STDIO transport).

Pattern 1: STDIO Transport
- Token stored in OS keychain (via CLI `auth login`)
- Validated per-request (true Zero Trust - no caching)
- Auto-refreshed when expired
- Logout/revocation takes effect immediately

This provider implements the IdentityProvider protocol, making it interchangeable
with LocalIdentityProvider (Stage 1) and future HTTPIdentityProvider (Pattern 2).

Thread-safety: Uses asyncio.Lock for concurrent request safety.

See docs/design/authentication_implementation.md for architecture details.
"""

from __future__ import annotations

__all__ = [
    "OIDCIdentityProvider",
]

import asyncio
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

# Warn user when token expires within this many seconds (15 minutes)
SESSION_EXPIRY_WARNING_SECONDS = 900

from mcp_acp.exceptions import AuthenticationError
from mcp_acp.security.auth import (
    JWTValidator,
    StoredToken,
    TokenRefreshExpiredError,
    TokenStorage,
    ValidatedToken,
    create_token_storage,
    refresh_tokens,
)
from mcp_acp.telemetry.models.audit import OIDCInfo, SubjectIdentity
from mcp_acp.telemetry.system.system_logger import get_system_logger
from mcp_acp.utils.logging.logging_context import get_request_id, get_session_id

if TYPE_CHECKING:
    from mcp_acp.config import OIDCConfig
    from mcp_acp.manager.client import ManagerClient
    from mcp_acp.manager.state import ProxyState
    from mcp_acp.telemetry.audit.auth_logger import AuthLogger


@dataclass
class _CachedIdentity:
    """Holds the last validated identity for get_validated_token() access."""

    identity: SubjectIdentity
    validated_token: ValidatedToken
    cached_at: float  # monotonic timestamp (for debugging/logging)


class OIDCIdentityProvider:
    """OIDC identity provider for STDIO transport (Pattern 1).

    Loads OAuth tokens from OS keychain, validates JWT per-request,
    and auto-refreshes when expired. Implements IdentityProvider protocol.

    Features:
    - Per-request validation (true Zero Trust - no caching)
    - Automatic token refresh when access_token expires
    - Rich SubjectIdentity with OIDC claims for policy evaluation
    - Concurrency-safe with asyncio.Lock
    - Immediate logout/revocation effect (no cache delay)

    Usage:
        provider = OIDCIdentityProvider(oidc_config)
        identity = await provider.get_identity()
        print(f"User: {identity.subject_id}")

    Raises:
        AuthenticationError: If not authenticated or token refresh fails.
    """

    def __init__(
        self,
        config: "OIDCConfig",
        token_storage: TokenStorage | None = None,
        jwt_validator: JWTValidator | None = None,
        auth_logger: "AuthLogger | None" = None,
    ) -> None:
        """Initialize OIDC identity provider.

        Args:
            config: OIDC configuration (issuer, client_id, audience).
            token_storage: Token storage backend (default: auto-detect keychain/file).
            jwt_validator: JWT validator (default: create from config).
            auth_logger: Logger for auth events to auth.jsonl (optional for tests).
        """
        self._config = config
        self._storage = token_storage or create_token_storage(config)
        self._validator = jwt_validator or JWTValidator(config)
        self._cache: _CachedIdentity | None = None
        self._current_token: StoredToken | None = None
        self._system_logger = get_system_logger()
        self._auth_logger = auth_logger
        # Lock protects cache read-modify-write operations
        self._lock = asyncio.Lock()
        # ProxyState for SSE event emission (set via set_proxy_state after creation)
        self._proxy_state: "ProxyState | None" = None
        # Track if we've warned about session expiring (reset on new token)
        self._expiry_warned: bool = False
        # Manager client for distributed tokens (set via set_manager_client)
        self._manager_client: "ManagerClient | None" = None
        # Token received from manager (takes precedence over local storage)
        self._manager_token: StoredToken | None = None

    def set_proxy_state(self, proxy_state: "ProxyState") -> None:
        """Set ProxyState for SSE event emission.

        Called after ProxyState is created to enable auth event notifications
        to the web UI via SSE.

        Args:
            proxy_state: ProxyState instance for SSE emission.
        """
        self._proxy_state = proxy_state

    def set_manager_client(self, manager_client: "ManagerClient") -> None:
        """Set manager client for distributed token updates.

        Called during proxy setup to enable manager-distributed tokens.
        When set, the provider prefers manager-provided tokens over
        local storage and skips local refresh (manager handles refresh).

        Args:
            manager_client: ManagerClient instance for token updates.
        """
        self._manager_client = manager_client
        # Register callback to receive token updates
        manager_client.set_token_callback(self._on_manager_token)

        # Check if manager already has a token
        if manager_client.manager_token is not None:
            self._on_manager_token(manager_client.manager_token)

    def _on_manager_token(self, token: StoredToken) -> None:
        """Handle token update from manager.

        Called by ManagerClient when a new token is received.

        Args:
            token: New token from manager.
        """
        self._manager_token = token
        self._current_token = token
        self._cache = None  # Force re-validation
        self._expiry_warned = False  # Reset for new token

        self._system_logger.info(
            {
                "event": "manager_token_received",
                "message": "Received token update from manager",
                "expires_at": token.expires_at.isoformat(),
                "is_expired": token.is_expired,
            }
        )

        # Emit SSE event for UI notification
        if self._proxy_state is not None:
            from mcp_acp.manager.events import SSEEventType

            self._proxy_state.emit_system_event(
                SSEEventType.AUTH_LOGIN,
                severity="success",
                message="Token updated from manager",
            )

    async def get_identity(self) -> SubjectIdentity:
        """Get the current user's identity.

        Implements IdentityProvider protocol. Called per-request by middleware.

        Flow:
        1. Acquire lock for thread-safe access
        2. Load token from keychain
        3. Validate JWT (signature, issuer, audience, expiry)
        4. If expired, try refresh
        5. Build SubjectIdentity with OIDC claims

        Zero Trust: Validates on every request. No caching - ensures logout
        and token revocation take effect immediately.

        Returns:
            SubjectIdentity with subject_id and OIDC claims.

        Raises:
            AuthenticationError: If not authenticated, token invalid,
                or refresh fails (user must re-login).
        """
        async with self._lock:
            # Load token from storage (validates token exists)
            token = self._load_token()

            # Validate and potentially refresh
            validated = await self._validate_token(token)

            # Build identity from validated claims
            identity = self._build_identity(validated)

            # Store for get_validated_token() access
            self._cache = _CachedIdentity(
                identity=identity,
                validated_token=validated,
                cached_at=time.monotonic(),
            )

            return identity

    async def get_validated_token(self) -> ValidatedToken:
        """Get the validated token (for advanced use cases).

        Returns the full ValidatedToken with all claims, useful for
        audit logging or building full Subject objects.

        Returns:
            ValidatedToken with all OIDC claims.

        Raises:
            AuthenticationError: If not authenticated.
        """
        # Ensure identity is loaded/validated (populates cache)
        await self.get_identity()

        if self._cache is None:
            raise AuthenticationError("No validated token available")

        return self._cache.validated_token

    def _load_token(self) -> StoredToken:
        """Load token from storage or manager.

        Prefers manager-provided token if available (multi-proxy mode).
        Falls back to local keychain storage.

        Returns:
            StoredToken from manager or keychain/encrypted file.

        Raises:
            AuthenticationError: If no token available (user not logged in).
        """
        # Prefer manager-provided token (multi-proxy mode)
        if self._manager_token is not None:
            self._current_token = self._manager_token
            return self._manager_token

        # Fall back to local storage
        token = self._storage.load()

        if token is None:
            raise AuthenticationError("Not authenticated. Run 'mcp-acp auth login' to authenticate.")

        self._current_token = token
        return token

    def _build_oidc_info(self, validated: ValidatedToken) -> OIDCInfo:
        """Build OIDCInfo from validated token for logging."""
        from datetime import datetime, timezone

        return OIDCInfo(
            issuer=validated.issuer,
            audience=validated.audience,
            scopes=list(validated.scopes) if validated.scopes else None,
            token_type="access",
            token_exp=(
                datetime.fromtimestamp(validated.claims.get("exp", 0), tz=timezone.utc)
                if validated.claims.get("exp")
                else None
            ),
            token_iat=(
                datetime.fromtimestamp(validated.claims.get("iat", 0), tz=timezone.utc)
                if validated.claims.get("iat")
                else None
            ),
        )

    async def _validate_token(self, token: StoredToken) -> ValidatedToken:
        """Validate token, refreshing if expired.

        Args:
            token: Stored token to validate.

        Returns:
            ValidatedToken with verified claims.

        Raises:
            AuthenticationError: If validation fails and refresh not possible.
        """
        # Check if token is expired based on stored expiry
        if token.is_expired:
            return await self._refresh_and_validate(token)

        # Ensure JWKS is available (async pre-flight check with proper timeout)
        # This must happen before the sync validate() call because sync httpx
        # has timeout bugs for unreachable hosts
        await self._validator.ensure_jwks_available()

        # Validate JWT (signature, issuer, audience, exp)
        try:
            validated = self._validator.validate(token.access_token)

            # Check if token is expiring soon (warn once per token)
            self._check_session_expiring(token)

            return validated

        except AuthenticationError as e:
            # Token validation failed - check if it's expiry
            # Check the cause for jwt.ExpiredSignatureError (more robust than string matching)
            import jwt

            is_expiry = isinstance(e.__cause__, jwt.ExpiredSignatureError)
            if is_expiry:
                return await self._refresh_and_validate(token)

            # Log validation failure to auth.jsonl and system (warning)
            if self._auth_logger:
                self._auth_logger.log_token_invalid(
                    mcp_session_id=get_session_id(),
                    request_id=get_request_id(),
                    error_type=type(e).__name__,
                    error_message=str(e),
                )
            self._system_logger.warning(
                {
                    "event": "token_validation_failed",
                    "error": str(e),
                }
            )
            # Emit SSE event for UI notification
            if self._proxy_state is not None:
                from mcp_acp.manager.events import SSEEventType

                self._proxy_state.emit_system_event(
                    SSEEventType.TOKEN_VALIDATION_FAILED,
                    severity="error",
                    message="Token validation failed",
                    error_type=type(e).__name__,
                )

            # Re-raise
            raise

    def _check_session_expiring(self, token: StoredToken) -> None:
        """Check if token is expiring soon and emit warning (once per token).

        Args:
            token: Current stored token to check.
        """
        if self._expiry_warned:
            return  # Already warned for this token

        if self._proxy_state is None:
            return  # No UI to notify

        seconds_until_expiry = token.seconds_until_expiry
        if seconds_until_expiry <= SESSION_EXPIRY_WARNING_SECONDS:
            self._expiry_warned = True
            minutes_left = int(seconds_until_expiry / 60)

            from mcp_acp.manager.events import SSEEventType

            self._proxy_state.emit_system_event(
                SSEEventType.AUTH_SESSION_EXPIRING,
                severity="warning",
                message=f"Session expires in {minutes_left} minutes",
                minutes_remaining=minutes_left,
            )

            self._system_logger.warning(
                {
                    "event": "auth_session_expiring",
                    "minutes_remaining": minutes_left,
                    "seconds_remaining": int(seconds_until_expiry),
                }
            )

    async def _refresh_and_validate(self, token: StoredToken) -> ValidatedToken:
        """Refresh token and validate the new one.

        In multi-proxy mode (manager_client set), skips local refresh since
        the manager handles token lifecycle. Instead, waits briefly for
        manager to provide a refreshed token.

        Runs the HTTP token refresh in a thread pool to avoid blocking
        the event loop (refresh can take up to 30 seconds on timeout).

        Args:
            token: Expired token with refresh_token.

        Returns:
            ValidatedToken from refreshed access_token.

        Raises:
            AuthenticationError: If refresh fails (user must re-login).
        """
        # In multi-proxy mode, manager handles refresh
        if self._manager_client is not None and self._manager_token is not None:
            error_msg = (
                "Token expired. Manager should refresh automatically. "
                "If this persists, run 'mcp-acp auth login' to re-authenticate."
            )
            # Log but don't fail immediately - manager may be refreshing
            self._system_logger.warning(
                {
                    "event": "token_expired_waiting_for_manager",
                    "message": "Token expired, waiting for manager refresh",
                }
            )
            # Emit SSE event
            if self._proxy_state is not None:
                from mcp_acp.manager.events import SSEEventType

                self._proxy_state.emit_system_event(
                    SSEEventType.AUTH_SESSION_EXPIRING,
                    severity="warning",
                    message="Token expired, waiting for refresh",
                )
            raise AuthenticationError(error_msg)

        if not token.refresh_token:
            error_msg = (
                "Token expired and no refresh token available. "
                "Run 'mcp-acp auth login' to re-authenticate."
            )
            # Log to auth.jsonl and system (error - user action required)
            if self._auth_logger:
                self._auth_logger.log_token_refresh_failed(
                    mcp_session_id=get_session_id(),
                    error_type="NoRefreshToken",
                    error_message=error_msg,
                )
            self._system_logger.error(
                {
                    "event": "token_refresh_failed",
                    "reason": "no_refresh_token",
                }
            )
            # Emit SSE event for UI notification
            if self._proxy_state is not None:
                from mcp_acp.manager.events import SSEEventType

                self._proxy_state.emit_system_event(
                    SSEEventType.TOKEN_REFRESH_FAILED,
                    severity="error",
                    message="Session expired - please log in again",
                    error_type="NoRefreshToken",
                )
            raise AuthenticationError(error_msg)

        try:
            # Refresh tokens in thread pool to avoid blocking event loop
            # (HTTP call can take up to 30 seconds on network timeout)
            refreshed = await asyncio.to_thread(refresh_tokens, self._config, token.refresh_token)

            # Save refreshed tokens to storage
            self._storage.save(refreshed)
            self._current_token = refreshed
            self._expiry_warned = False  # Reset warning for new token

            # Validate the new token
            validated = self._validator.validate(refreshed.access_token)

            # Log successful refresh to auth.jsonl
            if self._auth_logger:
                identity = self._build_identity(validated)
                self._auth_logger.log_token_refreshed(
                    mcp_session_id=get_session_id(),
                    subject=identity,
                    oidc=self._build_oidc_info(validated),
                )

            return validated

        except TokenRefreshExpiredError as e:
            # Refresh token has expired - user must re-authenticate
            error_msg = "Auth session expired. Run 'mcp-acp auth login' to re-authenticate."
            # Log to auth.jsonl and system (error - user action required)
            if self._auth_logger:
                self._auth_logger.log_token_refresh_failed(
                    mcp_session_id=get_session_id(),
                    error_type="TokenRefreshExpiredError",
                    error_message=str(e),
                )
            self._system_logger.error(
                {
                    "event": "token_refresh_failed",
                    "reason": "refresh_token_expired",
                }
            )
            # Emit SSE event for UI notification
            if self._proxy_state is not None:
                from mcp_acp.manager.events import SSEEventType

                self._proxy_state.emit_system_event(
                    SSEEventType.TOKEN_REFRESH_FAILED,
                    severity="error",
                    message="Session expired - please log in again",
                    error_type="TokenRefreshExpiredError",
                )
            raise AuthenticationError(error_msg) from e

    def _build_identity(self, validated: ValidatedToken) -> SubjectIdentity:
        """Build SubjectIdentity from validated token.

        Args:
            validated: Validated token with claims.

        Returns:
            SubjectIdentity for audit logging and policy evaluation.
        """
        # Extract safe claims for logging (no sensitive data)
        # SubjectIdentity.subject_claims is dict[str, str], so convert lists to comma-separated strings
        safe_claims: dict[str, str] = {
            "auth_type": "oidc",
            "issuer": validated.issuer,
        }

        # Store audience as comma-separated string
        if validated.audience:
            safe_claims["audience"] = ",".join(validated.audience)

        # Store scopes as comma-separated string
        if validated.scopes:
            safe_claims["scopes"] = ",".join(sorted(validated.scopes))

        # Add optional claims if present (explicitly convert to str for type safety)
        email = validated.claims.get("email")
        if email:
            safe_claims["email"] = str(email)
        name = validated.claims.get("name")
        if name:
            safe_claims["name"] = str(name)

        return SubjectIdentity(
            subject_id=validated.subject_id,
            subject_claims=safe_claims,
        )

    def clear_cache(self) -> None:
        """Clear the identity cache.

        Forces re-validation on next get_identity() call.
        Useful for testing or after token refresh.
        """
        self._cache = None

    def logout(self, emit_event: bool = True) -> None:
        """Clear stored tokens, identity cache, and HITL approval cache.

        Call this to log out the user. They will need to run
        'mcp-acp auth login' to re-authenticate.

        Also clears the HITL approval cache to prevent stale approvals
        from being visible to subsequent users.

        Args:
            emit_event: Whether to emit SSE events (default True).
                Set to False if caller will handle notification.
        """
        self._storage.delete()
        self._cache = None
        self._current_token = None
        self._expiry_warned = False  # Reset for next login

        if self._proxy_state is None:
            return

        # Clear HITL approval cache - prevents stale approvals from being
        # visible to subsequent users and ensures clean slate on re-login.
        # Note: clear_all_cached_approvals() emits CACHE_CLEARED SSE event.
        self._proxy_state.clear_all_cached_approvals()

        # Emit SSE event for UI notification
        if emit_event:
            from mcp_acp.manager.events import SSEEventType

            self._proxy_state.emit_system_event(
                SSEEventType.AUTH_LOGOUT,
                severity="info",
                message="Logged out",
            )

    @property
    def is_authenticated(self) -> bool:
        """Check if user is authenticated (has stored token).

        Note: This doesn't validate the token, just checks if one exists.
        Use get_identity() to validate.

        Returns:
            True if token exists in storage.
        """
        return self._storage.exists()

    def reload_token_from_storage(self, emit_event: bool = True) -> bool:
        """Reload token from storage (after CLI login).

        Called by notify-login API endpoint when CLI stores new tokens.
        Clears cache to force re-validation on next get_identity().

        Args:
            emit_event: Whether to emit SSE event (default True).

        Returns:
            True if token was loaded, False if no token in storage.
        """
        self._cache = None
        self._expiry_warned = False  # Reset warning for new token
        token = self._storage.load()

        if token is None:
            return False

        self._current_token = token

        # Emit SSE event for UI notification
        if emit_event and self._proxy_state is not None:
            from mcp_acp.manager.events import SSEEventType

            self._proxy_state.emit_system_event(
                SSEEventType.AUTH_LOGIN,
                severity="success",
                message="Logged in",
            )

        return True
