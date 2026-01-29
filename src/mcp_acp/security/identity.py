"""Identity providers for extracting user identity.

Supports two transport patterns:
- Pattern 1 (STDIO): OIDCIdentityProvider loads from keychain, validates JWT
- Pattern 2 (HTTP): HTTPIdentityProvider uses FastMCP get_access_token() [Future]

Zero Trust: Authentication is MANDATORY. There is no unauthenticated fallback.
The proxy refuses to start without valid OIDC configuration.

LocalIdentityProvider exists only for unit tests (not exported for production use).

All identity providers are async to support:
- OIDC token validation (network calls to JWKS endpoint)
- Token refresh (network calls to token endpoint)
- Concurrency-safe cache access with asyncio.Lock

See docs/design/authentication_implementation.md for architecture details.
"""

from __future__ import annotations

__all__ = [
    "IdentityProvider",
    "LocalIdentityProvider",
    "create_identity_provider",
]

import getpass
from typing import TYPE_CHECKING, Literal, Protocol, runtime_checkable

from mcp_acp.telemetry.models.audit import SubjectIdentity

if TYPE_CHECKING:
    from mcp_acp.config import AppConfig
    from mcp_acp.telemetry.audit.auth_logger import AuthLogger


@runtime_checkable
class IdentityProvider(Protocol):
    """Protocol for pluggable identity providers.

    Implementations provide user identity for audit logging and policy decisions.
    The middleware layer uses this protocol without knowing the concrete provider.

    Pattern 1 (STDIO): OIDCIdentityProvider - loads from keychain
    Pattern 2 (HTTP): HTTPIdentityProvider - uses get_access_token() [Future]

    All implementations must be async to support OIDC token operations.
    """

    async def get_identity(self) -> SubjectIdentity:
        """Get the current user's identity.

        Returns:
            SubjectIdentity with subject_id and optional claims.
        """
        ...


class LocalIdentityProvider:
    """Local user identity via getpass.getuser() - FOR TESTS ONLY.

    Uses Python's cross-platform getpass.getuser() which:
    - Tries environment variables: LOGNAME -> USER -> LNAME -> USERNAME
    - Falls back to pwd.getpwuid(os.getuid()).pw_name on Unix

    Identity is cached at initialization since local username doesn't
    change during proxy lifetime.

    WARNING: This provider is for unit tests only. It is NOT exported
    for production use. Production deployments MUST use OIDCIdentityProvider.
    """

    def __init__(self) -> None:
        """Initialize and cache the local user identity."""
        self._cached = self._resolve_local_user()

    def _resolve_local_user(self) -> SubjectIdentity:
        """Resolve local username via getpass.getuser().

        Returns:
            SubjectIdentity with local username and auth_type claim.
        """
        username = getpass.getuser()
        return SubjectIdentity(
            subject_id=username,
            subject_claims={"auth_type": "local"},
        )

    async def get_identity(self) -> SubjectIdentity:
        """Get the cached local user identity.

        Async for protocol compatibility with OIDCIdentityProvider.
        Local identity is cached at init, so this is a fast synchronous return.

        Returns:
            SubjectIdentity with local username.
        """
        return self._cached


def create_identity_provider(
    config: "AppConfig | None" = None,
    transport: Literal["stdio", "http"] = "stdio",
    auth_logger: "AuthLogger | None" = None,
) -> IdentityProvider:
    """Create the appropriate identity provider for the transport.

    Zero Trust: Authentication is MANDATORY. Raises error if not configured.

    Args:
        config: Application configuration with auth settings. Required.
        transport: Transport type ("stdio" or "http").
        auth_logger: Logger for auth events to auth.jsonl.

    Returns:
        IdentityProvider appropriate for the configuration:
        - stdio + auth: OIDCIdentityProvider (loads from keychain)
        - http + auth: HTTPIdentityProvider [Future]

    Raises:
        AuthenticationError: If auth not configured or OIDC auth fails.
    """
    from mcp_acp.exceptions import AuthenticationError

    # Zero Trust: auth is MANDATORY - no unauthenticated fallback
    if config is None or config.auth is None:
        raise AuthenticationError("Authentication not configured. Run 'mcp-acp init' to configure.")

    # Auth configured - use OIDC provider based on transport
    if transport == "stdio":
        # Pattern 1: STDIO transport - load from keychain
        from mcp_acp.pips.auth import OIDCIdentityProvider

        return OIDCIdentityProvider(config.auth.oidc, auth_logger=auth_logger)
    else:
        # Pattern 2: HTTP transport - use FastMCP get_access_token() [Future]
        raise NotImplementedError(
            "HTTP transport authentication not yet implemented. "
            "Use STDIO transport or wait for future release."
        )
