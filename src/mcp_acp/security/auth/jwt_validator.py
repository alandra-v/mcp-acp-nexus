"""JWT validation with JWKS caching for Auth0/OIDC tokens.

Validates OAuth access tokens using the JWKS (JSON Web Key Set) from
the OIDC provider. Implements caching to avoid fetching keys on every
request while still supporting key rotation.

Zero Trust: Per-request validation with 10-minute JWKS cache for performance.
"""

from __future__ import annotations

__all__ = [
    "JWTValidator",
    "ValidatedToken",
]

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

import httpx
import jwt
from jwt import PyJWKClient, PyJWKClientError

from mcp_acp.constants import JWKS_CACHE_TTL_SECONDS
from mcp_acp.exceptions import AuthenticationError, IdentityVerificationFailure

# Timeout for JWKS fetch - fail fast if identity provider is unreachable
JWKS_FETCH_TIMEOUT_SECONDS = 5

if TYPE_CHECKING:
    from mcp_acp.config import OIDCConfig


@dataclass
class ValidatedToken:
    """Result of successful token validation.

    Attributes:
        subject_id: The 'sub' claim - unique user identifier.
        issuer: The 'iss' claim - token issuer (Auth0 tenant).
        audience: The 'aud' claim - intended audience(s).
        scopes: OAuth scopes granted (from 'scope' claim).
        expires_at: When the token expires (from 'exp' claim).
        issued_at: When the token was issued (from 'iat' claim).
        auth_time: When user originally authenticated (from 'auth_time').
        claims: All token claims for extensibility.
    """

    subject_id: str
    issuer: str
    audience: list[str]
    scopes: frozenset[str]
    expires_at: datetime
    issued_at: datetime
    auth_time: datetime | None
    claims: dict[str, Any] = field(default_factory=dict)

    @property
    def token_age_seconds(self) -> float:
        """Seconds since token was issued."""
        return (datetime.now(timezone.utc) - self.issued_at).total_seconds()

    @property
    def auth_age_seconds(self) -> float | None:
        """Seconds since user originally authenticated."""
        if self.auth_time is None:
            return None
        return (datetime.now(timezone.utc) - self.auth_time).total_seconds()


@dataclass
class _CachedJWKS:
    """Cached JWKS client with expiration tracking."""

    client: PyJWKClient
    fetched_at: float
    ttl: float = JWKS_CACHE_TTL_SECONDS

    @property
    def is_expired(self) -> bool:
        """Check if cache has expired."""
        return time.monotonic() - self.fetched_at > self.ttl


class JWTValidator:
    """Validates JWT tokens using JWKS from OIDC provider.

    Features:
    - Fetches and caches JWKS from the issuer's well-known endpoint
    - Validates signature using RSA/EC keys from JWKS
    - Verifies issuer, audience, and expiration claims
    - Extracts scopes and user identity

    Usage:
        validator = JWTValidator(oidc_config)
        result = validator.validate(access_token)
        print(f"User: {result.subject_id}, Scopes: {result.scopes}")
    """

    def __init__(self, config: "OIDCConfig") -> None:
        """Initialize JWT validator.

        Args:
            config: OIDC configuration with issuer, client_id, audience.
        """
        self._config = config
        self._jwks_cache: _CachedJWKS | None = None

        # Keep issuer as-is for token validation (Auth0 includes trailing slash)
        # Only strip trailing slash for JWKS URI to avoid double slashes
        self._issuer = config.issuer
        issuer_base = config.issuer.rstrip("/")
        self._jwks_uri = f"{issuer_base}/.well-known/jwks.json"

    async def ensure_jwks_available(self) -> None:
        """Verify JWKS endpoint is reachable (async pre-flight check).

        Must be called from async context before validate() to ensure
        the identity provider is reachable. Uses async httpx which has
        proper timeout support (sync httpx has timeout bugs).

        Raises:
            IdentityVerificationFailure: If JWKS endpoint unreachable.
        """
        # Skip if we have a valid cache
        if self._jwks_cache is not None and not self._jwks_cache.is_expired:
            return

        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(JWKS_FETCH_TIMEOUT_SECONDS, connect=JWKS_FETCH_TIMEOUT_SECONDS)
            ) as client:
                response = await client.get(self._jwks_uri, follow_redirects=True)
                response.raise_for_status()
        except httpx.TimeoutException as e:
            raise IdentityVerificationFailure(
                f"Connection to identity provider timed out after {JWKS_FETCH_TIMEOUT_SECONDS}s.\n"
                f"Endpoint: {self._jwks_uri}\n\n"
                f"Check your OIDC issuer configuration in manager.json.\n"
                f"Run 'mcp-acp init' to reconfigure if needed."
            ) from e
        except httpx.HTTPStatusError as e:
            raise IdentityVerificationFailure(
                f"Identity provider returned error: HTTP {e.response.status_code}\n"
                f"Endpoint: {self._jwks_uri}\n\n"
                f"Check your OIDC issuer configuration in manager.json.\n"
                f"Run 'mcp-acp init' to reconfigure if needed."
            ) from e
        except httpx.RequestError as e:
            raise IdentityVerificationFailure(
                f"Cannot reach identity provider: {type(e).__name__}\n"
                f"Endpoint: {self._jwks_uri}\n\n"
                f"Check your OIDC issuer configuration in manager.json.\n"
                f"Run 'mcp-acp init' to reconfigure if needed."
            ) from e

    def _get_jwks_client(self) -> PyJWKClient:
        """Get or create JWKS client with caching.

        IMPORTANT: Call ensure_jwks_available() first from async context.
        The sync httpx client has timeout bugs for unreachable hosts.

        Returns:
            PyJWKClient configured for the issuer's JWKS endpoint.

        Raises:
            IdentityVerificationFailure: If JWKS fetch fails and no valid cache exists.
        """
        # Return cached client if still valid
        if self._jwks_cache is not None and not self._jwks_cache.is_expired:
            return self._jwks_cache.client

        # Cache is expired or doesn't exist - must fetch fresh JWKS
        # Note: ensure_jwks_available() should have been called first to verify connectivity
        try:
            client = PyJWKClient(
                self._jwks_uri,
                cache_keys=True,
                lifespan=JWKS_CACHE_TTL_SECONDS,
                timeout=JWKS_FETCH_TIMEOUT_SECONDS,
            )
            _ = client.get_jwk_set()

            self._jwks_cache = _CachedJWKS(
                client=client,
                fetched_at=time.monotonic(),
            )
            return client

        except (PyJWKClientError, Exception) as e:
            error_detail = str(e) if str(e) else type(e).__name__
            raise IdentityVerificationFailure(
                f"Cannot reach identity provider at {self._jwks_uri}\n"
                f"Error: {error_detail}\n\n"
                f"Check your OIDC issuer configuration in manager.json.\n"
                f"Run 'mcp-acp init' to reconfigure if needed."
            ) from e

    def _normalize_audience(self, aud: str | list[str]) -> list[str]:
        """Normalize audience claim to list.

        Args:
            aud: Audience claim (string or list).

        Returns:
            List of audience strings.
        """
        if isinstance(aud, str):
            return [aud]
        return list(aud)

    def validate(self, token: str) -> ValidatedToken:
        """Validate a JWT access token.

        Performs full validation:
        1. Fetch signing key from JWKS (cached)
        2. Verify signature
        3. Check issuer matches configured value
        4. Check audience matches configured value
        5. Verify token is not expired
        6. Extract claims

        Args:
            token: JWT access token string.

        Returns:
            ValidatedToken with extracted claims.

        Raises:
            AuthenticationError: If validation fails for any reason.
        """
        # Get signing key from JWKS
        try:
            jwks_client = self._get_jwks_client()
            signing_key = jwks_client.get_signing_key_from_jwt(token)
        except PyJWKClientError as e:
            raise AuthenticationError(f"Failed to get signing key: {e}") from e

        # Validate and decode token
        try:
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256", "ES256"],
                issuer=self._issuer,
                audience=self._config.audience,
                options={
                    "require": ["exp", "iat", "sub", "iss", "aud"],
                    "verify_exp": True,
                    "verify_iat": True,
                    "verify_iss": True,
                    "verify_aud": True,
                },
            )
        except jwt.ExpiredSignatureError as e:
            raise AuthenticationError("Token has expired") from e
        except jwt.InvalidIssuerError as e:
            raise AuthenticationError(f"Token issuer mismatch: expected {self._issuer}") from e
        except jwt.InvalidAudienceError as e:
            raise AuthenticationError(f"Token audience mismatch: expected {self._config.audience}") from e
        except jwt.InvalidSignatureError as e:
            raise AuthenticationError("Token signature is invalid") from e
        except jwt.DecodeError as e:
            raise AuthenticationError(f"Token decode error: {e}") from e
        except jwt.PyJWTError as e:
            raise AuthenticationError(f"Token validation error: {e}") from e

        # Extract and normalize claims
        subject_id = claims["sub"]
        issuer = claims["iss"]
        audience = self._normalize_audience(claims["aud"])

        # Parse scope claim (space-separated string)
        scope_str = claims.get("scope", "")
        scopes = frozenset(scope_str.split()) if scope_str else frozenset()

        # Parse timestamps
        expires_at = datetime.fromtimestamp(claims["exp"], tz=timezone.utc)
        issued_at = datetime.fromtimestamp(claims["iat"], tz=timezone.utc)

        # auth_time is optional (present after interactive authentication)
        auth_time = None
        if "auth_time" in claims:
            auth_time = datetime.fromtimestamp(claims["auth_time"], tz=timezone.utc)

        return ValidatedToken(
            subject_id=subject_id,
            issuer=issuer,
            audience=audience,
            scopes=scopes,
            expires_at=expires_at,
            issued_at=issued_at,
            auth_time=auth_time,
            claims=claims,
        )

    def validate_id_token(self, id_token: str) -> ValidatedToken:
        """Validate an OIDC ID token.

        ID tokens have slightly different validation requirements:
        - Audience is the client_id (not the API audience)
        - May contain additional OIDC claims (name, email, etc.)

        Args:
            id_token: OIDC ID token string.

        Returns:
            ValidatedToken with extracted claims.

        Raises:
            AuthenticationError: If validation fails.
        """
        # Get signing key from JWKS
        try:
            jwks_client = self._get_jwks_client()
            signing_key = jwks_client.get_signing_key_from_jwt(id_token)
        except PyJWKClientError as e:
            raise AuthenticationError(f"Failed to get signing key: {e}") from e

        # Validate ID token - audience is client_id
        try:
            claims = jwt.decode(
                id_token,
                signing_key.key,
                algorithms=["RS256", "ES256"],
                issuer=self._issuer,
                audience=self._config.client_id,
                options={
                    "require": ["exp", "iat", "sub", "iss", "aud"],
                    "verify_exp": True,
                    "verify_iat": True,
                    "verify_iss": True,
                    "verify_aud": True,
                },
            )
        except jwt.PyJWTError as e:
            raise AuthenticationError(f"ID token validation error: {e}") from e

        # Parse claims (same as access token)
        subject_id = claims["sub"]
        issuer = claims["iss"]
        audience = self._normalize_audience(claims["aud"])
        expires_at = datetime.fromtimestamp(claims["exp"], tz=timezone.utc)
        issued_at = datetime.fromtimestamp(claims["iat"], tz=timezone.utc)

        auth_time = None
        if "auth_time" in claims:
            auth_time = datetime.fromtimestamp(claims["auth_time"], tz=timezone.utc)

        # ID tokens don't have scope claim typically
        scopes: frozenset[str] = frozenset()

        return ValidatedToken(
            subject_id=subject_id,
            issuer=issuer,
            audience=audience,
            scopes=scopes,
            expires_at=expires_at,
            issued_at=issued_at,
            auth_time=auth_time,
            claims=claims,
        )

    def decode_without_validation(self, token: str) -> dict[str, Any]:
        """Decode token without validating signature.

        WARNING: Does not validate signature! Only use for extracting claims
        from trusted tokens (e.g., id_token from our own auth flow) for
        display purposes.

        Args:
            token: JWT token string.

        Returns:
            Token claims dict.

        Raises:
            AuthenticationError: If token is malformed.
        """
        try:
            claims: dict[str, Any] = jwt.decode(token, options={"verify_signature": False})
            return claims
        except jwt.DecodeError as e:
            raise AuthenticationError(f"Failed to decode token: {e}") from e

    def clear_cache(self) -> None:
        """Clear the JWKS cache.

        Use this if you need to force a fresh fetch, e.g., after key rotation.
        """
        self._jwks_cache = None
