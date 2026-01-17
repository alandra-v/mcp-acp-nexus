"""Token refresh for OAuth refresh_token grant.

When access_token expires, use refresh_token to obtain new tokens
without requiring user interaction.

Flow:
1. Access token expires
2. Call refresh_tokens() with refresh_token
3. Get new access_token (and possibly new refresh_token)
4. Store updated tokens
"""

from __future__ import annotations

__all__ = [
    "TokenRefreshError",
    "TokenRefreshExpiredError",
    "refresh_tokens",
]

from typing import TYPE_CHECKING

import httpx

from mcp_acp.constants import OAUTH_CLIENT_TIMEOUT_SECONDS
from mcp_acp.exceptions import AuthenticationError
from mcp_acp.security.auth.token_parser import parse_token_response
from mcp_acp.security.auth.token_storage import StoredToken

if TYPE_CHECKING:
    from mcp_acp.config import OIDCConfig


class TokenRefreshError(AuthenticationError):
    """Token refresh failed."""

    pass


class TokenRefreshExpiredError(TokenRefreshError):
    """Refresh token has expired - user must re-authenticate."""

    pass


def refresh_tokens(
    config: "OIDCConfig",
    refresh_token: str,
    http_client: httpx.Client | None = None,
) -> StoredToken:
    """Refresh access token using refresh_token grant.

    Args:
        config: OIDC configuration.
        refresh_token: Valid refresh token.
        http_client: Optional httpx client (for testing).

    Returns:
        New StoredToken with refreshed access_token.

    Raises:
        TokenRefreshExpiredError: If refresh token has expired (user must re-login).
        TokenRefreshError: For other refresh failures.
    """
    client = http_client or httpx.Client(timeout=OAUTH_CLIENT_TIMEOUT_SECONDS)
    owns_client = http_client is None

    try:
        issuer = config.issuer.rstrip("/")
        token_url = f"{issuer}/oauth/token"

        response = client.post(
            token_url,
            data={
                "grant_type": "refresh_token",
                "client_id": config.client_id,
                "refresh_token": refresh_token,
            },
        )

        if response.status_code == 200:
            token_data = response.json()
            return _parse_token_response(token_data)

        # Handle error responses
        error_data = {}
        try:
            error_data = response.json()
        except Exception:
            pass

        error = error_data.get("error", "")
        error_desc = error_data.get("error_description", str(response.status_code))

        if error in ("invalid_grant", "expired_token"):
            raise TokenRefreshExpiredError(
                "Refresh token has expired. Please run 'auth login' to re-authenticate."
            )

        raise TokenRefreshError(f"Token refresh failed: {error_desc}")

    except httpx.HTTPError as e:
        raise TokenRefreshError(f"HTTP error during token refresh: {e}") from e

    finally:
        if owns_client:
            client.close()


def _parse_token_response(data: dict) -> StoredToken:
    """Parse token response from Auth0.

    Args:
        data: Token response JSON.

    Returns:
        StoredToken ready for storage.
    """
    return parse_token_response(data)
