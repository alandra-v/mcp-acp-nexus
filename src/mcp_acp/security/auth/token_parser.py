"""Shared OAuth token response parsing.

Extracts duplicated token parsing logic from device_flow.py and token_refresh.py
to a single shared utility.
"""

from __future__ import annotations

__all__ = ["parse_token_response"]

from datetime import datetime, timezone
from typing import Any

from mcp_acp.security.auth.token_storage import StoredToken


def parse_token_response(data: dict[str, Any]) -> StoredToken:
    """Parse OAuth token response into StoredToken.

    Handles standard OAuth 2.0 token response fields:
    - access_token (required)
    - refresh_token (optional)
    - id_token (optional, for OIDC)
    - expires_in (optional, defaults to 24h)

    Args:
        data: Token response JSON from OAuth provider.

    Returns:
        StoredToken ready for storage.
    """
    now = datetime.now(timezone.utc)
    expires_in = data.get("expires_in", 86400)  # Default 24h

    return StoredToken(
        access_token=data["access_token"],
        refresh_token=data.get("refresh_token"),
        id_token=data.get("id_token"),
        expires_at=datetime.fromtimestamp(now.timestamp() + expires_in, tz=timezone.utc),
        issued_at=now,
    )
