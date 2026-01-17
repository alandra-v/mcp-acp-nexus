"""Validation utilities for mcp-acp-nexus.

Provides reusable validation functions for configuration values.
"""

from __future__ import annotations

__all__ = [
    "SHA256_HEX_LENGTH",
    "is_valid_http_url",
    "is_valid_oidc_issuer",
    "validate_sha256_hex",
]

# SHA-256 hash is 256 bits = 32 bytes = 64 hex characters
SHA256_HEX_LENGTH: int = 64

# Valid hexadecimal characters (lowercase)
_SHA256_VALID_CHARS: frozenset[str] = frozenset("0123456789abcdef")


def validate_sha256_hex(value: str) -> tuple[bool, str | None]:
    """Validate a SHA-256 hash hex string.

    Args:
        value: The hex string to validate.

    Returns:
        Tuple of (is_valid, normalized_value).
        - If valid: (True, lowercase_normalized_hash)
        - If invalid: (False, None)

    Example:
        >>> valid, normalized = validate_sha256_hex("ABC123...")
        >>> if valid:
        ...     config.expected_sha256 = normalized
    """
    if not value:
        return False, None

    normalized = value.strip().lower()

    if len(normalized) != SHA256_HEX_LENGTH:
        return False, None

    if not all(c in _SHA256_VALID_CHARS for c in normalized):
        return False, None

    return True, normalized


def is_valid_http_url(url: str) -> bool:
    """Check if URL has valid HTTP or HTTPS scheme.

    Args:
        url: URL string to validate.

    Returns:
        True if URL starts with http:// or https://.
    """
    return url.startswith("http://") or url.startswith("https://")


def is_valid_oidc_issuer(url: str) -> bool:
    """Check if OIDC issuer URL has valid HTTPS scheme.

    OIDC issuers must use HTTPS per the OpenID Connect specification.

    Args:
        url: URL string to validate.

    Returns:
        True if URL starts with https://.
    """
    return url.startswith("https://")
