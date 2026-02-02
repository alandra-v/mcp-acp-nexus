"""Authentication infrastructure for Zero Trust security.

This module provides:
- Token storage (OS keychain or encrypted file fallback)
- JWT validation with JWKS caching
- OAuth Device Flow for CLI authentication

These are authentication primitives used before policy evaluation.
The OIDCIdentityProvider (future) will use these to provide identity
to the policy engine.
"""

from mcp_acp.security.auth.device_flow import (
    DeviceCodeResponse,
    DeviceFlow,
    DeviceFlowResult,
    run_device_flow,
)
from mcp_acp.security.auth.jwt_validator import (
    JWTValidator,
    ValidatedToken,
)
from mcp_acp.security.auth.token_refresh import (
    refresh_tokens,
)
from mcp_acp.security.auth.token_storage import (
    EncryptedFileStorage,
    KeychainStorage,
    StoredToken,
    TokenStorage,
    create_token_storage,
    get_token_storage_info,
)

__all__ = [
    # Token storage
    "StoredToken",
    "TokenStorage",
    "KeychainStorage",
    "EncryptedFileStorage",
    "create_token_storage",
    "get_token_storage_info",
    # JWT validation
    "JWTValidator",
    "ValidatedToken",
    # Device flow
    "DeviceFlow",
    "DeviceCodeResponse",
    "DeviceFlowResult",
    "run_device_flow",
    # Token refresh
    "refresh_tokens",
]
