"""Authentication Policy Information Point.

This module contains identity providers that extract user identity from
authentication tokens for policy decisions (ABAC Subject).

Identity Providers:
- OIDCIdentityProvider: Pattern 1 (STDIO) - loads from keychain, validates JWT
- HTTPIdentityProvider: Pattern 2 (HTTP) - uses FastMCP get_access_token() [Future]

Session Management:
- BoundSession: Session bound to authenticated user (format: <user_id>:<session_id>)
- SessionManager: Create, validate, and manage user-bound sessions

Authentication primitives (token storage, JWT validation) are in security/auth/.
Device health checks are in security/posture/.
Auth audit logging is in telemetry/audit/auth_logger.py.

See docs/design/authentication_implementation.md for architecture details.
"""

from mcp_acp.pips.auth.claims import (
    build_subject_from_identity,
    build_subject_from_validated_token,
)
from mcp_acp.pips.auth.oidc_provider import OIDCIdentityProvider
from mcp_acp.pips.auth.session import (
    BoundSession,
    SessionManager,
    parse_bound_session_id,
)

__all__ = [
    "BoundSession",
    "OIDCIdentityProvider",
    "SessionManager",
    "build_subject_from_identity",
    "build_subject_from_validated_token",
    "parse_bound_session_id",
]
