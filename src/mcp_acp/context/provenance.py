"""Provenance tracking for security-relevant facts.

Every security-relevant fact should carry its source. This allows policies
to make trust decisions based on how information was obtained.

Trust hierarchy (high to low):
- TOKEN, MTLS: Cryptographically verified
- DIRECTORY: From trusted identity store
- PROXY_CONFIG: Admin-controlled configuration
- MCP_METHOD, MCP_REQUEST: From protocol (not verified)
- DERIVED: Computed by proxy (document assumptions)
- CLIENT_HINT: Client-provided, NOT TRUSTED
"""

from __future__ import annotations

__all__ = ["Provenance"]

from enum import Enum


class Provenance(str, Enum):
    """Source of a fact in the decision context.

    Used to track where security-relevant information came from,
    enabling policies to make trust decisions accordingly.

    Attributes:
        TOKEN: Validated OIDC/OAuth token claim (Stage 2+)
        DIRECTORY: IdP/LDAP/DB lookup
        MTLS: mTLS peer certificate
        PROXY_CONFIG: Static proxy configuration (e.g., server_name)
        MCP_METHOD: From MCP method semantics (e.g., "resources/read" → read)
        MCP_REQUEST: From MCP request arguments (tool name, path)
        DERIVED: Computed by proxy (heuristics, defaults, assumptions)
        CLIENT_HINT: Client-provided, NOT TRUSTED
    """

    TOKEN = "token"
    DIRECTORY = "directory"
    MTLS = "mtls"
    PROXY_CONFIG = "proxy_config"
    MCP_METHOD = "mcp_method"
    MCP_REQUEST = "mcp_request"
    DERIVED = "derived"
    CLIENT_HINT = "client_hint"
