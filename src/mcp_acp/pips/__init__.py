"""Policy Information Points (PIPs) - External attribute sources.

This module provides integrations with external systems that supply
attributes for policy decisions:

- auth/: OIDC authentication, token validation, session management
"""

# Namespace package - no direct exports, submodules accessed via:
#   from mcp_acp.pips.auth import SessionManager
__all__: list[str] = []
