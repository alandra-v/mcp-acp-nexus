"""Policy Enforcement Point (PEP) - Request interception and enforcement.

This module intercepts requests, calls PIP for context, PDP for decisions,
and enforces the decision. Following NIST SP 800-207 Zero Trust Architecture:

- PIP (Policy Information Point): ../pip/ - gathers context/attributes
- PDP (Policy Decision Point): ../pdp/ - evaluates policies
- PEP (Policy Enforcement Point): This module - enforces decisions

Request flow:
1. PEP intercepts request via middleware
2. PEP calls context builder to build DecisionContext
3. PEP calls PDP to evaluate policy → Decision
4. PEP enforces: ALLOW → forward, DENY → error, HITL → approval flow

Middleware order: Context (outer) -> Audit -> ClientLogger -> Enforcement (inner)

Structure:
    context_middleware.py - ContextMiddleware (outermost, sets up request context)
    middleware.py         - PolicyEnforcementMiddleware (innermost, enforces policy)
    hitl.py               - HITLHandler for user approval dialogs

Note: PermissionDeniedError is defined in mcp_acp.exceptions
"""

from mcp_acp.exceptions import PERMISSION_DENIED_CODE, PermissionDeniedError
from mcp_acp.pep.approval_store import ApprovalStore, CachedApproval
from mcp_acp.pep.context_middleware import ContextMiddleware, create_context_middleware
from mcp_acp.pep.hitl import HITLHandler, HITLOutcome, HITLResult
from mcp_acp.pep.middleware import (
    PolicyEnforcementMiddleware,
    create_enforcement_middleware,
)
from mcp_acp.pep.reloader import PolicyReloader, ReloadResult

__all__ = [
    # Errors
    "PermissionDeniedError",
    "PERMISSION_DENIED_CODE",
    # Approval caching
    "ApprovalStore",
    "CachedApproval",
    # HITL
    "HITLHandler",
    "HITLOutcome",
    "HITLResult",
    # Middleware
    "ContextMiddleware",
    "create_context_middleware",
    "PolicyEnforcementMiddleware",
    "create_enforcement_middleware",
    # Hot reload
    "PolicyReloader",
    "ReloadResult",
]
