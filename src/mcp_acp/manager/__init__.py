"""Manager package for UI backend infrastructure.

Provides state classes that expose proxy state to the web UI.
The proxy is the source of truth for all state - this package wraps existing
state (ApprovalStore, SessionManager) for API access.

Architecture:
    - Proxy owns all state (approvals, sessions)
    - ProxyState aggregates state for API exposure
    - API routes live in api/routes/ (not here)
    - In multi-proxy Phase 2, Manager will query proxies via their APIs
"""

from .state import (
    CachedApprovalSummary,
    PendingApprovalInfo,
    PendingApprovalRequest,
    ProxyInfo,
    ProxyState,
    get_global_proxy_state,
    set_global_proxy_state,
)

__all__ = [
    "CachedApprovalSummary",
    "PendingApprovalInfo",
    "PendingApprovalRequest",
    "ProxyInfo",
    "ProxyState",
    "get_global_proxy_state",
    "set_global_proxy_state",
]
