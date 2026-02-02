"""API route modules.

Route organization:
- approvals: Cached HITL approvals (previously approved decisions)
- pending: Pending HITL approvals (waiting for user decision)
- proxies: Proxy information
- sessions: Auth sessions (user authentication bindings)
- control: Proxy control (status, policy reload)
- policy: Policy management (CRUD)
- auth: Authentication management (login, logout, status)
- config: Configuration management (read, update)
- logs: Log viewer (decisions, operations, auth, system)
- incidents: Security shutdowns, bootstrap errors, emergency audit logs
- stats: Request statistics with latency data
- debug: Debug endpoints for testing
"""

from . import (
    approvals,
    auth,
    config,
    control,
    debug,
    incidents,
    logs,
    pending,
    policy,
    proxies,
    sessions,
    stats,
)

__all__ = [
    "approvals",
    "auth",
    "config",
    "control",
    "debug",
    "incidents",
    "logs",
    "pending",
    "policy",
    "proxies",
    "sessions",
    "stats",
]
