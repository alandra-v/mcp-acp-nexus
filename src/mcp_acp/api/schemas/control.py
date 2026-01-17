"""Proxy control API schemas."""

from __future__ import annotations

__all__ = [
    "ProxyStatus",
    "ReloadResponse",
]

from pydantic import BaseModel


class ProxyStatus(BaseModel):
    """Proxy and policy status."""

    running: bool
    uptime_seconds: float
    policy_version: str | None
    policy_rules_count: int
    last_reload_at: str | None
    reload_count: int


class ReloadResponse(BaseModel):
    """Policy reload response."""

    status: str  # "success", "validation_error", "file_error"
    old_rules_count: int
    new_rules_count: int
    approvals_cleared: int
    error: str | None = None
    policy_version: str | None = None
