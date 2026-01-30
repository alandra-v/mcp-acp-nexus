"""Pending HITL approval API schemas."""

from __future__ import annotations

__all__ = [
    "ApprovalActionResponse",
    "PendingApprovalResponse",
]

from datetime import datetime

from pydantic import BaseModel


class PendingApprovalResponse(BaseModel):
    """Response model for pending approval information."""

    id: str
    proxy_id: str
    tool_name: str
    path: str | None
    subject_id: str
    created_at: datetime
    timeout_seconds: int
    request_id: str
    can_cache: bool = True
    cache_ttl_seconds: int | None = None


class ApprovalActionResponse(BaseModel):
    """Response model for approval actions (approve/deny)."""

    status: str
    approval_id: str
