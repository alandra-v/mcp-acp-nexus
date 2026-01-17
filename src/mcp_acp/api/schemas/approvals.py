"""Cached approvals API schemas."""

from __future__ import annotations

__all__ = [
    "ApprovalCacheResponse",
    "CachedApprovalResponse",
    "ClearApprovalsResponse",
    "DeleteApprovalResponse",
]

from pydantic import BaseModel


class CachedApprovalResponse(BaseModel):
    """Cached approval for API response."""

    subject_id: str
    tool_name: str
    path: str | None
    request_id: str
    age_seconds: float
    ttl_seconds: int
    expires_in_seconds: float


class ApprovalCacheResponse(BaseModel):
    """Full cache state response."""

    count: int
    ttl_seconds: int
    approvals: list[CachedApprovalResponse]


class ClearApprovalsResponse(BaseModel):
    """Response for clear approvals endpoint."""

    cleared: int
    status: str


class DeleteApprovalResponse(BaseModel):
    """Response for single approval delete."""

    deleted: bool
    status: str
