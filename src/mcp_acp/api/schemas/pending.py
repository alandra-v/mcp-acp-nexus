"""Pending HITL approval API schemas."""

from __future__ import annotations

__all__ = [
    "ApprovalActionResponse",
    "PendingApprovalResponse",
]

from datetime import datetime

from pydantic import BaseModel


class PendingApprovalResponse(BaseModel):
    """Response model for pending approval information.

    Attributes:
        id: Unique approval request ID.
        proxy_id: ID of the proxy that created this request.
        tool_name: The tool being invoked.
        path: The path being accessed (if applicable).
        source_path: Source path for move/copy operations (None for single-path ops).
        dest_path: Destination path for move/copy operations (None for single-path ops).
        subject_id: The user making the request.
        created_at: When the request was created.
        timeout_seconds: How long to wait for decision.
        request_id: Original MCP request ID for correlation.
        can_cache: Whether this approval can be cached.
        cache_ttl_seconds: How long cached approval will last (for UI display).
    """

    id: str
    proxy_id: str
    tool_name: str
    path: str | None
    source_path: str | None = None
    dest_path: str | None = None
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
