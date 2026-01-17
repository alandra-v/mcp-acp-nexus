"""Incidents API schemas."""

from __future__ import annotations

__all__ = [
    "IncidentsSummary",
]

from pydantic import BaseModel, Field


class IncidentsSummary(BaseModel):
    """Summary of incidents for badge state and overview.

    Provides counts and latest timestamps for determining unread state.

    Critical incidents (contribute to badge):
    - Shutdowns: Intentional security shutdowns (audit failure, session hijacking)
    - Emergency: Audit fallback entries when normal audit fails

    Informational (don't contribute to badge):
    - Bootstrap: Startup validation errors (config/policy issues)
    """

    shutdowns_count: int = Field(description="Number of security shutdown entries")
    emergency_count: int = Field(description="Number of emergency audit entries")
    bootstrap_count: int = Field(description="Number of bootstrap error entries")

    # Latest timestamp for critical incidents only (for badge calculation)
    # Bootstrap is informational and doesn't trigger badge
    latest_critical_timestamp: str | None = Field(
        default=None,
        description="ISO timestamp of most recent shutdown or emergency entry",
    )

    # File paths for debugging
    shutdowns_path: str | None = Field(default=None, description="Path to shutdowns.jsonl")
    emergency_path: str | None = Field(default=None, description="Path to emergency_audit.jsonl")
    bootstrap_path: str | None = Field(default=None, description="Path to bootstrap.jsonl")
