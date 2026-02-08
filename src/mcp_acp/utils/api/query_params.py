"""Shared FastAPI query parameter definitions.

Provides reusable Query() definitions for common API parameters like
pagination (limit, before cursor) and time range filtering.

Usage:
    from mcp_acp.utils.api import LimitQuery, BeforeQuery, time_range_query

    @router.get("/logs")
    async def get_logs(
        limit: int = LimitQuery,
        before: str | None = BeforeQuery,
        time_range: TimeRange = time_range_query(default="5m"),
    ) -> LogsResponse:
        ...
"""

from __future__ import annotations

__all__ = [
    "BeforeQuery",
    "LimitQuery",
    "TimeRange",
    "time_range_query",
]

from typing import Any, Literal

# Type alias for time_range parameter values
TimeRange = Literal["5m", "1h", "24h", "all"]

from fastapi import Query


# =============================================================================
# Pagination Parameters
# =============================================================================

LimitQuery = Query(
    default=100,
    ge=1,
    le=1000,
    description="Max entries to return",
)

BeforeQuery = Query(
    default=None,
    description="Cursor for pagination: ISO timestamp to get entries older than this",
)


# =============================================================================
# Time Range Parameter
# =============================================================================

# Valid time range values and their regex pattern
TIME_RANGE_PATTERN = "^(5m|1h|24h|all)$"
TIME_RANGE_DESCRIPTION = "Time range: 5m, 1h, 24h, or all"


def time_range_query(default: str = "5m") -> Any:
    """Create a time range query parameter with configurable default.

    Args:
        default: Default time range value. Must be one of: 5m, 1h, 24h, all.

    Returns:
        FastAPI Query parameter definition (FieldInfo).

    Example:
        # For logs (default to recent):
        time_range: TimeRange = time_range_query(default="5m")

        # For incidents (default to all):
        time_range: TimeRange = time_range_query(default="all")
    """
    return Query(
        default=default,
        description=TIME_RANGE_DESCRIPTION,
        pattern=TIME_RANGE_PATTERN,
    )
