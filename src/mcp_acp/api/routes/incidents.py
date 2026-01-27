"""Incidents API endpoints.

Provides access to incident history:

- GET /api/incidents/shutdowns  - Security shutdowns (from shutdowns.jsonl)
- GET /api/incidents/bootstrap  - Bootstrap/startup errors (from bootstrap.jsonl)
- GET /api/incidents/emergency  - Emergency audit logs (from emergency_audit.jsonl)
- GET /api/incidents/summary    - Summary with counts and latest timestamps

Terminology:
- Shutdowns: Intentional security shutdowns (audit failure, session hijacking, etc.)
- Bootstrap: Startup validation errors (config/policy issues)
- Emergency: Audit fallback entries when normal audit fails

Routes mounted at: /api/incidents
"""

from __future__ import annotations

__all__ = ["router"]

import json
from pathlib import Path

from fastapi import APIRouter

from mcp_acp.api.deps import ConfigDep
from mcp_acp.api.schemas import IncidentsSummary, LogsResponse
from mcp_acp.utils.api import (
    BeforeQuery,
    LimitQuery,
    count_entries_and_latest,
    get_cutoff_time,
    get_log_base_path,
    parse_timestamp,
    read_jsonl_filtered,
    time_range_query,
)

router = APIRouter()


# =============================================================================
# File Path Helpers
# =============================================================================


def _get_shutdowns_path(config: "ConfigDep") -> Path:
    """Get path to shutdowns.jsonl in log directory (intentional security shutdowns)."""
    return get_log_base_path(config) / "shutdowns.jsonl"


def _get_bootstrap_path(config: "ConfigDep") -> Path:
    """Get path to bootstrap.jsonl in proxy config directory."""
    from mcp_acp.manager.config import get_proxy_config_path

    return get_proxy_config_path(config.proxy.name).parent / "bootstrap.jsonl"


def _get_emergency_path(config: "ConfigDep") -> Path:
    """Get path to emergency_audit.jsonl in proxy config directory."""
    from mcp_acp.manager.config import get_proxy_config_path

    return get_proxy_config_path(config.proxy.name).parent / "emergency_audit.jsonl"


# =============================================================================
# Query Parameters
# =============================================================================

# Shared params from api/utils/query_params: LimitQuery, BeforeQuery, time_range_query
# TimeRangeQuery uses "all" default for incidents (historical view)
TimeRangeQuery = time_range_query(default="all")


# =============================================================================
# Shared Helper Functions
# =============================================================================


def _fetch_incident_logs(
    log_path: Path,
    time_range: str,
    limit: int,
    before: str | None,
) -> LogsResponse:
    """Fetch incident logs from a JSONL file.

    Returns empty response if file doesn't exist (not an error for incidents).
    """
    if not log_path.exists():
        return LogsResponse(
            entries=[],
            total_returned=0,
            total_scanned=0,
            log_file=str(log_path),
            has_more=False,
            filters_applied={"time_range": time_range},
        )

    cutoff_time = get_cutoff_time(time_range)
    before_dt = parse_timestamp(before)

    entries, has_more, scanned = read_jsonl_filtered(
        log_path,
        limit,
        cutoff_time=cutoff_time,
        before=before_dt,
    )

    return LogsResponse(
        entries=entries,
        total_returned=len(entries),
        total_scanned=scanned,
        log_file=str(log_path),
        has_more=has_more,
        filters_applied={"time_range": time_range},
    )


# =============================================================================
# Incident Log Endpoints
# =============================================================================


@router.get("/shutdowns", response_model=LogsResponse)
async def get_shutdowns(
    config: ConfigDep,
    time_range: str = TimeRangeQuery,
    limit: int = LimitQuery,
    before: str | None = BeforeQuery,
) -> LogsResponse:
    """Get security shutdown logs (newest first).

    Returns entries from shutdowns.jsonl including:
    - Timestamp, failure type, exit code, reason, context

    These are INTENTIONAL security shutdowns (audit failure, session hijacking, etc.)
    """
    return _fetch_incident_logs(
        _get_shutdowns_path(config),
        time_range,
        limit,
        before,
    )


@router.get("/bootstrap", response_model=LogsResponse)
async def get_bootstrap_logs(
    config: ConfigDep,
    time_range: str = TimeRangeQuery,
    limit: int = LimitQuery,
    before: str | None = BeforeQuery,
) -> LogsResponse:
    """Get bootstrap/startup error logs (newest first).

    Returns entries from bootstrap.jsonl including:
    - Timestamp, event type, validation errors, component info
    """
    return _fetch_incident_logs(
        _get_bootstrap_path(config),
        time_range,
        limit,
        before,
    )


@router.get("/emergency", response_model=LogsResponse)
async def get_emergency_logs(
    config: ConfigDep,
    time_range: str = TimeRangeQuery,
    limit: int = LimitQuery,
    before: str | None = BeforeQuery,
) -> LogsResponse:
    """Get emergency audit logs (newest first).

    Returns entries from emergency_audit.jsonl including:
    - Timestamp, event type, failure reason, original operation data
    """
    return _fetch_incident_logs(
        _get_emergency_path(config),
        time_range,
        limit,
        before,
    )


@router.get("/summary", response_model=IncidentsSummary)
async def get_incidents_summary(config: ConfigDep) -> IncidentsSummary:
    """Get summary of all incidents.

    Returns counts and latest critical timestamp for badge calculation.
    Bootstrap errors are informational and don't count toward the badge.

    Critical incidents (contribute to badge):
    - Shutdowns: Intentional security shutdowns
    - Emergency: Audit fallback entries

    Informational (don't contribute to badge):
    - Bootstrap: Startup validation errors
    """
    shutdowns_path = _get_shutdowns_path(config)
    bootstrap_path = _get_bootstrap_path(config)
    emergency_path = _get_emergency_path(config)

    shutdowns_count, shutdowns_latest = count_entries_and_latest(shutdowns_path)
    bootstrap_count, _ = count_entries_and_latest(bootstrap_path)
    emergency_count, emergency_latest = count_entries_and_latest(emergency_path)

    # Latest critical timestamp is max of shutdowns and emergency (not bootstrap)
    critical_timestamps = [t for t in [shutdowns_latest, emergency_latest] if t]
    latest_critical = max(critical_timestamps) if critical_timestamps else None

    return IncidentsSummary(
        shutdowns_count=shutdowns_count,
        emergency_count=emergency_count,
        bootstrap_count=bootstrap_count,
        latest_critical_timestamp=latest_critical,
        shutdowns_path=str(shutdowns_path) if shutdowns_path.exists() else None,
        emergency_path=str(emergency_path) if emergency_path.exists() else None,
        bootstrap_path=str(bootstrap_path) if bootstrap_path.exists() else None,
    )
