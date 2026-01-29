"""Incidents aggregation endpoints.

Design record — system.jsonl events evaluated for incident-page inclusion:

- audit_fallback: Primary audit log failed, event written to system.jsonl as
  fallback. NOT surfaced here because the audit failure always triggers a proxy
  shutdown afterwards, which is recorded in shutdowns.jsonl (failure_type
  "audit_failure") and already appears as a "shutdown" incident.

- invalid_request_id / invalid_session_id: Log-injection attempt detected
  (newline in ID). NOT surfaced here because the malformed ID is rejected (set
  to None) and request processing continues — the attack is neutralized without
  a shutdown, so no incident is warranted. These events remain in system.jsonl
  for forensic review.
"""

from __future__ import annotations

__all__ = ["router", "INCIDENTS_FETCH_MULTIPLIER"]

from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import APIRouter

from mcp_acp.api.schemas import IncidentsSummary
from mcp_acp.config import load_proxy_config
from mcp_acp.manager.config import (
    get_proxy_config_path,
    get_proxy_log_dir,
    list_configured_proxies,
    load_manager_config,
)
from mcp_acp.manager.models import AggregatedIncidentsResponse, IncidentType
from mcp_acp.security.integrity.emergency_audit import get_emergency_audit_path
from mcp_acp.utils.api import (
    count_entries_and_latest,
    get_cutoff_time,
    parse_timestamp,
    read_jsonl_filtered,
)

router = APIRouter(prefix="/api/manager", tags=["incidents"])

# Incidents aggregation: fetch extra entries from each source to allow for proper
# merging and sorting across sources. The final limit is applied after merge.
INCIDENTS_FETCH_MULTIPLIER = 2


# ==========================================================================
# Incidents Helpers
# ==========================================================================


def _fetch_incidents(
    log_path: Path,
    incident_type: str,
    fetch_limit: int,
    cutoff_time: datetime | None,
    before_dt: datetime | None,
    proxy_name: str | None = None,
    proxy_id: str | None = None,
) -> list[dict[str, Any]]:
    """Fetch incidents from a log file and annotate with type.

    Args:
        log_path: Path to the JSONL log file.
        incident_type: Type to annotate entries with.
        fetch_limit: Maximum entries to fetch.
        cutoff_time: Time cutoff for filtering.
        before_dt: Pagination cursor.
        proxy_name: Proxy name to annotate (for per-proxy logs).
        proxy_id: Proxy ID to annotate (for correlation).

    Returns:
        List of incident entries with incident_type and proxy info.
    """
    entries, _, _ = read_jsonl_filtered(
        log_path,
        limit=fetch_limit,
        cutoff_time=cutoff_time,
        before=before_dt,
    )
    result = []
    for entry in entries:
        # Copy entry to avoid mutating original
        annotated = {**entry, "incident_type": incident_type}
        # Add proxy info if provided (for per-proxy logs)
        # Preserve existing values from entry (for emergency audit which has them embedded)
        if proxy_id is not None and "proxy_id" not in annotated:
            annotated["proxy_id"] = proxy_id
        if proxy_name is not None and "proxy_name" not in annotated:
            annotated["proxy_name"] = proxy_name
        result.append(annotated)
    return result


# ==========================================================================
# Incidents Endpoints
# ==========================================================================


@router.get("/incidents", response_model=AggregatedIncidentsResponse)
async def get_aggregated_incidents(
    proxy: str | None = None,
    incident_type: IncidentType | None = None,
    time_range: str = "all",
    limit: int = 100,
    before: str | None = None,
) -> AggregatedIncidentsResponse:
    """Get aggregated incidents from all proxies.

    Combines shutdowns (per-proxy) with bootstrap and emergency (global).
    Each entry includes 'incident_type' field and 'proxy_name' for shutdowns.

    Args:
        proxy: Filter by proxy name (only affects shutdowns).
        incident_type: Filter by type ('shutdown', 'bootstrap', 'emergency').
        time_range: Time range filter ('5m', '1h', '24h', 'all').
        limit: Maximum entries to return (default: 100).
        before: Cursor for pagination (ISO timestamp).

    Returns:
        Aggregated incidents sorted by time (newest first).
    """
    manager_config = load_manager_config()
    cutoff_time = get_cutoff_time(time_range)
    before_dt = parse_timestamp(before)
    fetch_limit = limit * INCIDENTS_FETCH_MULTIPLIER

    all_entries: list[dict[str, Any]] = []

    # Build proxy info cache (name -> id) for annotation
    proxy_names_to_fetch = [proxy] if proxy else list_configured_proxies()
    proxy_id_map: dict[str, str] = {}
    for pname in proxy_names_to_fetch:
        try:
            config = load_proxy_config(pname)
            proxy_id_map[pname] = config.proxy_id
        except (FileNotFoundError, ValueError, OSError):
            pass  # Skip if config can't be loaded

    # Collect shutdowns from all proxies (per-proxy log dirs)
    if incident_type is None or incident_type == "shutdown":
        for proxy_name in proxy_names_to_fetch:
            log_dir = get_proxy_log_dir(proxy_name, manager_config)
            shutdowns_path = log_dir / "shutdowns.jsonl"
            all_entries.extend(
                _fetch_incidents(
                    shutdowns_path,
                    "shutdown",
                    fetch_limit,
                    cutoff_time,
                    before_dt,
                    proxy_name=proxy_name,
                    proxy_id=proxy_id_map.get(proxy_name),
                )
            )

    # Collect bootstrap errors from all proxies (per-proxy directories)
    if incident_type is None or incident_type == "bootstrap":
        for proxy_name in proxy_names_to_fetch:
            proxy_dir = get_proxy_config_path(proxy_name).parent
            bootstrap_path = proxy_dir / "bootstrap.jsonl"
            all_entries.extend(
                _fetch_incidents(
                    bootstrap_path,
                    "bootstrap",
                    fetch_limit,
                    cutoff_time,
                    before_dt,
                    proxy_name=proxy_name,
                    proxy_id=proxy_id_map.get(proxy_name),
                )
            )

    # Collect emergency audit (global - has proxy_id/proxy_name embedded in entries)
    if incident_type is None or incident_type == "emergency":
        emergency_path = get_emergency_audit_path()
        all_entries.extend(_fetch_incidents(emergency_path, "emergency", fetch_limit, cutoff_time, before_dt))

    # Sort all entries by time (newest first)
    all_entries.sort(key=lambda e: e.get("time", ""), reverse=True)

    # Apply limit
    has_more = len(all_entries) > limit
    entries_to_return = all_entries[:limit]

    # Build filters applied
    filters_applied: dict[str, Any] = {"time_range": time_range}
    if proxy:
        filters_applied["proxy"] = proxy
    if incident_type:
        filters_applied["incident_type"] = incident_type

    return AggregatedIncidentsResponse(
        entries=entries_to_return,
        total_returned=len(entries_to_return),
        has_more=has_more,
        filters_applied=filters_applied,
    )


@router.get("/incidents/summary", response_model=IncidentsSummary)
async def get_incidents_summary(since: str | None = None) -> IncidentsSummary:
    """Get aggregated incidents summary from all proxies.

    Combines shutdown counts from all proxy log directories with
    global bootstrap and emergency counts.

    Args:
        since: Only count entries with ``time`` strictly after this ISO
            timestamp.  Used by the web UI badge to count unread incidents.

    Returns:
        IncidentsSummary with counts and latest critical timestamp.
    """
    manager_config = load_manager_config()

    # Count shutdowns from all proxies
    shutdowns_count = 0
    shutdowns_latest: str | None = None
    proxy_names = list_configured_proxies()
    for proxy_name in proxy_names:
        log_dir = get_proxy_log_dir(proxy_name, manager_config)
        shutdowns_path = log_dir / "shutdowns.jsonl"
        count, latest = count_entries_and_latest(shutdowns_path, since=since)
        shutdowns_count += count
        if latest and (shutdowns_latest is None or latest > shutdowns_latest):
            shutdowns_latest = latest

    # Count bootstrap from all proxies (per-proxy directories)
    bootstrap_count = 0
    for proxy_name in proxy_names:
        proxy_dir = get_proxy_config_path(proxy_name).parent
        bootstrap_path = proxy_dir / "bootstrap.jsonl"
        count, _ = count_entries_and_latest(bootstrap_path, since=since)
        bootstrap_count += count

    # Count emergency (global)
    emergency_path = get_emergency_audit_path()
    emergency_count, emergency_latest = count_entries_and_latest(emergency_path, since=since)

    # Latest critical timestamp (shutdowns + emergency, not bootstrap)
    critical_timestamps = [t for t in [shutdowns_latest, emergency_latest] if t]
    latest_critical = max(critical_timestamps) if critical_timestamps else None

    return IncidentsSummary(
        shutdowns_count=shutdowns_count,
        emergency_count=emergency_count,
        bootstrap_count=bootstrap_count,
        latest_critical_timestamp=latest_critical,
        # Paths not meaningful for aggregated summary (per-proxy files)
        shutdowns_path=None,
        emergency_path=str(emergency_path) if emergency_path.exists() else None,
        bootstrap_path=None,
    )
