"""Log viewing API endpoints.

Provides read-only access to JSONL log files with filtering:

Audit logs:
- GET /api/logs/decisions - Policy decision logs
- GET /api/logs/operations - Operation audit logs
- GET /api/logs/auth - Authentication event logs

System logs:
- GET /api/logs/system - System logs
- GET /api/logs/config_history - Configuration change history
- GET /api/logs/policy_history - Policy change history

Debug logs (only available when log_level=DEBUG):
- GET /api/logs/client_wire - Client↔Proxy wire logs
- GET /api/logs/backend_wire - Proxy↔Backend wire logs

Metadata:
- GET /api/logs/metadata - Available log files and filter options

Routes mounted at: /api/logs
"""

from __future__ import annotations

__all__ = ["router"]

from typing import Any

from fastapi import APIRouter, Query

from mcp_acp.api.deps import ConfigDep
from mcp_acp.api.errors import APIError, ErrorCode
from mcp_acp.api.schemas import (
    LogFileInfo,
    LogFolderInfo,
    LogsMetadataResponse,
    LogsResponse,
)
from mcp_acp.api.utils.jsonl import (
    LOG_PATHS,
    build_filters_applied,
    extract_versions,
    get_cutoff_time,
    get_log_base_path,
    parse_comma_separated,
    parse_timestamp,
    read_jsonl_filtered,
)
from mcp_acp.config import AppConfig

router = APIRouter()


# =============================================================================
# Shared Query Parameters
# =============================================================================

TimeRangeQuery = Query(
    default="5m",
    description="Time range: 5m, 1h, 24h, or all",
    pattern="^(5m|1h|24h|all)$",
)
LimitQuery = Query(default=100, ge=1, le=1000, description="Max entries to return")
BeforeQuery = Query(
    default=None,
    description="Cursor for pagination: ISO timestamp to get entries older than this",
)
SessionIdQuery = Query(default=None, description="Filter by MCP session ID")
BoundSessionIdQuery = Query(default=None, description="Filter by bound (auth) session ID")
RequestIdQuery = Query(default=None, description="Filter by request ID")
PolicyVersionQuery = Query(default=None, description="Filter by policy version")
ConfigVersionQuery = Query(default=None, description="Filter by config version")


# =============================================================================
# Shared Helper Functions
# =============================================================================


def _fetch_logs(
    config: AppConfig,
    log_key: str,
    time_range: str,
    limit: int,
    before: str | None,
    filters_applied: dict[str, Any],
    *,
    require_exists: bool = False,
    **filter_kwargs: Any,
) -> LogsResponse:
    """Fetch and filter logs from a JSONL file.

    Consolidates the common pattern used by all log endpoints:
    1. Resolve log path from key
    2. Parse time range and cursor
    3. Read and filter entries
    4. Build response with metadata

    Args:
        config: Application configuration.
        log_key: Key in LOG_PATHS (e.g., "decisions", "system").
        time_range: Time range filter (5m, 1h, 24h, all).
        limit: Maximum entries to return.
        before: Pagination cursor (ISO timestamp).
        filters_applied: Dict of filter names to values for response metadata.
        require_exists: If True, raise 404 if log file doesn't exist.
        **filter_kwargs: Additional filters passed to read_jsonl_filtered.

    Returns:
        LogsResponse with entries and metadata.

    Raises:
        APIError: 404 LOG_NOT_AVAILABLE if require_exists=True and file doesn't exist.
    """
    log_path = get_log_base_path(config) / LOG_PATHS[log_key]

    if require_exists and not log_path.exists():
        raise APIError(
            status_code=404,
            code=ErrorCode.LOG_NOT_AVAILABLE,
            message="Debug logs not available. Set log_level to DEBUG in config.",
            details={"log_type": log_key, "requires": "log_level=DEBUG"},
        )

    cutoff_time = get_cutoff_time(time_range)
    before_dt = parse_timestamp(before)

    entries, has_more, scanned = read_jsonl_filtered(
        log_path,
        limit,
        cutoff_time=cutoff_time,
        before=before_dt,
        **filter_kwargs,
    )

    return LogsResponse(
        entries=entries,
        total_returned=len(entries),
        total_scanned=scanned,
        log_file=str(log_path),
        has_more=has_more,
        filters_applied=build_filters_applied(time_range=time_range, **filters_applied),
    )


# =============================================================================
# Audit Log Endpoints
# =============================================================================


@router.get("/decisions", response_model=LogsResponse)
async def get_decision_logs(
    config: ConfigDep,
    time_range: str = TimeRangeQuery,
    limit: int = LimitQuery,
    before: str | None = BeforeQuery,
    session_id: str | None = SessionIdQuery,
    bound_session_id: str | None = BoundSessionIdQuery,
    request_id: str | None = RequestIdQuery,
    policy_version: str | None = PolicyVersionQuery,
    decision: str | None = Query(
        default=None,
        description="Filter by decision: allow, deny, hitl (comma-separated)",
    ),
    hitl_outcome: str | None = Query(
        default=None,
        description="Filter HITL by outcome: allowed, denied, timeout (comma-separated)",
    ),
) -> LogsResponse:
    """Get policy decision logs (newest first).

    Returns entries from audit/decisions.jsonl including:
    - Timestamp, request details, policy decision, matched rule info
    """
    decision_list = parse_comma_separated(decision)
    hitl_list = parse_comma_separated(hitl_outcome)

    return _fetch_logs(
        config,
        "decisions",
        time_range,
        limit,
        before,
        filters_applied={
            "session_id": session_id,
            "bound_session_id": bound_session_id,
            "request_id": request_id,
            "decision": decision_list,
            "hitl_outcome": hitl_list,
            "policy_version": policy_version,
        },
        session_id=session_id,
        bound_session_id=bound_session_id,
        request_id=request_id,
        decision=decision_list,
        hitl_outcome=hitl_list,
        policy_version=policy_version,
    )


@router.get("/operations", response_model=LogsResponse)
async def get_operation_logs(
    config: ConfigDep,
    time_range: str = TimeRangeQuery,
    limit: int = LimitQuery,
    before: str | None = BeforeQuery,
    session_id: str | None = SessionIdQuery,
    request_id: str | None = RequestIdQuery,
    config_version: str | None = ConfigVersionQuery,
) -> LogsResponse:
    """Get operation audit logs (newest first).

    Returns entries from audit/operations.jsonl including:
    - Timestamp, operation type, subject info, resource accessed, outcome
    """
    return _fetch_logs(
        config,
        "operations",
        time_range,
        limit,
        before,
        filters_applied={
            "session_id": session_id,
            "request_id": request_id,
            "config_version": config_version,
        },
        session_id=session_id,
        request_id=request_id,
        config_version=config_version,
    )


@router.get("/auth", response_model=LogsResponse)
async def get_auth_logs(
    config: ConfigDep,
    time_range: str = TimeRangeQuery,
    limit: int = LimitQuery,
    before: str | None = BeforeQuery,
    session_id: str | None = SessionIdQuery,
    bound_session_id: str | None = BoundSessionIdQuery,
    request_id: str | None = RequestIdQuery,
    event_type: str | None = Query(
        default=None,
        description="Filter by event type (comma-separated)",
    ),
) -> LogsResponse:
    """Get authentication event logs (newest first).

    Returns entries from audit/auth.jsonl including:
    - Timestamp, event type (login, logout, refresh, validation failure), subject info
    """
    event_list = parse_comma_separated(event_type)

    return _fetch_logs(
        config,
        "auth",
        time_range,
        limit,
        before,
        filters_applied={
            "session_id": session_id,
            "bound_session_id": bound_session_id,
            "request_id": request_id,
            "event_type": event_list,
        },
        session_id=session_id,
        bound_session_id=bound_session_id,
        request_id=request_id,
        event_type=event_list,
    )


# =============================================================================
# System Log Endpoints
# =============================================================================


@router.get("/system", response_model=LogsResponse)
async def get_system_logs(
    config: ConfigDep,
    time_range: str = TimeRangeQuery,
    limit: int = LimitQuery,
    before: str | None = BeforeQuery,
    session_id: str | None = SessionIdQuery,
    request_id: str | None = RequestIdQuery,
    config_version: str | None = ConfigVersionQuery,
    level: str | None = Query(
        default=None,
        description="Filter by level: WARNING, ERROR, CRITICAL (comma-separated)",
    ),
    event_type: str | None = Query(
        default=None,
        description="Filter by event type (comma-separated)",
    ),
) -> LogsResponse:
    """Get system logs (newest first).

    Returns entries from system/system.jsonl including:
    - Timestamp, log level, event type, component, message/details
    """
    level_list = parse_comma_separated(level, uppercase=True)
    event_list = parse_comma_separated(event_type)

    return _fetch_logs(
        config,
        "system",
        time_range,
        limit,
        before,
        filters_applied={
            "session_id": session_id,
            "request_id": request_id,
            "config_version": config_version,
            "level": level_list,
            "event_type": event_list,
        },
        session_id=session_id,
        request_id=request_id,
        config_version=config_version,
        level=level_list,
        event_type=event_list,
    )


@router.get("/config_history", response_model=LogsResponse)
async def get_config_history_logs(
    config: ConfigDep,
    time_range: str = TimeRangeQuery,
    limit: int = LimitQuery,
    before: str | None = BeforeQuery,
    config_version: str | None = ConfigVersionQuery,
    event_type: str | None = Query(
        default=None,
        description="Filter by event: config_created, config_updated, config_loaded, etc.",
    ),
) -> LogsResponse:
    """Get configuration history logs (newest first).

    Returns entries from system/config_history.jsonl including:
    - Timestamp, event type, config version, changes, checksums
    """
    event_list = parse_comma_separated(event_type)

    return _fetch_logs(
        config,
        "config_history",
        time_range,
        limit,
        before,
        filters_applied={
            "config_version": config_version,
            "event_type": event_list,
        },
        config_version=config_version,
        event_type=event_list,
    )


@router.get("/policy_history", response_model=LogsResponse)
async def get_policy_history_logs(
    config: ConfigDep,
    time_range: str = TimeRangeQuery,
    limit: int = LimitQuery,
    before: str | None = BeforeQuery,
    policy_version: str | None = PolicyVersionQuery,
    event_type: str | None = Query(
        default=None,
        description="Filter by event: policy_created, policy_loaded, policy_updated, etc.",
    ),
) -> LogsResponse:
    """Get policy history logs (newest first).

    Returns entries from system/policy_history.jsonl including:
    - Timestamp, event type, policy version, rule changes, checksums
    """
    event_list = parse_comma_separated(event_type)

    return _fetch_logs(
        config,
        "policy_history",
        time_range,
        limit,
        before,
        filters_applied={
            "policy_version": policy_version,
            "event_type": event_list,
        },
        policy_version=policy_version,
        event_type=event_list,
    )


# =============================================================================
# Debug Log Endpoints
# =============================================================================


@router.get("/client_wire", response_model=LogsResponse)
async def get_client_wire_logs(
    config: ConfigDep,
    time_range: str = TimeRangeQuery,
    limit: int = LimitQuery,
    before: str | None = BeforeQuery,
    session_id: str | None = SessionIdQuery,
    request_id: str | None = RequestIdQuery,
    event_type: str | None = Query(
        default=None,
        description="Filter by event: client_request, proxy_response, proxy_error",
    ),
) -> LogsResponse:
    """Get client↔proxy wire logs (newest first).

    Only available when log_level is DEBUG.

    Returns entries from debug/client_wire.jsonl including:
    - Timestamp, direction, method, payload info, timing
    """
    event_list = parse_comma_separated(event_type)

    return _fetch_logs(
        config,
        "client_wire",
        time_range,
        limit,
        before,
        filters_applied={
            "session_id": session_id,
            "request_id": request_id,
            "event_type": event_list,
        },
        require_exists=True,
        session_id=session_id,
        request_id=request_id,
        event_type=event_list,
    )


@router.get("/backend_wire", response_model=LogsResponse)
async def get_backend_wire_logs(
    config: ConfigDep,
    time_range: str = TimeRangeQuery,
    limit: int = LimitQuery,
    before: str | None = BeforeQuery,
    session_id: str | None = SessionIdQuery,
    request_id: str | None = RequestIdQuery,
    event_type: str | None = Query(
        default=None,
        description="Filter by event: proxy_request, backend_response, backend_error",
    ),
) -> LogsResponse:
    """Get proxy↔backend wire logs (newest first).

    Only available when log_level is DEBUG.

    Returns entries from debug/backend_wire.jsonl including:
    - Timestamp, direction, method, tool info, timing
    """
    event_list = parse_comma_separated(event_type)

    return _fetch_logs(
        config,
        "backend_wire",
        time_range,
        limit,
        before,
        filters_applied={
            "session_id": session_id,
            "request_id": request_id,
            "event_type": event_list,
        },
        require_exists=True,
        session_id=session_id,
        request_id=request_id,
        event_type=event_list,
    )


# =============================================================================
# Metadata Endpoint
# =============================================================================


@router.get("/metadata", response_model=LogsMetadataResponse)
async def get_logs_metadata(config: ConfigDep) -> LogsMetadataResponse:
    """Get metadata about available logs and filter options.

    Returns information about:
    - Available log folders and files
    - Whether debug logs are enabled
    - Available policy/config versions for filtering
    """
    base_path = get_log_base_path(config)

    folder_structure = {
        "audit": ["decisions", "operations", "auth"],
        "system": ["system", "config_history", "policy_history"],
        "debug": ["client_wire", "backend_wire"],
    }

    folders: list[LogFolderInfo] = []

    for folder_name, file_keys in folder_structure.items():
        files: list[LogFileInfo] = []
        for key in file_keys:
            rel_path = LOG_PATHS.get(key, "")
            full_path = base_path / rel_path
            exists = full_path.exists()
            size = full_path.stat().st_size if exists else None

            files.append(
                LogFileInfo(
                    name=key,
                    path=rel_path,
                    exists=exists,
                    size_bytes=size,
                )
            )

        folders.append(LogFolderInfo(name=folder_name, files=files))

    debug_enabled = (base_path / "debug").exists()

    policy_versions = extract_versions(
        base_path / LOG_PATHS["policy_history"],
        "policy_version",
    )
    config_versions = extract_versions(
        base_path / LOG_PATHS["config_history"],
        "config_version",
    )

    return LogsMetadataResponse(
        folders=folders,
        debug_enabled=debug_enabled,
        available_policy_versions=policy_versions,
        available_config_versions=config_versions,
    )
