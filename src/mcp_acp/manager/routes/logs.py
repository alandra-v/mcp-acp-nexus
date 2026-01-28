"""Log viewing endpoints."""

from __future__ import annotations

__all__ = ["router", "LOG_FOLDER_STRUCTURE"]

from typing import Any

from fastapi import APIRouter, Query

from mcp_acp.api.errors import APIError, ErrorCode
from mcp_acp.api.schemas.logs import (
    LogFileInfo,
    LogFolderInfo,
    LogsMetadataResponse,
    LogsResponse,
)
from mcp_acp.manager.config import get_proxy_log_dir, load_manager_config
from mcp_acp.utils.api import (
    LOG_PATHS,
    build_filters_applied,
    extract_versions,
    get_cutoff_time,
    parse_comma_separated,
    parse_timestamp,
    read_jsonl_filtered,
)

from .deps import find_proxy_by_id, get_backup_file_infos

router = APIRouter(prefix="/api/manager/proxies", tags=["logs"])

# Log folder structure for metadata endpoint
# Keys are folder names, values are log type keys (matching LOG_PATHS)
LOG_FOLDER_STRUCTURE: dict[str, list[str]] = {
    "audit": ["decisions", "operations", "auth"],
    "system": ["system", "config_history", "policy_history"],
    "debug": ["client_wire", "backend_wire"],
}


# ==========================================================================
# Log Helpers
# ==========================================================================


def _build_proxy_logs_response(
    proxy_name: str,
    log_type: str,
    time_range: str,
    limit: int,
    before: str | None,
    filters_applied: dict[str, Any],
    **filter_kwargs: Any,
) -> LogsResponse:
    """Build log response for a proxy by reading from disk.

    Args:
        proxy_name: Name of the proxy.
        log_type: Log type key (e.g., "decisions", "system").
        time_range: Time range filter (5m, 1h, 24h, all).
        limit: Maximum entries to return.
        before: Pagination cursor (ISO timestamp).
        filters_applied: Dict of filter names to values for response metadata.
        **filter_kwargs: Additional filters passed to read_jsonl_filtered.

    Returns:
        LogsResponse with entries and metadata.

    Raises:
        APIError: If log type is invalid or debug logs not available.
    """
    manager_config = load_manager_config()
    log_dir = get_proxy_log_dir(proxy_name, manager_config)
    log_path = log_dir / LOG_PATHS[log_type]

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


# ==========================================================================
# Log Endpoints
# ==========================================================================


@router.get(
    "/{proxy_id}/logs/decisions",
    response_model=LogsResponse,
)
async def get_proxy_decision_logs(
    proxy_id: str,
    time_range: str = Query(default="5m", description="Time range: 5m, 1h, 24h, all"),
    limit: int = Query(default=50, ge=1, le=1000, description="Max entries to return"),
    before: str | None = Query(default=None, description="Pagination cursor (ISO timestamp)"),
    session_id: str | None = Query(default=None, description="Filter by MCP session ID"),
    bound_session_id: str | None = Query(default=None, description="Filter by bound session ID"),
    request_id: str | None = Query(default=None, description="Filter by request ID"),
    policy_version: str | None = Query(default=None, description="Filter by policy version"),
    decision: str | None = Query(default=None, description="Filter by decision: allow,deny,hitl"),
    hitl_outcome: str | None = Query(default=None, description="Filter HITL outcome: allowed,denied,timeout"),
) -> LogsResponse:
    """Get policy decision logs for a proxy (newest first).

    Reads from disk, works regardless of proxy running state.

    Args:
        proxy_id: Stable proxy identifier.
        time_range: Time range filter (5m, 1h, 24h, all).
        limit: Maximum entries to return.
        before: Pagination cursor for infinite scroll.
        session_id: Filter by MCP session ID.
        bound_session_id: Filter by bound (auth) session ID.
        request_id: Filter by request ID.
        policy_version: Filter by policy version.
        decision: Filter by decision type (comma-separated).
        hitl_outcome: Filter by HITL outcome (comma-separated).

    Returns:
        LogsResponse with decision log entries.
    """
    result = find_proxy_by_id(proxy_id)
    if result is None:
        raise APIError(
            status_code=404,
            code=ErrorCode.PROXY_NOT_FOUND,
            message=f"Proxy with ID '{proxy_id}' not found",
            details={"proxy_id": proxy_id},
        )

    proxy_name, _ = result
    decision_list = parse_comma_separated(decision)
    hitl_list = parse_comma_separated(hitl_outcome)

    return _build_proxy_logs_response(
        proxy_name,
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


@router.get(
    "/{proxy_id}/logs/operations",
    response_model=LogsResponse,
)
async def get_proxy_operation_logs(
    proxy_id: str,
    time_range: str = Query(default="5m", description="Time range: 5m, 1h, 24h, all"),
    limit: int = Query(default=50, ge=1, le=1000, description="Max entries to return"),
    before: str | None = Query(default=None, description="Pagination cursor (ISO timestamp)"),
    session_id: str | None = Query(default=None, description="Filter by MCP session ID"),
    request_id: str | None = Query(default=None, description="Filter by request ID"),
    config_version: str | None = Query(default=None, description="Filter by config version"),
) -> LogsResponse:
    """Get operation audit logs for a proxy (newest first).

    Reads from disk, works regardless of proxy running state.

    Args:
        proxy_id: Stable proxy identifier.
        time_range: Time range filter (5m, 1h, 24h, all).
        limit: Maximum entries to return.
        before: Pagination cursor for infinite scroll.
        session_id: Filter by MCP session ID.
        request_id: Filter by request ID.
        config_version: Filter by config version.

    Returns:
        LogsResponse with operation log entries.
    """
    result = find_proxy_by_id(proxy_id)
    if result is None:
        raise APIError(
            status_code=404,
            code=ErrorCode.PROXY_NOT_FOUND,
            message=f"Proxy with ID '{proxy_id}' not found",
            details={"proxy_id": proxy_id},
        )

    proxy_name, _ = result
    return _build_proxy_logs_response(
        proxy_name,
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


@router.get(
    "/{proxy_id}/logs/auth",
    response_model=LogsResponse,
)
async def get_proxy_auth_logs(
    proxy_id: str,
    time_range: str = Query(default="5m", description="Time range: 5m, 1h, 24h, all"),
    limit: int = Query(default=50, ge=1, le=1000, description="Max entries to return"),
    before: str | None = Query(default=None, description="Pagination cursor (ISO timestamp)"),
    session_id: str | None = Query(default=None, description="Filter by MCP session ID"),
    bound_session_id: str | None = Query(default=None, description="Filter by bound session ID"),
    request_id: str | None = Query(default=None, description="Filter by request ID"),
    event_type: str | None = Query(default=None, description="Filter by event type"),
) -> LogsResponse:
    """Get authentication event logs for a proxy (newest first).

    Reads from disk, works regardless of proxy running state.

    Args:
        proxy_id: Stable proxy identifier.
        time_range: Time range filter (5m, 1h, 24h, all).
        limit: Maximum entries to return.
        before: Pagination cursor for infinite scroll.
        session_id: Filter by MCP session ID.
        bound_session_id: Filter by bound (auth) session ID.
        request_id: Filter by request ID.
        event_type: Filter by event type (comma-separated).

    Returns:
        LogsResponse with auth log entries.
    """
    result = find_proxy_by_id(proxy_id)
    if result is None:
        raise APIError(
            status_code=404,
            code=ErrorCode.PROXY_NOT_FOUND,
            message=f"Proxy with ID '{proxy_id}' not found",
            details={"proxy_id": proxy_id},
        )

    proxy_name, _ = result
    event_list = parse_comma_separated(event_type)

    return _build_proxy_logs_response(
        proxy_name,
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


@router.get(
    "/{proxy_id}/logs/system",
    response_model=LogsResponse,
)
async def get_proxy_system_logs(
    proxy_id: str,
    time_range: str = Query(default="5m", description="Time range: 5m, 1h, 24h, all"),
    limit: int = Query(default=50, ge=1, le=1000, description="Max entries to return"),
    before: str | None = Query(default=None, description="Pagination cursor (ISO timestamp)"),
    session_id: str | None = Query(default=None, description="Filter by MCP session ID"),
    request_id: str | None = Query(default=None, description="Filter by request ID"),
    config_version: str | None = Query(default=None, description="Filter by config version"),
    level: str | None = Query(default=None, description="Filter by level: WARNING,ERROR,CRITICAL"),
    event_type: str | None = Query(default=None, description="Filter by event type"),
) -> LogsResponse:
    """Get system logs for a proxy (newest first).

    Reads from disk, works regardless of proxy running state.

    Args:
        proxy_id: Stable proxy identifier.
        time_range: Time range filter (5m, 1h, 24h, all).
        limit: Maximum entries to return.
        before: Pagination cursor for infinite scroll.
        session_id: Filter by MCP session ID.
        request_id: Filter by request ID.
        config_version: Filter by config version.
        level: Filter by log level (comma-separated).
        event_type: Filter by event type (comma-separated).

    Returns:
        LogsResponse with system log entries.
    """
    result = find_proxy_by_id(proxy_id)
    if result is None:
        raise APIError(
            status_code=404,
            code=ErrorCode.PROXY_NOT_FOUND,
            message=f"Proxy with ID '{proxy_id}' not found",
            details={"proxy_id": proxy_id},
        )

    proxy_name, _ = result
    level_list = parse_comma_separated(level, uppercase=True)
    event_list = parse_comma_separated(event_type)

    return _build_proxy_logs_response(
        proxy_name,
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


@router.get(
    "/{proxy_id}/logs/config_history",
    response_model=LogsResponse,
)
async def get_proxy_config_history_logs(
    proxy_id: str,
    time_range: str = Query(default="5m", description="Time range: 5m, 1h, 24h, all"),
    limit: int = Query(default=50, ge=1, le=1000, description="Max entries to return"),
    before: str | None = Query(default=None, description="Pagination cursor (ISO timestamp)"),
    config_version: str | None = Query(default=None, description="Filter by config version"),
    event_type: str | None = Query(default=None, description="Filter by event type"),
) -> LogsResponse:
    """Get configuration history logs for a proxy (newest first).

    Reads from disk, works regardless of proxy running state.

    Args:
        proxy_id: Stable proxy identifier.
        time_range: Time range filter (5m, 1h, 24h, all).
        limit: Maximum entries to return.
        before: Pagination cursor for infinite scroll.
        config_version: Filter by config version.
        event_type: Filter by event type (comma-separated).

    Returns:
        LogsResponse with config history entries.
    """
    result = find_proxy_by_id(proxy_id)
    if result is None:
        raise APIError(
            status_code=404,
            code=ErrorCode.PROXY_NOT_FOUND,
            message=f"Proxy with ID '{proxy_id}' not found",
            details={"proxy_id": proxy_id},
        )

    proxy_name, _ = result
    event_list = parse_comma_separated(event_type)

    return _build_proxy_logs_response(
        proxy_name,
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


@router.get(
    "/{proxy_id}/logs/policy_history",
    response_model=LogsResponse,
)
async def get_proxy_policy_history_logs(
    proxy_id: str,
    time_range: str = Query(default="5m", description="Time range: 5m, 1h, 24h, all"),
    limit: int = Query(default=50, ge=1, le=1000, description="Max entries to return"),
    before: str | None = Query(default=None, description="Pagination cursor (ISO timestamp)"),
    policy_version: str | None = Query(default=None, description="Filter by policy version"),
    event_type: str | None = Query(default=None, description="Filter by event type"),
) -> LogsResponse:
    """Get policy history logs for a proxy (newest first).

    Reads from disk, works regardless of proxy running state.

    Args:
        proxy_id: Stable proxy identifier.
        time_range: Time range filter (5m, 1h, 24h, all).
        limit: Maximum entries to return.
        before: Pagination cursor for infinite scroll.
        policy_version: Filter by policy version.
        event_type: Filter by event type (comma-separated).

    Returns:
        LogsResponse with policy history entries.
    """
    result = find_proxy_by_id(proxy_id)
    if result is None:
        raise APIError(
            status_code=404,
            code=ErrorCode.PROXY_NOT_FOUND,
            message=f"Proxy with ID '{proxy_id}' not found",
            details={"proxy_id": proxy_id},
        )

    proxy_name, _ = result
    event_list = parse_comma_separated(event_type)

    return _build_proxy_logs_response(
        proxy_name,
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


@router.get(
    "/{proxy_id}/logs/client_wire",
    response_model=LogsResponse,
)
async def get_proxy_client_wire_logs(
    proxy_id: str,
    time_range: str = Query(default="5m", description="Time range: 5m, 1h, 24h, all"),
    limit: int = Query(default=50, ge=1, le=1000, description="Max entries to return"),
    before: str | None = Query(default=None, description="Pagination cursor (ISO timestamp)"),
    session_id: str | None = Query(default=None, description="Filter by MCP session ID"),
    request_id: str | None = Query(default=None, description="Filter by request ID"),
    event_type: str | None = Query(default=None, description="Filter by event type"),
) -> LogsResponse:
    """Get client wire logs for a proxy (newest first).

    Debug logs only available when proxy log_level is DEBUG.
    Reads from disk, works regardless of proxy running state.

    Args:
        proxy_id: Stable proxy identifier.
        time_range: Time range filter (5m, 1h, 24h, all).
        limit: Maximum entries to return.
        before: Pagination cursor for infinite scroll.
        session_id: Filter by MCP session ID.
        request_id: Filter by request ID.
        event_type: Filter by event type (comma-separated).

    Returns:
        LogsResponse with client wire log entries.

    Raises:
        APIError: 404 if debug logs not available.
    """
    result = find_proxy_by_id(proxy_id)
    if result is None:
        raise APIError(
            status_code=404,
            code=ErrorCode.PROXY_NOT_FOUND,
            message=f"Proxy with ID '{proxy_id}' not found",
            details={"proxy_id": proxy_id},
        )

    proxy_name, config = result

    # Check if debug logging is enabled
    if config.log_level != "DEBUG":
        raise APIError(
            status_code=404,
            code=ErrorCode.LOG_NOT_AVAILABLE,
            message="Debug logs not available. Set log_level to DEBUG in config.",
            details={"log_type": "client_wire", "requires": "log_level=DEBUG"},
        )

    event_list = parse_comma_separated(event_type)

    return _build_proxy_logs_response(
        proxy_name,
        "client_wire",
        time_range,
        limit,
        before,
        filters_applied={
            "session_id": session_id,
            "request_id": request_id,
            "event_type": event_list,
        },
        session_id=session_id,
        request_id=request_id,
        event_type=event_list,
    )


@router.get(
    "/{proxy_id}/logs/backend_wire",
    response_model=LogsResponse,
)
async def get_proxy_backend_wire_logs(
    proxy_id: str,
    time_range: str = Query(default="5m", description="Time range: 5m, 1h, 24h, all"),
    limit: int = Query(default=50, ge=1, le=1000, description="Max entries to return"),
    before: str | None = Query(default=None, description="Pagination cursor (ISO timestamp)"),
    session_id: str | None = Query(default=None, description="Filter by MCP session ID"),
    request_id: str | None = Query(default=None, description="Filter by request ID"),
    event_type: str | None = Query(default=None, description="Filter by event type"),
) -> LogsResponse:
    """Get backend wire logs for a proxy (newest first).

    Debug logs only available when proxy log_level is DEBUG.
    Reads from disk, works regardless of proxy running state.

    Args:
        proxy_id: Stable proxy identifier.
        time_range: Time range filter (5m, 1h, 24h, all).
        limit: Maximum entries to return.
        before: Pagination cursor for infinite scroll.
        session_id: Filter by MCP session ID.
        request_id: Filter by request ID.
        event_type: Filter by event type (comma-separated).

    Returns:
        LogsResponse with backend wire log entries.

    Raises:
        APIError: 404 if debug logs not available.
    """
    result = find_proxy_by_id(proxy_id)
    if result is None:
        raise APIError(
            status_code=404,
            code=ErrorCode.PROXY_NOT_FOUND,
            message=f"Proxy with ID '{proxy_id}' not found",
            details={"proxy_id": proxy_id},
        )

    proxy_name, config = result

    # Check if debug logging is enabled
    if config.log_level != "DEBUG":
        raise APIError(
            status_code=404,
            code=ErrorCode.LOG_NOT_AVAILABLE,
            message="Debug logs not available. Set log_level to DEBUG in config.",
            details={"log_type": "backend_wire", "requires": "log_level=DEBUG"},
        )

    event_list = parse_comma_separated(event_type)

    return _build_proxy_logs_response(
        proxy_name,
        "backend_wire",
        time_range,
        limit,
        before,
        filters_applied={
            "session_id": session_id,
            "request_id": request_id,
            "event_type": event_list,
        },
        session_id=session_id,
        request_id=request_id,
        event_type=event_list,
    )


@router.get(
    "/{proxy_id}/logs/metadata",
    response_model=LogsMetadataResponse,
)
async def get_proxy_logs_metadata(proxy_id: str) -> LogsMetadataResponse:
    """Get metadata about available logs for a proxy.

    Returns information about available log folders, files, and filter options.
    Reads from disk, works regardless of proxy running state.

    Args:
        proxy_id: Stable proxy identifier.

    Returns:
        LogsMetadataResponse with folder/file info and available versions.
    """
    result = find_proxy_by_id(proxy_id)
    if result is None:
        raise APIError(
            status_code=404,
            code=ErrorCode.PROXY_NOT_FOUND,
            message=f"Proxy with ID '{proxy_id}' not found",
            details={"proxy_id": proxy_id},
        )

    proxy_name, config = result
    manager_config = load_manager_config()
    log_dir = get_proxy_log_dir(proxy_name, manager_config)

    folders: list[LogFolderInfo] = []

    for folder_name, file_keys in LOG_FOLDER_STRUCTURE.items():
        files: list[LogFileInfo] = []
        for key in file_keys:
            rel_path = LOG_PATHS.get(key, "")
            full_path = log_dir / rel_path
            exists = full_path.exists()
            size = full_path.stat().st_size if exists else None

            # Scan for backup files (.broken.TIMESTAMP.jsonl)
            backups = get_backup_file_infos(full_path, log_dir)

            files.append(
                LogFileInfo(
                    name=key,
                    path=rel_path,
                    exists=exists,
                    size_bytes=size,
                    backups=backups,
                )
            )

        folders.append(LogFolderInfo(name=folder_name, files=files))

    # Check if debug logging is enabled based on config
    debug_enabled = config.log_level == "DEBUG"

    # Extract available versions from history logs
    policy_versions = extract_versions(
        log_dir / LOG_PATHS["policy_history"],
        "policy_version",
    )
    config_versions = extract_versions(
        log_dir / LOG_PATHS["config_history"],
        "config_version",
    )

    return LogsMetadataResponse(
        folders=folders,
        debug_enabled=debug_enabled,
        available_policy_versions=policy_versions,
        available_config_versions=config_versions,
    )
