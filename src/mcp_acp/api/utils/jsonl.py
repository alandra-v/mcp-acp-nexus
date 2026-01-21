"""JSONL file reading and filtering utilities for log API."""

from __future__ import annotations

__all__ = [
    "LOG_PATHS",
    "build_filters_applied",
    "extract_versions",
    "get_cutoff_time",
    "get_log_base_path",
    "parse_comma_separated",
    "parse_timestamp",
    "read_jsonl_filtered",
]

import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from mcp_acp.constants import APP_NAME

if TYPE_CHECKING:
    from mcp_acp.config import AppConfig

logger = logging.getLogger(__name__)


# =============================================================================
# Constants
# =============================================================================

# Maximum bytes to read from a log file (10MB)
MAX_READ_BYTES = 10 * 1024 * 1024

# Maximum entries to scan before stopping (prevents slow queries)
MAX_SCAN_ENTRIES = 50000

# Log file paths relative to log base directory
LOG_PATHS: dict[str, str] = {
    # audit/
    "decisions": "audit/decisions.jsonl",
    "operations": "audit/operations.jsonl",
    "auth": "audit/auth.jsonl",
    # system/
    "system": "system/system.jsonl",
    "config_history": "system/config_history.jsonl",
    "policy_history": "system/policy_history.jsonl",
    # debug/
    "client_wire": "debug/client_wire.jsonl",
    "backend_wire": "debug/backend_wire.jsonl",
}

# Time range presets (in seconds)
TIME_RANGES: dict[str, int] = {
    "5m": 5 * 60,
    "1h": 60 * 60,
    "24h": 24 * 60 * 60,
}

# HITL outcome mapping from user-friendly values to log values
HITL_OUTCOME_MAPPING: dict[str, str] = {
    "allowed": "user_allowed",
    "denied": "user_denied",
    "timeout": "timeout",
}


# =============================================================================
# Path Helpers
# =============================================================================


def get_log_base_path(config: "AppConfig") -> Path:
    """Get base path for log files.

    Args:
        config: Application configuration containing logging settings.

    Returns:
        Path to the log directory (e.g., ~/Library/Logs/mcp-acp/proxies/default).
    """
    return Path(config.logging.log_dir).expanduser() / APP_NAME / "proxies" / "default"


# =============================================================================
# Time Filtering
# =============================================================================


def parse_timestamp(ts: str | None) -> datetime | None:
    """Parse ISO 8601 timestamp to timezone-aware datetime.

    Args:
        ts: ISO 8601 timestamp string (e.g., "2025-12-11T10:30:45.123Z").

    Returns:
        Timezone-aware datetime, or None if parsing fails or ts is empty.
    """
    if not ts:
        return None
    try:
        # Handle 'time' field format: "2025-12-11T10:30:45.123Z"
        if ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        return datetime.fromisoformat(ts)
    except (ValueError, TypeError):
        return None


def get_cutoff_time(time_range: str | None) -> datetime | None:
    """Get cutoff datetime for time range filter.

    Args:
        time_range: One of "5m", "1h", "24h", "all", or None.

    Returns:
        Cutoff datetime (entries before this are excluded), or None for no filter.
    """
    if not time_range or time_range == "all":
        return None
    seconds = TIME_RANGES.get(time_range)
    if seconds is None:
        return None
    return datetime.now(timezone.utc) - timedelta(seconds=seconds)


# =============================================================================
# Entry Filtering
# =============================================================================


def _matches_filter(
    entry: dict[str, Any],
    *,
    cutoff_time: datetime | None = None,
    before: datetime | None = None,
    session_id: str | None = None,
    bound_session_id: str | None = None,
    request_id: str | None = None,
    decision: list[str] | None = None,
    hitl_outcome: list[str] | None = None,
    policy_version: str | None = None,
    config_version: str | None = None,
    level: list[str] | None = None,
    event_type: list[str] | None = None,
) -> bool:
    """Check if a log entry matches all specified filters.

    Filters are ANDed together - entry must match ALL specified filters.
    Empty/None filters are skipped (match all).

    Note: Entries without valid timestamps are included (fail-open) to avoid
    hiding potentially important log entries due to malformed data.
    """
    entry_time = parse_timestamp(entry.get("time"))

    # Time range filter (cutoff_time): exclude entries older than cutoff
    # Entries without timestamps are included (fail-open for visibility)
    if cutoff_time is not None and entry_time is not None:
        if entry_time < cutoff_time:
            return False

    # Cursor pagination filter (before): exclude entries newer than cursor
    # Entries without timestamps are included to avoid pagination gaps
    if before is not None and entry_time is not None:
        if entry_time >= before:
            return False

    # Session ID filter (check multiple possible fields)
    if session_id:
        entry_session = entry.get("session_id") or entry.get("mcp_session_id")
        if entry_session != session_id:
            return False

    # Bound session ID filter
    if bound_session_id:
        if entry.get("bound_session_id") != bound_session_id:
            return False

    # Request ID filter
    if request_id:
        if entry.get("request_id") != request_id:
            return False

    # Decision filter (for decisions.jsonl)
    if decision:
        entry_decision = entry.get("decision")
        if entry_decision not in decision:
            return False

    # HITL outcome filter (for decisions.jsonl)
    if hitl_outcome:
        entry_hitl = entry.get("hitl_outcome")
        # Map user-friendly values to actual log values using constant
        mapped_outcomes = [HITL_OUTCOME_MAPPING.get(o, o) for o in hitl_outcome]
        if entry_hitl not in mapped_outcomes:
            return False

    # Policy version filter
    if policy_version:
        if entry.get("policy_version") != policy_version:
            return False

    # Config version filter
    if config_version:
        if entry.get("config_version") != config_version:
            return False

    # Level filter (for system.jsonl)
    if level:
        entry_level = entry.get("level")
        if entry_level not in level:
            return False

    # Event type filter
    if event_type:
        entry_event = entry.get("event") or entry.get("event_type")
        if entry_event not in event_type:
            return False

    return True


# =============================================================================
# File Reading
# =============================================================================


def read_jsonl_filtered(
    path: Path,
    limit: int,
    *,
    cutoff_time: datetime | None = None,
    before: datetime | None = None,
    session_id: str | None = None,
    bound_session_id: str | None = None,
    request_id: str | None = None,
    decision: list[str] | None = None,
    hitl_outcome: list[str] | None = None,
    policy_version: str | None = None,
    config_version: str | None = None,
    level: list[str] | None = None,
    event_type: list[str] | None = None,
) -> tuple[list[dict[str, Any]], bool, int]:
    """Read and filter JSONL file entries (newest first).

    Efficiently reads from end of file and applies filters during parsing.
    Stops when limit is reached or max scan entries exceeded.

    Args:
        path: Path to JSONL file.
        limit: Maximum entries to return.
        cutoff_time: Only include entries after this time (for time_range filter).
        before: Only include entries before this time (for cursor pagination).
        session_id: Filter by MCP session ID.
        bound_session_id: Filter by bound (auth) session ID.
        request_id: Filter by request ID.
        decision: Filter by decision type(s).
        hitl_outcome: Filter by HITL outcome(s).
        policy_version: Filter by policy version.
        config_version: Filter by config version.
        level: Filter by log level(s).
        event_type: Filter by event type(s).

    Returns:
        Tuple of (matching_entries, has_more, total_scanned).
    """
    if not path.exists():
        return [], False, 0

    try:
        file_size = path.stat().st_size
        if file_size == 0:
            return [], False, 0

        # Read at most MAX_READ_BYTES from end of file
        read_size = min(file_size, MAX_READ_BYTES)

        with path.open("rb") as f:
            f.seek(max(0, file_size - read_size))

            # If we didn't start at beginning, skip partial first line
            if file_size > read_size:
                f.readline()

            content = f.read().decode("utf-8", errors="replace")

    except OSError as e:
        logger.warning(
            {
                "event": "log_file_read_failed",
                "message": f"Failed to read log file {path}: {e}",
                "component": "api_logs",
                "error_type": type(e).__name__,
                "error_message": str(e),
                "details": {"path": str(path)},
            }
        )
        return [], False, 0

    lines = content.strip().split("\n")
    lines = [line for line in lines if line.strip()]

    # Reverse for newest first
    lines = list(reversed(lines))

    # Filter and collect entries
    entries: list[dict[str, Any]] = []
    scanned = 0
    has_more = False

    for line in lines:
        if scanned >= MAX_SCAN_ENTRIES:
            has_more = True
            break

        scanned += 1

        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        # Apply filters
        if not _matches_filter(
            entry,
            cutoff_time=cutoff_time,
            before=before,
            session_id=session_id,
            bound_session_id=bound_session_id,
            request_id=request_id,
            decision=decision,
            hitl_outcome=hitl_outcome,
            policy_version=policy_version,
            config_version=config_version,
            level=level,
            event_type=event_type,
        ):
            continue

        entries.append(entry)

        if len(entries) >= limit:
            has_more = scanned < len(lines)
            break

    return entries, has_more, scanned


# =============================================================================
# Metadata Helpers
# =============================================================================


def extract_versions(path: Path, version_field: str) -> list[str]:
    """Extract unique version values from a log file.

    Reads the file to find all unique versions (for filter dropdowns).

    Args:
        path: Path to JSONL file.
        version_field: Field name containing version (e.g., "policy_version").

    Returns:
        List of unique versions, sorted newest first.
    """
    versions: set[str] = set()

    if not path.exists():
        return []

    try:
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                    version = entry.get(version_field)
                    if version:
                        versions.add(version)
                except json.JSONDecodeError:
                    continue
    except OSError as e:
        logger.warning(
            {
                "event": "log_file_read_failed",
                "message": f"Failed to read log file for versions {path}: {e}",
                "component": "api_logs",
                "error_type": type(e).__name__,
                "error_message": str(e),
                "details": {"path": str(path), "version_field": version_field},
            }
        )

    return sorted(versions, reverse=True)


# =============================================================================
# Response Helpers
# =============================================================================


def build_filters_applied(
    time_range: str | None = None,
    session_id: str | None = None,
    bound_session_id: str | None = None,
    request_id: str | None = None,
    decision: list[str] | None = None,
    hitl_outcome: list[str] | None = None,
    policy_version: str | None = None,
    config_version: str | None = None,
    level: list[str] | None = None,
    event_type: list[str] | None = None,
) -> dict[str, Any]:
    """Build dictionary of applied filters for API response.

    Only includes filters that have non-empty values, excluding
    default "all" time_range.

    Args:
        time_range: Time range filter (5m, 1h, 24h, all).
        session_id: MCP session ID filter.
        bound_session_id: Bound (auth) session ID filter.
        request_id: Request ID filter.
        decision: Decision type(s) filter.
        hitl_outcome: HITL outcome(s) filter.
        policy_version: Policy version filter.
        config_version: Config version filter.
        level: Log level(s) filter.
        event_type: Event type(s) filter.

    Returns:
        Dictionary with only the active filters for client display.
    """
    filters: dict[str, Any] = {}
    if time_range and time_range != "all":
        filters["time_range"] = time_range
    if session_id:
        filters["session_id"] = session_id
    if bound_session_id:
        filters["bound_session_id"] = bound_session_id
    if request_id:
        filters["request_id"] = request_id
    if decision:
        filters["decision"] = decision
    if hitl_outcome:
        filters["hitl_outcome"] = hitl_outcome
    if policy_version:
        filters["policy_version"] = policy_version
    if config_version:
        filters["config_version"] = config_version
    if level:
        filters["level"] = level
    if event_type:
        filters["event_type"] = event_type
    return filters


def parse_comma_separated(
    value: str | None,
    *,
    uppercase: bool = False,
) -> list[str] | None:
    """Parse comma-separated string into list of trimmed values.

    Args:
        value: Comma-separated string (e.g., "allow, deny, hitl") or None.
        uppercase: If True, convert values to uppercase.

    Returns:
        List of trimmed values, or None if input is None/empty.
    """
    if not value:
        return None
    items = [item.strip() for item in value.split(",")]
    if uppercase:
        items = [item.upper() for item in items]
    return items if items else None
