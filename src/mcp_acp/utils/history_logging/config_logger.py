"""Configuration history logging.

Logs configuration lifecycle events to config_history.jsonl:
- config_created: Initial creation via CLI init
- config_loaded: Loaded at proxy startup
- config_updated: Updated via CLI commands
- manual_change_detected: File modified outside of CLI
- config_validation_failed: Invalid JSON or schema
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mcp_acp.telemetry.models.system import ConfigHistoryEvent
from mcp_acp.utils.config.config_helpers import compute_config_checksum
from mcp_acp.utils.file_helpers import (
    VersionInfo,
    get_next_version,
)
from mcp_acp.utils.history_logging.base import (
    HistoryLoggerConfig,
    get_last_version_info_for_entity,
    log_entity_created,
    log_entity_loaded,
    log_entity_validation_failed,
    log_history_event,
)
from mcp_acp.utils.logging.logging_helpers import sanitize_config_snapshot

# Re-export for backwards compatibility
__all__ = [
    "VersionInfo",
    "get_next_version",
    "detect_config_changes",
    "log_config_created",
    "log_config_loaded",
    "log_config_updated",
    "log_config_validation_failed",
]


# Configuration for the config history logger
# - sanitize_snapshot: removes sensitive fields like client_key_path from snapshots
# - log_path_field=False: excludes config_path from logged events (avoids logging filesystem paths)
_CONFIG_LOGGER_CONFIG = HistoryLoggerConfig(
    version_field="config_version",
    path_field="config_path",
    entity_name="Configuration",
    entity_name_lower="config",
    logger_name="mcp-acp-nexus.config.history",
    event_class=ConfigHistoryEvent,
    compute_checksum=compute_config_checksum,
    created_change_type="initial_load",
    manual_change_message="Configuration file modified outside of CLI",
    sanitize_snapshot=sanitize_config_snapshot,
    log_path_field=False,
)


def detect_config_changes(
    old_config: dict[str, Any],
    new_config: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    """Detect changes between two configuration snapshots.

    Performs a deep comparison and returns a dictionary of changes with
    dotted paths as keys (e.g., "logging.log_level").

    Args:
        old_config: Previous configuration snapshot.
        new_config: New configuration snapshot.

    Returns:
        dict: Dictionary mapping changed paths to {"old": ..., "new": ...}

    Example:
        >>> detect_config_changes(
        ...     {"logging": {"log_level": "INFO"}},
        ...     {"logging": {"log_level": "DEBUG"}}
        ... )
        {"logging.log_level": {"old": "INFO", "new": "DEBUG"}}
    """
    changes: dict[str, dict[str, Any]] = {}

    def compare_dicts(old: dict[str, Any], new: dict[str, Any], path: str = "") -> None:
        """Recursively compare dictionaries and record changes."""
        # Check for changed or removed keys
        for key in old:
            current_path = f"{path}.{key}" if path else key
            if key not in new:
                changes[current_path] = {"old": old[key], "new": None}
            elif isinstance(old[key], dict) and isinstance(new[key], dict):
                compare_dicts(old[key], new[key], current_path)
            elif old[key] != new[key]:
                changes[current_path] = {"old": old[key], "new": new[key]}

        # Check for added keys
        for key in new:
            if key not in old:
                current_path = f"{path}.{key}" if path else key
                changes[current_path] = {"old": None, "new": new[key]}

    compare_dicts(old_config, new_config)
    return changes


def log_config_created(
    config_history_path: Path,
    config_path: Path,
    config_snapshot: dict[str, Any],
    source: str = "cli_init",
) -> str:
    """Log config creation event with versioning.

    Called when a new configuration is created via CLI init.
    If config history exists (e.g., init --force), increments version.

    Args:
        config_history_path: Path to config_history.jsonl.
        config_path: Path to the config file (for checksum computation).
        config_snapshot: Configuration as dictionary.
        source: Source of creation (default: cli_init).

    Returns:
        str: The new config version (e.g., "v1" or "v2" if overwriting).
    """
    return log_entity_created(
        _CONFIG_LOGGER_CONFIG,
        config_history_path,
        config_path,
        config_snapshot,
        source,
    )


def log_config_loaded(
    config_history_path: Path,
    config_path: Path,
    config_snapshot: dict[str, Any],
    component: str = "proxy",
    source: str = "proxy_startup",
) -> tuple[str, bool]:
    """Log config loaded event, detecting manual changes.

    Compares current checksum with last logged checksum.
    If different, logs manual_change_detected first.

    Args:
        config_history_path: Path to config_history.jsonl.
        config_path: Path to the config file.
        config_snapshot: Configuration as dictionary.
        component: Component loading config (default: proxy).
        source: Source of load (default: proxy_startup).

    Returns:
        Tuple of (current_version, manual_change_detected).
    """
    return log_entity_loaded(
        _CONFIG_LOGGER_CONFIG,
        config_history_path,
        config_path,
        config_snapshot,
        component,
        source,
    )


def log_config_updated(
    config_history_path: Path,
    config_path: Path,
    old_config: dict[str, Any],
    new_config: dict[str, Any],
    source: str = "cli_update",
) -> str | None:
    """Log config update event with detected changes.

    This is config-specific functionality (policies don't have updates tracked this way).

    Args:
        config_history_path: Path to config_history.jsonl.
        config_path: Path to the config file.
        old_config: Previous configuration snapshot.
        new_config: New configuration snapshot.
        source: Source of update (default: cli_update).

    Returns:
        str: New version number, or None if no changes detected.
    """
    changes = detect_config_changes(old_config, new_config)

    if not changes:
        # No changes, don't log
        return None

    last_info = get_last_version_info_for_entity(config_history_path, _CONFIG_LOGGER_CONFIG)
    new_version = get_next_version(last_info.version)
    checksum = compute_config_checksum(config_path)

    # Sanitize snapshot to remove sensitive fields (e.g., client_key_path)
    sanitized_config = sanitize_config_snapshot(new_config)

    event = ConfigHistoryEvent(
        event="config_updated",
        message=f"Configuration updated ({len(changes)} change(s))",
        config_version=new_version,
        previous_version=last_info.version,
        change_type="cli_update",
        component="cli",
        # config_path intentionally omitted - avoid logging filesystem paths
        source=source,
        checksum=checksum,
        snapshot_format="json",
        snapshot=json.dumps(sanitized_config, indent=2),
        changes=changes,
    )

    log_history_event(config_history_path, event, _CONFIG_LOGGER_CONFIG)
    return new_version


def log_config_validation_failed(
    config_history_path: Path,
    config_path: Path,
    error_type: str,
    error_message: str,
    component: str = "config",
    source: str = "load_from_files",
) -> None:
    """Log config validation failure event.

    Called when configuration fails to load due to invalid JSON or schema.

    Note on log location:
        When validation fails, we cannot read log_dir from the invalid config.
        The caller (cli.py) uses a fallback location in the config directory:
            <config_dir>/mcp_acp_logs/system/config_history.jsonl
        instead of the normal location:
            <log_dir>/mcp_acp_logs/system/config_history.jsonl

        This ensures validation failures are always logged to a predictable
        location even when the config is corrupt or missing required fields.

    Args:
        config_history_path: Path to config_history.jsonl (may be fallback path).
        config_path: Path to the config file.
        error_type: Type of error (e.g., "JSONDecodeError", "ValidationError").
        error_message: Human-readable error message.
        component: Component that detected error.
        source: Source of validation attempt.
    """
    log_entity_validation_failed(
        _CONFIG_LOGGER_CONFIG,
        config_history_path,
        config_path,
        error_type,
        error_message,
        component,
        source,
    )
