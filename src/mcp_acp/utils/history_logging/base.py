"""Base classes for history logging.

Provides generic history logging functionality shared between config and policy loggers.
This eliminates code duplication while preserving the specific behavior of each logger.

Usage:
    # In config_logger.py
    config = HistoryLoggerConfig(
        version_field="config_version",
        path_field="config_path",
        entity_name="config",
        ...
    )
    version = log_entity_created(config, history_path, file_path, snapshot)

    # In policy_logger.py
    config = HistoryLoggerConfig(
        version_field="policy_version",
        path_field="policy_path",
        entity_name="policy",
        ...
    )
    version = log_entity_created(config, history_path, file_path, snapshot)
"""

from __future__ import annotations

__all__ = [
    "HistoryLoggerConfig",
    "configure_history_logging_hash_chain",
    "get_last_version_info_for_entity",
    "log_history_event",
    "log_entity_created",
    "log_entity_loaded",
    "log_entity_validation_failed",
]

import json
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

from pydantic import BaseModel

from mcp_acp.constants import INITIAL_VERSION
from mcp_acp.security.integrity.emergency_audit import log_with_fallback
from mcp_acp.telemetry.system.system_logger import get_system_logger
from mcp_acp.utils.file_helpers import (
    VersionInfo,
    get_history_logger,
    get_last_version_info,
    get_next_version,
)
from mcp_acp.utils.logging.logging_helpers import serialize_audit_event

if TYPE_CHECKING:
    from mcp_acp.security.integrity.integrity_state import IntegrityStateManager


# Module-level state for hash chain support
# These are set by configure_history_logging_hash_chain() when the proxy starts.
# CLI commands don't set these, so history logging works without hash chains.
_history_state_manager: "IntegrityStateManager | None" = None
_history_log_dir: Path | None = None


def configure_history_logging_hash_chain(
    state_manager: "IntegrityStateManager",
    log_dir: Path,
) -> None:
    """Configure hash chain support for history logging.

    Should be called by the proxy after creating the IntegrityStateManager.
    This enables tamper-evident logging for config_history.jsonl and policy_history.jsonl.

    CLI commands don't call this, so history logging continues to work without
    hash chains (backwards compatibility).

    Args:
        state_manager: IntegrityStateManager for hash chain state.
        log_dir: Base log directory for computing relative file keys.
    """
    global _history_state_manager, _history_log_dir
    _history_state_manager = state_manager
    _history_log_dir = log_dir


@dataclass(frozen=True, slots=True)
class HistoryLoggerConfig:
    """Configuration for a history logger.

    Defines the entity-specific parameters that differ between config and policy logging.

    Attributes:
        version_field: Field name for version in event model (e.g., "config_version").
        path_field: Field name for file path in event model (e.g., "config_path").
        entity_name: Human-readable name for the entity (e.g., "Configuration", "Policy").
        entity_name_lower: Lowercase entity name for event names (e.g., "config", "policy").
        logger_name: Logger name for history events.
        event_class: Pydantic model class for history events.
        compute_checksum: Function to compute checksum for the file.
        created_change_type: change_type value for created events.
        manual_change_message: Message for manual change detection.
        sanitize_snapshot: Optional function to sanitize snapshot before logging.
                          Used to remove sensitive fields like private key paths.
        log_path_field: Whether to include the path field in logged events.
                       Set to False for config to avoid logging filesystem paths.
    """

    version_field: str
    path_field: str
    entity_name: str
    entity_name_lower: str
    logger_name: str
    event_class: type[BaseModel]
    compute_checksum: Callable[[Path], str]
    created_change_type: str
    manual_change_message: str
    sanitize_snapshot: Callable[[dict[str, Any]], dict[str, Any]] | None = None
    log_path_field: bool = True


def get_last_version_info_for_entity(
    history_path: Path,
    config: HistoryLoggerConfig,
) -> VersionInfo:
    """Get version info for an entity using its version field.

    Args:
        history_path: Path to the history JSONL file.
        config: History logger configuration.

    Returns:
        VersionInfo with version and checksum from last entry.
    """
    return get_last_version_info(history_path, version_field=config.version_field)


def log_history_event(
    history_path: Path,
    event: BaseModel,
    config: HistoryLoggerConfig,
) -> bool:
    """Log a history event to the JSONL file with fallback.

    Uses the same fallback chain as audit logs:
    - Primary: history_path (config_history.jsonl or policy_history.jsonl)
    - Fallback: system.jsonl
    - Last resort: emergency_audit.jsonl

    When configure_history_logging_hash_chain() has been called (proxy context),
    the logger will use HashChainFormatter for tamper-evident logging.
    Otherwise (CLI context), the logger uses ISO8601Formatter.

    Args:
        history_path: Path to the history JSONL file.
        event: Pydantic event model instance.
        config: History logger configuration.

    Returns:
        True if logged to primary, False if fallback was used.
    """
    logger = get_history_logger(
        history_path,
        config.logger_name,
        state_manager=_history_state_manager,
        log_dir=_history_log_dir,
    )
    log_data = serialize_audit_event(event)

    success, _ = log_with_fallback(
        primary_logger=logger,
        system_logger=get_system_logger(),
        event_data=log_data,
        event_type=config.entity_name_lower,
        source_file=history_path.name,
    )
    return success


def log_entity_created(
    config: HistoryLoggerConfig,
    history_path: Path,
    file_path: Path,
    snapshot: dict[str, Any],
    source: str = "cli_init",
) -> str:
    """Log entity creation event with versioning.

    Called when a new config/policy is created via CLI init.
    If history exists (e.g., init --force), increments version.

    Args:
        config: History logger configuration.
        history_path: Path to the history JSONL file.
        file_path: Path to the entity file (for checksum computation).
        snapshot: Entity content as dictionary.
        source: Source of creation (default: cli_init).

    Returns:
        str: The new version (e.g., "v1" or "v2" if overwriting).
    """
    checksum = config.compute_checksum(file_path)

    # Check for existing history (e.g., init --force overwrites)
    last_info = get_last_version_info_for_entity(history_path, config)
    if last_info.version is not None:
        # Overwriting existing entity - increment version
        new_version = get_next_version(last_info.version)
        previous_version = last_info.version
    else:
        # First time creation
        new_version = INITIAL_VERSION
        previous_version = None

    # Sanitize snapshot if sanitizer provided (e.g., remove sensitive fields)
    snapshot_to_log = snapshot
    if config.sanitize_snapshot is not None:
        snapshot_to_log = config.sanitize_snapshot(snapshot)

    # Build event kwargs dynamically based on config
    event_kwargs: dict[str, Any] = {
        "event": f"{config.entity_name_lower}_created",
        "message": f"{config.entity_name} created",
        config.version_field: new_version,
        "previous_version": previous_version,
        "change_type": config.created_change_type,
        "component": "cli",
        "source": source,
        "checksum": checksum,
        "snapshot_format": "json",
        "snapshot": json.dumps(snapshot_to_log, indent=2),
    }

    # Only include path field if configured to do so
    if config.log_path_field:
        event_kwargs[config.path_field] = str(file_path)

    event = config.event_class(**event_kwargs)
    log_history_event(history_path, event, config)
    return new_version


def log_entity_loaded(
    config: HistoryLoggerConfig,
    history_path: Path,
    file_path: Path,
    snapshot: dict[str, Any],
    component: str = "proxy",
    source: str = "proxy_startup",
) -> tuple[str, bool]:
    """Log entity loaded event, detecting manual changes.

    Compares current checksum with last logged checksum.
    If different, logs manual_change_detected first.

    Args:
        config: History logger configuration.
        history_path: Path to the history JSONL file.
        file_path: Path to the entity file.
        snapshot: Entity content as dictionary.
        component: Component loading entity (default: proxy).
        source: Source of load (default: proxy_startup).

    Returns:
        Tuple of (current_version, manual_change_detected).
    """
    current_checksum = config.compute_checksum(file_path)
    last_info = get_last_version_info_for_entity(history_path, config)

    manual_change = False
    current_version = last_info.version or INITIAL_VERSION

    # Check for manual edit (checksum changed but not through our logging)
    if last_info.checksum is not None and last_info.checksum != current_checksum:
        manual_change = True
        current_version = get_next_version(last_info.version)

        # Sanitize snapshot if sanitizer provided (e.g., remove sensitive fields)
        snapshot_to_log = snapshot
        if config.sanitize_snapshot is not None:
            snapshot_to_log = config.sanitize_snapshot(snapshot)

        # Log manual change detected
        manual_event_kwargs: dict[str, Any] = {
            "event": "manual_change_detected",
            "message": config.manual_change_message,
            config.version_field: current_version,
            "previous_version": last_info.version,
            "change_type": "manual_edit",
            "component": component,
            "source": "file_change",
            "checksum": current_checksum,
            "snapshot_format": "json",
            "snapshot": json.dumps(snapshot_to_log, indent=2),
        }
        # Only include path field if configured to do so
        if config.log_path_field:
            manual_event_kwargs[config.path_field] = str(file_path)

        manual_event = config.event_class(**manual_event_kwargs)
        log_history_event(history_path, manual_event, config)

    # Log entity loaded
    loaded_event_kwargs: dict[str, Any] = {
        "event": f"{config.entity_name_lower}_loaded",
        "message": f"{config.entity_name} loaded",
        config.version_field: current_version,
        "previous_version": None,  # Not applicable for loaded events
        "change_type": "startup_load",
        "component": component,
        "source": source,
        "checksum": current_checksum,
        "snapshot_format": "json",
        "snapshot": None,  # Don't duplicate snapshot for load events
    }
    # Only include path field if configured to do so
    if config.log_path_field:
        loaded_event_kwargs[config.path_field] = str(file_path)

    loaded_event = config.event_class(**loaded_event_kwargs)
    log_history_event(history_path, loaded_event, config)

    return current_version, manual_change


def log_entity_validation_failed(
    config: HistoryLoggerConfig,
    history_path: Path,
    file_path: Path,
    error_type: str,
    error_message: str,
    component: str,
    source: str,
) -> None:
    """Log entity validation failure event.

    Called when entity fails to load due to invalid JSON or schema.

    Args:
        config: History logger configuration.
        history_path: Path to the history JSONL file.
        file_path: Path to the entity file.
        error_type: Type of error (e.g., "JSONDecodeError", "ValidationError").
        error_message: Human-readable error message.
        component: Component that detected error.
        source: Source of validation attempt.
    """
    # Try to compute checksum even for invalid entity
    try:
        checksum = config.compute_checksum(file_path)
    except (OSError, FileNotFoundError):
        checksum = "sha256:unknown"

    last_info = get_last_version_info_for_entity(history_path, config)

    event_kwargs: dict[str, Any] = {
        "event": f"{config.entity_name_lower}_validation_failed",
        "message": f"{config.entity_name} validation failed: {error_type}",
        config.version_field: last_info.version or "unknown",
        "previous_version": None,
        "change_type": "validation_error",
        "component": component,
        "source": source,
        "checksum": checksum,
        "snapshot_format": "json",
        "snapshot": None,
        "error_type": error_type,
        "error_message": error_message,
    }

    # Only include path field if configured to do so
    if config.log_path_field:
        event_kwargs[config.path_field] = str(file_path)

    event = config.event_class(**event_kwargs)
    log_history_event(history_path, event, config)
