"""Policy history logging.

Logs policy lifecycle events to policy_history.jsonl:
- policy_created: Initial creation via CLI init
- policy_loaded: Loaded at proxy startup
- manual_change_detected: File modified outside of proxy
- policy_validation_failed: Invalid JSON or schema
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from mcp_acp.telemetry.models.system import PolicyHistoryEvent
from mcp_acp.utils.file_helpers import (
    VersionInfo,
    get_next_version,
)
from mcp_acp.utils.history_logging.base import (
    HistoryLoggerConfig,
    log_entity_created,
    log_entity_loaded,
    log_entity_validation_failed,
)
from mcp_acp.utils.policy import compute_policy_checksum

# Re-export for backwards compatibility
__all__ = [
    "VersionInfo",
    "get_next_version",
    "log_policy_created",
    "log_policy_loaded",
    "log_policy_validation_failed",
    "get_policy_history_path_from_config_dir",
]


# Configuration for the policy history logger
_POLICY_LOGGER_CONFIG = HistoryLoggerConfig(
    version_field="policy_version",
    path_field="policy_path",
    entity_name="Policy",
    entity_name_lower="policy",
    logger_name="mcp-acp.policy.history",
    event_class=PolicyHistoryEvent,
    compute_checksum=compute_policy_checksum,
    created_change_type="initial_creation",
    manual_change_message="Policy file modified outside of proxy",
)


def log_policy_created(
    policy_history_path: Path,
    policy_path: Path,
    policy_snapshot: dict[str, Any],
    source: str = "cli_init",
) -> str:
    """Log policy creation event with versioning.

    Called when a new policy is created via CLI init.
    If policy history exists (e.g., init --force), increments version.

    Args:
        policy_history_path: Path to policy_history.jsonl.
        policy_path: Path to the policy file (for checksum computation).
        policy_snapshot: Policy as dictionary.
        source: Source of creation (default: cli_init).

    Returns:
        str: The new policy version (e.g., "v1" or "v2" if overwriting).
    """
    return log_entity_created(
        _POLICY_LOGGER_CONFIG,
        policy_history_path,
        policy_path,
        policy_snapshot,
        source,
    )


def log_policy_loaded(
    policy_history_path: Path,
    policy_path: Path,
    policy_snapshot: dict[str, Any],
    component: str = "proxy",
    source: str = "proxy_startup",
) -> tuple[str, bool]:
    """Log policy loaded event, detecting manual changes.

    Compares current checksum with last logged checksum.
    If different, logs manual_change_detected first.

    Args:
        policy_history_path: Path to policy_history.jsonl.
        policy_path: Path to the policy file.
        policy_snapshot: Policy as dictionary.
        component: Component loading policy (default: proxy).
        source: Source of load (default: proxy_startup).

    Returns:
        Tuple of (current_version, manual_change_detected).
    """
    return log_entity_loaded(
        _POLICY_LOGGER_CONFIG,
        policy_history_path,
        policy_path,
        policy_snapshot,
        component,
        source,
    )


def log_policy_validation_failed(
    policy_history_path: Path,
    policy_path: Path,
    error_type: str,
    error_message: str,
    component: str = "policy",
    source: str = "load_policy",
) -> None:
    """Log policy validation failure event.

    Called when policy fails to load due to invalid JSON or schema.

    Args:
        policy_history_path: Path to policy_history.jsonl.
        policy_path: Path to the policy file.
        error_type: Type of error (e.g., "JSONDecodeError", "ValidationError").
        error_message: Human-readable error message.
        component: Component that detected error.
        source: Source of validation attempt.
    """
    log_entity_validation_failed(
        _POLICY_LOGGER_CONFIG,
        policy_history_path,
        policy_path,
        error_type,
        error_message,
        component,
        source,
    )


def get_policy_history_path_from_config_dir() -> Path:
    """Get policy history path in config directory (fallback location).

    Used when we can't read log_dir from config (e.g., validation failure).

    Returns:
        Path to policy_history.jsonl in config directory.
    """
    from mcp_acp.utils.policy import get_policy_dir

    return get_policy_dir() / "mcp_acp_logs" / "system" / "policy_history.jsonl"
