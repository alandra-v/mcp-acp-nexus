"""Pydantic models for system/operational logs.

IMPORTANT: The 'time' field in all models is Optional[str] = None because:
- Model instances are created WITHOUT timestamps (time=None)
- ISO8601Formatter adds the timestamp during log serialization
- This provides a single source of truth for timestamps
- Logged events ALWAYS have a 'time' field in ISO 8601 format (e.g., "2025-12-11T10:30:45.123Z")

This separation means:
- Models define the structured event DATA
- Formatter adds the TIMESTAMP during serialization
- No duplicate timestamp generation across the codebase
"""

from __future__ import annotations

__all__ = [
    "ConfigHistoryEvent",
    "PolicyHistoryEvent",
    "SystemEvent",
]

from typing import Any, Dict, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


class SystemEvent(BaseModel):
    """
    One system/operational log entry (logs/system/system.jsonl).

    Inspired by:
      - OCSF Application Error (6008): error_type, error_message, stacktrace
      - OCSF Process Activity (1007): component identity, operational activity, status

    Used for WARNING, ERROR, and CRITICAL events that indicate operational issues.

    Note: 'time' is None when created, populated by ISO8601Formatter during logging.
    """

    # --- core ---
    time: Optional[str] = Field(
        None,
        description="ISO 8601 timestamp, added by formatter during serialization",
    )
    level: str  # "WARNING", "ERROR", "CRITICAL"
    event: str  # machine-friendly event name
    message: Optional[str] = None  # human-readable description

    # --- component / context ---
    component: Optional[str] = None  # "proxy", "backend_client", etc.
    session_id: Optional[str] = None  # if tied to an MCP session
    request_id: Optional[str] = None  # if tied to an MCP request
    backend_id: Optional[str] = None  # if backend-specific
    config_version: Optional[str] = None  # config active at the time

    # --- error details ---
    error_type: Optional[str] = None  # Exception class, e.g. TimeoutError
    error_message: Optional[str] = None  # Short error message
    stacktrace: Optional[str] = None  # Optional full traceback

    # --- additional structured details ---
    details: Optional[Dict[str, Any]] = None  # retry_count, timeout_ms, etc.

    model_config = ConfigDict(extra="allow")


class ConfigHistoryEvent(BaseModel):
    """
    One configuration history log entry (logs/system/config_history.jsonl).

    Captures the full lifecycle of configuration:
    - config_created: Initial configuration creation via CLI init
    - config_updated: Configuration updated via CLI commands
    - config_loaded: Configuration loaded at proxy startup
    - manual_change_detected: File modified outside of CLI (checksum mismatch)
    - config_validation_failed: Invalid JSON or schema validation error

    The design follows general security logging and configuration
    management guidance (e.g., OWASP logging recommendations,
    NIST SP 800-128 for security-focused configuration management,
    and NIST SP 800-92 / CIS Control 8 for audit log management),
    by recording when configuration changes occur, which version
    is active, and a snapshot sufficient to reconstruct the effective
    configuration during later analysis.

    Note: 'time' is None when created, populated by ISO8601Formatter during logging.
    """

    # --- core ---
    time: Optional[str] = Field(
        None,
        description="ISO 8601 timestamp, added by formatter during serialization",
    )
    event: Literal[
        "config_created",
        "config_updated",
        "config_loaded",
        "manual_change_detected",
        "config_validation_failed",
    ]
    message: Optional[str] = None  # human-readable description

    # --- versioning ---
    config_version: str  # version ID (e.g., "v1", "v2")
    previous_version: Optional[str] = None
    change_type: Literal[
        "initial_load",  # First time config is created
        "cli_update",  # CLI update command
        "manual_edit",  # Detected manual file edit
        "startup_load",  # Loading config on proxy startup
        "validation_error",  # Config failed validation
    ]

    # --- source / component ---
    component: Optional[str] = None  # e.g. "cli", "proxy", "config"
    config_path: Optional[str] = None  # path to the config file on disk
    source: Optional[str] = None  # e.g. "cli_init", "cli_update", "proxy_startup"

    # --- integrity ---
    checksum: str  # e.g. "sha256:abcd1234..."

    # --- snapshot ---
    snapshot_format: Literal["json"] = "json"
    snapshot: Optional[str] = None  # full config content (optional for load events)

    # --- change details (for update events) ---
    changes: Optional[Dict[str, Dict[str, Any]]] = None  # {"path": {"old": x, "new": y}}

    # --- error details (for validation failures) ---
    error_type: Optional[str] = None  # e.g. "JSONDecodeError", "ValidationError"
    error_message: Optional[str] = None  # human-readable error

    model_config = ConfigDict(extra="forbid")


class PolicyHistoryEvent(BaseModel):
    """
    One policy history log entry (logs/system/policy_history.jsonl).

    Captures the full lifecycle of policy configuration:
    - policy_created: Initial policy creation via CLI init
    - policy_loaded: Policy loaded at proxy startup
    - policy_updated: Policy updated (e.g., rule added/removed)
    - manual_change_detected: File modified outside of proxy (checksum mismatch)
    - policy_validation_failed: Invalid JSON or schema validation error

    The design mirrors ConfigHistoryEvent for consistency.

    Note: 'time' is None when created, populated by ISO8601Formatter during logging.
    """

    # --- core ---
    time: Optional[str] = Field(
        None,
        description="ISO 8601 timestamp, added by formatter during serialization",
    )
    event: Literal[
        "policy_created",
        "policy_loaded",
        "policy_updated",
        "manual_change_detected",
        "policy_validation_failed",
    ]
    message: Optional[str] = None  # human-readable description

    # --- versioning ---
    policy_version: str  # version ID (e.g., "v1", "v2")
    previous_version: Optional[str] = None
    change_type: Literal[
        "initial_creation",  # First time policy is created
        "startup_load",  # Loading policy on proxy startup
        "rule_update",  # Rules added/removed
        "manual_edit",  # Detected manual file edit
        "validation_error",  # Policy failed validation
    ]

    # --- source / component ---
    component: Optional[str] = None  # e.g. "cli", "proxy", "pep", "hitl"
    policy_path: Optional[str] = None  # path to policy.json on disk
    source: Optional[str] = None  # e.g. "cli_init", "proxy_startup", "hitl_handler"

    # --- integrity ---
    checksum: str  # e.g. "sha256:abcd1234..."

    # --- snapshot ---
    snapshot_format: Literal["json"] = "json"
    snapshot: Optional[str] = None  # full policy content (optional for load events)

    # --- rule details (for rule updates) ---
    rule_id: Optional[str] = None  # ID of added/removed rule
    rule_effect: Optional[str] = None  # "allow", "deny", "hitl"
    rule_conditions: Optional[Dict[str, Any]] = None  # conditions of added rule

    # --- error details (for validation failures) ---
    error_type: Optional[str] = None  # e.g. "JSONDecodeError", "ValidationError"
    error_message: Optional[str] = None  # human-readable error

    model_config = ConfigDict(extra="forbid")
