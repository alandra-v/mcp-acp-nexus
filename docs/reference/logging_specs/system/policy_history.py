"""Pydantic models for policy history logs.

IMPORTANT: The 'time' field is Optional[str] = None because:
- Model instances are created WITHOUT timestamps (time=None)
- ISO8601Formatter/HashChainFormatter adds the timestamp during log serialization
- This provides a single source of truth for timestamps

Hash chain fields (sequence, prev_hash, entry_hash) are also added by
HashChainFormatter during serialization for tamper-evident logging (proxy context only).
CLI commands log without hash chain for backwards compatibility.
"""

from __future__ import annotations

from typing import Any, Dict, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


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
    sequence: Optional[int] = Field(
        None,
        description="Monotonically increasing entry number (proxy context only)",
    )
    prev_hash: Optional[str] = Field(
        None,
        description="SHA-256 hash of previous entry, or 'GENESIS' (proxy context only)",
    )
    entry_hash: Optional[str] = Field(
        None,
        description="SHA-256 hash of this entry (proxy context only)",
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
