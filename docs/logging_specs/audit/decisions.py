"""Pydantic models for policy decision logs.

IMPORTANT: The 'time' field is Optional[str] = None because:
- Model instances are created WITHOUT timestamps (time=None)
- ISO8601Formatter/HashChainFormatter adds the timestamp during log serialization
- This provides a single source of truth for timestamps

Hash chain fields (sequence, prev_hash, entry_hash) are also added by
HashChainFormatter during serialization for tamper-evident logging.

Decision events are logged to audit/decisions.jsonl for every policy evaluation,
including discovery method bypasses.
"""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


class MatchedRuleLog(BaseModel):
    """Matched rule info for decision trace logging.

    Provides context about which rules matched and why they were
    evaluated in a particular order (HITL > DENY > ALLOW).
    """

    id: str
    effect: Literal["allow", "deny", "hitl"]
    description: Optional[str] = None

    model_config = ConfigDict(extra="forbid")


class DecisionEvent(BaseModel):
    """One policy decision log entry (audit/decisions.jsonl).

    Logged on every policy evaluation for forensics and debugging.
    Includes discovery bypasses for complete audit trail.

    Note: 'time' is None when created, populated by ISO8601Formatter during logging.
    """

    # --- core ---
    time: Optional[str] = Field(
        None,
        description="ISO 8601 timestamp, added by formatter during serialization",
    )
    sequence: Optional[int] = Field(
        None,
        description="Monotonically increasing entry number, added by HashChainFormatter",
    )
    prev_hash: Optional[str] = Field(
        None,
        description="SHA-256 hash of previous entry, or 'GENESIS' for first entry",
    )
    entry_hash: Optional[str] = Field(
        None,
        description="SHA-256 hash of this entry for chain verification",
    )
    event: Literal["policy_decision"] = "policy_decision"

    # --- decision outcome ---
    decision: Literal["allow", "deny", "hitl"]
    hitl_outcome: Optional[Literal["user_allowed", "user_denied", "timeout"]] = None
    hitl_cache_hit: Optional[bool] = Field(
        None,
        description="True if approval was from cache, False if user prompted, None if not HITL",
    )
    hitl_approver_id: Optional[str] = Field(
        None,
        description="OIDC subject ID of user who approved/denied (None if timeout or cache hit)",
    )
    matched_rules: list[MatchedRuleLog] = Field(
        default_factory=list,
        description="All rules that matched, with effect and optional description for trace",
    )
    final_rule: str  # Rule ID that determined outcome, or "default", "discovery_bypass"

    # --- context summary (not full context for privacy) ---
    mcp_method: str
    tool_name: Optional[str] = None
    path: Optional[str] = None  # File path (from tool arguments)
    source_path: Optional[str] = None  # Source path for move/copy operations
    dest_path: Optional[str] = None  # Destination path for move/copy operations
    uri: Optional[str] = None  # Resource URI (from resources/read)
    scheme: Optional[str] = None  # URI scheme (file, https, s3, etc.)
    subject_id: Optional[str] = None  # Optional until auth is fully implemented
    backend_id: str  # Backend server ID (always known from config)
    side_effects: Optional[list[str]] = None  # Tool side effects (FS_WRITE, CODE_EXEC, etc.)

    # --- policy ---
    policy_version: str  # Policy version for replay/forensics (always loaded)

    # --- performance ---
    policy_eval_ms: float  # Policy rule evaluation time
    policy_hitl_ms: Optional[float] = None  # HITL wait time (only for HITL decisions)
    policy_total_ms: float  # Total evaluation time (eval + HITL)

    # --- correlation ---
    request_id: str  # JSON-RPC request ID (every decision has a request)
    session_id: Optional[str] = None  # May not exist during initialize

    model_config = ConfigDict(extra="forbid")
