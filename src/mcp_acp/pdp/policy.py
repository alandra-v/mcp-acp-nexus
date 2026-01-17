"""Policy models for ABAC policy evaluation.

This module defines the policy schema used by the policy engine.
Designed for DSL compatibility (future Cedar/Rego migration).

Policy structure:
    PolicyConfig
    ├── version: Schema version for migrations
    ├── default_action: "deny" (zero trust)
    ├── rules: List[PolicyRule]
    │   └── PolicyRule
    │       ├── id: Optional identifier
    │       ├── effect: "allow" | "deny" | "hitl"
    │       └── conditions: RuleConditions (AND logic)
    └── hitl: HITLConfig
        ├── timeout_seconds
        └── default_on_timeout

Design principles:
1. All conditions use AND logic (all must match)
2. Deny-overrides combining: HITL > DENY > ALLOW
3. Default to DENY if no rule matches (zero trust)
4. DSL-compatible structure for future migration
"""

from __future__ import annotations

__all__ = [
    "ConditionValue",
    "PolicyConfig",
    "PolicyRule",
    "RuleConditions",
    "VALID_OPERATIONS",
    "create_default_policy",
]

import hashlib
import json
from typing import Literal, Self, get_args

# Operations type for policy rules - single source of truth
OperationType = Literal["read", "write", "delete"]

# Exported constant for use in API schema and validation
VALID_OPERATIONS: tuple[str, ...] = get_args(OperationType)

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from mcp_acp.context.resource import SideEffect

# Type alias for conditions that accept single value or list (OR logic)
ConditionValue = str | list[str] | None


class RuleConditions(BaseModel):
    """Conditions for a policy rule (AND logic - all must match).

    At least one condition MUST be specified. Empty conditions are not allowed
    as they would match everything, which is a security risk.

    Most conditions accept either a single value or a list. When a list is
    provided, the condition matches if ANY value matches (OR logic within
    the field, AND logic across fields).

    Attributes:
        tool_name: Tool name pattern (glob: *, ?) - case-insensitive.
            Can be a single pattern or list of patterns (OR logic).
        path_pattern: Glob pattern for file paths (*, **, ?) - matches ANY path.
            Can be a single pattern or list of patterns (OR logic).
        source_path: Glob pattern for source path in move/copy operations.
            Can be a single pattern or list of patterns (OR logic).
        dest_path: Glob pattern for destination path in move/copy operations.
            Can be a single pattern or list of patterns (OR logic).
        operations: List of operations to match (read, write, delete).
        extension: Exact file extension match (e.g., ".key", ".env").
            Can be a single value or list of values (OR logic).
        scheme: Exact URI scheme match (e.g., "file", "db", "s3").
            Can be a single value or list of values (OR logic).
        backend_id: Server ID pattern (glob: *, ?) - case-insensitive.
            Can be a single pattern or list of patterns (OR logic).
        resource_type: Exact resource type ("tool", "resource", "prompt", "server").
        mcp_method: MCP method pattern (glob: *, ?) e.g., "resources/*".
            Can be a single pattern or list of patterns (OR logic).
        subject_id: Exact subject/user ID match.
            Can be a single value or list of values (OR logic).
        side_effects: Tool must have ANY of these side effects.
    """

    # Original conditions (now support lists with OR logic)
    tool_name: ConditionValue = None
    path_pattern: ConditionValue = None
    operations: list[OperationType] | None = None

    # Source/destination path conditions (for move/copy operations)
    source_path: ConditionValue = None
    dest_path: ConditionValue = None

    # Resource conditions
    extension: ConditionValue = None
    scheme: ConditionValue = None
    backend_id: ConditionValue = None
    resource_type: Literal["tool", "resource", "prompt", "server"] | None = None

    # Action conditions
    mcp_method: ConditionValue = None

    # Subject conditions
    subject_id: ConditionValue = None

    # Side effects (ANY logic - matches if tool has any of the listed effects)
    side_effects: list[SideEffect] | None = None

    model_config = ConfigDict(frozen=True)

    @field_validator(
        "tool_name",
        "path_pattern",
        "source_path",
        "dest_path",
        "extension",
        "scheme",
        "backend_id",
        "mcp_method",
        "subject_id",
        mode="after",
    )
    @classmethod
    def reject_empty_strings(cls, v: str | list[str] | None) -> str | list[str] | None:
        """Reject empty or whitespace-only strings in condition values.

        Empty strings would silently never match, which is confusing.
        Better to fail fast with a clear error.
        """
        if v is None:
            return v

        if isinstance(v, str):
            if not v.strip():
                raise ValueError("Condition value cannot be empty or whitespace-only")
            return v

        # List case
        for item in v:
            if not item.strip():
                raise ValueError("List conditions cannot contain empty or whitespace-only strings")
        return v

    @model_validator(mode="after")
    def at_least_one_condition(self) -> Self:
        """Validate that at least one condition is specified.

        Empty conditions would match everything, which is a security risk.
        """
        all_none = all(
            v is None
            for v in [
                self.tool_name,
                self.path_pattern,
                self.source_path,
                self.dest_path,
                self.operations,
                self.extension,
                self.scheme,
                self.backend_id,
                self.resource_type,
                self.mcp_method,
                self.subject_id,
                self.side_effects,
            ]
        )
        if all_none:
            raise ValueError(
                "At least one condition must be specified. " "Empty conditions would match everything."
            )
        return self


class PolicyRule(BaseModel):
    """A single policy rule.

    All matching rules are collected and combined: HITL > DENY > ALLOW.
    All conditions use AND logic (all specified conditions must match).

    Attributes:
        id: Optional identifier for logging/debugging
        description: Optional human-readable description for documentation
        effect: What happens when rule matches
        conditions: Matching criteria (AND logic)
        cache_side_effects: (HITL only) Side effects that allow approval caching.
            If None (default), tools with ANY side effect are never cached.
            Set to a list of SideEffects to allow caching for those effects.
            CODE_EXEC is never cached regardless of this setting (security).
    """

    id: str | None = None
    description: str | None = None
    effect: Literal["allow", "deny", "hitl"]
    conditions: RuleConditions = Field(default_factory=RuleConditions)
    cache_side_effects: list[SideEffect] | None = None

    model_config = ConfigDict(frozen=True)

    @model_validator(mode="after")
    def validate_cache_side_effects(self) -> Self:
        """Validate cache_side_effects is only set for HITL rules."""
        if self.cache_side_effects is not None and self.effect != "hitl":
            raise ValueError(
                "cache_side_effects can only be set when effect='hitl'. "
                f"Got effect='{self.effect}' with cache_side_effects={self.cache_side_effects}"
            )
        return self


def _generate_rule_id(rule: PolicyRule) -> str:
    """Generate deterministic ID from rule content.

    Creates a stable hash-based ID using the rule's effect and conditions.
    Same rule content always produces the same ID.

    Args:
        rule: PolicyRule to generate ID for.

    Returns:
        ID in format "rule_<8-char-hex>", e.g., "rule_a1b2c3d4".
    """
    # Create stable JSON representation (sorted keys, exclude None values)
    content = json.dumps(
        {
            "effect": rule.effect,
            "conditions": rule.conditions.model_dump(exclude_none=True),
        },
        sort_keys=True,
    )

    # Hash and take first 8 chars
    hash_id = hashlib.sha256(content.encode()).hexdigest()[:8]
    return f"rule_{hash_id}"


class PolicyConfig(BaseModel):
    """Complete policy configuration.

    Attributes:
        version: Schema version for migrations
        default_action: What to do when no rule matches (always "deny")
        rules: List of rules; all matches combined via HITL > DENY > ALLOW

    Note:
        HITL configuration (timeout, caching) is in the config file, not policy.
        Rules without IDs get deterministic auto-generated IDs based on content hash.
        User-provided IDs must be unique within the policy.
    """

    version: str = "1"
    default_action: Literal["deny"] = "deny"
    rules: list[PolicyRule] = Field(default_factory=list)

    model_config = ConfigDict(frozen=True)

    @model_validator(mode="after")
    def ensure_rule_ids(self) -> Self:
        """Ensure all rules have unique IDs, generating them if needed.

        1. Check user-provided IDs are unique
        2. Generate deterministic IDs for rules without them
        3. Check all final IDs (user + generated) are unique
        """
        # Check user-provided IDs are unique
        user_ids = [r.id for r in self.rules if r.id is not None]
        if len(user_ids) != len(set(user_ids)):
            duplicates = [id for id in user_ids if user_ids.count(id) > 1]
            raise ValueError(f"Duplicate rule IDs: {set(duplicates)}")

        # Generate IDs for rules without them
        new_rules = []
        for rule in self.rules:
            if rule.id is None:
                generated_id = _generate_rule_id(rule)
                new_rules.append(rule.model_copy(update={"id": generated_id}))
            else:
                new_rules.append(rule)

        # Check all final IDs are unique (handles edge case of user ID matching generated)
        all_ids = [r.id for r in new_rules]
        if len(all_ids) != len(set(all_ids)):
            duplicates = [id for id in all_ids if all_ids.count(id) > 1]
            raise ValueError(
                f"Rule ID collision: {set(duplicates)}. " "Add explicit IDs to conflicting rules."
            )

        # Replace rules list (model is frozen, use object.__setattr__)
        object.__setattr__(self, "rules", new_rules)
        return self


def create_default_policy() -> PolicyConfig:
    """Create a default policy with zero trust defaults.

    Returns:
        PolicyConfig with empty rules and deny default.
        Discovery methods bypass policy entirely (handled in engine).
    """
    return PolicyConfig(
        version="1",
        default_action="deny",
        rules=[],
    )
