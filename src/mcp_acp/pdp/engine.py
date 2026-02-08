"""Policy engine - evaluate DecisionContext against policy rules.

This module provides the PolicyEngine class that evaluates requests
against policy rules to produce ALLOW/DENY/HITL decisions.

Evaluation flow:
1. Discovery methods (tools/list, etc.) → ALLOW (bypass policy)
2. Collect all matching rules
3. Apply combining algorithm: HITL > DENY > ALLOW
4. Within each effect level, select the most specific rule
5. No match → return default_action (DENY)

Design principles:
1. All conditions in a rule use AND logic
2. Combining algorithm: HITL overrides DENY overrides ALLOW
3. Within the same effect level, the most specific rule wins
4. Discovery methods bypass policy entirely
5. Default to DENY if no rule matches (zero trust)

Specificity scoring:
Rules are ranked by specificity to determine the "final_rule" when multiple
rules with the same effect match. Specificity is calculated as:

  Score = (condition_count × 100) + exactness_bonus + path_depth_bonus

Where:
- condition_count: Number of non-null conditions (+100 each)
- exactness_bonus: +10 for each pattern without wildcards (*, ?, **)
- path_depth_bonus: +1 per path segment before wildcard in path patterns

Example scores:
- tool_name: "read*"                                    → 100 (1 condition)
- tool_name: "read_file"                                → 110 (1 condition + exact)
- tool_name: "read*", extension: ".py"                  → 200 (2 conditions)
- tool_name: "read*", path_pattern: "/a/b/c/**"         → 203 (2 conditions + depth 3)

Tie-breaker: If two rules have the same specificity score, the rule
that appears first in the policy file wins (preserves predictability).

Known limitations:
- Bracket glob patterns `[...]` are not detected as wildcards
- Escaped wildcards are not supported
- List conditions count as 1 condition regardless of list length
"""

from __future__ import annotations

__all__ = [
    "MatchedRule",
    "PolicyEngine",
]

import os
from dataclasses import dataclass
from typing import Literal

from mcp_acp.context import ActionCategory, DecisionContext
from mcp_acp.exceptions import PolicyEnforcementFailure
from mcp_acp.pdp.decision import Decision
from mcp_acp.pdp.matcher import (
    _match_any,
    _match_exact_case_insensitive,
    _match_exact_case_sensitive,
    _match_glob_case_insensitive,
    _match_glob_case_sensitive,
    _match_operations,
    _match_side_effects,
    infer_operation,
    match_path_pattern,
    match_tool_name,
)
from mcp_acp.context.resource import SideEffect
from mcp_acp.pdp.policy import PolicyConfig, PolicyRule

# Wildcard characters used in glob patterns
_WILDCARD_CHARS = {"*", "?"}


def _has_wildcards(pattern: str | list[str] | None) -> bool:
    """Check if a pattern contains wildcard characters (*, ?).

    For lists, returns True if ANY pattern has wildcards.

    Args:
        pattern: Single pattern string, list of patterns, or None.

    Returns:
        True if any wildcard character is present, False otherwise.
    """
    if pattern is None:
        return False
    if isinstance(pattern, str):
        return any(c in pattern for c in _WILDCARD_CHARS)
    # List of patterns - check if any has wildcards
    return any(any(c in p for c in _WILDCARD_CHARS) for p in pattern)


def _count_path_depth(pattern: str | list[str] | None) -> int:
    """Count path segments before the first wildcard.

    Deeper paths are more specific (e.g., /a/b/c/** scores higher than /a/**).
    For lists, returns the maximum depth across all patterns.

    Args:
        pattern: Path pattern string, list of patterns, or None.

    Returns:
        Number of path segments before the first wildcard.
    """
    if pattern is None:
        return 0

    def _depth_for_single(p: str) -> int:
        # Split by / and count segments before first wildcard
        segments = p.split("/")
        depth = 0
        for seg in segments:
            if any(c in seg for c in _WILDCARD_CHARS):
                break
            if seg:  # Skip empty segments (leading /)
                depth += 1
        return depth

    if isinstance(pattern, str):
        return _depth_for_single(pattern)
    # List of patterns - return max depth
    return max(_depth_for_single(p) for p in pattern) if pattern else 0


@dataclass(frozen=True, slots=True)
class MatchedRule:
    """A policy rule that matched the decision context.

    Attributes:
        id: Rule identifier (from rule.id or auto-generated).
        description: Optional human-readable description.
        effect: The rule's effect ("allow", "deny", "hitl").
        specificity: Specificity score for tie-breaking within same effect level.
            Higher scores indicate more specific rules.
        cache_side_effects: (HITL only) Side effects that allow approval caching.
    """

    id: str
    description: str | None
    effect: Literal["allow", "deny", "hitl"]
    specificity: int = 0
    cache_side_effects: list["SideEffect"] | None = None


class PolicyEngine:
    """Policy evaluation engine.

    Evaluates DecisionContext against policy rules to produce decisions.
    Discovery methods bypass policy entirely and always return ALLOW.

    Uses HITL > DENY > ALLOW combining algorithm:
    - If ANY matching rule says HITL → HITL (human decides)
    - Else if ANY matching rule says DENY → DENY
    - Else if ANY matching rule says ALLOW → ALLOW
    - Else → default_action (DENY)

    Attributes:
        policy: The policy configuration to evaluate against.
    """

    def __init__(
        self,
        policy: PolicyConfig,
        protected_dirs: tuple[str, ...] = (),
    ) -> None:
        """Initialize the policy engine.

        Args:
            policy: Policy configuration with rules and defaults.
            protected_dirs: Directories that are protected from MCP tool access.
                These are resolved to real paths to prevent symlink bypass.
        """
        self.policy = policy
        # Resolve all protected dirs to real paths at init time
        self._protected_dirs = tuple(os.path.realpath(d) for d in protected_dirs)

    def reload_policy(self, new_policy: PolicyConfig) -> None:
        """Reload policy configuration for hot reload.

        Atomically swaps the policy reference. Thread-safe because:
        - Python's GIL ensures reference assignment is atomic
        - PolicyConfig is frozen (immutable) - no partial state
        - Evaluation methods only read self.policy

        Args:
            new_policy: New validated PolicyConfig to use.
        """
        self.policy = new_policy

    @property
    def rule_count(self) -> int:
        """Get the number of policy rules.

        Used by reloader for hot reload statistics.

        Returns:
            Number of rules in the current policy.
        """
        return len(self.policy.rules)

    def is_protected_path(self, path: str | None) -> bool:
        """Check if path is under a protected directory.

        Protected paths cannot be accessed by MCP tools regardless of policy.
        This is a built-in security measure that cannot be overridden.

        Symlink-safe: resolves path to real path before checking.

        Args:
            path: File path to check (may be None).

        Returns:
            True if path is under a protected directory, False otherwise.
        """
        if path is None or not self._protected_dirs:
            return False

        try:
            resolved = os.path.realpath(path)
            return any(resolved == d or resolved.startswith(d + os.sep) for d in self._protected_dirs)
        except (OSError, ValueError):
            # Can't resolve path - not a protected path match
            return False

    def evaluate(self, context: DecisionContext) -> Decision:
        """Evaluate a request context against the policy.

        Evaluation order:
        1. Built-in protected paths → DENY (cannot be overridden)
        2. Discovery methods → ALLOW (bypass policy)
        3. Collect matching rules → apply HITL > DENY > ALLOW combining
        4. No match → default_action (DENY)

        Args:
            context: DecisionContext built from the request.

        Returns:
            Decision: ALLOW, DENY, or HITL based on policy evaluation.

        Raises:
            PolicyEnforcementFailure: If policy evaluation fails unexpectedly.
                This is a critical security failure requiring proxy shutdown.
        """
        try:
            # Built-in protection - check FIRST, cannot be overridden by policy
            path = context.resource.resource.path if context.resource.resource else None
            if self.is_protected_path(path):
                return Decision.DENY

            # Discovery methods bypass policy entirely
            if context.action.category == ActionCategory.DISCOVERY:
                return Decision.ALLOW

            # Collect all matching rules
            matching_rules = [rule for rule in self.policy.rules if self._rule_matches(rule, context)]

            if not matching_rules:
                # No rules matched - return default action (DENY)
                return self._effect_to_decision(self.policy.default_action)

            # Apply combining algorithm: HITL > DENY > ALLOW
            # HITL has highest priority - let human decide
            for rule in matching_rules:
                if rule.effect == "hitl":
                    return Decision.HITL

            # DENY has second priority - security first
            for rule in matching_rules:
                if rule.effect == "deny":
                    return Decision.DENY

            # All matching rules must be ALLOW
            return Decision.ALLOW

        except PolicyEnforcementFailure:
            # Re-raise our own exceptions
            raise
        except Exception as e:
            # Unexpected error during policy evaluation - critical failure
            # Cannot trust policy decisions if evaluation crashes
            raise PolicyEnforcementFailure(
                f"Policy evaluation failed unexpectedly: {type(e).__name__}: {e}. "
                "Cannot safely evaluate requests - proxy must shutdown."
            ) from e

    def get_matching_rules(self, context: DecisionContext) -> list[MatchedRule]:
        """Get all rules that match the given context.

        This is the public API for retrieving matched rules. Use this instead
        of accessing _rule_matches directly.

        Each matched rule includes a specificity score for tie-breaking when
        multiple rules with the same effect match. Higher scores indicate
        more specific rules.

        Args:
            context: DecisionContext to match against.

        Returns:
            List of MatchedRule with id, description, effect, and specificity
            for each matching rule.
        """
        matched: list[MatchedRule] = []

        for idx, rule in enumerate(self.policy.rules):
            if self._rule_matches(rule, context):
                rule_id = rule.id or f"rule_{idx}"
                matched.append(
                    MatchedRule(
                        id=rule_id,
                        description=rule.description,
                        effect=rule.effect,
                        specificity=self._calculate_specificity(rule),
                        cache_side_effects=rule.cache_side_effects,
                    )
                )

        return matched

    def _rule_matches(self, rule: PolicyRule, context: DecisionContext) -> bool:
        """Check if a rule matches the context.

        All conditions use AND logic - all specified conditions must match.

        Args:
            rule: Policy rule to check.
            context: DecisionContext to match against.

        Returns:
            True if all conditions match, False otherwise.
        """
        conditions = rule.conditions

        # Extract values from context for easy access
        tool_name = context.resource.tool.name if context.resource.tool else None
        tool_side_effects = context.resource.tool.side_effects if context.resource.tool else None
        path = context.resource.resource.path if context.resource.resource else None
        source_path = context.resource.resource.source_path if context.resource.resource else None
        dest_path = context.resource.resource.dest_path if context.resource.resource else None
        extension = context.resource.resource.extension if context.resource.resource else None
        scheme = context.resource.resource.scheme if context.resource.resource else None
        backend_id = context.resource.server.id
        resource_type = context.resource.type.value  # Convert enum to string
        mcp_method = context.action.mcp_method
        subject_id = context.subject.id

        # Check tool_name condition (glob, case-insensitive, OR logic for lists)
        if not _match_any(conditions.tool_name, tool_name, match_tool_name):
            return False

        # Check path_pattern condition (glob with **, OR logic for lists)
        if not _match_any(conditions.path_pattern, path, match_path_pattern):
            return False

        # Check source_path condition (glob with **, OR logic for lists)
        if not _match_any(conditions.source_path, source_path, match_path_pattern):
            return False

        # Check dest_path condition (glob with **, OR logic for lists)
        if not _match_any(conditions.dest_path, dest_path, match_path_pattern):
            return False

        # Check operations condition (heuristic from tool name)
        if conditions.operations is not None:
            inferred_op = infer_operation(tool_name)
            if not _match_operations(conditions.operations, inferred_op):
                return False

        # Check extension condition (exact, case-insensitive, OR logic for lists)
        if not _match_any(conditions.extension, extension, _match_exact_case_insensitive):
            return False

        # Check scheme condition (exact, case-insensitive, OR logic for lists)
        if not _match_any(conditions.scheme, scheme, _match_exact_case_insensitive):
            return False

        # Check backend_id condition (glob, case-insensitive, OR logic for lists)
        if not _match_any(conditions.backend_id, backend_id, _match_glob_case_insensitive):
            return False

        # Check resource_type condition (exact, case-insensitive) - single value only
        if conditions.resource_type is not None:
            if not _match_exact_case_insensitive(conditions.resource_type, resource_type):
                return False

        # Check mcp_method condition (glob, case-sensitive, OR logic for lists)
        if not _match_any(conditions.mcp_method, mcp_method, _match_glob_case_sensitive):
            return False

        # Check subject_id condition (exact, case-sensitive, OR logic for lists)
        if not _match_any(conditions.subject_id, subject_id, _match_exact_case_sensitive):
            return False

        # Check side_effects condition (ANY logic)
        if conditions.side_effects is not None:
            if not _match_side_effects(conditions.side_effects, tool_side_effects):
                return False

        # All specified conditions matched
        return True

    def _calculate_specificity(self, rule: PolicyRule) -> int:
        """Calculate specificity score for a rule.

        Higher scores indicate more specific rules. Used to select the
        "final_rule" when multiple rules with the same effect match.

        Scoring formula:
            Score = (condition_count × 100) + exactness_bonus + path_depth_bonus

        Where:
        - condition_count: Number of non-null conditions (+100 each)
        - exactness_bonus: +10 for patterns without wildcards (*, ?, **)
        - path_depth_bonus: +1 per path segment before wildcard

        Args:
            rule: PolicyRule to calculate specificity for.

        Returns:
            Integer specificity score (higher = more specific).
        """
        score = 0
        conditions = rule.conditions

        # Count conditions and add exactness bonuses
        # Each non-null condition adds 100 points
        # Exact patterns (no wildcards) add 10 bonus points

        if conditions.tool_name is not None:
            score += 100
            if not _has_wildcards(conditions.tool_name):
                score += 10

        if conditions.path_pattern is not None:
            score += 100
            if not _has_wildcards(conditions.path_pattern):
                score += 10
            # Path depth bonus: deeper paths are more specific
            score += _count_path_depth(conditions.path_pattern)

        if conditions.source_path is not None:
            score += 100
            if not _has_wildcards(conditions.source_path):
                score += 10
            score += _count_path_depth(conditions.source_path)

        if conditions.dest_path is not None:
            score += 100
            if not _has_wildcards(conditions.dest_path):
                score += 10
            score += _count_path_depth(conditions.dest_path)

        if conditions.operations is not None:
            score += 100

        if conditions.extension is not None:
            score += 100
            # Extensions are typically exact (no wildcards)

        if conditions.scheme is not None:
            score += 100

        if conditions.backend_id is not None:
            score += 100
            if not _has_wildcards(conditions.backend_id):
                score += 10

        if conditions.resource_type is not None:
            score += 100
            # resource_type is always exact (enum value)
            score += 10

        if conditions.mcp_method is not None:
            score += 100
            if not _has_wildcards(conditions.mcp_method):
                score += 10

        if conditions.subject_id is not None:
            score += 100
            # subject_id is always exact (no wildcards supported)
            score += 10

        if conditions.side_effects is not None:
            score += 100

        return score

    def _get_most_specific_rule(self, rules: list[PolicyRule]) -> PolicyRule:
        """Get the most specific rule from a list of rules.

        Uses specificity scoring to determine which rule is most specific.
        If two rules have the same score, the first one in the list wins
        (preserves policy file order for predictability).

        Args:
            rules: Non-empty list of PolicyRule objects.

        Returns:
            The most specific rule from the list.
        """
        # Sort by specificity (descending), preserving original order for ties
        # enumerate() captures original index for stable sorting
        scored = [(self._calculate_specificity(rule), idx, rule) for idx, rule in enumerate(rules)]
        # Sort by score descending, then by original index ascending (for ties)
        scored.sort(key=lambda x: (-x[0], x[1]))
        return scored[0][2]

    def _effect_to_decision(self, effect: str) -> Decision:
        """Convert rule effect string to Decision enum.

        Args:
            effect: Effect string ("allow", "deny", "hitl")

        Returns:
            Corresponding Decision enum value.
        """
        return Decision(effect)
