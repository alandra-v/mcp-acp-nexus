"""Unit tests for policy rule specificity scoring.

Tests the specificity calculation used for tie-breaking when multiple
rules with the same effect match a request.

NOTE: These tests cover basic functionality but are not exhaustive.
Known limitations not yet tested:
- Bracket glob patterns `[...]` are not detected as wildcards
- Escaped wildcards `\\*` are treated as wildcards (no escape support)
- List conditions (e.g., tool_name: ["a", "b"]) count as 1 condition
- Performance of specificity calculation is not benchmarked
"""

import pytest

from mcp_acp.pdp.engine import (
    PolicyEngine,
    _count_path_depth,
    _has_wildcards,
)
from mcp_acp.pdp.policy import PolicyConfig, PolicyRule, RuleConditions


class TestHasWildcards:
    """Tests for _has_wildcards() helper function."""

    def test_returns_false_for_none(self) -> None:
        assert _has_wildcards(None) is False

    def test_returns_false_for_exact_string(self) -> None:
        assert _has_wildcards("read_file") is False

    def test_returns_true_for_star(self) -> None:
        assert _has_wildcards("read*") is True

    def test_returns_true_for_question_mark(self) -> None:
        assert _has_wildcards("file?.txt") is True

    def test_returns_true_for_double_star(self) -> None:
        assert _has_wildcards("/path/**") is True

    def test_returns_false_for_empty_string(self) -> None:
        assert _has_wildcards("") is False

    def test_list_returns_true_if_any_has_wildcards(self) -> None:
        assert _has_wildcards(["exact", "pattern*"]) is True

    def test_list_returns_false_if_none_have_wildcards(self) -> None:
        assert _has_wildcards(["exact", "also_exact"]) is False

    def test_empty_list_returns_false(self) -> None:
        assert _has_wildcards([]) is False


class TestCountPathDepth:
    """Tests for _count_path_depth() helper function."""

    def test_returns_zero_for_none(self) -> None:
        assert _count_path_depth(None) == 0

    def test_returns_zero_for_empty_string(self) -> None:
        assert _count_path_depth("") == 0

    def test_counts_segments_before_wildcard(self) -> None:
        assert _count_path_depth("/<home>/<user>/<projects>/**") == 3

    def test_counts_single_segment(self) -> None:
        assert _count_path_depth("/Users/**") == 1

    def test_counts_all_segments_for_exact_path(self) -> None:
        assert _count_path_depth("/a/b/c/d") == 4

    def test_stops_at_star_in_segment(self) -> None:
        assert _count_path_depth("/a/b/file*.txt") == 2

    def test_handles_double_slashes(self) -> None:
        # Empty segments are skipped
        assert _count_path_depth("//a//b//**") == 2

    def test_handles_relative_path(self) -> None:
        assert _count_path_depth("relative/path/**") == 2

    def test_list_returns_max_depth(self) -> None:
        patterns = ["/a/**", "/a/b/c/**", "/x/**"]
        assert _count_path_depth(patterns) == 3

    def test_empty_list_returns_zero(self) -> None:
        assert _count_path_depth([]) == 0


class TestCalculateSpecificity:
    """Tests for PolicyEngine._calculate_specificity() method."""

    @pytest.fixture
    def engine(self) -> PolicyEngine:
        """Create a minimal policy engine for testing."""
        policy = PolicyConfig(rules=[])
        return PolicyEngine(policy)

    def test_single_condition_scores_100(self, engine: PolicyEngine) -> None:
        rule = PolicyRule(
            effect="allow",
            conditions=RuleConditions(tool_name="read*"),
        )
        assert engine._calculate_specificity(rule) == 100

    def test_exact_tool_name_adds_10_bonus(self, engine: PolicyEngine) -> None:
        rule = PolicyRule(
            effect="allow",
            conditions=RuleConditions(tool_name="read_file"),
        )
        assert engine._calculate_specificity(rule) == 110

    def test_two_conditions_score_200(self, engine: PolicyEngine) -> None:
        rule = PolicyRule(
            effect="allow",
            conditions=RuleConditions(tool_name="read*", extension=".py"),
        )
        assert engine._calculate_specificity(rule) == 200

    def test_path_depth_adds_bonus(self, engine: PolicyEngine) -> None:
        rule = PolicyRule(
            effect="allow",
            conditions=RuleConditions(
                tool_name="read*",
                path_pattern="/<home>/<user>/<projects>/**",
            ),
        )
        # 2 conditions (200) + 3 depth = 203
        assert engine._calculate_specificity(rule) == 203

    def test_exact_path_adds_exactness_and_depth(self, engine: PolicyEngine) -> None:
        rule = PolicyRule(
            effect="allow",
            conditions=RuleConditions(
                path_pattern="/a/b/c/file.txt",
            ),
        )
        # 1 condition (100) + exact (10) + depth 4 = 114
        assert engine._calculate_specificity(rule) == 114

    def test_multiple_exact_conditions(self, engine: PolicyEngine) -> None:
        rule = PolicyRule(
            effect="allow",
            conditions=RuleConditions(
                tool_name="read_file",  # exact +10
                extension=".py",  # extension always exact (no wildcard check)
                resource_type="tool",  # always exact +10
            ),
        )
        # 3 conditions (300) + tool_name exact (10) + resource_type exact (10) = 320
        assert engine._calculate_specificity(rule) == 320

    def test_subject_id_adds_exact_bonus(self, engine: PolicyEngine) -> None:
        rule = PolicyRule(
            effect="allow",
            conditions=RuleConditions(
                tool_name="read*",
                subject_id="user123",
            ),
        )
        # 2 conditions (200) + subject_id exact (10) = 210
        assert engine._calculate_specificity(rule) == 210


class TestSpecificityTieBreaking:
    """Integration tests for specificity-based final_rule selection."""

    def test_more_conditions_wins(self) -> None:
        """Rule with more conditions should win over rule with fewer."""
        policy = PolicyConfig(
            rules=[
                PolicyRule(
                    id="less-specific",
                    effect="hitl",
                    conditions=RuleConditions(tool_name="read*"),
                ),
                PolicyRule(
                    id="more-specific",
                    effect="hitl",
                    conditions=RuleConditions(tool_name="read*", extension=".py"),
                ),
            ]
        )
        engine = PolicyEngine(policy)

        # Create a mock context that matches both rules
        from unittest.mock import MagicMock

        context = MagicMock()
        context.resource.tool.name = "read_file"
        context.resource.tool.side_effects = None
        context.resource.resource.path = "/test/file.py"
        context.resource.resource.source_path = None
        context.resource.resource.dest_path = None
        context.resource.resource.extension = ".py"
        context.resource.resource.scheme = None
        context.resource.server.id = "test"
        context.resource.type.value = "tool"
        context.action.mcp_method = "tools/call"
        context.action.category = None  # Not discovery
        context.subject.id = "user1"

        matched = engine.get_matching_rules(context)

        # Both should match
        assert len(matched) == 2

        # More specific rule should have higher score
        less_specific = next(m for m in matched if m.id == "less-specific")
        more_specific = next(m for m in matched if m.id == "more-specific")
        assert more_specific.specificity > less_specific.specificity

    def test_exact_beats_wildcard(self) -> None:
        """Exact pattern should score higher than wildcard pattern."""
        policy = PolicyConfig(
            rules=[
                PolicyRule(
                    id="wildcard",
                    effect="allow",
                    conditions=RuleConditions(tool_name="read*"),
                ),
                PolicyRule(
                    id="exact",
                    effect="allow",
                    conditions=RuleConditions(tool_name="read_file"),
                ),
            ]
        )
        engine = PolicyEngine(policy)

        from unittest.mock import MagicMock

        context = MagicMock()
        context.resource.tool.name = "read_file"
        context.resource.tool.side_effects = None
        context.resource.resource = None
        context.resource.server.id = "test"
        context.resource.type.value = "tool"
        context.action.mcp_method = "tools/call"
        context.action.category = None
        context.subject.id = "user1"

        matched = engine.get_matching_rules(context)

        wildcard = next(m for m in matched if m.id == "wildcard")
        exact = next(m for m in matched if m.id == "exact")
        assert exact.specificity > wildcard.specificity

    def test_file_order_breaks_ties(self) -> None:
        """When specificity is equal, first rule in file should win."""
        policy = PolicyConfig(
            rules=[
                PolicyRule(
                    id="first",
                    effect="deny",
                    conditions=RuleConditions(tool_name="read*"),
                ),
                PolicyRule(
                    id="second",
                    effect="deny",
                    conditions=RuleConditions(tool_name="read*"),
                ),
            ]
        )
        engine = PolicyEngine(policy)

        from unittest.mock import MagicMock

        context = MagicMock()
        context.resource.tool.name = "read_file"
        context.resource.tool.side_effects = None
        context.resource.resource = None
        context.resource.server.id = "test"
        context.resource.type.value = "tool"
        context.action.mcp_method = "tools/call"
        context.action.category = None
        context.subject.id = "user1"

        matched = engine.get_matching_rules(context)

        # Both have same specificity
        first = next(m for m in matched if m.id == "first")
        second = next(m for m in matched if m.id == "second")
        assert first.specificity == second.specificity

        # First in list wins (verified by middleware selection logic)
        # max() returns first among equals
        winner = max(matched, key=lambda m: m.specificity)
        assert winner.id == "first"
