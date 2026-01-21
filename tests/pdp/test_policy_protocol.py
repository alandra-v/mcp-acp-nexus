"""Tests for PolicyEngineProtocol abstraction.

Verifies that the built-in PolicyEngine satisfies the protocol,
enabling future external engine integration.
"""

from __future__ import annotations

import pytest

from mcp_acp.pdp import (
    Decision,
    PolicyConfig,
    PolicyEngine,
    PolicyEngineProtocol,
    PolicyRule,
    RuleConditions,
)


class TestPolicyEngineProtocolCompliance:
    """Verify PolicyEngine satisfies the PolicyEngineProtocol."""

    @pytest.fixture
    def sample_policy(self) -> PolicyConfig:
        """Create a sample policy for testing."""
        return PolicyConfig(
            rules=[
                PolicyRule(
                    id="allow-all",
                    effect="allow",
                    conditions=RuleConditions(tool_name="*"),
                )
            ]
        )

    def test_policy_engine_is_protocol_instance(self, sample_policy: PolicyConfig) -> None:
        """PolicyEngine should satisfy PolicyEngineProtocol (runtime check)."""
        engine = PolicyEngine(sample_policy)
        # runtime_checkable allows isinstance() to work
        assert isinstance(engine, PolicyEngineProtocol)

    def test_protocol_has_required_methods(self) -> None:
        """Protocol should define all required methods."""
        # These are the methods that any policy engine must implement
        assert hasattr(PolicyEngineProtocol, "evaluate")
        assert hasattr(PolicyEngineProtocol, "get_matching_rules")
        assert hasattr(PolicyEngineProtocol, "reload_policy")
        assert hasattr(PolicyEngineProtocol, "policy")
        assert hasattr(PolicyEngineProtocol, "rule_count")

    def test_engine_has_policy_property(self, sample_policy: PolicyConfig) -> None:
        """PolicyEngine should expose policy property."""
        engine = PolicyEngine(sample_policy)
        assert engine.policy is sample_policy

    def test_engine_has_evaluate_method(self, sample_policy: PolicyConfig) -> None:
        """PolicyEngine should have evaluate method returning Decision."""
        engine = PolicyEngine(sample_policy)
        assert callable(engine.evaluate)

    def test_engine_has_get_matching_rules_method(self, sample_policy: PolicyConfig) -> None:
        """PolicyEngine should have get_matching_rules method."""
        engine = PolicyEngine(sample_policy)
        assert callable(engine.get_matching_rules)

    def test_engine_has_reload_policy_method(self, sample_policy: PolicyConfig) -> None:
        """PolicyEngine should have reload_policy method."""
        engine = PolicyEngine(sample_policy)
        assert callable(engine.reload_policy)

    def test_engine_has_rule_count_property(self, sample_policy: PolicyConfig) -> None:
        """PolicyEngine should expose rule_count property."""
        engine = PolicyEngine(sample_policy)
        assert engine.rule_count == 1  # sample_policy has 1 rule

    def test_reload_policy_swaps_reference(self, sample_policy: PolicyConfig) -> None:
        """reload_policy should atomically swap the policy reference."""
        engine = PolicyEngine(sample_policy)
        original_policy = engine.policy

        new_policy = PolicyConfig(
            rules=[
                PolicyRule(
                    id="deny-all",
                    effect="deny",
                    conditions=RuleConditions(tool_name="*"),
                )
            ]
        )
        engine.reload_policy(new_policy)

        assert engine.policy is not original_policy
        assert engine.policy is new_policy


class TestProtocolTypeHints:
    """Verify protocol type hints work correctly."""

    @pytest.fixture
    def sample_policy(self) -> PolicyConfig:
        """Create a sample policy for testing."""
        return PolicyConfig(
            rules=[
                PolicyRule(
                    id="allow-all",
                    effect="allow",
                    conditions=RuleConditions(tool_name="*"),
                )
            ]
        )

    def test_engine_can_be_assigned_to_protocol_type(self, sample_policy: PolicyConfig) -> None:
        """PolicyEngine should be assignable to PolicyEngineProtocol variable."""
        engine: PolicyEngineProtocol = PolicyEngine(sample_policy)
        # This should work without type errors
        assert engine.policy is not None


class TestCustomEngineCompliance:
    """Test that a custom engine can satisfy the protocol."""

    def test_minimal_custom_engine(self) -> None:
        """A minimal custom engine should satisfy the protocol."""
        from mcp_acp.pdp.engine import MatchedRule

        class MinimalEngine:
            """Minimal engine that satisfies PolicyEngineProtocol."""

            def __init__(self) -> None:
                self._policy = PolicyConfig(
                    rules=[
                        PolicyRule(
                            id="custom",
                            effect="allow",
                            conditions=RuleConditions(tool_name="*"),
                        )
                    ]
                )

            @property
            def policy(self) -> PolicyConfig:
                return self._policy

            @property
            def rule_count(self) -> int:
                return len(self._policy.rules)

            def evaluate(self, context: object) -> Decision:
                return Decision.ALLOW

            def get_matching_rules(self, context: object) -> list[MatchedRule]:
                return []

            def reload_policy(self, new_policy: PolicyConfig) -> None:
                self._policy = new_policy

        engine = MinimalEngine()
        # Should satisfy the protocol via structural subtyping
        assert isinstance(engine, PolicyEngineProtocol)
        assert engine.rule_count == 1
