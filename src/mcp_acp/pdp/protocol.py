"""Protocol definition for pluggable policy engines.

Defines the interface that all policy engines must implement,
enabling future integration with external engines like Casbin or OPA.

This follows the same pattern as IdentityProvider in security/identity.py.
External engines implement this protocol via adapters without inheriting
from our code (structural subtyping).

Example future adapter:

    class CasbinPolicyEngine:
        def evaluate(self, context: DecisionContext) -> Decision:
            sub = context.subject.id
            obj = context.resource.resource.path or ""
            act = context.action.mcp_method
            return Decision.ALLOW if self._enforcer.enforce(sub, obj, act) else Decision.DENY
"""

from __future__ import annotations

__all__ = [
    "PolicyEngineProtocol",
]

from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from mcp_acp.context import DecisionContext
    from mcp_acp.pdp.decision import Decision
    from mcp_acp.pdp.engine import MatchedRule
    from mcp_acp.pdp.policy import PolicyConfig


@runtime_checkable
class PolicyEngineProtocol(Protocol):
    """Protocol for pluggable policy engines.

    Implementations evaluate DecisionContext against policies to produce decisions.
    External engines (Casbin, OPA, Cedar) can implement this protocol via adapters.

    The protocol intentionally excludes:
    - is_protected_path(): Built-in security feature handled by middleware
    - Policy-specific internals (specificity scoring, rule matching details)

    Required methods:
    - evaluate(): Core decision logic (ALLOW/DENY/HITL)
    - get_matching_rules(): Audit trail support
    - reload_policy(): Hot reload support

    Required properties:
    - policy: Access to current policy configuration

    Thread-safety:
    - evaluate() and get_matching_rules() must be safe for concurrent calls
    - reload_policy() must perform atomic reference swap
    """

    @property
    def policy(self) -> "PolicyConfig":
        """Get current policy configuration.

        Used by middleware for:
        - Policy version tracking

        Note: For rule count, prefer using the rule_count property which
        works with external engines that don't use PolicyConfig.

        Returns:
            Current PolicyConfig instance.
        """
        ...

    @property
    def rule_count(self) -> int:
        """Get the number of policy rules.

        Used by reloader for hot reload statistics.
        External engines should return their equivalent rule count.

        Returns:
            Number of rules in the current policy.
        """
        ...

    def evaluate(self, context: "DecisionContext") -> "Decision":
        """Evaluate a request context against the policy.

        This is the core policy decision method. Implementations should:
        1. Match context against policy rules
        2. Apply combining algorithm (e.g., HITL > DENY > ALLOW)
        3. Return appropriate decision

        Args:
            context: DecisionContext built from the MCP request.

        Returns:
            Decision: ALLOW, DENY, or HITL.

        Raises:
            PolicyEnforcementFailure: On critical evaluation errors that
                should trigger proxy shutdown (fail-closed).
        """
        ...

    def get_matching_rules(self, context: "DecisionContext") -> list["MatchedRule"]:
        """Get all rules that match the given context.

        Required for audit logging - all engines must provide matched rules
        so decisions can be traced back to specific policy rules.

        Args:
            context: DecisionContext to match against.

        Returns:
            List of MatchedRule with id, description, effect, and specificity.
            Empty list if no rules match (will use default action).
        """
        ...

    def reload_policy(self, new_policy: Any) -> None:
        """Reload policy configuration atomically.

        Must be thread-safe for hot reload support. Implementations should:
        - Use atomic reference swap (not gradual update)
        - Not block evaluate() calls during reload
        - Preserve any engine-specific state that survives reload

        Args:
            new_policy: New policy to apply. For built-in engine this is
                PolicyConfig; external engines may use their own formats.
        """
        ...
