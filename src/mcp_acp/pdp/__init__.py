"""Policy Decision Point (PDP) - Policy evaluation engine.

This module evaluates policies against DecisionContext to produce decisions.
Following NIST SP 800-207 Zero Trust Architecture:

- context/: Builds DecisionContext from requests
- pdp/ (this module): Evaluates policies against context
- pep/: Enforces decisions (middleware)

The PDP is intentionally stateless and side-effect free.
All I/O and enforcement happens in the PEP.

Structure:
    decision.py       - Decision enum (ALLOW/DENY/HITL)
    policy.py         - Policy models (PolicyConfig, PolicyRule, etc.)
    matcher.py        - Pattern matching for conditions
    engine.py         - PolicyEngine for evaluation

Policy file I/O is in utils/policy/policy_helpers.py.
"""

from mcp_acp.pdp.decision import Decision
from mcp_acp.pdp.engine import MatchedRule, PolicyEngine
from mcp_acp.pdp.policy import (
    PolicyConfig,
    PolicyRule,
    RuleConditions,
    create_default_policy,
)
from mcp_acp.pdp.protocol import PolicyEngineProtocol

# NOTE: Policy I/O functions (load_policy, save_policy, etc.) are in utils.policy
# to avoid circular imports. Import them directly:
#   from mcp_acp.utils.policy import load_policy, save_policy, ...

__all__ = [
    # Decision
    "Decision",
    # Engine
    "PolicyEngine",
    "PolicyEngineProtocol",
    "MatchedRule",
    # Policy models
    "PolicyConfig",
    "PolicyRule",
    "RuleConditions",
    "create_default_policy",
]
