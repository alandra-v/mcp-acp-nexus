"""Context building for ABAC policy evaluation.

This module builds DecisionContext from MCP requests for policy decisions.
Following NIST SP 800-207 Zero Trust Architecture:

- context/ (this module): Builds decision context from requests
- pdp/: Policy Decision Point - evaluates policies
- pep/: Policy Enforcement Point - enforces decisions

Core design principles:
1. Context describes reality, not intent
2. Policies express distrust, not optimism
3. Facts carry provenance - know where each piece of information came from
4. You cannot trust tool names, descriptions, or declared behavior

Structure:
    provenance.py     - Provenance enum (source of facts)
    subject.py        - Subject model (WHO)
    action.py         - Action model (WHAT operation)
    resource.py       - Resource models (ON WHAT)
    environment.py    - Environment model (CONTEXT)
    context.py        - DecisionContext + builder
"""

from mcp_acp.context.provenance import Provenance
from mcp_acp.context.subject import Subject, SubjectProvenance
from mcp_acp.context.action import (
    Action,
    ActionCategory,
    ActionProvenance,
)
from mcp_acp.constants import DISCOVERY_METHODS
from mcp_acp.context.resource import (
    Resource,
    ResourceType,
    ServerInfo,
    ToolInfo,
    ResourceInfo,
    SideEffect,
)
from mcp_acp.context.environment import Environment
from mcp_acp.context.context import DecisionContext, build_decision_context
from mcp_acp.context.parsing import parse_path_resource, parse_uri_resource

__all__ = [
    # Provenance
    "Provenance",
    # Subject (WHO)
    "Subject",
    "SubjectProvenance",
    # Action (WHAT)
    "Action",
    "ActionCategory",
    "ActionProvenance",
    "DISCOVERY_METHODS",
    # Resource (ON WHAT)
    "Resource",
    "ResourceType",
    "ServerInfo",
    "ToolInfo",
    "ResourceInfo",
    "SideEffect",
    # Environment
    "Environment",
    # Context
    "DecisionContext",
    "build_decision_context",
    # Parsing
    "parse_path_resource",
    "parse_uri_resource",
]
