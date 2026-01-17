"""DecisionContext and builder - complete context for policy evaluation.

This module provides the DecisionContext model and build_decision_context()
function that brings together all context components to create a complete
context for ABAC policy evaluation.

Design principles:
1. Context describes reality, not intent
2. Policies express distrust, not optimism
3. Facts carry provenance
4. You cannot trust tool names or descriptions
"""

from __future__ import annotations

__all__ = [
    "DecisionContext",
    "build_decision_context",
]

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict

from mcp_acp.constants import DISCOVERY_METHODS
from mcp_acp.context.tool_side_effects import TOOL_SIDE_EFFECTS
from mcp_acp.context.action import (
    Action,
    ActionCategory,
    ActionProvenance,
)
from mcp_acp.context.environment import Environment
from mcp_acp.context.provenance import Provenance
from mcp_acp.context.resource import (
    Resource,
    ResourceInfo,
    ResourceType,
    ServerInfo,
    SideEffect,
    ToolInfo,
)
from mcp_acp.context.subject import Subject
from mcp_acp.context.parsing import (
    extract_resource_info as _extract_resource_info,
    parse_uri_resource as _parse_uri_resource,
)
from mcp_acp.pips.auth.claims import build_subject_from_identity
from mcp_acp.security.identity import IdentityProvider

# Action intent mapping - ONLY for methods where intent is a FACT
# For tools/call, we return None because we can't know what a tool does
METHOD_INTENTS: dict[str, str] = {
    "resources/read": "read",
}


class DecisionContext(BaseModel):
    """Complete context for ABAC policy evaluation.

    Follows standard ABAC model:
    - Subject: WHO is making the request
    - Action: WHAT operation is being performed
    - Resource: ON WHAT (the target)
    - Environment: Contextual information

    Design principles:
    1. Context describes reality, not intent
    2. Policies express distrust, not optimism
    3. Facts carry provenance
    4. You cannot trust tool names or descriptions
    """

    subject: Subject
    action: Action
    resource: Resource
    environment: Environment

    model_config = ConfigDict(frozen=True)


async def build_decision_context(
    method: str,
    arguments: dict[str, Any] | None,
    identity_provider: IdentityProvider,
    session_id: str,
    request_id: str,
    backend_id: str,
    client_name: str | None = None,
    client_version: str | None = None,
) -> DecisionContext:
    """Build DecisionContext from MCP request components.

    Extracts ABAC attributes from the request. Only reports facts,
    never guesses or interprets. See module docstring for details.

    Args:
        method: MCP method name (e.g., "tools/call", "resources/read").
        arguments: Request arguments (may contain tool name, file paths, URIs).
        identity_provider: Provider for user identity.
        session_id: FastMCP session identifier.
        request_id: Request correlation ID.
        backend_id: Backend server identifier.
        client_name: Client application name (from initialize).
        client_version: Client version (from initialize).

    Returns:
        DecisionContext with ABAC attributes populated from observable facts.

    Raises:
        SessionBindingViolationError: If current identity doesn't match bound session.
    """
    from mcp_acp.exceptions import SessionBindingViolationError
    from mcp_acp.utils.logging.logging_context import get_bound_user_id

    # Build Subject from identity
    # - OIDC: Full claims (issuer, audience, scopes) with TOKEN provenance
    # - Local: Minimal (id only) with DERIVED provenance
    identity = await identity_provider.get_identity()

    # Session binding validation: reject if identity changed mid-session
    # Per MCP spec: sessions SHOULD be bound to user ID from validated token
    # This prevents session hijacking if attacker obtains different credentials
    bound_user_id = get_bound_user_id()
    if bound_user_id is not None and identity.subject_id != bound_user_id:
        raise SessionBindingViolationError(
            f"Session binding violation: identity mismatch. "
            f"Session bound to '{bound_user_id}', but request from '{identity.subject_id}'. "
            f"This session cannot be used by a different user."
        )

    subject = build_subject_from_identity(identity)

    # Build Action
    action = _build_action(method)

    # Build Resource
    resource = _build_resource(method, arguments, backend_id)

    # Build Environment
    environment = Environment(
        timestamp=datetime.now(timezone.utc),
        request_id=request_id,
        session_id=session_id,
        mcp_client_name=client_name,
        mcp_client_version=client_version,
    )

    return DecisionContext(
        subject=subject,
        action=action,
        resource=resource,
        environment=environment,
    )


def _build_action(method: str) -> Action:
    """Build Action from MCP method.

    IMPORTANT: For tools/call, intent is None because we can't know
    what an arbitrary tool does from its name alone. We don't guess.

    Args:
        method: MCP method name.

    Returns:
        Action with intent only if KNOWN from method semantics.
    """
    # Get intent if known (only for methods where it's a FACT)
    intent = METHOD_INTENTS.get(method)

    # Determine category - discovery (metadata) vs action (does something)
    category = ActionCategory.DISCOVERY if method in DISCOVERY_METHODS else ActionCategory.ACTION

    # Determine provenance for intent
    intent_provenance = Provenance.MCP_METHOD if intent else None

    return Action(
        mcp_method=method,
        name=method.replace("/", "."),
        intent=intent,
        category=category,
        provenance=ActionProvenance(
            intent=intent_provenance,
        ),
    )


def _build_resource(
    method: str,
    arguments: dict[str, Any] | None,
    backend_id: str,
) -> Resource:
    """Build Resource from request.

    Args:
        method: MCP method name.
        arguments: Request arguments.
        backend_id: Backend server ID.

    Returns:
        Resource with appropriate type and details.
    """
    server = ServerInfo(id=backend_id, provenance=Provenance.PROXY_CONFIG)

    # Determine resource type
    if method == "tools/call":
        return _build_tool_resource(arguments, server)
    elif method.startswith("resources/"):
        return _build_mcp_resource(arguments, server)
    elif method.startswith("prompts/"):
        return Resource(type=ResourceType.PROMPT, server=server)
    else:
        return Resource(type=ResourceType.SERVER, server=server)


def _build_tool_resource(
    arguments: dict[str, Any] | None,
    server: ServerInfo,
) -> Resource:
    """Build Resource for tools/call request.

    Args:
        arguments: Request arguments containing tool name.
        server: Server info.

    Returns:
        Resource with tool info and optional resource info.
    """
    tool_name = arguments.get("name") if arguments else None

    tool = None
    if tool_name:
        # Look up side effects from the manual map
        side_effects = _get_tool_side_effects(tool_name)

        tool = ToolInfo(
            name=tool_name,
            provenance=Provenance.MCP_REQUEST,
            side_effects=side_effects,
            side_effects_provenance=Provenance.PROXY_CONFIG if side_effects else None,
        )

    # Extract file path if present (for tools that access files)
    # For tools/call, paths may be in nested "arguments" dict (real MCP format)
    # or at top level (test/simplified format). Check nested first.
    tool_arguments = arguments.get("arguments") if arguments else None
    resource_info = _extract_resource_info(tool_arguments)
    if resource_info is None:
        # Fall back to top-level arguments (for backwards compatibility)
        resource_info = _extract_resource_info(arguments)

    return Resource(
        type=ResourceType.TOOL,
        server=server,
        tool=tool,
        resource=resource_info,
    )


def _get_tool_side_effects(tool_name: str) -> frozenset[SideEffect] | None:
    """Get side effects for a tool from the manual map.

    Args:
        tool_name: Name of the tool.

    Returns:
        frozenset of SideEffect enums, or None if tool not in map.
    """
    # Look up by exact name (case-insensitive)
    effect_strings = TOOL_SIDE_EFFECTS.get(tool_name.lower())

    if not effect_strings:
        return None

    # Convert strings to SideEffect enums
    effects = set()
    for effect_str in effect_strings:
        try:
            effects.add(SideEffect(effect_str))
        except ValueError:
            # Unknown effect string, skip it
            pass

    return frozenset(effects) if effects else None


def _build_mcp_resource(
    arguments: dict[str, Any] | None,
    server: ServerInfo,
) -> Resource:
    """Build Resource for MCP resource access (resources/read, etc.).

    Args:
        arguments: Request arguments containing URI.
        server: Server info.

    Returns:
        Resource with resource info.
    """
    uri = arguments.get("uri") if arguments else None

    resource_info = None
    if uri:
        resource_info = _parse_uri_resource(str(uri))
    else:
        resource_info = _extract_resource_info(arguments)

    return Resource(
        type=ResourceType.RESOURCE,
        server=server,
        resource=resource_info,
    )
