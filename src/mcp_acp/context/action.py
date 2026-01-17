"""Action model - WHAT operation is being performed.

Design principle: We report what we KNOW, not what we guess.
- mcp_method: Raw fact from request
- name: Normalized form (for easier policy writing)
- intent: Only populated when KNOWN from method semantics
- category: DISCOVERY (metadata/listing) vs ACTION (actually does something)
"""

from __future__ import annotations

__all__ = [
    "Action",
    "ActionCategory",
    "ActionProvenance",
]

from enum import Enum

from pydantic import BaseModel, ConfigDict

from mcp_acp.context.provenance import Provenance


class ActionCategory(str, Enum):
    """Category of MCP action.

    DISCOVERY: Metadata and listing operations that don't modify state.
               These are typically safe to allow without policy rules.
    ACTION: Operations that actually do something (execute, read data, write).
            These should go through policy evaluation.
    """

    DISCOVERY = "discovery"
    ACTION = "action"


class ActionProvenance(BaseModel):
    """Provenance tracking for derived action fields.

    intent may be None if we don't know what the action does.
    """

    intent: Provenance | None = None


class Action(BaseModel):
    """The operation being performed (ABAC Action).

    Design principle: We report what we KNOW, not what we guess.
    For tools/call, intent is None because we can't know what
    an arbitrary tool does from its name alone.

    Attributes:
        mcp_method: Raw MCP method name ("tools/call", "resources/read")
        name: Normalized form ("tools.call", "resources.read")
        intent: Action intent when KNOWN ("read", "write", "exec"), None otherwise
        category: DISCOVERY (metadata) vs ACTION (does something)
        provenance: Source tracking for derived fields
    """

    # Raw fact
    mcp_method: str

    # Normalized (derived but deterministic)
    name: str

    # Intent - None if unknown (we don't guess!)
    intent: str | None

    # Category - discovery (listing/metadata) vs action (does something)
    category: ActionCategory

    # Provenance tracking
    provenance: ActionProvenance

    model_config = ConfigDict(frozen=True)  # Immutable after creation
