"""Decision enum for policy evaluation outcomes.

These values define the possible outcomes of policy evaluation,
used by the policy engine to communicate decisions to the PEP.
"""

from __future__ import annotations

__all__ = ["Decision"]

from enum import Enum


class Decision(str, Enum):
    """Policy decision outcome.

    Inherits from str for easy serialization and comparison.

    Attributes:
        ALLOW: Request is permitted, forward to backend.
        DENY: Request is blocked, return error to client.
        HITL: Human-in-the-loop approval required before proceeding.
    """

    ALLOW = "allow"
    DENY = "deny"
    HITL = "hitl"
