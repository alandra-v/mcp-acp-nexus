"""Subject model - WHO is making the request.

The Subject represents the identity of the requester in ABAC terms.
Stage 1 (local): Only id populated via getpass.getuser()
Stage 2+ (OIDC): Full token claims populated from FastMCP JWT
"""

from __future__ import annotations

__all__ = [
    "Subject",
    "SubjectProvenance",
]

from datetime import datetime

from pydantic import BaseModel, ConfigDict

from mcp_acp.context.provenance import Provenance


class SubjectProvenance(BaseModel):
    """Provenance tracking for trust-relevant subject fields.

    Only fields where trust level matters for policy decisions
    need provenance tracking.
    """

    id: Provenance
    scopes: Provenance | None = None


class Subject(BaseModel):
    """Identity of the requester (ABAC Subject).

    Stage 1 (local): Only id populated via getpass.getuser()
    Stage 2+ (OIDC): Full token claims populated

    Attributes:
        id: OIDC 'sub' claim or local username
        issuer: OIDC 'iss' claim (token issuer URL)
        audience: OIDC 'aud' claim (intended recipients)
        client_id: OIDC 'azp' or 'client_id' (requesting application)
        scopes: OIDC 'scope' claim (granted permissions)
        token_age_s: Seconds since token was issued (now - iat)
        auth_time: When user actually authenticated (OIDC 'auth_time')
        provenance: Source tracking for trust-relevant fields
    """

    # Core identity
    id: str
    issuer: str | None = None
    audience: list[str] | None = None

    # Client/app identity
    client_id: str | None = None
    scopes: frozenset[str] | None = None

    # Token metadata (for freshness policies)
    token_age_s: float | None = None
    auth_time: datetime | None = None

    # Provenance tracking
    provenance: SubjectProvenance

    model_config = ConfigDict(frozen=True)  # Immutable after creation
