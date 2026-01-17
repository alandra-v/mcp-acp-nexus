"""Shared claims-to-Subject mapping utilities.

Converts validated OIDC token claims to ABAC Subject model.
This logic is shared between STDIO (OIDCIdentityProvider) and
future HTTP (HTTPIdentityProvider) patterns.

See docs/design/authentication_implementation.md for architecture details.
"""

from __future__ import annotations

__all__ = [
    "build_subject_from_identity",
    "build_subject_from_validated_token",
]

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcp_acp.context.provenance import Provenance
    from mcp_acp.context.subject import Subject, SubjectProvenance
    from mcp_acp.security.auth import ValidatedToken
    from mcp_acp.telemetry.models.audit import SubjectIdentity


def build_subject_from_validated_token(validated: "ValidatedToken") -> "Subject":
    """Build ABAC Subject from validated OIDC token.

    Converts ValidatedToken claims to the Subject model used in policy
    evaluation. All fields have TOKEN provenance since they come from
    a cryptographically verified JWT.

    Args:
        validated: Validated token with OIDC claims.

    Returns:
        Subject with full OIDC attributes for policy evaluation.
    """
    # Import at runtime to avoid circular import with context module
    from mcp_acp.context.provenance import Provenance
    from mcp_acp.context.subject import Subject, SubjectProvenance

    return Subject(
        id=validated.subject_id,
        issuer=validated.issuer,
        audience=validated.audience,
        client_id=validated.claims.get("azp"),  # Authorized party (client)
        scopes=validated.scopes if validated.scopes else None,
        token_age_s=validated.token_age_seconds,
        auth_time=validated.auth_time,
        provenance=SubjectProvenance(
            id=Provenance.TOKEN,
            scopes=Provenance.TOKEN if validated.scopes else None,
        ),
    )


def build_subject_from_identity(
    identity: "SubjectIdentity",
    provenance: "Provenance | None" = None,
) -> "Subject":
    """Build ABAC Subject from SubjectIdentity (minimal claims).

    Used when full ValidatedToken is not available (e.g., LocalIdentityProvider).
    Only populates id and provenance.

    Args:
        identity: Subject identity with subject_id.
        provenance: Source of the identity (DERIVED for local, TOKEN for OIDC).
            If None, uses DERIVED as default.

    Returns:
        Subject with minimal attributes.
    """
    # Import at runtime to avoid circular import with context module
    from mcp_acp.context.provenance import Provenance
    from mcp_acp.context.subject import Subject, SubjectProvenance

    if provenance is None:
        provenance = Provenance.DERIVED

    # Check if identity has OIDC claims
    claims = identity.subject_claims or {}
    auth_type = claims.get("auth_type", "local")

    if auth_type == "oidc":
        # OIDC identity - populate more fields from claims
        # Claims are stored as strings, need to parse them
        issuer = claims.get("issuer")

        # Validate issuer is present for OIDC identity
        # If missing, fall back to DERIVED provenance (incomplete OIDC data)
        if not issuer:
            return Subject(
                id=identity.subject_id,
                provenance=SubjectProvenance(id=Provenance.DERIVED),
            )

        # Audience and scopes are stored as comma-separated strings
        # Strip whitespace to handle "read , write" -> ["read", "write"]
        audience_str = claims.get("audience")
        audience = [a.strip() for a in audience_str.split(",")] if audience_str else None

        scopes_str = claims.get("scopes")
        scopes = frozenset(s.strip() for s in scopes_str.split(",")) if scopes_str else None

        return Subject(
            id=identity.subject_id,
            issuer=issuer,
            audience=audience,
            scopes=scopes,
            provenance=SubjectProvenance(
                id=Provenance.TOKEN,
                scopes=Provenance.TOKEN if scopes else None,
            ),
        )
    else:
        # Local identity - minimal subject
        return Subject(
            id=identity.subject_id,
            provenance=SubjectProvenance(id=provenance),
        )
