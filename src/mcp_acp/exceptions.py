"""Custom exceptions for mcp-acp.

This module contains all custom exceptions used throughout the package.
Exceptions are organized into two categories:

Recoverable Errors (proxy continues):
    - PermissionDeniedError: Policy denied a request, client gets MCP error

Critical Failures (proxy must shutdown):
    - CriticalSecurityFailure: Base for unrecoverable security failures
    - AuditFailure: Audit log integrity compromised
    - PolicyEnforcementFailure: Policy engine cannot evaluate reliably
    - IdentityVerificationFailure: Cannot verify caller identity

Usage:
    from mcp_acp.exceptions import PermissionDeniedError, AuditFailure
"""

from __future__ import annotations

__all__ = [
    "AuditFailure",
    "AuthenticationError",
    "ConfigurationError",
    "CriticalSecurityFailure",
    "DeviceHealthError",
    "IdentityVerificationFailure",
    "PERMISSION_DENIED_CODE",
    "PermissionDeniedError",
    "PolicyEnforcementFailure",
    "ProxyRunningError",
    "SessionBindingViolationError",
]

from typing import TYPE_CHECKING, Any

from mcp import McpError
from mcp.types import ErrorData

if TYPE_CHECKING:
    from mcp_acp.pdp.decision import Decision


# =============================================================================
# Recoverable Errors (proxy continues, client receives error response)
# =============================================================================

# Custom JSON-RPC error code for permission denied
# In the reserved range -32000 to -32099 for server-defined errors
PERMISSION_DENIED_CODE = -32001


class PermissionDeniedError(McpError):
    """Raised when a request is denied by policy.

    This is a recoverable error - the proxy continues running and the client
    receives a proper MCP error response. Use this for policy denials.

    Inherits from McpError and constructs ErrorData with code -32001, which
    FastMCP serializes as a proper MCP error response.

    Attributes:
        code: JSON-RPC error code (-32001).
        message: Human-readable denial reason.
        decision: The policy decision (DENY or HITL that resulted in deny).
        tool_name: Name of the tool that was denied (if applicable).
        path: File path that was denied (if applicable).
        matched_rules: List of rule IDs that matched.
        final_rule: The rule that determined the outcome.
    """

    code: int = PERMISSION_DENIED_CODE

    def __init__(
        self,
        message: str,
        *,
        decision: "Decision | None" = None,
        tool_name: str | None = None,
        path: str | None = None,
        matched_rules: list[str] | None = None,
        final_rule: str | None = None,
    ) -> None:
        """Initialize PermissionDeniedError.

        Args:
            message: Human-readable denial reason.
            decision: The policy decision.
            tool_name: Name of the tool that was denied.
            path: File path that was denied.
            matched_rules: List of rule IDs that matched.
            final_rule: The rule that determined the outcome.
        """
        self.decision = decision
        self.tool_name = tool_name
        self.path = path
        self.matched_rules = matched_rules or []
        self.final_rule = final_rule

        error_data = ErrorData(
            code=PERMISSION_DENIED_CODE,
            message=message,
            data=self._build_error_data(),
        )

        super().__init__(error_data)
        self.message = message

    def _build_error_data(self) -> dict[str, Any] | None:
        """Build structured data for the MCP error response."""
        data: dict[str, Any] = {}

        if self.tool_name is not None:
            data["tool_name"] = self.tool_name
        if self.path is not None:
            data["path"] = self.path
        if self.matched_rules:
            data["matched_rules"] = self.matched_rules
        if self.final_rule is not None:
            data["final_rule"] = self.final_rule
        if self.decision is not None:
            data["decision"] = self.decision.value

        return data if data else None

    @property
    def error_data(self) -> dict[str, Any]:
        """Structured data for JSON-RPC error response."""
        return self._build_error_data() or {}

    def to_json_rpc_error(self) -> dict[str, Any]:
        """Convert to JSON-RPC error object."""
        error: dict[str, Any] = {
            "code": self.error.code,
            "message": self.error.message,
        }
        if self.error.data is not None:
            error["data"] = self.error.data
        return error

    def __repr__(self) -> str:
        """Return detailed representation for debugging."""
        parts = [f"PermissionDeniedError({self.message!r}"]
        if self.tool_name is not None:
            parts.append(f", tool_name={self.tool_name!r}")
        if self.path is not None:
            parts.append(f", path={self.path!r}")
        if self.final_rule is not None:
            parts.append(f", final_rule={self.final_rule!r}")
        if self.matched_rules:
            parts.append(f", matched_rules={self.matched_rules!r}")
        parts.append(")")
        return "".join(parts)

    def __str__(self) -> str:
        """Return human-readable string representation."""
        return self.message


# =============================================================================
# Critical Failures (proxy must shutdown - security invariants violated)
# =============================================================================


class CriticalSecurityFailure(Exception):
    """Base exception for failures requiring immediate proxy shutdown.

    These exceptions represent unrecoverable security failures. They should
    not be caught and handled - they signal that security invariants cannot
    be maintained and the proxy must terminate.

    Subclasses define specific failure types with distinct exit codes:
    - AuditFailure (exit 10): Audit trail compromised
    - PolicyEnforcementFailure (exit 11): Policy engine failed
    - IdentityVerificationFailure (exit 12): Cannot verify identity

    Attributes:
        exit_code: Process exit code (10-12 reserved for security failures).
        failure_type: Category string for logging and breadcrumb files.
    """

    exit_code: int = 1
    failure_type: str = "unknown"


class AuditFailure(CriticalSecurityFailure):
    """Audit trail integrity has been compromised.

    Raised when:
    - Audit log file is deleted while proxy is running
    - Audit log file is replaced (different inode)
    - Audit log becomes unwritable
    - Write to audit log fails

    The proxy cannot continue without a reliable audit trail.
    Exit code 10 indicates audit failure to operators.
    """

    exit_code = 10
    failure_type = "audit_failure"


class PolicyEnforcementFailure(CriticalSecurityFailure):
    """Policy enforcement mechanism has failed.

    Raised when the policy engine cannot evaluate requests reliably,
    e.g., unexpected errors during rule matching or evaluation.

    Exit code 11 indicates policy enforcement failure.
    """

    exit_code = 11
    failure_type = "policy_failure"


class IdentityVerificationFailure(CriticalSecurityFailure):
    """Cannot verify caller identity.

    Raised when identity cannot be determined and zero-trust
    requires known subjects, e.g., JWKS fetch fails with no valid cache.

    Exit code 12 indicates identity verification failure.
    """

    exit_code = 12
    failure_type = "identity_failure"


class AuthenticationError(CriticalSecurityFailure):
    """Authentication failed - cannot verify user identity.

    Raised when:
    - No token found in keychain (user not logged in)
    - Token is invalid or expired and cannot be refreshed
    - Token signature verification fails
    - OIDC issuer/audience validation fails

    The proxy cannot start without authenticated user.
    Exit code 13 indicates authentication failure.
    """

    exit_code = 13
    failure_type = "authentication_failure"


class DeviceHealthError(CriticalSecurityFailure):
    """Device health check failed - device does not meet security requirements.

    Raised when:
    - Disk encryption is required but not enabled (FileVault/BitLocker/LUKS)
    - Firewall is required but not enabled

    The proxy cannot start on a device that fails health checks.
    Exit code 14 indicates device health failure.
    """

    exit_code = 14
    failure_type = "device_health_failure"


class SessionBindingViolationError(CriticalSecurityFailure):
    """Session binding violated - identity changed mid-session.

    Raised when:
    - A request is made with a different user identity than the session was bound to
    - This indicates possible session hijacking or credential swap

    Per MCP spec: sessions SHOULD be bound to user ID from validated token.
    The proxy must shutdown to prevent unauthorized access.
    Exit code 15 indicates session binding violation.
    """

    exit_code = 15
    failure_type = "session_binding_violation"


class ProxyRunningError(Exception):
    """Proxy is currently running and cannot be deleted.

    Raised when attempting to delete a proxy that is registered with
    the manager (currently running). The proxy must be stopped first.
    """


class ConfigurationError(CriticalSecurityFailure):
    """Configuration is invalid or incomplete.

    Raised when:
    - Config file does not exist (not initialized)
    - Config file exists but auth section is missing
    - Config file contains invalid JSON
    - Config file fails Pydantic validation

    Exit code 16 indicates configuration failure.
    """

    exit_code = 16
    failure_type = "configuration_failure"
