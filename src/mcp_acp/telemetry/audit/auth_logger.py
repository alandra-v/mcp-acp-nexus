"""Authentication audit logger with fail-closed behavior.

Logs authentication events to audit/auth.jsonl:
- Token validation failures
- Token refresh attempts (success/failure)
- Session lifecycle (start/end)
- Device health check failures

Note: Success events for token_validated and device_health_passed are not
logged as they create noise (per-request validation fires constantly).
Only failures are logged for security auditing.

Uses fail-closed handler - if auth logging fails, proxy shuts down.
This is a Zero Trust requirement: no operation without audit trail.
"""

from __future__ import annotations

__all__ = [
    "AuthLogger",
    "create_auth_logger",
]

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Literal

if TYPE_CHECKING:
    from mcp_acp.security.integrity.integrity_state import IntegrityStateManager

from mcp_acp.constants import APP_NAME
from mcp_acp.security.integrity.emergency_audit import log_with_fallback
from mcp_acp.telemetry.models.audit import (
    AuthEvent,
    DeviceHealthChecks,
    OIDCInfo,
    SubjectIdentity,
)
from mcp_acp.telemetry.system.system_logger import get_system_logger
from mcp_acp.utils.logging.logger_setup import setup_failclosed_audit_logger
from mcp_acp.utils.logging.logging_helpers import (
    hash_auth_event_ids,
    serialize_audit_event,
)

_system_logger = get_system_logger()


class AuthLogger:
    """Audit logger for authentication events.

    Provides typed methods for logging auth events with fail-closed behavior.
    If the audit log is compromised, triggers proxy shutdown.

    Usage:
        logger = create_auth_logger(
            log_path=get_auth_log_path(config),
            shutdown_callback=on_critical_failure,
        )
        logger.log_session_started(bound_session_id="...", subject=..., oidc=...)
    """

    def __init__(self, logger: logging.Logger) -> None:
        """Initialize auth logger.

        Args:
            logger: Configured logger with fail-closed handler.
        """
        self._logger = logger

    def _log_event(self, event: AuthEvent) -> bool:
        """Log an auth event with fallback chain.

        Args:
            event: The auth event to log.

        Returns:
            True if logged to primary, False if fallback was used.
        """
        # Use json_mode=True for OIDC token data with datetime/enum values
        event_data = serialize_audit_event(event, json_mode=True)
        # Hash sensitive IDs (subject_id, bound_session_id) before logging
        event_data = hash_auth_event_ids(event_data)
        success, _ = log_with_fallback(
            primary_logger=self._logger,
            system_logger=_system_logger,
            event_data=event_data,
            event_type="auth",
            source_file="auth.jsonl",
        )
        return success

    def log_token_invalid(
        self,
        *,
        bound_session_id: str | None = None,
        mcp_session_id: str | None = None,
        request_id: str | None = None,
        subject: SubjectIdentity | None = None,
        oidc: OIDCInfo | None = None,
        error_type: str | None = None,
        error_message: str | None = None,
        method: str | None = None,
        message: str | None = None,
    ) -> bool:
        """Log failed token validation.

        Args:
            bound_session_id: Security-bound session ID (<user_id>:<session_uuid>).
            mcp_session_id: MCP session ID (for correlation with other logs).
            request_id: JSON-RPC request ID (for per-request validation).
            subject: Partial identity if token was parseable.
            oidc: OIDC token details if available.
            error_type: Exception class name (e.g., "TokenExpiredError").
            error_message: Human-readable error description.
            method: MCP method being validated (for per-request).
            message: Optional human-readable message.

        Returns:
            True if logged successfully.
        """
        event = AuthEvent(
            event_type="token_invalid",
            status="Failure",
            bound_session_id=bound_session_id,
            mcp_session_id=mcp_session_id,
            request_id=request_id,
            subject=subject,
            oidc=oidc,
            error_type=error_type,
            error_message=error_message,
            method=method,
            message=message,
        )
        return self._log_event(event)

    def log_token_refreshed(
        self,
        *,
        bound_session_id: str | None = None,
        mcp_session_id: str | None = None,
        subject: SubjectIdentity | None = None,
        oidc: OIDCInfo | None = None,
        message: str | None = None,
    ) -> bool:
        """Log successful token refresh.

        Args:
            bound_session_id: Security-bound session ID (<user_id>:<session_uuid>).
            mcp_session_id: MCP session ID (for correlation with other logs).
            subject: User identity.
            oidc: New token details.
            message: Optional human-readable message.

        Returns:
            True if logged successfully.
        """
        event = AuthEvent(
            event_type="token_refreshed",
            status="Success",
            bound_session_id=bound_session_id,
            mcp_session_id=mcp_session_id,
            subject=subject,
            oidc=oidc,
            message=message,
        )
        return self._log_event(event)

    def log_token_refresh_failed(
        self,
        *,
        bound_session_id: str | None = None,
        mcp_session_id: str | None = None,
        subject: SubjectIdentity | None = None,
        error_type: str | None = None,
        error_message: str | None = None,
        message: str | None = None,
    ) -> bool:
        """Log failed token refresh.

        Args:
            bound_session_id: Security-bound session ID (<user_id>:<session_uuid>).
            mcp_session_id: MCP session ID (for correlation with other logs).
            subject: User identity (from expired token).
            error_type: Exception class name.
            error_message: Human-readable error description.
            message: Optional human-readable message.

        Returns:
            True if logged successfully.
        """
        event = AuthEvent(
            event_type="token_refresh_failed",
            status="Failure",
            bound_session_id=bound_session_id,
            mcp_session_id=mcp_session_id,
            subject=subject,
            error_type=error_type,
            error_message=error_message,
            message=message,
        )
        return self._log_event(event)

    def log_session_started(
        self,
        *,
        bound_session_id: str,
        mcp_session_id: str | None = None,
        subject: SubjectIdentity | None = None,
        oidc: OIDCInfo | None = None,
        message: str | None = None,
    ) -> bool:
        """Log session start.

        Args:
            bound_session_id: Security-bound session ID (<user_id>:<session_uuid>).
            mcp_session_id: MCP session ID (for correlation with other logs).
            subject: Authenticated user identity.
            oidc: OIDC token details.
            message: Optional human-readable message.

        Returns:
            True if logged successfully.
        """
        event = AuthEvent(
            event_type="session_started",
            status="Success",
            bound_session_id=bound_session_id,
            mcp_session_id=mcp_session_id,
            subject=subject,
            oidc=oidc,
            message=message,
        )
        return self._log_event(event)

    def log_session_ended(
        self,
        *,
        bound_session_id: str,
        mcp_session_id: str | None = None,
        subject: SubjectIdentity | None = None,
        end_reason: Literal[
            "normal", "timeout", "error", "auth_expired", "session_binding_violation"
        ] = "normal",
        error_type: str | None = None,
        error_message: str | None = None,
        message: str | None = None,
    ) -> bool:
        """Log session end.

        Args:
            bound_session_id: Security-bound session ID (<user_id>:<session_uuid>).
            mcp_session_id: MCP session ID (for correlation with other logs).
            subject: User identity.
            end_reason: Why the session ended.
            error_type: Exception class name (if end_reason is "error").
            error_message: Human-readable error (if end_reason is "error").
            message: Optional human-readable message.

        Returns:
            True if logged successfully.
        """
        status: Literal["Success", "Failure"] = (
            "Failure" if end_reason in ("error", "auth_expired", "session_binding_violation") else "Success"
        )
        event = AuthEvent(
            event_type="session_ended",
            status=status,
            bound_session_id=bound_session_id,
            mcp_session_id=mcp_session_id,
            subject=subject,
            end_reason=end_reason,
            error_type=error_type,
            error_message=error_message,
            message=message,
        )
        return self._log_event(event)

    def log_device_health_failed(
        self,
        *,
        bound_session_id: str | None = None,
        mcp_session_id: str | None = None,
        subject: SubjectIdentity | None = None,
        device_checks: DeviceHealthChecks,
        error_type: str | None = None,
        error_message: str | None = None,
        message: str | None = None,
    ) -> bool:
        """Log failed device health check.

        Args:
            bound_session_id: Security-bound session ID (may not exist during startup).
            mcp_session_id: MCP session ID (for correlation with other logs).
            subject: User identity.
            device_checks: Individual check results (showing which failed).
            error_type: Exception class name.
            error_message: Human-readable error description.
            message: Optional human-readable message.

        Returns:
            True if logged successfully.
        """
        event = AuthEvent(
            event_type="device_health_failed",
            status="Failure",
            bound_session_id=bound_session_id,
            mcp_session_id=mcp_session_id,
            subject=subject,
            device_checks=device_checks,
            error_type=error_type,
            error_message=error_message,
            message=message,
        )
        return self._log_event(event)


def create_auth_logger(
    log_path: Path,
    shutdown_callback: Callable[[str], None],
    state_manager: "IntegrityStateManager | None" = None,
    log_dir: Path | None = None,
) -> AuthLogger:
    """Create an auth logger with fail-closed behavior.

    Args:
        log_path: Path to auth.jsonl (from get_auth_log_path()).
        shutdown_callback: Called if audit log integrity check fails.
                           This callback must handle the sync-to-async transition.
        state_manager: Optional IntegrityStateManager for hash chain support.
        log_dir: Base log directory for computing relative file keys.

    Returns:
        AuthLogger: Configured logger for authentication events.
    """
    logger = setup_failclosed_audit_logger(
        f"{APP_NAME}.audit.auth",
        log_path,
        shutdown_callback=shutdown_callback,
        log_level=logging.INFO,
        state_manager=state_manager,
        log_dir=log_dir,
    )
    return AuthLogger(logger)
