"""Decision logging for policy enforcement.

This module provides logging for policy decisions (ALLOW, DENY, HITL).
Logs are written to <log_dir>/mcp_acp_logs/audit/decisions.jsonl.

Decision logs are ALWAYS enabled (not controlled by log_level).
"""

from __future__ import annotations

__all__ = [
    "create_decision_logger",
    "DecisionEventLogger",
]

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Callable

from mcp.shared.exceptions import McpError
from mcp.types import ErrorData, INTERNAL_ERROR

from mcp_acp.context import DecisionContext
from mcp_acp.pdp import Decision, MatchedRule
from mcp_acp.security.integrity.emergency_audit import log_with_fallback

if TYPE_CHECKING:
    from mcp_acp.pep.hitl import HITLOutcome
    from mcp_acp.security.integrity.integrity_state import IntegrityStateManager

from mcp_acp.telemetry.models.decision import DecisionEvent, MatchedRuleLog
from mcp_acp.utils.logging.logger_setup import setup_failclosed_audit_logger
from mcp_acp.utils.logging.logging_helpers import serialize_audit_event


def create_decision_logger(
    log_path: Path,
    shutdown_callback: Callable[[str], None],
    state_manager: "IntegrityStateManager | None" = None,
    log_dir: Path | None = None,
) -> logging.Logger:
    """Create logger for decision events with fail-closed integrity checking.

    Args:
        log_path: Path to decisions.jsonl file.
        shutdown_callback: Called if audit log integrity check fails.
        state_manager: Optional IntegrityStateManager for hash chain support.
        log_dir: Base log directory for computing relative file keys.

    Returns:
        Configured logger instance with fail-closed handler.
    """
    return setup_failclosed_audit_logger(
        "mcp-acp.audit.decisions",
        log_path,
        shutdown_callback=shutdown_callback,
        log_level=logging.INFO,
        state_manager=state_manager,
        log_dir=log_dir,
    )


class DecisionEventLogger:
    """Logs policy decision events to decisions.jsonl with fallback chain.

    Uses fallback chain: decisions.jsonl -> system.jsonl -> emergency_audit.jsonl.
    If primary logging fails, logs to fallbacks and raises McpError.
    """

    def __init__(
        self,
        *,
        logger: logging.Logger,
        system_logger: logging.Logger,
        backend_id: str,
        policy_version: str | None,
    ) -> None:
        """Initialize decision event logger.

        Args:
            logger: Primary logger for decision events (decisions.jsonl).
            system_logger: System logger for fallback logging.
            backend_id: Backend server ID for audit trail.
            policy_version: Policy version for audit trail.
        """
        self._logger = logger
        self._system_logger = system_logger
        self._backend_id = backend_id
        self._policy_version = policy_version

    @property
    def policy_version(self) -> str | None:
        """Get current policy version for audit trail."""
        return self._policy_version

    @policy_version.setter
    def policy_version(self, value: str | None) -> None:
        """Set policy version for audit trail (used during hot reload)."""
        self._policy_version = value

    def log(
        self,
        decision: Decision,
        decision_context: DecisionContext,
        matched_rules: list[MatchedRule],
        final_rule: str,
        policy_eval_ms: float,
        hitl_outcome: HITLOutcome | None = None,
        policy_hitl_ms: float | None = None,
        hitl_cache_hit: bool | None = None,
        hitl_approver_id: str | None = None,
    ) -> None:
        """Log policy decision to decisions.jsonl with fallback chain.

        Args:
            decision: The policy decision.
            decision_context: Context used for evaluation.
            matched_rules: Matched rules with id, effect, and description.
            final_rule: Rule that determined outcome.
            policy_eval_ms: Policy rule evaluation time.
            hitl_outcome: HITL outcome if applicable.
            policy_hitl_ms: HITL wait time if applicable.
            hitl_cache_hit: True if approval from cache, False if user prompted.
            hitl_approver_id: OIDC subject ID of user who approved/denied.

        Raises:
            McpError: If primary logging fails (after logging to fallbacks).
        """
        # Extract context summary
        tool = decision_context.resource.tool
        resource = decision_context.resource.resource

        tool_name = tool.name if tool else None
        path = resource.path if resource else None
        source_path = resource.source_path if resource else None
        dest_path = resource.dest_path if resource else None
        uri = resource.uri if resource else None
        scheme = resource.scheme if resource else None

        # Extract side effects as list of strings
        side_effects: list[str] | None = None
        if tool and tool.side_effects:
            side_effects = [effect.value for effect in tool.side_effects]

        # Calculate total time (eval + HITL, excludes context)
        policy_total_ms = policy_eval_ms + (policy_hitl_ms or 0.0)

        # Map USER_ALLOWED_ONCE to user_allowed for logging (same outcome, different caching)
        hitl_outcome_value: str | None = None
        if hitl_outcome:
            # Local import to avoid circular dependency (pep.hitl -> pep.__init__ -> pep.middleware -> here)
            from mcp_acp.pep.hitl import HITLOutcome

            if hitl_outcome == HITLOutcome.USER_ALLOWED_ONCE:
                hitl_outcome_value = "user_allowed"
            else:
                hitl_outcome_value = hitl_outcome.value

        # Convert MatchedRule to MatchedRuleLog for logging
        matched_rules_log = [
            MatchedRuleLog(
                id=rule.id,
                effect=rule.effect,
                description=rule.description,
            )
            for rule in matched_rules
        ]

        event = DecisionEvent(
            decision=decision.value,
            matched_rules=matched_rules_log,
            final_rule=final_rule,
            mcp_method=decision_context.action.mcp_method,
            tool_name=tool_name,
            path=path,
            source_path=source_path,
            dest_path=dest_path,
            uri=uri,
            scheme=scheme,
            subject_id=decision_context.subject.id,
            backend_id=self._backend_id,
            side_effects=side_effects,
            policy_version=self._policy_version or "unknown",
            policy_eval_ms=round(policy_eval_ms, 2),
            policy_hitl_ms=round(policy_hitl_ms, 2) if policy_hitl_ms else None,
            policy_total_ms=round(policy_total_ms, 2),
            request_id=decision_context.environment.request_id,
            session_id=decision_context.environment.session_id,
            hitl_outcome=hitl_outcome_value,
            hitl_cache_hit=hitl_cache_hit,
            hitl_approver_id=hitl_approver_id,
        )

        # Log with fallback chain
        event_data = serialize_audit_event(event)
        success, failure_reason = log_with_fallback(
            primary_logger=self._logger,
            system_logger=self._system_logger,
            event_data=event_data,
            event_type="decision",
            source_file="decisions.jsonl",
        )

        # If primary audit failed, raise error to client before shutdown
        if not success:
            raise McpError(
                ErrorData(
                    code=INTERNAL_ERROR,
                    message="Decision audit log failure - logged to fallback, proxy shutting down",
                )
            )
