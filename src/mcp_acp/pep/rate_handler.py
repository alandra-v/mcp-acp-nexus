"""Rate limit breach handler for policy enforcement.

Handles rate limit violations by triggering HITL approval dialogs.
Extracted from middleware.py for better separation of concerns.
"""

from __future__ import annotations

__all__ = [
    "ContextBuilder",
    "RateBreachHandler",
]

import logging
from typing import TYPE_CHECKING, Any, Callable, Coroutine

from mcp_acp.context import DecisionContext
from mcp_acp.pdp import Decision, MatchedRule
from mcp_acp.exceptions import PermissionDeniedError
from mcp_acp.pep.hitl import HITLHandler, HITLOutcome


# Synthetic rule for rate limit breaches (not a policy rule)
_RATE_LIMIT_RULE = MatchedRule(
    id="rate_limit_breach",
    description="Rate limit exceeded for tool calls",
    effect="hitl",
)

if TYPE_CHECKING:
    from mcp_acp.security.rate_limiter import SessionRateTracker
    from mcp_acp.telemetry.audit.decision_logger import DecisionEventLogger


# Type alias for context builder callable
ContextBuilder = Callable[
    [str, dict[str, Any] | None, str, str],
    Coroutine[Any, Any, DecisionContext],
]


class RateBreachHandler:
    """Handles rate limit breach by triggering HITL approval.

    If user approves, returns normally so caller can continue with policy evaluation.
    If user denies or times out, raises PermissionDeniedError.
    """

    def __init__(
        self,
        *,
        hitl_handler: HITLHandler,
        rate_tracker: "SessionRateTracker",
        decision_logger: "DecisionEventLogger",
        system_logger: logging.Logger,
        context_builder: ContextBuilder,
    ) -> None:
        """Initialize rate breach handler.

        Args:
            hitl_handler: HITL handler for approval dialogs.
            rate_tracker: Rate tracker for resetting counters.
            decision_logger: Decision event logger for audit trail.
            system_logger: System logger for operational events.
            context_builder: Async callable to build decision context.
        """
        self._hitl_handler = hitl_handler
        self._rate_tracker = rate_tracker
        self._decision_logger = decision_logger
        self._system_logger = system_logger
        self._build_context = context_builder

    async def handle(
        self,
        *,
        tool_name: str,
        rate_count: int,
        threshold: int,
        session_id: str,
        request_id: str,
    ) -> None:
        """Handle rate limit breach by triggering HITL.

        If user approves, returns normally so caller can continue with policy evaluation.
        If user denies or times out, raises PermissionDeniedError.

        Args:
            tool_name: Tool that exceeded rate limit.
            rate_count: Current call count in window.
            threshold: Threshold that was exceeded.
            session_id: Session identifier.
            request_id: Request identifier.

        Raises:
            PermissionDeniedError: If user denied or timeout.
        """
        self._system_logger.warning(
            {
                "event": "rate_limit_exceeded",
                "message": f"Rate limit exceeded for {tool_name}: {rate_count}/{threshold} calls",
                "tool_name": tool_name,
                "count": rate_count,
                "threshold": threshold,
                "session_id": session_id,
                "request_id": request_id,
            }
        )

        # Emit SSE event for UI notification
        if self._hitl_handler.proxy_state is not None:
            from mcp_acp.manager.events import SSEEventType

            self._hitl_handler.proxy_state.emit_system_event(
                SSEEventType.RATE_LIMIT_TRIGGERED,
                severity="warning",
                message=f"Rate limit exceeded: {tool_name} ({rate_count}/{threshold})",
                tool_name=tool_name,
                count=rate_count,
                threshold=threshold,
            )

        # Show HITL dialog for rate breach
        # Build a minimal decision context for the dialog
        try:
            decision_context = await self._build_context(
                "tools/call",
                {"name": tool_name},
                request_id,
                session_id,
            )
        except Exception:
            # If context building fails, deny by default
            raise PermissionDeniedError(
                f"Rate limit exceeded: {rate_count} calls to {tool_name} in {int(self._rate_tracker.window_seconds)}s",
                decision=Decision.DENY,
                tool_name=tool_name,
                matched_rules=["rate_limit"],
                final_rule="rate_limit_breach",
            )

        # Show approval dialog
        hitl_result = await self._hitl_handler.request_approval(
            decision_context,
            matched_rule="rate_limit_breach",
            will_cache=False,  # Never cache rate limit approvals
        )

        if hitl_result.outcome in (HITLOutcome.USER_ALLOWED, HITLOutcome.USER_ALLOWED_ONCE):
            # User allowed - reset rate counter to avoid immediate re-trigger
            self._rate_tracker.reset_tool(session_id, tool_name)

            # Log to decisions.jsonl for audit trail
            self._decision_logger.log(
                decision=Decision.HITL,
                decision_context=decision_context,
                hitl_outcome=hitl_result.outcome,
                matched_rules=[_RATE_LIMIT_RULE],
                final_rule="rate_limit_breach",
                policy_eval_ms=0.0,  # No policy eval - rate limit check
                policy_hitl_ms=hitl_result.response_time_ms,
                hitl_cache_hit=False,  # Rate limits never cached
            )

            self._system_logger.warning(
                {
                    "event": "rate_limit_approved",
                    "message": f"User approved rate limit breach for {tool_name}",
                    "tool_name": tool_name,
                    "count": rate_count,
                    "hitl_outcome": hitl_result.outcome.value,
                    "session_id": session_id,
                    "request_id": request_id,
                }
            )

            # Emit SSE event for UI notification
            if self._hitl_handler.proxy_state is not None:
                from mcp_acp.manager.events import SSEEventType

                self._hitl_handler.proxy_state.emit_system_event(
                    SSEEventType.RATE_LIMIT_APPROVED,
                    severity="success",
                    message=f"Rate limit breach approved: {tool_name}",
                    tool_name=tool_name,
                )
            # Return normally - caller will continue with policy evaluation
            return
        else:
            # User denied or timeout
            reason = "User denied" if hitl_result.outcome == HITLOutcome.USER_DENIED else "Approval timeout"

            # Log to decisions.jsonl for audit trail
            self._decision_logger.log(
                decision=Decision.HITL,
                decision_context=decision_context,
                hitl_outcome=hitl_result.outcome,
                matched_rules=[_RATE_LIMIT_RULE],
                final_rule="rate_limit_breach",
                policy_eval_ms=0.0,  # No policy eval - rate limit check
                policy_hitl_ms=hitl_result.response_time_ms,
                hitl_cache_hit=False,  # Rate limits never cached
            )

            self._system_logger.warning(
                {
                    "event": "rate_limit_denied",
                    "message": f"{reason} for rate limit breach on {tool_name}",
                    "tool_name": tool_name,
                    "count": rate_count,
                    "hitl_outcome": hitl_result.outcome.value,
                    "session_id": session_id,
                    "request_id": request_id,
                }
            )

            # Emit SSE event for UI notification
            if self._hitl_handler.proxy_state is not None:
                from mcp_acp.manager.events import SSEEventType

                self._hitl_handler.proxy_state.emit_system_event(
                    SSEEventType.RATE_LIMIT_DENIED,
                    severity="warning",
                    message=f"Rate limit breach denied: {tool_name}",
                    tool_name=tool_name,
                )
            raise PermissionDeniedError(
                f"{reason}: Rate limit exceeded ({rate_count} calls to {tool_name})",
                decision=Decision.DENY,
                tool_name=tool_name,
                matched_rules=["rate_limit"],
                final_rule="rate_limit_breach",
            )
