"""Human-in-the-Loop (HITL) approval handler.

Prompts user for approval on sensitive operations via native OS dialogs.
macOS uses osascript for native dialogs that work without terminal access.

On non-macOS platforms, HITL requests are auto-denied with a warning.

Security Note:
    The subprocess call in _show_macos_dialog intentionally uses synchronous
    subprocess.run() rather than async subprocess. This is a deliberate security
    choice: HITL approval MUST block the request pipeline to prevent any
    possibility of the operation proceeding before user consent is obtained.
    Using async patterns could introduce race conditions where operations
    execute before approval completes.
"""

from __future__ import annotations

import asyncio
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

from mcp_acp.pep.applescript import (
    escape_applescript_string,
    parse_applescript_record as _parse_applescript_record,
)
from mcp_acp.telemetry.system.system_logger import get_system_logger

if TYPE_CHECKING:
    from mcp_acp.config import HITLConfig
    from mcp_acp.context import DecisionContext
    from mcp_acp.manager.state import ProxyState

__all__ = [
    "HITLOutcome",
    "HITLResult",
    "HITLHandler",
    "escape_applescript_string",
]


class HITLOutcome(Enum):
    """Outcome of HITL approval request."""

    USER_ALLOWED = "user_allowed"  # User allowed AND wants to cache
    USER_ALLOWED_ONCE = "user_allowed_once"  # User allowed but no cache
    USER_DENIED = "user_denied"
    TIMEOUT = "timeout"


@dataclass
class HITLResult:
    """Result of HITL approval request.

    Attributes:
        outcome: The user's decision or timeout.
        response_time_ms: How long the user took to respond.
        approver_id: OIDC subject ID of the user who approved/denied (None for timeout/cache).
    """

    outcome: HITLOutcome
    response_time_ms: float
    approver_id: str | None = None


class HITLHandler:
    """Handler for Human-in-the-Loop approval requests.

    Uses native OS dialogs to prompt user for approval.
    Currently only supports macOS via osascript.

    On non-macOS platforms, all HITL requests are auto-denied.

    Attributes:
        config: HITL configuration (timeout, defaults).
        is_supported: Whether HITL dialogs are supported on this platform.
    """

    def __init__(self, config: "HITLConfig", proxy_name: str | None = None) -> None:
        """Initialize HITL handler.

        Logs a warning on non-macOS platforms since HITL dialogs
        will be auto-denied.

        Args:
            config: HITL configuration.
            proxy_name: Proxy instance name for dialog identification.
        """
        self.config = config
        self._proxy_name = proxy_name
        self._system_logger = get_system_logger()
        self.is_supported = sys.platform == "darwin"

        # ProxyState for web UI integration (set via set_proxy_state after creation)
        # When set and UI is connected, HITL uses web UI instead of osascript
        self._proxy_state: "ProxyState | None" = None

        # Event to signal manager disconnect during web UI approval wait
        # When set, pending web UI approvals should abort and fall back to osascript
        self._manager_disconnect_event: asyncio.Event = asyncio.Event()

        # Track pending approval requests for queue indicator.
        # NOTE: This queuing logic is currently ineffective with the macOS
        # osascript implementation because _show_macos_dialog uses synchronous
        # subprocess.run(), which blocks the async event loop. This means only
        # one dialog can ever be "in flight" at a time, so queue_position is
        # always 1. The logic is preserved for future HITL backends that may
        # be async (web UI, notification systems, non-blocking platform APIs).
        # To enable concurrent dialogs, _show_macos_dialog would need to run
        # in a thread executor: await loop.run_in_executor(None, self._show_macos_dialog, ...)
        self._pending_count = 0
        self._pending_lock = threading.Lock()

        if not self.is_supported:
            self._system_logger.warning(
                {
                    "event": "hitl_platform_unsupported",
                    "message": f"HITL dialogs not supported on {sys.platform}. "
                    "All HITL requests will be auto-denied.",
                    "platform": sys.platform,
                }
            )

    @property
    def proxy_state(self) -> "ProxyState | None":
        """Get ProxyState for web UI integration.

        Returns:
            ProxyState instance if set, None otherwise.
        """
        return self._proxy_state

    def set_proxy_state(self, proxy_state: "ProxyState") -> None:
        """Set ProxyState for web UI integration.

        Called after ProxyState is created to enable web-based HITL approvals.
        When proxy_state is set and UI is connected via SSE, HITL requests
        are routed to the web UI instead of osascript dialogs.

        Args:
            proxy_state: ProxyState instance for UI connectivity checks.
        """
        self._proxy_state = proxy_state

    def notify_manager_disconnected(self) -> None:
        """Notify handler that manager connection was lost.

        Called by ManagerClient when connection drops. This interrupts any
        pending web UI approval waits so they can fall back to osascript.
        The disconnect event is checked by _request_approval_via_ui().
        """
        self._manager_disconnect_event.set()

    async def _request_approval_via_ui(
        self,
        context: "DecisionContext",
        matched_rule: str | None,
        will_cache: bool,
    ) -> HITLResult | None:
        """Request approval via web UI.

        Creates a pending approval in ProxyState and waits for user decision
        via the web UI. The pending approval is broadcast to SSE subscribers.

        If the manager disconnects while waiting, returns None so the caller
        can fall back to osascript.

        Args:
            context: Decision context with operation details.
            matched_rule: The rule ID that triggered HITL.
            will_cache: Whether approval can be cached (affects UI display).

        Returns:
            HITLResult with user's decision and response time, or None if
            manager disconnected (caller should fall back to osascript).
        """
        start_time = time.perf_counter()
        timeout_seconds = self.config.timeout_seconds

        # Clear disconnect event for this approval wait
        self._manager_disconnect_event.clear()

        # Extract context for pending approval
        tool_name = context.resource.tool.name if context.resource.tool else "unknown"
        path = context.resource.resource.path if context.resource.resource else None
        subject_id = context.subject.id
        request_id = context.environment.request_id

        # Create pending approval (broadcasts to SSE subscribers)
        pending = self._proxy_state.create_pending(
            tool_name=tool_name,
            path=path,
            subject_id=subject_id,
            timeout_seconds=timeout_seconds,
            request_id=request_id,
            can_cache=will_cache,
            cache_ttl_seconds=self.config.approval_ttl_seconds if will_cache else None,
        )

        # Wait for decision from web UI, but also watch for manager disconnect
        decision_task = asyncio.create_task(self._proxy_state.wait_for_decision(pending.id, timeout_seconds))
        disconnect_task = asyncio.create_task(self._manager_disconnect_event.wait())

        done, pending_tasks = await asyncio.wait(
            [decision_task, disconnect_task],
            return_when=asyncio.FIRST_COMPLETED,
        )

        response_time_ms = (time.perf_counter() - start_time) * 1000

        # Cancel the task that didn't complete
        for task in pending_tasks:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        # Check if manager disconnected - return None to trigger osascript fallback
        if disconnect_task in done:
            self._system_logger.warning(
                {
                    "event": "hitl_manager_disconnected",
                    "message": "Manager disconnected during web UI approval wait, falling back to osascript",
                    "approval_id": pending.id,
                    "tool_name": tool_name,
                    "response_time_ms": response_time_ms,
                }
            )
            # Clean up the pending approval to prevent memory leak and stale UI
            self._proxy_state.cancel_pending(pending.id, reason="manager_disconnected")
            return None  # Signal caller to fall back to osascript

        # Get the decision result
        decision, approver_id = decision_task.result()

        if decision == "allow":
            # Allow with caching (if caching is possible)
            outcome = HITLOutcome.USER_ALLOWED if will_cache else HITLOutcome.USER_ALLOWED_ONCE
            return HITLResult(outcome=outcome, response_time_ms=response_time_ms, approver_id=approver_id)

        elif decision == "allow_once":
            # Allow without caching (user explicitly chose not to cache)
            return HITLResult(
                outcome=HITLOutcome.USER_ALLOWED_ONCE,
                response_time_ms=response_time_ms,
                approver_id=approver_id,
            )

        elif decision == "deny":
            return HITLResult(
                outcome=HITLOutcome.USER_DENIED,
                response_time_ms=response_time_ms,
                approver_id=approver_id,
            )

        else:
            # Timeout (decision is None)
            return HITLResult(outcome=HITLOutcome.TIMEOUT, response_time_ms=response_time_ms)

    async def request_approval(
        self,
        context: "DecisionContext",
        matched_rule: str | None = None,
        will_cache: bool = True,
    ) -> HITLResult:
        """Request user approval for an operation.

        Routes to web UI if connected, otherwise falls back to native OS dialog.
        On unsupported platforms (non-macOS without UI), returns USER_DENIED.

        Approval flow:
        1. If web UI is connected (SSE subscriber): use web-based approval
        2. Else if macOS: show native osascript dialog
        3. Else: auto-deny (platform unsupported)

        Args:
            context: Decision context with operation details.
            matched_rule: The rule ID that triggered HITL (for user context).
            will_cache: Whether approval will be cached. If True, shows 3 buttons
                (Allow cached, Allow once, Deny). If False, shows 2 buttons
                (Allow, Deny) since caching isn't possible anyway.

        Returns:
            HITLResult with user's decision and response time.
        """
        # Check if web UI is connected (preferred over osascript)
        if self._proxy_state is not None and self._proxy_state.is_ui_connected:
            result = await self._request_approval_via_ui(context, matched_rule, will_cache)
            if result is not None:
                return result
            # result is None = manager disconnected, fall through to osascript

        # Fall back to osascript on macOS
        if not self.is_supported:
            return HITLResult(
                outcome=HITLOutcome.USER_DENIED,
                response_time_ms=0.0,
            )

        # Track pending approvals for queue indicator
        with self._pending_lock:
            self._pending_count += 1
            queue_position = self._pending_count

        try:
            return await self._do_request_approval(context, matched_rule, queue_position, will_cache)
        finally:
            with self._pending_lock:
                self._pending_count -= 1

    async def _do_request_approval(
        self,
        context: "DecisionContext",
        matched_rule: str | None,
        queue_position: int,
        will_cache: bool,
    ) -> HITLResult:
        """Internal method to perform the actual approval request."""
        start_time = time.perf_counter()

        # Build dialog content
        tool_name = context.resource.tool.name if context.resource.tool else "unknown"
        tool = context.resource.tool
        path = context.resource.resource.path if context.resource.resource else None
        subject_id = context.subject.id
        request_id = context.environment.request_id
        backend_id = context.resource.server.id

        # Build structured message
        message_parts: list[str] = []
        timeout_seconds = self.config.timeout_seconds

        # Proxy identification (for multi-proxy deployments)
        if self._proxy_name:
            message_parts.append(f"Proxy: {self._proxy_name}")

        # Header: What operation
        message_parts.append(f"Tool: {tool_name}")

        # Target path if present
        if path:
            # Truncate long paths for readability
            display_path = path if len(path) <= 60 else "..." + path[-57:]
            message_parts.append(f"Path: {display_path}")

        # Side effects (security-relevant info)
        if tool and tool.side_effects:
            effects = ", ".join(effect.value for effect in tool.side_effects)
            message_parts.append(f"Effects: {effects}")

        # Which backend server
        message_parts.append(f"Server: {backend_id}")

        # User making the request
        message_parts.append(f"User: {subject_id}")

        # Queue indicator (only show if there are multiple pending)
        if queue_position > 1:
            message_parts.append(f"Queue: #{queue_position} pending")

        # Timeout warning and keyboard hints
        message_parts.append("")  # Empty line for spacing
        message_parts.append(f"Auto-deny in {timeout_seconds}s")
        if will_cache:
            ttl_min = self.config.approval_ttl_seconds // 60
            # Legend matches button order (left to right): Deny, Allow (Xm), Allow once
            message_parts.append(f"[Esc] Deny | Allow ({ttl_min}m) | [Return] Allow once")
        else:
            # Legend matches button order: Deny, Allow
            message_parts.append("[Esc] Deny | [Return] Allow")

        # Escape each part individually, then join with AppleScript return syntax
        # This ensures user input is escaped but the return keyword works
        escaped_parts = [escape_applescript_string(part) for part in message_parts]
        safe_message = '" & return & "'.join(escaped_parts)

        # Show dialog and get response
        outcome = self._show_macos_dialog(safe_message, request_id, queue_position, will_cache)

        response_time_ms = (time.perf_counter() - start_time) * 1000

        return HITLResult(outcome=outcome, response_time_ms=response_time_ms)

    def _show_macos_dialog(
        self,
        message: str,
        request_id: str | None,
        queue_position: int,
        will_cache: bool,
    ) -> HITLOutcome:
        """Show macOS approval dialog via osascript.

        Args:
            message: Message to display in dialog (parts pre-escaped, joined with return).
            request_id: Request correlation ID for logging.
            queue_position: Position in approval queue (1 = first, plays sound).
            will_cache: Whether caching is possible. If True, shows 3 buttons.

        Returns:
            HITLOutcome based on user response or timeout.
        """
        timeout_seconds = self.config.timeout_seconds

        # Build osascript command
        # Play Funk sound only for first request (queue_position == 1)
        # No sound for queued requests since user is already engaged
        sound_cmd = (
            'do shell script "afplay /System/Library/Sounds/Funk.aiff &"' if queue_position == 1 else ""
        )

        # Button configuration depends on whether caching is possible
        # Buttons appear left-to-right as listed in the array
        # default button = Return/Enter activates it
        # cancel button = Escape activates it (returns exit code 1, "User canceled")
        if will_cache:
            # 3 buttons (left to right): Deny, Allow (Xm), Allow once
            ttl_minutes = self.config.approval_ttl_seconds // 60
            allow_cached_button = f"Allow ({ttl_minutes}m)"
            allow_once_button = "Allow once"
            # Buttons appear: [Deny] [Allow (Xm)] [Allow once]
            buttons_str = f'{{"Deny", "{allow_cached_button}", "{allow_once_button}"}}'
            default_button = allow_once_button  # Return = Allow once (safer default)
        else:
            # 2 buttons: Deny, Allow (caching not possible for this tool)
            allow_cached_button = None
            allow_once_button = "Allow"
            buttons_str = f'{{"Deny", "{allow_once_button}"}}'
            default_button = allow_once_button

        script = f"""
            {sound_cmd}
            display dialog ("{message}") \
                with title "MCP-ACP: Approval Required" \
                buttons {buttons_str} \
                default button "{default_button}" \
                cancel button "Deny" \
                with icon caution \
                giving up after {timeout_seconds}
        """

        try:
            result = subprocess.run(
                ["osascript", "-e", script],
                capture_output=True,
                text=True,
                timeout=timeout_seconds + 5,  # Extra buffer for subprocess overhead
            )

            # Check returncode first - non-zero means error or user cancelled
            if result.returncode != 0:
                # returncode 1 with "User canceled" means Escape was pressed (Deny)
                if result.returncode == 1 and "User canceled" in result.stderr:
                    return HITLOutcome.USER_DENIED

                # Other error
                self._system_logger.warning(
                    {
                        "event": "hitl_osascript_error",
                        "message": "osascript returned non-zero exit code",
                        "returncode": result.returncode,
                        "stderr": result.stderr.strip() if result.stderr else None,
                        "request_id": request_id,
                    }
                )
                return HITLOutcome.USER_DENIED

            output = result.stdout.strip()

            # Parse AppleScript output - defensive handling
            try:
                parsed = _parse_applescript_record(output)
            except Exception as e:
                self._system_logger.warning(
                    {
                        "event": "hitl_parse_error",
                        "message": f"Failed to parse osascript output: {e}",
                        "output": output,
                        "error_type": type(e).__name__,
                        "request_id": request_id,
                    }
                )
                # Emit SSE event for UI notification
                if self._proxy_state is not None:
                    from mcp_acp.manager.events import SSEEventType

                    self._proxy_state.emit_system_event(
                        SSEEventType.HITL_PARSE_FAILED,
                        severity="error",
                        message="HITL dialog response parse failed",
                        error_type=type(e).__name__,
                    )
                return HITLOutcome.USER_DENIED

            # Check for timeout (dialog gave up)
            if parsed.get("gave up") == "true":
                self._system_logger.warning(
                    {
                        "event": "hitl_timeout",
                        "message": f"HITL dialog timed out after {timeout_seconds}s",
                        "timeout_seconds": timeout_seconds,
                        "request_id": request_id,
                    }
                )
                return HITLOutcome.TIMEOUT

            # Check button pressed
            button = parsed.get("button returned")
            if will_cache and button == allow_cached_button:
                return HITLOutcome.USER_ALLOWED  # Allow + cache
            elif button == allow_once_button:
                return HITLOutcome.USER_ALLOWED_ONCE  # Allow without cache
            elif button == "Deny":
                return HITLOutcome.USER_DENIED
            else:
                # Unexpected output, treat as deny
                self._system_logger.warning(
                    {
                        "event": "hitl_unexpected_response",
                        "message": "Unexpected osascript output, defaulting to deny",
                        "output": output,
                        "parsed": parsed,
                        "request_id": request_id,
                    }
                )
                return HITLOutcome.USER_DENIED

        except subprocess.TimeoutExpired:
            self._system_logger.warning(
                {
                    "event": "hitl_subprocess_timeout",
                    "message": "osascript subprocess timed out",
                    "timeout_seconds": timeout_seconds,
                    "request_id": request_id,
                }
            )
            return HITLOutcome.TIMEOUT

        except FileNotFoundError:
            self._system_logger.error(
                {
                    "event": "hitl_osascript_not_found",
                    "message": "osascript not found - HITL requires macOS",
                    "request_id": request_id,
                }
            )
            return HITLOutcome.USER_DENIED

        except subprocess.SubprocessError as e:
            self._system_logger.error(
                {
                    "event": "hitl_subprocess_error",
                    "message": f"osascript failed: {e}",
                    "error_type": type(e).__name__,
                    "request_id": request_id,
                }
            )
            return HITLOutcome.USER_DENIED
