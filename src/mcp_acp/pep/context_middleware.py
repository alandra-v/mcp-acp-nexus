"""Request context middleware for MCP proxy.

This middleware is the outermost in the chain and responsible for:
1. Setting up request context (request_id, session_id) from FastMCP context
2. Extracting tool context (tool_name, arguments) for tools/call requests
3. Cleaning up all context in the finally block

Middleware order: Context (outer) -> Audit -> ClientLogger -> Enforcement (inner)

By handling context at the outermost layer:
- All downstream middleware has access to context vars
- Audit gets tool_name/arguments even for denied requests
- Context is reliably cleaned up regardless of success/failure
"""

from __future__ import annotations

__all__ = [
    "ContextMiddleware",
    "create_context_middleware",
]

from typing import Any

from fastmcp.server.middleware import Middleware
from fastmcp.server.middleware.middleware import CallNext, MiddlewareContext

from mcp_acp.telemetry.system.system_logger import get_system_logger
from mcp_acp.utils.logging.logging_context import (
    clear_all_context,
    set_request_id,
    set_session_id,
    set_tool_context,
)

_system_logger = get_system_logger()


class ContextMiddleware(Middleware):
    """Outermost middleware that manages request context lifecycle.

    Sets up context vars early so all downstream middleware can use them.
    Cleans up in finally block to prevent memory leaks.

    For tools/call requests, also extracts and sets tool context so that
    audit logging has access to tool_name and arguments even for denied requests.
    """

    async def on_message(
        self,
        context: MiddlewareContext[Any],
        call_next: CallNext[Any],
    ) -> Any:
        """Set up context, process request, and clean up.

        Args:
            context: Middleware context containing request.
            call_next: Next middleware in chain.

        Returns:
            Response from downstream middleware/handler.
        """
        request_id: str | None = None
        session_id: str | None = None

        try:
            # Extract context IDs from FastMCP context
            # Wrap in try/except because fastmcp_context may not be available
            # during early connection phase (e.g., initialize)
            try:
                if hasattr(context, "fastmcp_context") and context.fastmcp_context is not None:
                    request_id = context.fastmcp_context.request_id
                    session_id = context.fastmcp_context.session_id

                    # Set context vars for downstream middleware
                    if request_id:
                        set_request_id(request_id)
                    if session_id:
                        set_session_id(session_id)
            except (AttributeError, RuntimeError):
                # Context not available (expected during early connection phase)
                pass

            # For tools/call requests, extract and set tool context
            # This ensures audit logging has tool info even for denied requests
            if context.method == "tools/call":
                self._set_tool_context(context, request_id)

            # Process request through the chain
            return await call_next(context)

        finally:
            # Clean up all context to prevent memory leaks
            # Use the request_id we captured (not from context var, which may be cleared)
            clear_all_context(request_id)

    def _set_tool_context(
        self,
        context: MiddlewareContext[Any],
        request_id: str | None,
    ) -> None:
        """Extract and set tool context from tools/call request.

        Args:
            context: Middleware context containing request.
            request_id: Request ID for dict-based storage.
        """
        try:
            message = context.message
            if message is None:
                return

            # In FastMCP, context.message IS the params object (CallToolRequestParams)
            # It has 'name' and 'arguments' attributes directly
            tool_name: str | None = None
            arguments: dict[str, Any] | None = None

            if hasattr(message, "name"):
                tool_name = message.name
            if hasattr(message, "arguments"):
                arguments = message.arguments

            if tool_name:
                set_tool_context(tool_name, arguments, request_id)
            else:
                _system_logger.warning(
                    {
                        "event": "tool_context_extraction_failed",
                        "reason": "no tool name in message",
                        "message_type": type(message).__name__,
                        "request_id": request_id,
                    }
                )

        except (AttributeError, TypeError) as e:
            _system_logger.warning(
                {
                    "event": "tool_context_extraction_error",
                    "error": str(e),
                    "error_type": type(e).__name__,
                    "request_id": request_id,
                }
            )


def create_context_middleware() -> ContextMiddleware:
    """Create context middleware.

    Factory function for consistency with other middleware creation patterns.

    Returns:
        Configured ContextMiddleware.
    """
    return ContextMiddleware()
