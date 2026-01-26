"""Context variables for request tracing and correlation.

This module provides async-safe context variables for propagating trace and
session IDs throughout the request lifecycle. These IDs are extracted from
FastMCP's Context and made available to all audit logging code.

Context variables are thread-safe and automatically scoped per-async-task,
making them ideal for propagating request-scoped data without explicit
parameter passing.
"""

from __future__ import annotations

__all__ = [
    "bound_user_id_var",
    "clear_all_context",
    "clear_context",
    "clear_tool_context",
    "get_bound_user_id",
    "get_request_id",
    "get_session_id",
    "get_tool_arguments",
    "get_tool_name",
    "request_id_var",
    "session_id_var",
    "set_bound_user_id",
    "set_request_id",
    "set_session_id",
    "set_tool_context",
]

# NOTE: Tool context is stored in a module-level dict keyed by request_id,
# NOT in ContextVars. This is because FastMCP copies the async context when
# setting up request handlers - the middleware runs in a context snapshot taken
# BEFORE the ProxyClient call happens, so ContextVar changes don't propagate back.
# The request_id IS available in both places, so we use it as a key.

import time
from contextvars import ContextVar
from typing import Any, cast

from mcp_acp.telemetry.system.system_logger import get_system_logger

# Module-level system logger for validation errors
_system_logger = get_system_logger()

# Trace ID for correlating all logs within a single request
# This is FastMCP's request_id, used for distributed tracing
request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)
"""Trace ID (request ID) for correlating logs within a single MCP request/response cycle."""

# Session ID for correlating all requests within a client connection
# This is FastMCP's session_id, used for tracking user sessions
session_id_var: ContextVar[str | None] = ContextVar("session_id", default=None)
"""Session ID for correlating all requests within a single client connection."""

# Bound user ID for session binding validation
# This is the user_id from the initial session creation - used to detect identity changes
bound_user_id_var: ContextVar[str | None] = ContextVar("bound_user_id", default=None)
"""User ID from session creation for identity binding validation."""

# Tool call metadata - set by LoggingProxyClient.call_tool_mcp(), read by audit middleware
# These provide tool info that's hard to extract from MiddlewareContext
#
# TTL cleanup: Entries older than _TOOL_CONTEXT_TTL_SECONDS are purged on each
# set_tool_context() call to prevent unbounded growth from missed cleanups.
_tool_context_by_request: dict[str, dict[str, Any]] = {}
"""Tool context keyed by request_id. Contains 'tool_name', 'arguments', and '_created_at'."""

# TTL for tool context entries (5 minutes - requests should complete well before this)
_TOOL_CONTEXT_TTL_SECONDS = 300

# Counter to trigger periodic cleanup (every N calls)
_cleanup_counter = 0
_CLEANUP_INTERVAL = 50


def get_request_id() -> str | None:
    """Get the current trace ID from context.

    Returns:
        str | None: Current trace ID if set, None otherwise.
    """
    return request_id_var.get()


def get_session_id() -> str | None:
    """Get the current session ID from context.

    Returns:
        str | None: Current session ID if set, None otherwise.
    """
    return session_id_var.get()


def get_bound_user_id() -> str | None:
    """Get the bound user ID from context.

    This is the user_id from when the session was created, used to detect
    if a different user is trying to use the session (identity mismatch).

    Returns:
        str | None: Bound user ID if set, None otherwise.
    """
    return bound_user_id_var.get()


def set_bound_user_id(user_id: str) -> None:
    """Set the bound user ID in context.

    Called when session is created to record which user started the session.
    Used for session binding validation on subsequent requests.

    Args:
        user_id: User ID from validated identity (e.g., "auth0|123").
    """
    bound_user_id_var.set(user_id)


def set_request_id(request_id: str) -> None:
    """Set the trace ID in context with minimal validation.

    Only validates that the request_id doesn't contain newline characters,
    which would corrupt the JSONL log format. FastMCP is assumed a trusted source,
    so we don't add extensive validation.

    Args:
        request_id: Trace ID to set (typically from FastMCP's request_id).
    """
    if not request_id:
        request_id_var.set(None)
        return

    # Only check for newlines (would break JSONL format)
    # CRITICAL: Log injection attempt is a security event
    if "\n" in request_id or "\r" in request_id:
        _system_logger.critical(
            {
                "event": "invalid_request_id",
                "request_id": repr(request_id),
                "error": "request_id contains newline characters",
                "message": "Rejecting malformed request_id to prevent log injection",
            }
        )
        request_id_var.set(None)
        return

    request_id_var.set(request_id)


def set_session_id(session_id: str) -> None:
    """Set the session ID in context with minimal validation.

    Only validates that the session_id doesn't contain newline characters,
    which would corrupt the JSONL log format. FastMCP is a trusted source,
    so we don't need extensive validation.

    Args:
        session_id: Session ID to set (typically from FastMCP's session_id).
    """
    if not session_id:
        session_id_var.set(None)
        return

    # Only check for newlines (would break JSONL format)
    # CRITICAL: Log injection attempt is a security event
    if "\n" in session_id or "\r" in session_id:
        _system_logger.critical(
            {
                "event": "invalid_session_id",
                "session_id": repr(session_id),
                "error": "session_id contains newline characters",
                "message": "Rejecting malformed session_id to prevent log injection",
            }
        )
        session_id_var.set(None)
        return

    session_id_var.set(session_id)


def get_tool_name(request_id: str | None = None) -> str | None:
    """Get the current tool name from context.

    Args:
        request_id: Request ID to look up. Required for tool context lookup.

    Returns:
        Tool name if found, None otherwise.
    """
    if request_id and request_id in _tool_context_by_request:
        return cast(str | None, _tool_context_by_request[request_id].get("tool_name"))
    return None


def get_tool_arguments(request_id: str | None = None) -> dict[str, Any] | None:
    """Get the current tool arguments from context.

    Args:
        request_id: Request ID to look up. Required for tool context lookup.

    Returns:
        Tool arguments if found, None otherwise.
    """
    if request_id and request_id in _tool_context_by_request:
        return cast(dict[str, Any] | None, _tool_context_by_request[request_id].get("arguments"))
    return None


def _cleanup_stale_tool_contexts() -> None:
    """Remove tool context entries older than TTL.

    Called periodically to prevent unbounded memory growth from missed cleanups.
    """
    now = time.monotonic()
    stale_keys = [
        key
        for key, value in _tool_context_by_request.items()
        if now - value.get("_created_at", 0) > _TOOL_CONTEXT_TTL_SECONDS
    ]
    for key in stale_keys:
        del _tool_context_by_request[key]


def set_tool_context(tool_name: str, arguments: dict[str, Any] | None, request_id: str | None = None) -> None:
    """Set tool call context for audit logging.

    Called by LoggingProxyClient.call_tool_mcp() before executing tool.
    Read by audit middleware in finally block after call_next() returns.

    Includes periodic TTL cleanup to prevent unbounded memory growth.

    Args:
        tool_name: Name of the tool being called.
        arguments: Tool arguments.
        request_id: Request ID for dict-based storage. Required for context to be retrievable.
    """
    global _cleanup_counter

    # Store in dict keyed by request_id (works across async context boundaries)
    if request_id:
        _tool_context_by_request[request_id] = {
            "tool_name": tool_name,
            "arguments": arguments,
            "_created_at": time.monotonic(),
        }

        # Periodic cleanup every N calls
        _cleanup_counter += 1
        if _cleanup_counter >= _CLEANUP_INTERVAL:
            _cleanup_counter = 0
            _cleanup_stale_tool_contexts()


def clear_tool_context(request_id: str | None = None) -> None:
    """Clear tool context after request completes.

    Should be called by audit middleware after logging to prevent memory leaks.

    Args:
        request_id: Request ID to clear from dict.
    """
    if request_id and request_id in _tool_context_by_request:
        del _tool_context_by_request[request_id]


def clear_context() -> None:
    """Clear request and session context variables.

    Clears request_id and session_id context vars. Does NOT clear tool context
    (tool_name, tool_arguments) - use clear_tool_context() for that.

    Useful for cleanup in tests or when explicitly ending a request context.
    """
    request_id_var.set(None)
    session_id_var.set(None)


def clear_all_context(request_id: str | None = None) -> None:
    """Clear all context variables (request, session, and tool context).

    This is the complete cleanup function that should be called at the end
    of request processing by the outermost ContextMiddleware.

    Args:
        request_id: Request ID for clearing tool context from dict storage.
    """
    clear_context()
    clear_tool_context(request_id)
