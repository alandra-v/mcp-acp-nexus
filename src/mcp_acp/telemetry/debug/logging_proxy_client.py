"""LoggingProxyClient wrapper for Proxy↔Backend wire-level debugging.

This module provides wire-level DEBUG logging for all communication between
the proxy and backend MCP servers.

Wire logs include:
- Method names and metadata (tool names, file paths, operation types)
- Response summaries and metrics
- Errors and duration data
- Server information during initialization

Logs are written to <log_dir>/mcp-acp/proxies/default/debug/backend_wire.jsonl using Pydantic models.
The log_dir is specified in the user's configuration file.

IMPORTANT - Backend Connection Error Handling:

This module also handles SSE event emission for backend connection errors. This is
necessary because FastMCP's architecture calls get_tools() BEFORE middleware runs,
so connection errors bypass the middleware exception handlers.

Error handling happens at TWO layers:
1. HERE (LoggingProxyClient.__aenter__): Catches connection establishment errors
2. PolicyEnforcementMiddleware: Catches mid-request errors (backend dies during call)

Both layers call mark_backend_success() on success to detect reconnection.
See docs/implementation/sse-system-events.md for full architecture details.

IMPORTANT - Initialize Logging Limitation:
Initialize is logged as INGRESS ONLY (backend_response), with no corresponding
EGRESS (proxy_request). This is because FastMCP's ProxyClient handles the MCP
initialize handshake internally within __aenter__(), and we cannot intercept
the outgoing request - only the completed result afterwards. This is documented
behavior and correctly reflects what we can observe from our position in the
call stack.
"""

from __future__ import annotations

__all__ = [
    "LoggingProxyClient",
    "create_logging_proxy_client",
]

import logging
from datetime import timedelta
from pathlib import Path
from typing import Any, Callable, Optional

import mcp.types
from fastmcp.client.progress import ProgressHandler
from fastmcp.client.transports import ClientTransport
from fastmcp.server.proxy import ProxyClient
from pydantic.networks import AnyUrl

from mcp_acp.constants import APP_NAME
from mcp_acp.telemetry.debug.backend_logger import (
    log_backend_error,
    log_backend_response,
    log_proxy_request,
    setup_backend_wire_logger,
)
from mcp_acp.telemetry.models.wire import BackendResponseEvent
from mcp_acp.telemetry.system.system_logger import get_system_logger
from mcp_acp.utils.logging.extractors import extract_initialize_metadata
from mcp_acp.utils.logging.logging_context import (
    get_request_id,
    get_session_id,
)


class LoggingProxyClient(ProxyClient):
    """ProxyClient wrapper for wire-level debug logging of backend communication.

    Logs parsed method calls with metadata and summaries. All logs use Pydantic models:
    - ProxyRequestEvent: Proxy request to backend (egress)
    - BackendResponseEvent: Backend response to proxy (ingress, success)
    - BackendErrorEvent: Backend error to proxy (ingress, error)

    Security metadata extraction (NO file content logging):
    - Tool names and operation types (read/write/delete/list)
    - File paths (normalized)
    - File sizes and extensions
    - NO file contents or hashes
    """

    # Class-level set to track logged sessions across all instances.
    # This prevents duplicate initialize logs when multiple client instances
    # (created via .new()) exist for the same session. We track by session_id
    # because FastMCP creates new initialize_result objects for each instance,
    # making object-ID-based tracking ineffective.
    _logged_sessions_global: set[str] = set()

    def __init__(
        self,
        transport_or_client: ClientTransport | ProxyClient,
        logger: logging.Logger,
        transport_type: str = "stdio",
        system_logger: Optional[logging.Logger] = None,
        _is_wrapper: bool = False,
    ) -> None:
        """Initialize the logging wrapper.

        Args:
            transport_or_client: Transport (initial) or ProxyClient (from .new())
            logger: Logger instance for writing backend wire logs.
            transport_type: Transport type being used ("stdio" or "http").
            system_logger: Logger instance for system/operational errors. If None, uses singleton.
            _is_wrapper: Internal flag - True when wrapping a client from .new()
        """
        self._logger = logger
        self._system_logger = system_logger or get_system_logger()
        self._transport = transport_type
        self._is_wrapper = _is_wrapper

        if _is_wrapper:
            # Wrapping mode: wrapping a ProxyClient from .new()
            self._client = transport_or_client
        else:
            # Initial mode: inherit from ProxyClient with transport
            super().__init__(transport_or_client)
            self._client = None

    async def _wrap_call(
        self,
        method: str,
        wrapped_fn: Callable[..., Any],
        *args: Any,
        **log_kwargs: Any,
    ) -> Any:
        """Wrap an async method call with logging.

        Args:
            method: MCP method name
            wrapped_fn: The actual async function to call
            *args: Positional arguments to pass to wrapped_fn
            **log_kwargs: Additional keyword arguments for request logging

        Returns:
            The result from wrapped_fn

        Raises:
            Exception: Re-raises any exception from wrapped_fn after logging
        """
        start_time = log_proxy_request(
            self._logger, self._transport, method, self._system_logger, **log_kwargs
        )
        try:
            result = await wrapped_fn(*args)
            log_backend_response(self._logger, self._transport, method, start_time, result)
            return result
        except Exception as e:
            log_backend_error(self._logger, self._transport, method, start_time, e)
            raise

    def _emit_connection_error(self, error: Exception) -> None:
        """Emit SSE event for backend connection failure.

        This catches connection errors that bypass middleware (e.g., during
        get_tools() which runs before tool call middleware).

        Args:
            error: The connection exception.
        """
        from mcp_acp.manager.state import SSEEventType, get_global_proxy_state

        # Log to system logger
        self._system_logger.error(
            {
                "event": "backend_disconnected",
                "message": "Backend connection lost",
                "error_type": type(error).__name__,
                "error": str(error)[:200],
                "transport": self._transport,
            }
        )

        # Emit SSE event if proxy state is available
        proxy_state = get_global_proxy_state()
        if proxy_state is not None:
            proxy_state.mark_backend_disconnected()
            proxy_state.emit_system_event(
                SSEEventType.BACKEND_DISCONNECTED,
                severity="error",
                message="Backend connection lost",
                error_type=type(error).__name__,
            )

    def _emit_connection_success(self) -> None:
        """Check for reconnection and emit SSE event if recovering from disconnect.

        Called after successful connection. If we were previously disconnected,
        emits BACKEND_RECONNECTED event.
        """
        from mcp_acp.manager.state import get_global_proxy_state

        proxy_state = get_global_proxy_state()
        if proxy_state is not None:
            # mark_backend_success() emits BACKEND_RECONNECTED if recovering
            proxy_state.mark_backend_success()

    # ==================== MCP Method Wrappers ====================
    # FastMCP proxy managers call the _mcp variants, not the regular methods

    async def call_tool_mcp(
        self,
        name: str,
        arguments: dict[str, Any],
        progress_handler: ProgressHandler | None = None,
        timeout: timedelta | float | int | None = None,
        meta: dict[str, Any] | None = None,
    ) -> mcp.types.CallToolResult:
        """Call a tool on the backend server with logging (MCP version).

        Logs the request/response to backend_wire.jsonl.
        Tool context is set by ContextMiddleware (outermost) for audit logging.

        Args:
            name: Name of the tool to call.
            arguments: Tool arguments as a dictionary.
            progress_handler: Optional callback for progress updates.
            timeout: Optional timeout for the call.
            meta: Optional metadata for the call.

        Returns:
            CallToolResult from the backend server.

        Raises:
            Exception: Re-raises any exception from the backend after logging.
        """
        start_time = log_proxy_request(
            self._logger,
            self._transport,
            "tools/call",
            self._system_logger,
            tool_name=name,
            arguments=arguments,
        )
        try:
            if self._is_wrapper:
                result = await self._client.call_tool_mcp(name, arguments, progress_handler, timeout, meta)  # type: ignore
            else:
                result = await super().call_tool_mcp(name, arguments, progress_handler, timeout, meta)
            log_backend_response(self._logger, self._transport, "tools/call", start_time, result)
            return result
        except Exception as e:
            log_backend_error(self._logger, self._transport, "tools/call", start_time, e)
            raise

    async def list_tools_mcp(self) -> mcp.types.ListToolsResult:
        """List available tools from the backend server with logging (MCP version)."""
        fn = self._client.list_tools_mcp if self._is_wrapper else super().list_tools_mcp  # type: ignore[union-attr]
        return await self._wrap_call("tools/list", fn)  # type: ignore[no-any-return]

    async def ping(self) -> None:
        """Send a ping to the backend server with logging."""
        fn = self._client.ping if self._is_wrapper else super().ping  # type: ignore[union-attr]
        return await self._wrap_call("ping", fn)  # type: ignore[no-any-return]

    async def read_resource_mcp(
        self, uri: AnyUrl | str, meta: dict[str, Any] | None = None
    ) -> mcp.types.ReadResourceResult:
        """Read a resource from the backend server with logging (MCP version)."""
        fn = self._client.read_resource_mcp if self._is_wrapper else super().read_resource_mcp  # type: ignore[union-attr]
        return await self._wrap_call("resources/read", fn, uri, meta, uri=str(uri))  # type: ignore[no-any-return]

    async def list_resources_mcp(self) -> mcp.types.ListResourcesResult:
        """List available resources from the backend server with logging (MCP version)."""
        fn = self._client.list_resources_mcp if self._is_wrapper else super().list_resources_mcp  # type: ignore[union-attr]
        return await self._wrap_call("resources/list", fn)  # type: ignore[no-any-return]

    async def list_resource_templates_mcp(self) -> mcp.types.ListResourceTemplatesResult:
        """List resource templates from the backend server with logging (MCP version)."""
        fn = (
            self._client.list_resource_templates_mcp  # type: ignore[union-attr]
            if self._is_wrapper
            else super().list_resource_templates_mcp
        )
        return await self._wrap_call("resources/templates/list", fn)  # type: ignore[no-any-return]

    async def get_prompt_mcp(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        meta: dict[str, Any] | None = None,
    ) -> mcp.types.GetPromptResult:
        """Get a prompt from the backend server with logging (MCP version)."""
        fn = self._client.get_prompt_mcp if self._is_wrapper else super().get_prompt_mcp  # type: ignore[union-attr]
        return await self._wrap_call(  # type: ignore[no-any-return]
            "prompts/get",
            fn,
            name,
            arguments,
            meta,
            prompt_name=name,
            arguments=arguments,
        )

    async def list_prompts_mcp(self) -> mcp.types.ListPromptsResult:
        """List available prompts from the backend server with logging (MCP version)."""
        fn = self._client.list_prompts_mcp if self._is_wrapper else super().list_prompts_mcp  # type: ignore[union-attr]
        return await self._wrap_call("prompts/list", fn)  # type: ignore[no-any-return]

    async def complete_mcp(
        self,
        ref: mcp.types.ResourceTemplateReference | mcp.types.PromptReference,
        argument: dict[str, str],
        context_arguments: dict[str, Any] | None = None,
    ) -> mcp.types.CompleteResult:
        """Request completion suggestions from the backend server with logging (MCP version)."""
        fn = self._client.complete_mcp if self._is_wrapper else super().complete_mcp  # type: ignore[union-attr]
        return await self._wrap_call(  # type: ignore[no-any-return]
            "completion/complete",
            fn,
            ref,
            argument,
            context_arguments,
            ref_type=type(ref).__name__,
        )

    # ==================== Other Methods ====================

    async def send_roots_list_changed(self) -> None:
        """Notify backend that roots list changed with logging."""
        fn = self._client.send_roots_list_changed if self._is_wrapper else super().send_roots_list_changed  # type: ignore[union-attr]
        return await self._wrap_call(  # type: ignore[no-any-return]
            "notifications/roots/list_changed",
            fn,
        )

    async def set_logging_level(self, level: mcp.types.LoggingLevel) -> None:
        """Set logging level on backend server with logging."""
        fn = self._client.set_logging_level if self._is_wrapper else super().set_logging_level  # type: ignore[union-attr]
        return await self._wrap_call(  # type: ignore[no-any-return]
            "logging/setLevel",
            fn,
            level,
            level=level,
        )

    # ==================== Context Manager ====================

    async def __aenter__(self) -> "LoggingProxyClient":
        """Async context manager entry - log initialize handshake.

        IMPORTANT: Why we log initialize here (retroactively) instead of "when it happens":

        FastMCP's ProxyClient handles the MCP initialize handshake INTERNALLY during
        __aenter__() - it's not exposed as a method we can wrap like call_tool() or
        list_tools(). The initialize happens inside self._wrapped_client.__aenter__()
        and we only get access to the result afterwards via initialize_result attribute.

        This means we must log initialize retroactively after the connection is established,
        rather than intercepting the actual request/response like we do for other methods.

        Why we use class-level session tracking (_logged_sessions_global):

        FastMCP uses .new() to create multiple client instances for session isolation.
        Each instance gets its own initialize_result object (different object IDs), but
        they all belong to the same session (same session_id). Without global tracking
        by session_id, each instance would log initialize separately, creating duplicates.

        By tracking session_id globally, we ensure initialize is logged exactly once per
        session, regardless of how many client instances are created.

        Returns:
            LoggingProxyClient: The logging client instance.

        Raises:
            Exception: If connection fails.
        """
        # Enter context manager - catch connection failures for SSE notification
        try:
            if self._is_wrapper:
                await self._client.__aenter__()  # type: ignore[union-attr]
            else:
                await super().__aenter__()
        except Exception as e:
            # Emit SSE event for backend connection failure
            # This catches errors that bypass middleware (e.g., get_tools() before tool call)
            self._emit_connection_error(e)
            raise

        # Connection succeeded - check for reconnection (emits BACKEND_RECONNECTED if recovering)
        self._emit_connection_success()

        # Log initialize response (once per session, globally)
        try:
            init_result_obj = self._client if self._is_wrapper else self
            if hasattr(init_result_obj, "initialize_result") and init_result_obj.initialize_result:
                init_result = init_result_obj.initialize_result

                # Get context IDs
                request_id = get_request_id()
                session_id = get_session_id()

                # For tests where session_id isn't set, use object id as fallback
                if not session_id:
                    session_id = f"test-{id(init_result)}"

                # Only log if we haven't logged initialize for this session yet
                if session_id not in LoggingProxyClient._logged_sessions_global:
                    LoggingProxyClient._logged_sessions_global.add(session_id)

                    # Extract metadata
                    metadata = extract_initialize_metadata(init_result, self._system_logger)

                    # Create Pydantic event (use original session_id from context, which may be None)
                    event = BackendResponseEvent(
                        transport=self._transport,
                        method="initialize",
                        duration_ms=0.0,  # Duration not available for auto-initialize
                        request_id=request_id,
                        session_id=get_session_id(),  # Original from context (may be None for tests)
                        **metadata,
                    )

                    self._logger.info(event.model_dump(exclude_none=True))

        except Exception as e:
            # Log failure to system logger but don't break connection
            # This is debug logging, not audit - failure is not security-critical
            self._system_logger.warning(
                {
                    "event": "initialize_logging_failed",
                    "error": str(e),
                    "error_type": type(e).__name__,
                    "message": "Failed to log initialize handshake - debug trail incomplete",
                }
            )

        return self

    async def __aexit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Any,
    ) -> None:
        """Async context manager exit."""
        if self._is_wrapper:
            return await self._client.__aexit__(exc_type, exc_val, exc_tb)  # type: ignore[union-attr, no-any-return]
        else:
            return await super().__aexit__(exc_type, exc_val, exc_tb)  # type: ignore[no-any-return]

    # ==================== Helper Methods ====================

    def new(self) -> "LoggingProxyClient":
        """Create a new logging client instance for session isolation.

        This is called by FastMCP.as_proxy() for session isolation.
        Returns a new LoggingProxyClient that wraps the result of super().new().

        Returns:
            LoggingProxyClient: New logging client wrapping a fresh ProxyClient.
        """
        # Get a new instance from parent
        new_client = super().new()

        # If super().new() already returns LoggingProxyClient (due to type(self) in parent),
        # just return it directly - no need to wrap
        if isinstance(new_client, LoggingProxyClient):
            return new_client

        # Otherwise wrap plain ProxyClient in LoggingProxyClient
        return LoggingProxyClient(
            new_client,  # type: ignore[arg-type]
            self._logger,
            self._transport,
            self._system_logger,
            _is_wrapper=True,
        )

    def __getattr__(self, name: str) -> Any:
        """Forward unknown attributes to wrapped client in wrapper mode."""
        # Use __dict__ to avoid infinite recursion when checking _is_wrapper
        if self.__dict__.get("_is_wrapper") and self.__dict__.get("_client"):
            return getattr(self.__dict__["_client"], name)
        raise AttributeError(f"'{type(self).__name__}' object has no attribute '{name}'")


def create_logging_proxy_client(
    transport: ClientTransport,
    log_path: Path,
    transport_type: str = "stdio",
    debug_enabled: bool = True,
) -> LoggingProxyClient:
    """Create a LoggingProxyClient for Proxy↔Backend wire-level debugging.

    This sets up the backend logger and creates a ProxyClient with logging enabled
    for all method calls, arguments, responses, and errors using Pydantic models.

    Security-focused logging extracts:
    - Tool names and operation types
    - File paths and metadata (size, extension, mime type)
    - Server information (name, version, capabilities)
    - NO file contents or hashes

    Args:
        transport: Transport object (StdioTransport, HttpTransport, etc.)
        log_path: Path to the backend wire log file (from config via get_backend_log_path()).
        transport_type: Transport type being used ("stdio" or "streamablehttp").
        debug_enabled: Whether debug wire logging is enabled. If False, logs are discarded.

    Returns:
        LoggingProxyClient: Client with logging for all backend communication.
    """
    if debug_enabled:
        logger = setup_backend_wire_logger(log_path)
    else:
        # Create a logger that discards all messages
        logger = logging.getLogger(f"{APP_NAME}.debug.backend.null")
        logger.handlers.clear()
        logger.addHandler(logging.NullHandler())
        logger.propagate = False

    return LoggingProxyClient(transport, logger, transport_type)
