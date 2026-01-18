"""Audit logging middleware for MCP operations.

This module provides security audit logging for all MCP operations.
Unlike debug wire logs (two events: before/after), audit logs use a
single-event pattern per operation for atomic records and query simplicity.

Audit logs are ALWAYS enabled (not controlled by log_level).

Logs are written to <log_dir>/mcp_acp_logs/audit/operations.jsonl.
"""

import logging

__all__ = [
    "AuditLoggingMiddleware",
    "create_audit_logging_middleware",
]
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:
    from mcp_acp.security.integrity.integrity_state import IntegrityStateManager

from fastmcp.server.middleware import Middleware
from fastmcp.server.middleware.middleware import MiddlewareContext

from mcp.shared.exceptions import McpError
from mcp.types import ErrorData, INTERNAL_ERROR

from mcp_acp.telemetry.models.audit import (
    ArgumentsSummary,
    DurationInfo,
    OperationEvent,
    ResponseSummary,
    SubjectIdentity,
)
from mcp_acp.security.identity import IdentityProvider
from mcp_acp.security.shutdown import ShutdownCoordinator
from mcp_acp.security.integrity.emergency_audit import log_with_fallback
from mcp_acp.telemetry.system.system_logger import (
    get_system_logger,
    is_transport_error,
    log_backend_disconnect,
)
from mcp_acp.utils.logging.extractors import extract_client_info, extract_tool_metadata
from mcp_acp.utils.logging.logger_setup import setup_failclosed_audit_logger
from mcp_acp.utils.logging.logging_context import (
    get_request_id,
    get_session_id,
    get_tool_arguments,
    get_tool_name,
)
from mcp_acp.utils.logging.logging_helpers import (
    clean_backend_error,
    create_arguments_summary,
    create_response_summary,
    serialize_audit_event,
)

_system_logger = get_system_logger()


class AuditLoggingMiddleware(Middleware):
    """Security audit logging middleware for MCP operations.

    Logs a single OperationEvent per MCP operation after completion.
    Always enabled - audit trail cannot be disabled.

    Log events capture:
    - Who: SubjectIdentity (local username, cached at init)
    - What: method, tool_name, arguments summary
    - When: timestamp (added by ISO8601Formatter)
    - Outcome: status (Success/Failure), error_code (MCP/JSON-RPC), duration_ms
    - Context: session_id, request_id, backend_id, transport, config_version
    """

    def __init__(
        self,
        *,
        logger: logging.Logger,
        shutdown_coordinator: ShutdownCoordinator,
        backend_id: str,
        identity_provider: IdentityProvider,
        transport: str | None = None,
        config_version: str | None = None,
    ) -> None:
        """Initialize audit logging middleware.

        Args:
            logger: Logger instance for audit logs.
            shutdown_coordinator: Coordinator to check for shutdown state.
            backend_id: Backend server identifier (from config.backend.server_name).
            identity_provider: Provider for user identity (local or OIDC).
            transport: Backend transport type ("stdio" or "streamablehttp").
            config_version: Current config version (from config history).
        """
        self.logger = logger
        self.shutdown_coordinator = shutdown_coordinator
        self.backend_id = backend_id
        self.transport = transport
        self.config_version = config_version
        # Identity provider - get_identity() is async, so we fetch on first request
        self._identity_provider = identity_provider
        self._subject: SubjectIdentity | None = None
        # Client ID extracted from initialize request, cached for all subsequent requests
        self._client_id: str | None = None

    def _extract_client_id(self, context: MiddlewareContext[Any]) -> None:
        """Extract and cache client ID from initialize request.

        Called on every request, but only extracts from initialize.
        Once cached, subsequent calls are no-ops.

        Args:
            context: Middleware context.
        """
        if self._client_id is not None:
            return  # Already cached

        client_info = extract_client_info(context)
        if client_info.name:
            self._client_id = client_info.name

    def _extract_tool_call_metadata(self, request_id: str | None) -> dict[str, Any]:
        """Extract tool metadata from context variables.

        Tool context is set by ContextMiddleware for tools/call requests,
        making it available for all requests including denied ones.

        Args:
            request_id: Request ID for dict-based lookup (works across async context boundaries).

        Returns:
            Dict with tool_name, file_path, file_extension, source_path, dest_path.
            Empty dict if no tool context is set.
        """
        tool_name = get_tool_name(request_id)
        arguments = get_tool_arguments(request_id)

        if not tool_name:
            return {}

        arguments = arguments or {}

        # Use shared extractor for consistent metadata extraction
        metadata = extract_tool_metadata(tool_name, arguments)

        return {
            "tool_name": metadata.get("tool_name"),
            "file_path": metadata.get("file_path"),
            "file_extension": metadata.get("file_extension"),
            "source_path": metadata.get("source_path"),
            "dest_path": metadata.get("dest_path"),
        }

    def _create_arguments_summary(self, context: MiddlewareContext[Any]) -> ArgumentsSummary | None:
        """Create summary of request arguments without sensitive data.

        Args:
            context: Middleware context.

        Returns:
            ArgumentsSummary with hash and length, or None.
        """
        return create_arguments_summary(context.message)

    async def on_message(
        self,
        context: MiddlewareContext[Any],
        call_next: Any,
    ) -> Any:
        """Process message and log audit event after completion.

        Overrides FastMCP's Middleware.on_message hook to implement
        single-event pattern: logs once after response or error.

        Note: For initialize requests, session_id and request_id are not available
        because the session doesn't exist yet (it's created lazily when the backend
        connection is established on the first real request). This is expected.

        Args:
            context: Middleware context containing request.
            call_next: Next middleware in chain.

        Returns:
            Response from downstream middleware/handler.

        Raises:
            McpError: If proxy is shutting down due to security failure.
        """
        # Reject requests if we're shutting down
        if self.shutdown_coordinator.is_shutting_down:
            raise McpError(
                ErrorData(
                    code=INTERNAL_ERROR,
                    message="Proxy shutting down due to security failure",
                )
            )

        # Fetch identity on first request (async, so can't be done in __init__)
        if self._subject is None:
            self._subject = await self._identity_provider.get_identity()

        # Extract client_id from initialize request (cached for subsequent requests)
        self._extract_client_id(context)

        start_time = time.perf_counter()
        status = "Success"
        error_message = None
        error_code = None
        response_summary: ResponseSummary | None = None

        try:
            # Process request through chain
            result = await call_next(context)

            # Capture response metadata for audit trail
            response_summary = create_response_summary(result)

            return result

        except Exception as e:
            status = "Failure"
            error_message = str(e)
            # Extract MCP/JSON-RPC error code if available
            if hasattr(e, "code"):
                error_code = e.code
            # Log backend disconnect to system.jsonl if transport error
            if is_transport_error(e):
                # Clean error message for audit log (raw errors go to debug logs)
                error_message = clean_backend_error(error_message)
                log_backend_disconnect(
                    self.transport or "unknown",
                    e,
                    context.method or "unknown",
                    get_session_id(),
                )
            raise

        finally:
            # Calculate duration
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

            # Get correlation IDs (set by ContextMiddleware, the outermost middleware)
            # Skip for initialize - session doesn't exist yet
            request_id: str | None = None
            session_id: str | None = None

            if context.method != "initialize":
                request_id = get_request_id()
                session_id = get_session_id()

            # Extract tool metadata (tool_name, file_path, file_extension)
            # Tool context is set by ContextMiddleware for tools/call requests
            tool_metadata = self._extract_tool_call_metadata(request_id)

            # Create audit event
            event = OperationEvent(
                session_id=session_id or "unknown",
                request_id=request_id or "unknown",
                method=context.method or "unknown",
                status=status,
                error_code=error_code,
                message=error_message,
                subject=self._subject,
                client_id=self._client_id,
                backend_id=self.backend_id,
                transport=self.transport,
                tool_name=tool_metadata.get("tool_name"),
                file_path=tool_metadata.get("file_path"),
                file_extension=tool_metadata.get("file_extension"),
                source_path=tool_metadata.get("source_path"),
                dest_path=tool_metadata.get("dest_path"),
                arguments_summary=self._create_arguments_summary(context),
                config_version=self.config_version,
                duration=DurationInfo(duration_ms=duration_ms),
                response_summary=response_summary,
            )

            # Log audit event with fallback chain
            # If primary fails, logs to system.jsonl then emergency_audit.jsonl
            event_data = serialize_audit_event(event)
            success, failure_reason = log_with_fallback(
                primary_logger=self.logger,
                system_logger=_system_logger,
                event_data=event_data,
                event_type="operation",
                source_file="operations.jsonl",
            )

            # If primary audit failed, raise error to client before shutdown
            if not success:
                raise McpError(
                    ErrorData(
                        code=INTERNAL_ERROR,
                        message="Audit log failure - operation logged to fallback, proxy shutting down",
                    )
                )

            # Note: Tool context is cleared by ContextMiddleware (outermost) in its finally block


def create_audit_logging_middleware(
    log_path: Path,
    shutdown_coordinator: ShutdownCoordinator,
    shutdown_callback: Callable[[str], None],
    backend_id: str,
    identity_provider: IdentityProvider,
    transport: str | None = None,
    config_version: str | None = None,
    state_manager: "IntegrityStateManager | None" = None,
    log_dir: Path | None = None,
) -> AuditLoggingMiddleware:
    """Create middleware for audit logging of MCP operations.

    Audit logging is ALWAYS enabled - the security audit trail cannot
    be disabled via configuration. Uses fail-closed handler that triggers
    shutdown if audit log integrity is compromised.

    Args:
        log_path: Path to operations.jsonl (from get_audit_log_path()).
        shutdown_coordinator: Coordinator to check for shutdown state.
        shutdown_callback: Called if audit log integrity check fails.
        backend_id: Backend server identifier (config.backend.server_name).
        identity_provider: Provider for user identity (local or OIDC).
        transport: Backend transport type ("stdio" or "streamablehttp").
        config_version: Current config version (from log_config_loaded).
        state_manager: Optional IntegrityStateManager for hash chain support.
        log_dir: Base log directory for computing relative file keys.

    Returns:
        AuditLoggingMiddleware: Configured middleware for the proxy.
    """
    logger = setup_failclosed_audit_logger(
        "mcp-acp.audit.operations",
        log_path,
        shutdown_callback=shutdown_callback,
        log_level=logging.INFO,
        state_manager=state_manager,
        log_dir=log_dir,
    )

    return AuditLoggingMiddleware(
        logger=logger,
        shutdown_coordinator=shutdown_coordinator,
        backend_id=backend_id,
        identity_provider=identity_provider,
        transport=transport,
        config_version=config_version,
    )
