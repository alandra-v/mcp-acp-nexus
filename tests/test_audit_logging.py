"""Unit tests for audit logging middleware.

Tests the AuditLoggingMiddleware and related components using the AAA pattern
(Arrange-Act-Assert). Tests verify behavior through actual log output to temp files.
"""

import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from pydantic import BaseModel

from mcp_acp.telemetry.audit.operation_logger import (
    AuditLoggingMiddleware,
    create_audit_logging_middleware,
)
from mcp_acp.telemetry.models.audit import (
    ArgumentsSummary,
    DurationInfo,
    OperationEvent,
    SubjectIdentity,
)
from mcp_acp.security.identity import (
    IdentityProvider,
    LocalIdentityProvider,
)
from mcp_acp.security.shutdown import ShutdownCoordinator
from mcp_acp.security.integrity.audit_monitor import AuditHealthMonitor
from mcp_acp.telemetry.system.system_logger import get_system_logger
from mcp_acp.utils.logging.logging_context import (
    clear_context,
    clear_tool_context,
    set_request_id,
    set_session_id,
    set_tool_context,
)
from mcp_acp.utils.logging.logging_helpers import hash_sensitive_id


# ============================================================================
# Minimal Mock Objects (mimicking FastMCP interfaces)
# ============================================================================


class MockParams(BaseModel):
    """Mock MCP request params."""

    name: str | None = None
    arguments: dict[str, Any] | None = None


class MockMessage:
    """Mock MCP message with params."""

    def __init__(self, params: MockParams | None = None):
        self.params = params


class MockFastMCPContext:
    """Mock FastMCP context with request/session IDs."""

    def __init__(self, request_id: str | None = None, session_id: str | None = None):
        self.request_id = request_id
        self.session_id = session_id


class MockMiddlewareContext:
    """Mock MiddlewareContext from FastMCP."""

    def __init__(
        self,
        method: str | None = None,
        message: MockMessage | None = None,
        fastmcp_context: MockFastMCPContext | None = None,
    ):
        self.method = method
        self.message = message or MockMessage()
        self.fastmcp_context = fastmcp_context


class MockExceptionWithCode(Exception):
    """Exception with MCP/JSON-RPC error code."""

    def __init__(self, message: str, code: int):
        super().__init__(message)
        self.code = code


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def temp_log_file():
    """Create a temporary log file in a subdirectory for testing.

    We use a subdirectory because the logger setup tries to chmod the parent
    directory, and we can't chmod system temp directories like /tmp.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        log_path = Path(tmpdir) / "audit" / "operations.jsonl"
        yield log_path
        # Cleanup handled by TemporaryDirectory context manager


@pytest.fixture
def identity_provider() -> IdentityProvider:
    """Create a local identity provider for testing."""
    return LocalIdentityProvider()


@pytest.fixture
def shutdown_coordinator(temp_log_file: Path) -> ShutdownCoordinator:
    """Create a shutdown coordinator for testing."""
    return ShutdownCoordinator(temp_log_file.parent, get_system_logger())


@pytest.fixture
def shutdown_callback() -> callable:
    """Create a no-op shutdown callback for testing."""

    def noop_callback(reason: str) -> None:
        pass  # No-op for tests

    return noop_callback


@pytest.fixture
def audit_middleware(
    temp_log_file: Path,
    identity_provider: IdentityProvider,
    shutdown_coordinator: ShutdownCoordinator,
    shutdown_callback: callable,
) -> AuditLoggingMiddleware:
    """Create audit middleware with temp file logger."""
    return create_audit_logging_middleware(
        log_path=temp_log_file,
        shutdown_coordinator=shutdown_coordinator,
        shutdown_callback=shutdown_callback,
        backend_id="test-backend",
        identity_provider=identity_provider,
        config_version="v1",
    )


def read_log_entries(log_path: Path) -> list[dict[str, Any]]:
    """Read and parse all JSONL entries from log file."""
    if not log_path.exists():
        return []
    entries = []
    with open(log_path) as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries


def create_test_audit_middleware(
    log_path: Path,
    identity_provider: IdentityProvider,
    backend_id: str = "test",
    config_version: str | None = None,
) -> AuditLoggingMiddleware:
    """Helper to create audit middleware with test defaults for new params."""
    shutdown_coord = ShutdownCoordinator(log_path.parent, get_system_logger())
    return create_audit_logging_middleware(
        log_path=log_path,
        shutdown_coordinator=shutdown_coord,
        shutdown_callback=lambda reason: None,  # No-op for tests
        backend_id=backend_id,
        identity_provider=identity_provider,
        config_version=config_version,
    )


# ============================================================================
# Tests: AuditLoggingMiddleware.process_request()
# ============================================================================


class TestProcessRequestSuccess:
    """Tests for successful request processing."""

    async def test_logs_successful_operation(
        self, audit_middleware: AuditLoggingMiddleware, temp_log_file: Path
    ):
        """Given a successful operation, logs event with status Success."""
        # Arrange
        fastmcp_ctx = MockFastMCPContext(request_id="req-123", session_id="sess-456")
        context = MockMiddlewareContext(method="tools/list", fastmcp_context=fastmcp_ctx)

        # Simulate ContextMiddleware setting context vars
        set_request_id("req-123")
        set_session_id("sess-456")

        async def call_next(_ctx):
            return {"tools": []}

        # Act
        result = await audit_middleware.on_message(context, call_next)

        # Assert
        assert result == {"tools": []}
        entries = read_log_entries(temp_log_file)
        assert len(entries) == 1
        entry = entries[0]
        assert entry["status"] == "Success"
        assert entry["method"] == "tools/list"
        assert entry["request_id"] == "req-123"
        assert entry["session_id"] == "sess-456"
        assert entry["backend_id"] == "test-backend"
        assert entry["config_version"] == "v1"
        assert "error_code" not in entry  # excluded when None
        assert "message" not in entry  # excluded when None

    async def test_logs_tools_call_with_tool_name(
        self, audit_middleware: AuditLoggingMiddleware, temp_log_file: Path
    ):
        """Given tools/call request with tool context set, logs tool_name and file metadata."""
        # Arrange
        params = MockParams(name="read_file", arguments={"path": "/tmp/test.txt"})
        message = MockMessage(params=params)
        fastmcp_ctx = MockFastMCPContext(request_id="req-789", session_id="sess-abc")
        context = MockMiddlewareContext(method="tools/call", message=message, fastmcp_context=fastmcp_ctx)

        async def call_next(_ctx):
            # Simulate what LoggingProxyClient.call_tool_mcp() does
            set_tool_context("read_file", {"path": "/tmp/test.txt"})
            return {"content": "file contents"}

        try:
            # Act
            await audit_middleware.on_message(context, call_next)

            # Assert
            entries = read_log_entries(temp_log_file)
            assert len(entries) == 1
            entry = entries[0]
            assert entry["tool_name"] == "read_file"
            # Path may be resolved (e.g., /tmp -> /private/tmp on macOS)
            assert entry["file_path"].endswith("/tmp/test.txt") or entry["file_path"] == "/tmp/test.txt"
            assert entry["file_extension"] == ".txt"
            assert entry["arguments_summary"]["redacted"] is True
            assert "body_hash" in entry["arguments_summary"]
            assert (
                entry["arguments_summary"]["body_hash"].startswith("sha256:")
                or len(entry["arguments_summary"]["body_hash"]) == 64
            )
        finally:
            clear_context()

    async def test_measures_positive_duration(
        self, audit_middleware: AuditLoggingMiddleware, temp_log_file: Path
    ):
        """Given an operation that takes time, logs positive duration_ms."""
        # Arrange
        fastmcp_ctx = MockFastMCPContext(request_id="req-dur", session_id="sess-dur")
        context = MockMiddlewareContext(method="ping", fastmcp_context=fastmcp_ctx)

        async def call_next(_ctx):
            time.sleep(0.01)  # 10ms delay
            return None

        # Act
        await audit_middleware.on_message(context, call_next)

        # Assert
        entries = read_log_entries(temp_log_file)
        assert len(entries) == 1
        duration_ms = entries[0]["duration"]["duration_ms"]
        assert duration_ms >= 10.0  # At least 10ms

    async def test_logs_response_summary_for_dict_response(
        self, audit_middleware: AuditLoggingMiddleware, temp_log_file: Path
    ):
        """Given a dict response, logs response_summary with size and hash."""
        # Arrange
        fastmcp_ctx = MockFastMCPContext(request_id="req-resp", session_id="sess-resp")
        context = MockMiddlewareContext(method="tools/call", fastmcp_context=fastmcp_ctx)

        async def call_next(_ctx):
            return {"content": "file contents", "status": "ok"}

        # Act
        await audit_middleware.on_message(context, call_next)

        # Assert
        entries = read_log_entries(temp_log_file)
        assert len(entries) == 1
        assert "response_summary" in entries[0]
        resp_summary = entries[0]["response_summary"]
        assert resp_summary["size_bytes"] > 0
        assert len(resp_summary["body_hash"]) == 64  # SHA256 hex length

    async def test_logs_response_summary_for_list_response(
        self, audit_middleware: AuditLoggingMiddleware, temp_log_file: Path
    ):
        """Given a list response, logs response_summary."""
        # Arrange
        fastmcp_ctx = MockFastMCPContext(request_id="req-list", session_id="sess-list")
        context = MockMiddlewareContext(method="tools/list", fastmcp_context=fastmcp_ctx)

        async def call_next(_ctx):
            return {"tools": [{"name": "tool1"}, {"name": "tool2"}]}

        # Act
        await audit_middleware.on_message(context, call_next)

        # Assert
        entries = read_log_entries(temp_log_file)
        assert len(entries) == 1
        assert "response_summary" in entries[0]
        assert entries[0]["response_summary"]["size_bytes"] > 0

    async def test_no_response_summary_for_none_response(
        self, audit_middleware: AuditLoggingMiddleware, temp_log_file: Path
    ):
        """Given None response, response_summary is excluded."""
        # Arrange
        fastmcp_ctx = MockFastMCPContext(request_id="req-none-resp", session_id="sess-none-resp")
        context = MockMiddlewareContext(method="ping", fastmcp_context=fastmcp_ctx)

        async def call_next(_ctx):
            return None

        # Act
        await audit_middleware.on_message(context, call_next)

        # Assert
        entries = read_log_entries(temp_log_file)
        assert len(entries) == 1
        assert "response_summary" not in entries[0]

    async def test_same_response_produces_same_hash(
        self, audit_middleware: AuditLoggingMiddleware, temp_log_file: Path
    ):
        """Given identical responses, produces identical hash."""
        # Arrange
        fastmcp_ctx = MockFastMCPContext(request_id="req-hash1", session_id="sess-hash")
        context1 = MockMiddlewareContext(method="test1", fastmcp_context=fastmcp_ctx)
        context2 = MockMiddlewareContext(method="test2", fastmcp_context=fastmcp_ctx)

        response = {"key": "value", "count": 42}

        async def call_next(_ctx):
            return response

        # Act
        await audit_middleware.on_message(context1, call_next)
        await audit_middleware.on_message(context2, call_next)

        # Assert
        entries = read_log_entries(temp_log_file)
        assert len(entries) == 2
        assert entries[0]["response_summary"]["body_hash"] == entries[1]["response_summary"]["body_hash"]


class TestProcessRequestFailure:
    """Tests for failed request processing."""

    async def test_logs_failure_status_on_exception(
        self, audit_middleware: AuditLoggingMiddleware, temp_log_file: Path
    ):
        """Given an exception, logs status Failure and re-raises."""
        # Arrange
        fastmcp_ctx = MockFastMCPContext(request_id="req-fail", session_id="sess-fail")
        context = MockMiddlewareContext(method="tools/call", fastmcp_context=fastmcp_ctx)

        async def call_next(_ctx):
            raise ValueError("Something went wrong")

        # Act & Assert
        with pytest.raises(ValueError, match="Something went wrong"):
            await audit_middleware.on_message(context, call_next)

        entries = read_log_entries(temp_log_file)
        assert len(entries) == 1
        entry = entries[0]
        assert entry["status"] == "Failure"
        assert entry["message"] == "Something went wrong"

    async def test_extracts_error_code_from_exception(
        self, audit_middleware: AuditLoggingMiddleware, temp_log_file: Path
    ):
        """Given exception with .code attribute, logs error_code."""
        # Arrange
        fastmcp_ctx = MockFastMCPContext(request_id="req-code", session_id="sess-code")
        context = MockMiddlewareContext(method="tools/call", fastmcp_context=fastmcp_ctx)

        async def call_next(_ctx):
            raise MockExceptionWithCode("Parse error", code=-32700)

        # Act
        with pytest.raises(MockExceptionWithCode):
            await audit_middleware.on_message(context, call_next)

        # Assert
        entries = read_log_entries(temp_log_file)
        assert len(entries) == 1
        assert entries[0]["error_code"] == -32700

    async def test_no_error_code_for_regular_exception(
        self, audit_middleware: AuditLoggingMiddleware, temp_log_file: Path
    ):
        """Given exception without .code, error_code is not in output."""
        # Arrange
        fastmcp_ctx = MockFastMCPContext(request_id="req-nocode", session_id="sess-nocode")
        context = MockMiddlewareContext(method="tools/call", fastmcp_context=fastmcp_ctx)

        async def call_next(_ctx):
            raise RuntimeError("Generic error")

        # Act
        with pytest.raises(RuntimeError):
            await audit_middleware.on_message(context, call_next)

        # Assert
        entries = read_log_entries(temp_log_file)
        assert len(entries) == 1
        assert "error_code" not in entries[0]


class TestProcessRequestEdgeCases:
    """Tests for edge cases in request processing."""

    async def test_handles_none_method(self, audit_middleware: AuditLoggingMiddleware, temp_log_file: Path):
        """Given None method, logs 'unknown'."""
        # Arrange
        fastmcp_ctx = MockFastMCPContext(request_id="req-none", session_id="sess-none")
        context = MockMiddlewareContext(method=None, fastmcp_context=fastmcp_ctx)

        async def call_next(_ctx):
            return {}

        # Act
        await audit_middleware.on_message(context, call_next)

        # Assert
        entries = read_log_entries(temp_log_file)
        assert entries[0]["method"] == "unknown"

    async def test_handles_missing_correlation_ids(
        self, audit_middleware: AuditLoggingMiddleware, temp_log_file: Path
    ):
        """Given no fastmcp_context, logs 'unknown' for correlation IDs."""
        # Arrange
        context = MockMiddlewareContext(method="ping", fastmcp_context=None)

        async def call_next(_ctx):
            return None

        # Act
        await audit_middleware.on_message(context, call_next)

        # Assert
        entries = read_log_entries(temp_log_file)
        assert entries[0]["request_id"] == "unknown"
        assert entries[0]["session_id"] == "unknown"


# ============================================================================
# Tests: LocalIdentityProvider
# ============================================================================


class TestLocalIdentityProvider:
    """Tests for LocalIdentityProvider identity extraction."""

    async def test_returns_current_user(self):
        """Given normal environment, returns getpass.getuser() username."""
        import getpass

        # Arrange & Act
        provider = LocalIdentityProvider()
        identity = await provider.get_identity()

        # Assert
        assert identity.subject_id == getpass.getuser()
        assert identity.subject_claims == {"auth_type": "local"}

    async def test_caches_identity(self):
        """Given provider, get_identity() returns same cached instance."""
        # Arrange
        provider = LocalIdentityProvider()

        # Act
        identity1 = await provider.get_identity()
        identity2 = await provider.get_identity()

        # Assert
        assert identity1 is identity2

    async def test_middleware_uses_identity_provider(
        self, temp_log_file: Path, identity_provider: IdentityProvider
    ):
        """Given middleware with provider, subject comes from provider after first request."""
        import getpass

        # Arrange
        middleware = create_test_audit_middleware(
            log_path=temp_log_file,
            identity_provider=identity_provider,
        )

        # Initially, subject is None (fetched lazily)
        assert middleware._subject is None

        # Act - make a request to trigger identity fetch
        context = MockMiddlewareContext(method="ping")

        async def call_next(_ctx):
            return None

        await middleware.on_message(context, call_next)

        # Assert - after request, subject is populated from identity provider
        assert middleware._subject.subject_id == getpass.getuser()
        assert middleware._subject.subject_claims == {"auth_type": "local"}


# ============================================================================
# Tests: _extract_client_id()
# ============================================================================


class MockClientInfo:
    """Mock MCP clientInfo object."""

    def __init__(self, name: str | None = None, version: str | None = None):
        self.name = name
        self.version = version


class MockInitializeParams:
    """Mock MCP initialize params with clientInfo."""

    def __init__(self, client_info: MockClientInfo | None = None):
        self.clientInfo = client_info


class TestExtractClientId:
    """Tests for client ID extraction and caching."""

    def test_extracts_client_id_from_initialize(
        self, temp_log_file: Path, identity_provider: IdentityProvider
    ):
        """Given initialize request with clientInfo, extracts client_id."""
        # Arrange
        middleware = create_test_audit_middleware(log_path=temp_log_file, identity_provider=identity_provider)
        client_info = MockClientInfo(name="Claude Desktop", version="1.0.0")
        params = MockInitializeParams(client_info=client_info)
        message = MockMessage(params=params)
        context = MockMiddlewareContext(method="initialize", message=message)

        # Act
        middleware._extract_client_id(context)

        # Assert
        assert middleware._client_id == "Claude Desktop"

    def test_caches_client_id_for_subsequent_requests(
        self, temp_log_file: Path, identity_provider: IdentityProvider
    ):
        """Given client_id already cached, doesn't overwrite."""
        # Arrange
        middleware = create_test_audit_middleware(log_path=temp_log_file, identity_provider=identity_provider)
        middleware._client_id = "First Client"

        # New initialize with different client
        client_info = MockClientInfo(name="Second Client")
        params = MockInitializeParams(client_info=client_info)
        message = MockMessage(params=params)
        context = MockMiddlewareContext(method="initialize", message=message)

        # Act
        middleware._extract_client_id(context)

        # Assert - should still be first client
        assert middleware._client_id == "First Client"

    def test_ignores_non_initialize_methods(self, temp_log_file: Path, identity_provider: IdentityProvider):
        """Given non-initialize method, doesn't extract client_id."""
        # Arrange
        middleware = create_test_audit_middleware(log_path=temp_log_file, identity_provider=identity_provider)
        context = MockMiddlewareContext(method="tools/call")

        # Act
        middleware._extract_client_id(context)

        # Assert
        assert middleware._client_id is None

    async def test_client_id_included_in_log_output(
        self, audit_middleware: AuditLoggingMiddleware, temp_log_file: Path
    ):
        """Given initialize request, client_id appears in log."""
        # Arrange
        client_info = MockClientInfo(name="MCP Inspector")
        params = MockInitializeParams(client_info=client_info)
        message = MockMessage(params=params)
        fastmcp_ctx = MockFastMCPContext(request_id="req-init", session_id="sess-init")
        context = MockMiddlewareContext(method="initialize", message=message, fastmcp_context=fastmcp_ctx)

        async def call_next(_ctx):
            return {"protocolVersion": "2024-11-05"}

        # Act
        await audit_middleware.on_message(context, call_next)

        # Assert
        entries = read_log_entries(temp_log_file)
        assert len(entries) == 1
        assert entries[0]["client_id"] == "MCP Inspector"

    async def test_client_id_persists_to_subsequent_requests(
        self, audit_middleware: AuditLoggingMiddleware, temp_log_file: Path
    ):
        """Given initialize followed by tools/call, both have client_id."""
        # Arrange - initialize first
        client_info = MockClientInfo(name="Claude Desktop")
        init_params = MockInitializeParams(client_info=client_info)
        init_message = MockMessage(params=init_params)
        fastmcp_ctx = MockFastMCPContext(request_id="req-1", session_id="sess-1")
        init_context = MockMiddlewareContext(
            method="initialize", message=init_message, fastmcp_context=fastmcp_ctx
        )

        async def call_next(_ctx):
            return {}

        # Act - initialize
        await audit_middleware.on_message(init_context, call_next)

        # Arrange - tools/call
        tool_context = MockMiddlewareContext(method="tools/call", fastmcp_context=fastmcp_ctx)

        # Act - tools/call
        await audit_middleware.on_message(tool_context, call_next)

        # Assert - both entries have client_id
        entries = read_log_entries(temp_log_file)
        assert len(entries) == 2
        assert entries[0]["client_id"] == "Claude Desktop"
        assert entries[1]["client_id"] == "Claude Desktop"


# ============================================================================
# Tests: _extract_tool_call_metadata()
# ============================================================================


class TestExtractToolCallMetadata:
    """Tests for tool metadata extraction from context variables."""

    def test_extracts_tool_name_from_context_var(
        self, temp_log_file: Path, identity_provider: IdentityProvider
    ):
        """Given tool context set, extracts tool name."""
        # Arrange
        middleware = create_test_audit_middleware(log_path=temp_log_file, identity_provider=identity_provider)
        request_id = "test-request-123"
        set_tool_context("write_file", {}, request_id)

        try:
            # Act
            result = middleware._extract_tool_call_metadata(request_id)

            # Assert
            assert result["tool_name"] == "write_file"
        finally:
            clear_tool_context(request_id)
            clear_context()

    def test_returns_empty_dict_when_no_context(
        self, temp_log_file: Path, identity_provider: IdentityProvider
    ):
        """Given no tool context, returns empty dict."""
        # Arrange
        middleware = create_test_audit_middleware(log_path=temp_log_file, identity_provider=identity_provider)
        clear_context()  # Ensure no context is set

        # Act
        result = middleware._extract_tool_call_metadata(None)

        # Assert
        assert result == {}

    def test_extracts_file_metadata_for_file_operations(
        self, temp_log_file: Path, identity_provider: IdentityProvider
    ):
        """Given tool context with file path argument, extracts file metadata."""
        # Arrange
        middleware = create_test_audit_middleware(log_path=temp_log_file, identity_provider=identity_provider)
        request_id = "test-request-456"
        set_tool_context("read_file", {"path": "/tmp/test.py"}, request_id)

        try:
            # Act
            result = middleware._extract_tool_call_metadata(request_id)

            # Assert
            assert result["tool_name"] == "read_file"
            # Path may be resolved (e.g., /tmp -> /private/tmp on macOS)
            assert result["file_path"].endswith("/tmp/test.py") or result["file_path"] == "/tmp/test.py"
            assert result["file_extension"] == ".py"
        finally:
            clear_tool_context(request_id)
            clear_context()

    def test_extracts_file_extension_for_write_tools(
        self, temp_log_file: Path, identity_provider: IdentityProvider
    ):
        """Given write tool context, extracts file extension."""
        # Arrange
        middleware = create_test_audit_middleware(log_path=temp_log_file, identity_provider=identity_provider)
        request_id = "test-request-789"
        set_tool_context("write_file", {"path": "/tmp/output.txt", "content": "hello"}, request_id)

        try:
            # Act
            result = middleware._extract_tool_call_metadata(request_id)

            # Assert
            assert result["tool_name"] == "write_file"
            assert result["file_extension"] == ".txt"
        finally:
            clear_tool_context(request_id)
            clear_context()


# ============================================================================
# Tests: _create_arguments_summary()
# ============================================================================


class TestCreateArgumentsSummary:
    """Tests for arguments summary creation."""

    def test_creates_summary_with_hash(self, temp_log_file: Path, identity_provider: IdentityProvider):
        """Given params, creates summary with hash and length."""
        # Arrange
        middleware = create_test_audit_middleware(log_path=temp_log_file, identity_provider=identity_provider)
        params = MockParams(name="test", arguments={"path": "/tmp/file.txt"})
        message = MockMessage(params=params)
        context = MockMiddlewareContext(method="tools/call", message=message)

        # Act
        result = middleware._create_arguments_summary(context)

        # Assert
        assert result is not None
        assert result.redacted is True
        assert result.body_hash is not None
        assert len(result.body_hash) == 64  # SHA256 hex length
        assert result.payload_length > 0

    def test_returns_none_without_params(self, temp_log_file: Path, identity_provider: IdentityProvider):
        """Given no params, returns None."""
        # Arrange
        middleware = create_test_audit_middleware(log_path=temp_log_file, identity_provider=identity_provider)
        message = MockMessage(params=None)
        context = MockMiddlewareContext(method="tools/call", message=message)

        # Act
        result = middleware._create_arguments_summary(context)

        # Assert
        assert result is None

    def test_same_params_produce_same_hash(self, temp_log_file: Path, identity_provider: IdentityProvider):
        """Given identical params, produces identical hash."""
        # Arrange
        middleware = create_test_audit_middleware(log_path=temp_log_file, identity_provider=identity_provider)
        params1 = MockParams(name="test", arguments={"key": "value"})
        params2 = MockParams(name="test", arguments={"key": "value"})
        context1 = MockMiddlewareContext(method="tools/call", message=MockMessage(params=params1))
        context2 = MockMiddlewareContext(method="tools/call", message=MockMessage(params=params2))

        # Act
        result1 = middleware._create_arguments_summary(context1)
        result2 = middleware._create_arguments_summary(context2)

        # Assert
        assert result1.body_hash == result2.body_hash

    def test_different_params_produce_different_hash(
        self, temp_log_file: Path, identity_provider: IdentityProvider
    ):
        """Given different params, produces different hash."""
        # Arrange
        middleware = create_test_audit_middleware(log_path=temp_log_file, identity_provider=identity_provider)
        params1 = MockParams(name="test", arguments={"key": "value1"})
        params2 = MockParams(name="test", arguments={"key": "value2"})
        context1 = MockMiddlewareContext(method="tools/call", message=MockMessage(params=params1))
        context2 = MockMiddlewareContext(method="tools/call", message=MockMessage(params=params2))

        # Act
        result1 = middleware._create_arguments_summary(context1)
        result2 = middleware._create_arguments_summary(context2)

        # Assert
        assert result1.body_hash != result2.body_hash


# ============================================================================
# Tests: JSONL Output Format
# ============================================================================


class TestJSONLOutput:
    """Tests for JSONL log file format and validity."""

    async def test_output_is_valid_jsonl(self, audit_middleware: AuditLoggingMiddleware, temp_log_file: Path):
        """Given multiple operations, each line is valid JSON."""
        # Arrange
        fastmcp_ctx = MockFastMCPContext(request_id="req-1", session_id="sess-1")

        async def call_next(_ctx):
            return {}

        # Act - log multiple events
        for i in range(3):
            context = MockMiddlewareContext(method=f"method_{i}", fastmcp_context=fastmcp_ctx)
            await audit_middleware.on_message(context, call_next)

        # Assert - each line is valid JSON
        with open(temp_log_file) as f:
            lines = f.readlines()
        assert len(lines) == 3
        for line in lines:
            json.loads(line)  # Should not raise

    async def test_output_has_timestamp(self, audit_middleware: AuditLoggingMiddleware, temp_log_file: Path):
        """Given an operation, output includes ISO 8601 timestamp."""
        # Arrange
        fastmcp_ctx = MockFastMCPContext(request_id="req-ts", session_id="sess-ts")
        context = MockMiddlewareContext(method="ping", fastmcp_context=fastmcp_ctx)

        async def call_next(_ctx):
            return None

        # Act
        await audit_middleware.on_message(context, call_next)

        # Assert
        entries = read_log_entries(temp_log_file)
        assert len(entries) == 1
        assert "time" in entries[0]
        # ISO 8601 format check (basic)
        assert "T" in entries[0]["time"]
        assert entries[0]["time"].endswith("Z")

    async def test_output_excludes_none_values(
        self, audit_middleware: AuditLoggingMiddleware, temp_log_file: Path
    ):
        """Given optional None fields, they are excluded from output."""
        # Arrange
        clear_context()  # Ensure no leftover tool context from previous tests
        fastmcp_ctx = MockFastMCPContext(request_id="req-excl", session_id="sess-excl")
        context = MockMiddlewareContext(method="ping", fastmcp_context=fastmcp_ctx)  # No tool_name

        async def call_next(_ctx):
            return None

        # Act
        await audit_middleware.on_message(context, call_next)

        # Assert
        entries = read_log_entries(temp_log_file)
        assert len(entries) == 1
        assert "tool_name" not in entries[0]
        assert "arguments_summary" not in entries[0]
        assert "error_code" not in entries[0]
        assert "message" not in entries[0]


# ============================================================================
# Tests: Factory Function
# ============================================================================


class TestCreateAuditLoggingMiddleware:
    """Tests for the factory function."""

    def test_creates_middleware_with_correct_config(
        self, temp_log_file: Path, identity_provider: IdentityProvider
    ):
        """Given config params, creates middleware with those values."""
        # Act
        middleware = create_test_audit_middleware(
            log_path=temp_log_file,
            backend_id="my-backend",
            identity_provider=identity_provider,
            config_version="v42",
        )

        # Assert
        assert middleware.backend_id == "my-backend"
        assert middleware.config_version == "v42"
        # Subject is fetched lazily on first request (async)
        assert middleware._identity_provider is identity_provider

    def test_creates_log_directory_if_missing(self, identity_provider: IdentityProvider):
        """Given non-existent directory, creates it."""
        # Arrange
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "subdir" / "audit.jsonl"

            # Act
            middleware = create_test_audit_middleware(
                log_path=log_path,
                identity_provider=identity_provider,
            )

            # Assert - directory should be created when first log is written
            # (logger setup creates parent dirs)
            assert middleware is not None

    def test_config_version_optional(self, temp_log_file: Path, identity_provider: IdentityProvider):
        """Given no config_version, middleware still works."""
        # Act
        middleware = create_test_audit_middleware(
            log_path=temp_log_file,
            identity_provider=identity_provider,
            config_version=None,
        )

        # Assert
        assert middleware.config_version is None


# ============================================================================
# Tests: Pydantic Models
# ============================================================================


class TestDurationInfo:
    """Tests for DurationInfo model."""

    def test_requires_duration_ms(self):
        """Given no duration_ms, raises validation error."""
        with pytest.raises(Exception):  # Pydantic ValidationError
            DurationInfo()

    def test_accepts_positive_duration(self):
        """Given positive duration, creates model."""
        info = DurationInfo(duration_ms=123.45)
        assert info.duration_ms == 123.45

    def test_accepts_zero_duration(self):
        """Given zero duration, creates model."""
        info = DurationInfo(duration_ms=0.0)
        assert info.duration_ms == 0.0


class TestSubjectIdentity:
    """Tests for SubjectIdentity model."""

    def test_requires_subject_id(self):
        """Given no subject_id, raises validation error."""
        with pytest.raises(Exception):
            SubjectIdentity()

    def test_claims_optional(self):
        """Given no claims, defaults to None."""
        subject = SubjectIdentity(subject_id="user123")
        assert subject.subject_claims is None

    def test_accepts_claims(self):
        """Given claims dict, stores it."""
        subject = SubjectIdentity(
            subject_id="user123",
            subject_claims={"auth_type": "oidc", "email": "user@example.com"},
        )
        assert subject.subject_claims["auth_type"] == "oidc"


class TestArgumentsSummary:
    """Tests for ArgumentsSummary model."""

    def test_defaults_to_redacted(self):
        """Given no redacted value, defaults to True."""
        summary = ArgumentsSummary()
        assert summary.redacted is True

    def test_hash_and_length_optional(self):
        """Given no hash/length, defaults to None."""
        summary = ArgumentsSummary()
        assert summary.body_hash is None
        assert summary.payload_length is None


# ============================================================================
# Tests: AuditHealthMonitor
# ============================================================================


class TestAuditHealthMonitorCheckIntegrity:
    """Tests for AuditHealthMonitor._check_integrity()."""

    def test_returns_none_when_file_intact(self):
        """Given unchanged file, returns None (no error)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Arrange
            audit_path = Path(tmpdir) / "audit.jsonl"
            audit_path.write_text("test\n")

            shutdown_coord = ShutdownCoordinator(Path(tmpdir), get_system_logger())
            monitor = AuditHealthMonitor([audit_path], shutdown_coord)

            # Record original identity
            stat = audit_path.stat()
            monitor._original_identities[audit_path] = (stat.st_dev, stat.st_ino)

            # Act
            result = monitor._check_integrity(audit_path)

            # Assert
            assert result is None

    def test_returns_error_when_file_missing(self):
        """Given deleted file, returns error message."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Arrange
            audit_path = Path(tmpdir) / "audit.jsonl"
            audit_path.write_text("test\n")

            shutdown_coord = ShutdownCoordinator(Path(tmpdir), get_system_logger())
            monitor = AuditHealthMonitor([audit_path], shutdown_coord)

            # Record original identity then delete
            stat = audit_path.stat()
            monitor._original_identities[audit_path] = (stat.st_dev, stat.st_ino)
            audit_path.unlink()

            # Act
            result = monitor._check_integrity(audit_path)

            # Assert
            assert result is not None
            assert "missing" in result

    def test_returns_error_when_file_replaced(self):
        """Given replaced file (different inode), returns error message."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Arrange
            audit_path = Path(tmpdir) / "audit.jsonl"
            audit_path.write_text("original\n")

            shutdown_coord = ShutdownCoordinator(Path(tmpdir), get_system_logger())
            monitor = AuditHealthMonitor([audit_path], shutdown_coord)

            # Record original identity
            stat = audit_path.stat()
            monitor._original_identities[audit_path] = (stat.st_dev, stat.st_ino)

            # Delete and recreate (new inode)
            audit_path.unlink()
            audit_path.write_text("replacement\n")

            # Act
            result = monitor._check_integrity(audit_path)

            # Assert
            assert result is not None
            assert "replaced" in result

    def test_returns_error_when_path_not_registered(self):
        """Given unregistered path, returns error message."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Arrange
            audit_path = Path(tmpdir) / "audit.jsonl"
            audit_path.write_text("test\n")

            shutdown_coord = ShutdownCoordinator(Path(tmpdir), get_system_logger())
            monitor = AuditHealthMonitor([audit_path], shutdown_coord)
            # Don't register the identity

            # Act
            result = monitor._check_integrity(audit_path)

            # Assert
            assert result is not None
            assert "not registered" in result

    def test_returns_error_when_permission_denied(self):
        """Given unreadable file, returns permission error."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Arrange
            audit_path = Path(tmpdir) / "audit.jsonl"
            audit_path.write_text("test\n")

            shutdown_coord = ShutdownCoordinator(Path(tmpdir), get_system_logger())
            monitor = AuditHealthMonitor([audit_path], shutdown_coord)

            # Record original identity
            stat = audit_path.stat()
            monitor._original_identities[audit_path] = (stat.st_dev, stat.st_ino)

            # Remove all permissions
            audit_path.chmod(0o000)

            try:
                # Act
                result = monitor._check_integrity(audit_path)

                # Assert
                assert result is not None
                assert "permission" in result.lower() or "inaccessible" in result.lower()
            finally:
                # Restore permissions for cleanup
                audit_path.chmod(0o644)

    def test_verifies_write_capability(self):
        """Given file that exists, verifies we can write and fsync."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Arrange
            audit_path = Path(tmpdir) / "audit.jsonl"
            audit_path.write_text("test\n")
            original_size = audit_path.stat().st_size

            shutdown_coord = ShutdownCoordinator(Path(tmpdir), get_system_logger())
            monitor = AuditHealthMonitor([audit_path], shutdown_coord)

            # Record original identity
            stat = audit_path.stat()
            monitor._original_identities[audit_path] = (stat.st_dev, stat.st_ino)

            # Act
            result = monitor._check_integrity(audit_path)

            # Assert - check passed and file size unchanged (empty write)
            assert result is None
            assert audit_path.stat().st_size == original_size


class TestAuditHealthMonitorLifecycle:
    """Tests for AuditHealthMonitor start/stop lifecycle."""

    async def test_start_records_file_identities(self):
        """Given paths, start() records their dev/ino."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Arrange
            path1 = Path(tmpdir) / "audit1.jsonl"
            path2 = Path(tmpdir) / "audit2.jsonl"
            path1.write_text("test1\n")
            path2.write_text("test2\n")

            shutdown_coord = ShutdownCoordinator(Path(tmpdir), get_system_logger())
            monitor = AuditHealthMonitor([path1, path2], shutdown_coord)

            # Act
            await monitor.start()

            try:
                # Assert
                assert path1 in monitor._original_identities
                assert path2 in monitor._original_identities
                assert monitor._running is True
                assert monitor._task is not None
            finally:
                await monitor.stop()

    async def test_stop_cancels_task(self):
        """Given running monitor, stop() cancels the task."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Arrange
            audit_path = Path(tmpdir) / "audit.jsonl"
            audit_path.write_text("test\n")

            shutdown_coord = ShutdownCoordinator(Path(tmpdir), get_system_logger())
            monitor = AuditHealthMonitor([audit_path], shutdown_coord, check_interval_seconds=0.1)

            await monitor.start()
            assert monitor._running is True

            # Act
            await monitor.stop()

            # Assert
            assert monitor._running is False

    async def test_start_is_idempotent(self):
        """Given already started monitor, start() is a no-op."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Arrange
            audit_path = Path(tmpdir) / "audit.jsonl"
            audit_path.write_text("test\n")

            shutdown_coord = ShutdownCoordinator(Path(tmpdir), get_system_logger())
            monitor = AuditHealthMonitor([audit_path], shutdown_coord)

            await monitor.start()
            original_task = monitor._task

            # Act
            await monitor.start()  # Second start

            try:
                # Assert - same task, not replaced
                assert monitor._task is original_task
            finally:
                await monitor.stop()

    async def test_is_healthy_true_when_running(self):
        """Given running monitor, is_healthy returns True."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Arrange
            audit_path = Path(tmpdir) / "audit.jsonl"
            audit_path.write_text("test\n")

            shutdown_coord = ShutdownCoordinator(Path(tmpdir), get_system_logger())
            monitor = AuditHealthMonitor([audit_path], shutdown_coord)

            # Act
            await monitor.start()

            try:
                # Assert
                assert monitor.is_healthy is True
            finally:
                await monitor.stop()

    async def test_is_healthy_false_when_stopped(self):
        """Given stopped monitor, is_healthy returns False."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Arrange
            audit_path = Path(tmpdir) / "audit.jsonl"
            audit_path.write_text("test\n")

            shutdown_coord = ShutdownCoordinator(Path(tmpdir), get_system_logger())
            monitor = AuditHealthMonitor([audit_path], shutdown_coord)

            await monitor.start()
            await monitor.stop()

            # Assert
            assert monitor.is_healthy is False

    async def test_is_healthy_false_before_start(self):
        """Given unstarted monitor, is_healthy returns False."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Arrange
            audit_path = Path(tmpdir) / "audit.jsonl"
            audit_path.write_text("test\n")

            shutdown_coord = ShutdownCoordinator(Path(tmpdir), get_system_logger())
            monitor = AuditHealthMonitor([audit_path], shutdown_coord)

            # Assert
            assert monitor.is_healthy is False

    async def test_task_has_name(self):
        """Given started monitor, task has descriptive name."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Arrange
            audit_path = Path(tmpdir) / "audit.jsonl"
            audit_path.write_text("test\n")

            shutdown_coord = ShutdownCoordinator(Path(tmpdir), get_system_logger())
            monitor = AuditHealthMonitor([audit_path], shutdown_coord)

            await monitor.start()

            try:
                # Assert
                assert monitor._task.get_name() == "audit_health_monitor"
            finally:
                await monitor.stop()


class TestAuditHealthMonitorLoop:
    """Tests for AuditHealthMonitor periodic checking."""

    async def test_detects_file_deletion_during_idle(self):
        """Given file deleted while monitoring, triggers shutdown."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Arrange
            audit_path = Path(tmpdir) / "audit.jsonl"
            audit_path.write_text("test\n")

            shutdown_coord = ShutdownCoordinator(Path(tmpdir), get_system_logger())
            # Short interval for testing
            monitor = AuditHealthMonitor([audit_path], shutdown_coord, check_interval_seconds=0.05)

            await monitor.start()

            # Act - delete file and wait for detection
            audit_path.unlink()

            # Wait for monitor to detect (2 check intervals + buffer)
            import asyncio

            await asyncio.sleep(0.15)

            # Assert - monitor should have stopped after detecting failure
            # and initiated shutdown
            assert shutdown_coord.is_shutting_down is True

            await monitor.stop()


# ============================================================================
# Tests: hash_sensitive_id()
# ============================================================================


class TestHashSensitiveId:
    """Tests for hash_sensitive_id() function."""

    def test_returns_correct_format(self):
        """Given a value, returns sha256:<prefix> format."""
        # Act
        result = hash_sensitive_id("test_value")

        # Assert
        assert result.startswith("sha256:")
        assert len(result) == len("sha256:") + 8  # Default prefix_length is 8

    def test_prefix_length_parameter(self):
        """Given custom prefix_length, returns hash with that length."""
        # Act
        result = hash_sensitive_id("test_value", prefix_length=4)

        # Assert
        prefix = result.split(":")[1]
        assert len(prefix) == 4

    def test_consistent_hashing(self):
        """Given same input, always returns same output."""
        # Arrange
        value = "auth0|user123"

        # Act
        result1 = hash_sensitive_id(value)
        result2 = hash_sensitive_id(value)

        # Assert
        assert result1 == result2

    def test_different_inputs_different_hashes(self):
        """Given different inputs, returns different hashes."""
        # Act
        result1 = hash_sensitive_id("user1")
        result2 = hash_sensitive_id("user2")

        # Assert
        assert result1 != result2

    def test_empty_value_returns_empty_marker(self):
        """Given empty string, returns sha256:empty."""
        # Act
        result = hash_sensitive_id("")

        # Assert
        assert result == "sha256:empty"

    def test_none_value_returns_empty_marker(self):
        """Given None (falsy), returns sha256:empty."""
        # Act
        result = hash_sensitive_id(None)

        # Assert
        assert result == "sha256:empty"

    def test_prefix_is_valid_hex(self):
        """Given any input, prefix is valid hexadecimal."""
        # Act
        result = hash_sensitive_id("test@example.com")
        prefix = result.split(":")[1]

        # Assert - should not raise
        int(prefix, 16)

    def test_long_prefix_length(self):
        """Given prefix_length of 64, returns full SHA256 hash."""
        # Act
        result = hash_sensitive_id("test_value", prefix_length=64)
        prefix = result.split(":")[1]

        # Assert
        assert len(prefix) == 64  # Full SHA256 hex length
