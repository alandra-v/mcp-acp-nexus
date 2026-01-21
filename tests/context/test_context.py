"""Unit tests for context building components.

Tests the DecisionContext builder and related models for ABAC policy evaluation.

Key design principles tested:
1. Context describes reality, not intent
2. Facts carry provenance
3. For tools/call, intent is None (we don't guess what tools do)
"""

import getpass
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from mcp_acp.pdp import Decision
from mcp_acp.context import (
    Action,
    ActionCategory,
    ActionProvenance,
    DecisionContext,
    DISCOVERY_METHODS,
    Environment,
    Provenance,
    Resource,
    ResourceInfo,
    ResourceType,
    ServerInfo,
    SideEffect,
    Subject,
    SubjectProvenance,
    ToolInfo,
    build_decision_context,
)
from mcp_acp.security.identity import LocalIdentityProvider


# ============================================================================
# Fixtures
# ============================================================================


from typing import Any, Callable, Coroutine


@pytest.fixture
def identity_provider() -> LocalIdentityProvider:
    """Create a local identity provider for testing."""
    return LocalIdentityProvider()


@pytest.fixture
def build_ctx(
    identity_provider: LocalIdentityProvider,
) -> Callable[..., Coroutine[Any, Any, DecisionContext]]:
    """Factory fixture to build DecisionContext with defaults.

    Returns an async function that creates contexts with sensible defaults,
    reducing boilerplate in tests.
    """

    async def _build(method: str, arguments: dict | None = None, **overrides):
        defaults = {
            "method": method,
            "arguments": arguments or {},
            "identity_provider": identity_provider,
            "session_id": "sess-123",
            "request_id": "req-456",
            "backend_id": "filesystem",
        }
        defaults.update(overrides)
        return await build_decision_context(**defaults)

    return _build


@pytest.fixture
def minimal_subject() -> Subject:
    """Create a minimal Subject for testing."""
    return Subject(
        id="testuser",
        provenance=SubjectProvenance(id=Provenance.DERIVED),
    )


@pytest.fixture
def oidc_subject() -> Subject:
    """Create a Subject with full OIDC fields for testing."""
    return Subject(
        id="user-123",
        issuer="https://accounts.google.com",
        audience=["my-proxy"],
        client_id="claude-desktop",
        scopes=frozenset({"read", "write"}),
        token_age_s=300.5,
        auth_time=datetime(2025, 12, 18, 10, 30, 0, tzinfo=timezone.utc),
        provenance=SubjectProvenance(
            id=Provenance.TOKEN,
            scopes=Provenance.TOKEN,
        ),
    )


# ============================================================================
# Tests: Decision enum
# ============================================================================


class TestDecision:
    """Tests for Decision enum."""

    @pytest.mark.parametrize(
        ("decision", "expected_value"),
        [
            (Decision.ALLOW, "allow"),
            (Decision.DENY, "deny"),
            (Decision.HITL, "hitl"),
        ],
        ids=["allow", "deny", "hitl"],
    )
    def test_decision_has_expected_value(self, decision: Decision, expected_value: str) -> None:
        """Given a Decision enum member, returns its expected string value."""
        assert decision.value == expected_value

    def test_decision_enum_is_exhaustive(self) -> None:
        """Decision enum contains exactly the expected members."""
        assert len(Decision) == 3


# ============================================================================
# Tests: Provenance enum
# ============================================================================


class TestProvenance:
    """Tests for Provenance enum."""

    @pytest.mark.parametrize(
        ("provenance", "expected_value"),
        [
            (Provenance.TOKEN, "token"),
            (Provenance.DIRECTORY, "directory"),
            (Provenance.MTLS, "mtls"),
            (Provenance.PROXY_CONFIG, "proxy_config"),
            (Provenance.MCP_METHOD, "mcp_method"),
            (Provenance.MCP_REQUEST, "mcp_request"),
            (Provenance.DERIVED, "derived"),
            (Provenance.CLIENT_HINT, "client_hint"),
        ],
        ids=[
            "token",
            "directory",
            "mtls",
            "proxy_config",
            "mcp_method",
            "mcp_request",
            "derived",
            "client_hint",
        ],
    )
    def test_provenance_has_expected_value(self, provenance: Provenance, expected_value: str) -> None:
        """Given a Provenance enum member, returns its expected string value."""
        assert provenance.value == expected_value


# ============================================================================
# Tests: Subject model
# ============================================================================


class TestSubject:
    """Tests for Subject model."""

    def test_creates_with_minimal_fields(self, minimal_subject: Subject) -> None:
        """Given minimal fields, Subject is created with defaults for optional fields."""
        # Assert
        assert minimal_subject.id == "testuser"
        assert minimal_subject.provenance.id == Provenance.DERIVED
        assert minimal_subject.issuer is None
        assert minimal_subject.scopes is None

    def test_creates_with_oidc_fields(self, oidc_subject: Subject) -> None:
        """Given full OIDC fields, Subject stores all identity information."""
        # Assert
        assert oidc_subject.id == "user-123"
        assert oidc_subject.issuer == "https://accounts.google.com"
        assert oidc_subject.scopes == frozenset({"read", "write"})
        assert oidc_subject.provenance.id == Provenance.TOKEN


# ============================================================================
# Tests: Action model
# ============================================================================


class TestAction:
    """Tests for Action model."""

    def test_tools_call_has_none_intent(self) -> None:
        """Given tools/call action, intent is None because we don't guess."""
        # Arrange
        action = Action(
            mcp_method="tools/call",
            name="tools.call",
            intent=None,
            category=ActionCategory.ACTION,
            provenance=ActionProvenance(intent=None),
        )

        # Assert
        assert action.intent is None

    def test_resources_read_has_read_intent(self) -> None:
        """Given resources/read action, intent is 'read' (known from method semantics)."""
        # Arrange
        action = Action(
            mcp_method="resources/read",
            name="resources.read",
            intent="read",
            category=ActionCategory.ACTION,
            provenance=ActionProvenance(intent=Provenance.MCP_METHOD),
        )

        # Assert
        assert action.intent == "read"
        assert action.provenance.intent == Provenance.MCP_METHOD

    @pytest.mark.parametrize(
        ("category", "expected_value"),
        [
            (ActionCategory.DISCOVERY, "discovery"),
            (ActionCategory.ACTION, "action"),
        ],
        ids=["discovery", "action"],
    )
    def test_action_category_has_expected_value(self, category: ActionCategory, expected_value: str) -> None:
        """Given ActionCategory enum member, returns expected string value."""
        assert category.value == expected_value


# ============================================================================
# Tests: Resource models
# ============================================================================


class TestResource:
    """Tests for Resource model."""

    def test_creates_tool_resource(self) -> None:
        """Given tool info, Resource correctly represents a tool."""
        # Arrange & Act
        resource = Resource(
            type=ResourceType.TOOL,
            server=ServerInfo(id="filesystem", provenance=Provenance.PROXY_CONFIG),
            tool=ToolInfo(name="write_file", provenance=Provenance.MCP_REQUEST),
        )

        # Assert
        assert resource.type == ResourceType.TOOL
        assert resource.server.id == "filesystem"
        assert resource.tool.name == "write_file"

    def test_creates_file_resource(self) -> None:
        """Given file info, Resource correctly represents a file."""
        # Arrange & Act
        resource = Resource(
            type=ResourceType.RESOURCE,
            server=ServerInfo(id="filesystem", provenance=Provenance.PROXY_CONFIG),
            resource=ResourceInfo(
                path="/tmp/test.txt",
                filename="test.txt",
                extension=".txt",
                parent_dir="/tmp",
                provenance=Provenance.MCP_REQUEST,
            ),
        )

        # Assert
        assert resource.type == ResourceType.RESOURCE
        assert resource.resource.path == "/tmp/test.txt"
        assert resource.resource.extension == ".txt"


# ============================================================================
# Tests: build_decision_context() - Facts Only Principle
# ============================================================================


class TestBuildDecisionContextFactsOnly:
    """Tests verifying the context builder only reports facts, never guesses."""

    @pytest.mark.parametrize(
        "tool_name",
        ["read_file", "write_file", "bash", "process_data"],
        ids=["read-like", "write-like", "dangerous", "ambiguous"],
    )
    async def test_tools_call_intent_is_always_none(self, build_ctx, tool_name: str) -> None:
        """Given tools/call, intent is None regardless of tool name."""
        # Act
        ctx = await build_ctx("tools/call", {"name": tool_name})

        # Assert
        assert ctx.action.intent is None

    @pytest.mark.parametrize(
        "tool_name",
        ["read_file", "write_file", "bash", "process_data"],
        ids=["read-like", "write-like", "dangerous", "ambiguous"],
    )
    async def test_tools_call_extracts_tool_name(self, build_ctx, tool_name: str) -> None:
        """Given tools/call, tool name is extracted from arguments."""
        # Act
        ctx = await build_ctx("tools/call", {"name": tool_name})

        # Assert
        assert ctx.resource.tool.name == tool_name


# ============================================================================
# Tests: build_decision_context() - Known Actions from MCP Methods
# ============================================================================


class TestBuildDecisionContextKnownActions:
    """Tests for actions that ARE known facts from MCP method semantics."""

    @pytest.mark.parametrize(
        ("method", "expected_intent"),
        [
            ("resources/read", "read"),
            ("ping", None),
            ("tools/list", None),
            ("resources/list", None),
            ("prompts/list", None),
        ],
        ids=["resources/read", "ping", "tools/list", "resources/list", "prompts/list"],
    )
    async def test_mcp_method_intent(self, build_ctx, method: str, expected_intent: str | None) -> None:
        """Given MCP method, intent is correctly derived from method semantics."""
        # Act
        ctx = await build_ctx(method)

        # Assert
        assert ctx.action.intent == expected_intent


# ============================================================================
# Tests: build_decision_context() - Resource Extraction
# ============================================================================


class TestBuildDecisionContextResources:
    """Tests for resource attribute extraction."""

    async def test_tools_call_extracts_tool_info(self, build_ctx) -> None:
        """Given tools/call, extracts tool info with correct provenance."""
        # Act
        ctx = await build_ctx("tools/call", {"name": "read_file", "path": "/tmp/secrets.key"})

        # Assert
        assert ctx.resource.type == ResourceType.TOOL
        assert ctx.resource.tool.name == "read_file"
        assert ctx.resource.tool.provenance == Provenance.MCP_REQUEST

    async def test_tools_call_extracts_filename(self, build_ctx) -> None:
        """Given tools/call with path, extracts filename."""
        # Act
        ctx = await build_ctx("tools/call", {"name": "read_file", "path": "/tmp/secrets.key"})

        # Assert
        assert ctx.resource.resource.filename == "secrets.key"

    async def test_tools_call_extracts_extension(self, build_ctx) -> None:
        """Given tools/call with path, extracts file extension."""
        # Act
        ctx = await build_ctx("tools/call", {"name": "read_file", "path": "/tmp/secrets.key"})

        # Assert
        assert ctx.resource.resource.extension == ".key"

    async def test_resources_read_extracts_uri(self, build_ctx) -> None:
        """Given resources/read with URI, extracts full URI."""
        # Act
        ctx = await build_ctx("resources/read", {"uri": "file:///tmp/test.txt"})

        # Assert
        assert ctx.resource.resource.uri == "file:///tmp/test.txt"

    async def test_resources_read_extracts_scheme(self, build_ctx) -> None:
        """Given resources/read with URI, extracts URI scheme."""
        # Act
        ctx = await build_ctx("resources/read", {"uri": "file:///tmp/test.txt"})

        # Assert
        assert ctx.resource.resource.scheme == "file"

    async def test_tool_without_path_has_no_resource_info(self, build_ctx) -> None:
        """Given tools/call without path argument, resource info is None."""
        # Act
        ctx = await build_ctx("tools/call", {"name": "get_weather", "city": "London"})

        # Assert
        assert ctx.resource.tool.name == "get_weather"
        assert ctx.resource.resource is None

    async def test_move_file_extracts_source_and_dest_paths(self, build_ctx) -> None:
        """Given move_file with source/destination, extracts both paths."""
        # Act - matches official MCP filesystem server format
        ctx = await build_ctx(
            "tools/call",
            {
                "name": "move_file",
                "arguments": {"source": "/tmp/file.txt", "destination": "/home/user/file.txt"},
            },
        )

        # Assert
        assert ctx.resource.resource is not None
        assert ctx.resource.resource.source_path == "/tmp/file.txt"
        assert ctx.resource.resource.dest_path == "/home/user/file.txt"
        # path should be set to source (first found) for backwards compat
        assert ctx.resource.resource.path == "/tmp/file.txt"

    async def test_copy_path_extracts_source_and_dest_paths(self, build_ctx) -> None:
        """Given copy_path with source/destination, extracts both paths."""
        # Act - matches cyanheads/filesystem-mcp-server format
        ctx = await build_ctx(
            "tools/call",
            {
                "name": "copy_path",
                "arguments": {"source": "/data/backup.db", "destination": "/archive/backup.db"},
            },
        )

        # Assert
        assert ctx.resource.resource is not None
        assert ctx.resource.resource.source_path == "/data/backup.db"
        assert ctx.resource.resource.dest_path == "/archive/backup.db"

    async def test_single_path_tool_has_no_source_dest(self, build_ctx) -> None:
        """Given tool with single path, source_path and dest_path are None."""
        # Act
        ctx = await build_ctx(
            "tools/call",
            {"name": "read_file", "arguments": {"path": "/etc/hosts"}},
        )

        # Assert
        assert ctx.resource.resource is not None
        assert ctx.resource.resource.path == "/etc/hosts"
        assert ctx.resource.resource.source_path is None
        assert ctx.resource.resource.dest_path is None

    async def test_handles_none_arguments(self, build_ctx) -> None:
        """Given None arguments, handles gracefully."""
        # Act
        ctx = await build_ctx("tools/list", None)

        # Assert
        assert ctx.resource.type == ResourceType.SERVER
        assert ctx.resource.tool is None
        assert ctx.resource.resource is None


# ============================================================================
# Tests: build_decision_context() - Subject Extraction
# ============================================================================


class TestBuildDecisionContextSubject:
    """Tests for subject (identity) extraction."""

    async def test_extracts_subject_id_from_identity_provider(self, build_ctx) -> None:
        """Given identity provider, extracts correct subject id."""
        # Act
        ctx = await build_ctx("tools/call", {"name": "test"})

        # Assert
        assert ctx.subject.id == getpass.getuser()

    async def test_subject_has_derived_provenance(self, build_ctx) -> None:
        """Given local identity provider, subject has DERIVED provenance."""
        # Act
        ctx = await build_ctx("tools/call", {"name": "test"})

        # Assert
        assert ctx.subject.provenance.id == Provenance.DERIVED


# ============================================================================
# Tests: build_decision_context() - Environment Extraction
# ============================================================================


class TestBuildDecisionContextEnvironment:
    """Tests for environment attribute extraction."""

    async def test_includes_client_name(self, build_ctx) -> None:
        """Given client_name, includes it in environment."""
        # Act
        ctx = await build_ctx("tools/call", {"name": "test"}, client_name="Claude Desktop")

        # Assert
        assert ctx.environment.mcp_client_name == "Claude Desktop"

    async def test_includes_session_id(self, build_ctx) -> None:
        """Given session_id, includes it in environment."""
        # Act
        ctx = await build_ctx("tools/call", {"name": "test"})

        # Assert
        assert ctx.environment.session_id == "sess-123"

    async def test_includes_request_id(self, build_ctx) -> None:
        """Given request_id, includes it in environment."""
        # Act
        ctx = await build_ctx("tools/call", {"name": "test"})

        # Assert
        assert ctx.environment.request_id == "req-456"

    async def test_timestamp_is_utc(self, build_ctx) -> None:
        """Given any request, timestamp is in UTC."""
        # Act
        ctx = await build_ctx("tools/call", {"name": "test"})

        # Assert
        assert ctx.environment.timestamp.tzinfo == timezone.utc


# ============================================================================
# Tests: DecisionContext structure
# ============================================================================


class TestDecisionContextStructure:
    """Tests for the full DecisionContext structure."""

    async def test_context_is_immutable(self, build_ctx, minimal_subject: Subject) -> None:
        """Given a DecisionContext, it cannot be modified after creation."""
        # Arrange
        ctx = await build_ctx("tools/call", {"name": "test"})

        # Act & Assert
        with pytest.raises(ValidationError):
            ctx.subject = minimal_subject

    @pytest.mark.parametrize(
        "field",
        ["subject", "action", "resource", "environment"],
    )
    async def test_context_has_required_abac_field(self, build_ctx, field: str) -> None:
        """Given a DecisionContext, all core ABAC fields are present."""
        # Act
        ctx = await build_ctx("tools/call", {"name": "test"})

        # Assert
        assert getattr(ctx, field) is not None

    async def test_context_serializes_to_json(self, build_ctx) -> None:
        """Given a DecisionContext, it can be serialized to JSON for audit."""
        # Arrange
        ctx = await build_ctx("tools/call", {"name": "bash", "command": "ls"})

        # Act
        data = ctx.model_dump(mode="json")

        # Assert
        assert data["action"]["mcp_method"] == "tools/call"
        assert data["resource"]["tool"]["name"] == "bash"


# ============================================================================
# Tests: Edge Cases - File Extensions
# ============================================================================


class TestFileExtensionExtraction:
    """Tests for file extension extraction edge cases."""

    @pytest.mark.parametrize(
        ("path", "expected_filename"),
        [
            ("/home/user/.env", ".env"),
            ("/app/config.prod.json", "config.prod.json"),
            ("/tmp/test.txt", "test.txt"),
            ("/tmp/Makefile", "Makefile"),
        ],
        ids=["dotfile", "multi-dot", "normal", "no-extension"],
    )
    async def test_filename_extraction(self, build_ctx, path: str, expected_filename: str) -> None:
        """Given various paths, filename is correctly extracted."""
        # Act
        ctx = await build_ctx("tools/call", {"name": "read_file", "path": path})

        # Assert
        assert ctx.resource.resource.filename == expected_filename

    @pytest.mark.parametrize(
        ("path", "expected_ext"),
        [
            ("/home/user/.env", None),
            ("/app/config.prod.json", ".json"),
            ("/tmp/test.txt", ".txt"),
            ("/tmp/Makefile", None),
        ],
        ids=["dotfile", "multi-dot", "normal", "no-extension"],
    )
    async def test_extension_extraction(self, build_ctx, path: str, expected_ext: str | None) -> None:
        """Given various paths, extension is correctly extracted (or None)."""
        # Act
        ctx = await build_ctx("tools/call", {"name": "read_file", "path": path})

        # Assert
        assert ctx.resource.resource.extension == expected_ext


# ============================================================================
# Tests: Edge Cases - URI Schemes
# ============================================================================


class TestUriSchemeExtraction:
    """Tests for URI scheme extraction."""

    @pytest.mark.parametrize(
        ("uri", "expected_scheme"),
        [
            ("https://example.com/api/data", "https"),
            ("file:///tmp/test.txt", "file"),
            ("s3://bucket/key", "s3"),
        ],
        ids=["https", "file", "s3"],
    )
    async def test_uri_scheme_extraction(self, build_ctx, uri: str, expected_scheme: str) -> None:
        """Given various URIs, scheme is correctly extracted."""
        # Act
        ctx = await build_ctx("resources/read", {"uri": uri})

        # Assert
        assert ctx.resource.resource.scheme == expected_scheme


# ============================================================================
# Tests: Edge Cases - Special Methods
# ============================================================================


class TestSpecialMethods:
    """Tests for special method handling."""

    async def test_prompts_method_has_prompt_type(self, build_ctx) -> None:
        """Given prompts method, resource type is PROMPT."""
        # Act
        ctx = await build_ctx("prompts/get", {"name": "my-prompt"})

        # Assert
        assert ctx.resource.type == ResourceType.PROMPT

    async def test_prompts_method_has_no_tool(self, build_ctx) -> None:
        """Given prompts method, tool is None."""
        # Act
        ctx = await build_ctx("prompts/get", {"name": "my-prompt"})

        # Assert
        assert ctx.resource.tool is None

    async def test_unknown_method_has_none_intent(self, build_ctx) -> None:
        """Given unknown method, intent is None (we don't guess)."""
        # Act
        ctx = await build_ctx("custom/dangerous_operation", {})

        # Assert
        assert ctx.action.intent is None


# ============================================================================
# Tests: Action Category Assignment
# ============================================================================


class TestActionCategoryAssignment:
    """Tests for action category assignment (discovery vs action)."""

    @pytest.mark.parametrize(
        "method",
        [
            "initialize",
            "ping",
            "tools/list",
            "resources/list",
            "resources/templates/list",
            "prompts/list",
        ],
        ids=[
            "initialize",
            "ping",
            "tools/list",
            "resources/list",
            "resources/templates/list",
            "prompts/list",
        ],
    )
    async def test_discovery_methods_have_discovery_category(self, build_ctx, method: str) -> None:
        """Given discovery method, action category is DISCOVERY."""
        # Act
        ctx = await build_ctx(method)

        # Assert
        assert ctx.action.category == ActionCategory.DISCOVERY

    @pytest.mark.parametrize(
        "method",
        ["tools/call", "resources/read", "prompts/get", "custom/operation"],
        ids=["tools/call", "resources/read", "prompts/get", "custom"],
    )
    async def test_action_methods_have_action_category(self, build_ctx, method: str) -> None:
        """Given action method, action category is ACTION."""
        # Act
        ctx = await build_ctx(method, {"name": "test"})

        # Assert
        assert ctx.action.category == ActionCategory.ACTION

    @pytest.mark.parametrize(
        "method",
        [
            "initialize",
            "ping",
            "tools/list",
            "resources/list",
            "resources/templates/list",
            "prompts/list",
        ],
    )
    def test_discovery_methods_constant_contains_method(self, method: str) -> None:
        """Given expected discovery method, it is in DISCOVERY_METHODS constant."""
        # Assert
        assert method in DISCOVERY_METHODS

    def test_prompts_get_not_in_discovery_methods(self) -> None:
        """prompts/get is excluded from DISCOVERY_METHODS (requires policy evaluation)."""
        # Assert - security decision: prompts/get returns content
        assert "prompts/get" not in DISCOVERY_METHODS

    async def test_tools_list_is_discovery_but_call_is_action(self, build_ctx) -> None:
        """Given tools/list vs tools/call, categories differ appropriately."""
        # Act
        list_ctx = await build_ctx("tools/list")
        call_ctx = await build_ctx("tools/call", {"name": "bash"})

        # Assert
        assert list_ctx.action.category == ActionCategory.DISCOVERY
        assert call_ctx.action.category == ActionCategory.ACTION
