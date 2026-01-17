"""Unit tests for Policy Enforcement Point (PEP) components.

Tests use the AAA pattern (Arrange-Act-Assert) for clarity.

Tests cover:
- PermissionDeniedError (errors.py)
- HITLHandler and escape function (hitl.py)
- DecisionEvent model (decision.py)
- PolicyEnforcementMiddleware (middleware.py)
"""

from __future__ import annotations

import logging
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from mcp import McpError

from mcp_acp.config import HITLConfig
from mcp_acp.pdp.decision import Decision
from mcp_acp.exceptions import PERMISSION_DENIED_CODE, PermissionDeniedError
from mcp_acp.pep.hitl import (
    HITLHandler,
    HITLOutcome,
    HITLResult,
    _parse_applescript_record,
    escape_applescript_string,
)
from mcp_acp.pep.middleware import PolicyEnforcementMiddleware
from mcp_acp.telemetry.models.decision import DecisionEvent, MatchedRuleLog


# =============================================================================
# PermissionDeniedError Tests
# =============================================================================


class TestPermissionDeniedError:
    """Tests for PermissionDeniedError exception."""

    def test_inherits_from_mcp_error(self) -> None:
        """PermissionDeniedError should inherit from McpError."""
        # Assert
        assert issubclass(PermissionDeniedError, McpError)

    def test_creates_with_message_only(self) -> None:
        """Should create error with just a message."""
        # Act
        err = PermissionDeniedError("Access denied")

        # Assert
        assert err.message == "Access denied"
        assert str(err) == "Access denied"
        assert err.error.code == PERMISSION_DENIED_CODE
        assert err.error.message == "Access denied"
        assert err.error.data is None

    def test_creates_with_full_context(self) -> None:
        """Should create error with full context."""
        # Act
        err = PermissionDeniedError(
            "Policy denied: tools/call on /etc/passwd",
            decision=Decision.DENY,
            tool_name="read_file",
            path="/etc/passwd",
            matched_rules=["deny_etc", "deny_system"],
            final_rule="deny_etc",
        )

        # Assert
        assert err.message == "Policy denied: tools/call on /etc/passwd"
        assert err.decision == Decision.DENY
        assert err.tool_name == "read_file"
        assert err.path == "/etc/passwd"
        assert err.matched_rules == ["deny_etc", "deny_system"]
        assert err.final_rule == "deny_etc"

    def test_error_data_excludes_none_values(self) -> None:
        """error_data should exclude None values."""
        # Arrange
        err = PermissionDeniedError("Test", tool_name="test_tool")

        # Act
        data = err.error_data

        # Assert
        assert data == {"tool_name": "test_tool"}
        assert "path" not in data
        assert "matched_rules" not in data

    def test_error_data_includes_decision_value(self) -> None:
        """error_data should include decision as string value."""
        # Arrange
        err = PermissionDeniedError("Test", decision=Decision.DENY)

        # Act
        data = err.error_data

        # Assert
        assert data["decision"] == "deny"

    def test_to_json_rpc_error(self) -> None:
        """to_json_rpc_error should return proper JSON-RPC format."""
        # Arrange
        err = PermissionDeniedError(
            "Test error",
            tool_name="test_tool",
            final_rule="test_rule",
        )

        # Act
        json_rpc = err.to_json_rpc_error()

        # Assert
        assert json_rpc["code"] == PERMISSION_DENIED_CODE
        assert json_rpc["message"] == "Test error"
        assert json_rpc["data"]["tool_name"] == "test_tool"
        assert json_rpc["data"]["final_rule"] == "test_rule"

    def test_code_class_attribute(self) -> None:
        """code should be accessible as class attribute."""
        # Assert
        assert PermissionDeniedError.code == PERMISSION_DENIED_CODE

    def test_repr(self) -> None:
        """__repr__ should include key attributes."""
        # Arrange
        err = PermissionDeniedError(
            "Test",
            tool_name="test_tool",
            path="/test/path",
            final_rule="test_rule",
        )

        # Act
        repr_str = repr(err)

        # Assert
        assert "PermissionDeniedError" in repr_str
        assert "test_tool" in repr_str
        assert "/test/path" in repr_str
        assert "test_rule" in repr_str

    def test_can_be_caught_as_mcp_error(self) -> None:
        """Should be catchable as McpError."""
        # Act & Assert
        try:
            raise PermissionDeniedError("Test")
        except McpError as e:
            assert e.error.code == PERMISSION_DENIED_CODE
        else:
            pytest.fail("Exception was not raised")


# =============================================================================
# escape_applescript_string Tests
# =============================================================================


class TestEscapeApplescriptString:
    """Tests for escape_applescript_string function."""

    def test_escapes_double_quotes(self) -> None:
        """Should escape double quotes."""
        # Act
        result = escape_applescript_string('test"quote')

        # Assert
        assert result == 'test\\"quote'

    def test_escapes_backslashes(self) -> None:
        """Should escape backslashes."""
        # Act
        result = escape_applescript_string("path\\to\\file")

        # Assert
        assert result == "path\\\\to\\\\file"

    def test_escapes_both(self) -> None:
        """Should escape both backslashes and quotes in correct order."""
        # Act
        result = escape_applescript_string('test\\"both')

        # Assert - first backslash is escaped to \\, then quote is escaped
        assert result == 'test\\\\\\"both'

    def test_no_escaping_needed(self) -> None:
        """Should return unchanged string when no escaping needed."""
        # Act
        result = escape_applescript_string("normal string")

        # Assert
        assert result == "normal string"

    def test_empty_string(self) -> None:
        """Should handle empty string."""
        # Act
        result = escape_applescript_string("")

        # Assert
        assert result == ""

    def test_injection_attempt(self) -> None:
        """Should neutralize injection attempts."""
        # Arrange - attempt to break out of string and execute code
        malicious = 'test" & do shell script "rm -rf /"'

        # Act
        result = escape_applescript_string(malicious)

        # Assert - quotes should be escaped, preventing injection
        assert result == 'test\\" & do shell script \\"rm -rf /\\"'
        assert result.count('\\"') == 3

    def test_escapes_newlines(self) -> None:
        """Should replace newline characters with spaces."""
        # Act
        result = escape_applescript_string("line1\nline2\nline3")

        # Assert
        assert result == "line1 line2 line3"
        assert "\n" not in result

    def test_escapes_carriage_returns(self) -> None:
        """Should replace carriage return characters with spaces."""
        # Act
        result = escape_applescript_string("line1\rline2")

        # Assert
        assert result == "line1 line2"
        assert "\r" not in result

    def test_escapes_tabs(self) -> None:
        """Should replace tab characters with spaces."""
        # Act
        result = escape_applescript_string("col1\tcol2\tcol3")

        # Assert
        assert result == "col1 col2 col3"
        assert "\t" not in result

    def test_escapes_mixed_control_chars(self) -> None:
        """Should handle mixed control characters."""
        # Act
        result = escape_applescript_string("a\nb\rc\td")

        # Assert
        assert result == "a b c d"

    def test_control_chars_with_quotes(self) -> None:
        """Should escape control chars before quotes."""
        # Act
        result = escape_applescript_string('path\n"with quote"')

        # Assert - newline becomes space, then quotes are escaped
        assert result == 'path \\"with quote\\"'


# =============================================================================
# _parse_applescript_record Tests
# =============================================================================


class TestParseApplescriptRecord:
    """Tests for _parse_applescript_record function."""

    def test_parses_button_returned(self) -> None:
        """Should parse button returned value."""
        # Act
        result = _parse_applescript_record('{button returned:"Allow"}')

        # Assert
        assert result.get("button returned") == "Allow"

    def test_parses_gave_up(self) -> None:
        """Should parse gave up boolean."""
        # Act
        result = _parse_applescript_record('{button returned:"OK", gave up:true}')

        # Assert
        assert result.get("button returned") == "OK"
        assert result.get("gave up") == "true"

    def test_parses_gave_up_false(self) -> None:
        """Should parse gave up false."""
        # Act
        result = _parse_applescript_record('{button returned:"Allow", gave up:false}')

        # Assert
        assert result.get("gave up") == "false"

    def test_handles_empty_string(self) -> None:
        """Should return empty dict for empty string."""
        # Act
        result = _parse_applescript_record("")

        # Assert
        assert result == {}

    def test_handles_malformed_input(self) -> None:
        """Should return empty dict for malformed input."""
        # Act
        result = _parse_applescript_record("not a record")

        # Assert
        assert result == {}

    def test_handles_spacing_variations(self) -> None:
        """Should handle different spacing."""
        # Act
        result = _parse_applescript_record('{button returned: "Allow" , gave up: true}')

        # Assert
        assert result.get("button returned") == "Allow"
        assert result.get("gave up") == "true"


# =============================================================================
# HITLHandler Tests
# =============================================================================


class TestHITLHandler:
    """Tests for HITLHandler class."""

    @pytest.fixture
    def mock_config(self) -> MagicMock:
        """Create mock HITLConfig."""
        config = MagicMock()
        config.timeout_seconds = 30
        return config

    @pytest.fixture
    def mock_context(self) -> MagicMock:
        """Create mock DecisionContext."""
        context = MagicMock()
        context.resource.tool.name = "test_tool"
        context.resource.tool.side_effects = None
        context.resource.resource.path = "/test/path"
        context.subject.id = "test_user"
        context.environment.session_id = "session123"
        context.environment.request_id = "request456"
        return context

    def test_is_supported_on_macos(self, mock_config: MagicMock) -> None:
        """On macOS, is_supported should be True."""
        # Act
        with patch("mcp_acp.pep.hitl.sys.platform", "darwin"):
            handler = HITLHandler(mock_config)

            # Assert
            assert handler.is_supported is True

    def test_is_not_supported_on_non_macos(self, mock_config: MagicMock) -> None:
        """On non-macOS, is_supported should be False."""
        # Act
        with patch("mcp_acp.pep.hitl.sys.platform", "linux"):
            with patch("mcp_acp.pep.hitl.get_system_logger") as mock_logger:
                mock_logger.return_value = MagicMock()
                handler = HITLHandler(mock_config)

                # Assert
                assert handler.is_supported is False
                mock_logger.return_value.warning.assert_called_once()

    @pytest.mark.asyncio
    async def test_auto_denies_on_unsupported_platform(
        self, mock_config: MagicMock, mock_context: MagicMock
    ) -> None:
        """On unsupported platform, should auto-deny without showing dialog."""
        # Arrange
        with patch("mcp_acp.pep.hitl.sys.platform", "linux"):
            with patch("mcp_acp.pep.hitl.get_system_logger") as mock_logger:
                mock_logger.return_value = MagicMock()
                handler = HITLHandler(mock_config)

                # Act
                result = await handler.request_approval(mock_context)

                # Assert
                assert result.outcome == HITLOutcome.USER_DENIED
                assert result.response_time_ms == 0.0


# =============================================================================
# HITLResult Tests
# =============================================================================


class TestHITLResult:
    """Tests for HITLResult dataclass."""

    def test_creates_with_allowed_outcome(self) -> None:
        """Should create result with USER_ALLOWED outcome."""
        # Act
        result = HITLResult(outcome=HITLOutcome.USER_ALLOWED, response_time_ms=1500.0)

        # Assert
        assert result.outcome == HITLOutcome.USER_ALLOWED
        assert result.response_time_ms == 1500.0

    def test_creates_with_denied_outcome(self) -> None:
        """Should create result with USER_DENIED outcome."""
        # Act
        result = HITLResult(outcome=HITLOutcome.USER_DENIED, response_time_ms=500.0)

        # Assert
        assert result.outcome == HITLOutcome.USER_DENIED
        assert result.response_time_ms == 500.0

    def test_creates_with_timeout_outcome(self) -> None:
        """Should create result with TIMEOUT outcome."""
        # Act
        result = HITLResult(outcome=HITLOutcome.TIMEOUT, response_time_ms=30000.0)

        # Assert
        assert result.outcome == HITLOutcome.TIMEOUT
        assert result.response_time_ms == 30000.0


# =============================================================================
# HITLOutcome Tests
# =============================================================================


class TestHITLOutcome:
    """Tests for HITLOutcome enum."""

    def test_has_user_allowed(self) -> None:
        """Should have USER_ALLOWED value."""
        # Assert
        assert HITLOutcome.USER_ALLOWED.value == "user_allowed"

    def test_has_user_denied(self) -> None:
        """Should have USER_DENIED value."""
        # Assert
        assert HITLOutcome.USER_DENIED.value == "user_denied"

    def test_has_timeout(self) -> None:
        """Should have TIMEOUT value."""
        # Assert
        assert HITLOutcome.TIMEOUT.value == "timeout"


# =============================================================================
# DecisionEvent Tests
# =============================================================================


class TestDecisionEvent:
    """Tests for DecisionEvent Pydantic model."""

    def test_creates_minimal_event(self) -> None:
        """Should create event with minimal required fields."""
        # Act
        event = DecisionEvent(
            decision="allow",
            final_rule="test_rule",
            mcp_method="tools/call",
            backend_id="test-server",
            policy_version="v1",
            request_id="req123",
            policy_eval_ms=1.5,
            policy_total_ms=1.5,
        )

        # Assert
        assert event.decision == "allow"
        assert event.final_rule == "test_rule"
        assert event.mcp_method == "tools/call"
        assert event.policy_eval_ms == 1.5
        assert event.policy_total_ms == 1.5
        assert event.event == "policy_decision"

    def test_creates_full_event(self) -> None:
        """Should create event with all fields."""
        # Act
        event = DecisionEvent(
            decision="deny",
            matched_rules=[
                MatchedRuleLog(id="rule1", effect="deny", description="Block sensitive files"),
                MatchedRuleLog(id="rule2", effect="allow"),
            ],
            final_rule="rule1",
            mcp_method="tools/call",
            tool_name="read_file",
            path="/etc/passwd",
            uri="file:///etc/passwd",
            scheme="file",
            subject_id="test_user",
            backend_id="test-server",
            side_effects=["FS_READ"],
            policy_version="v1",
            policy_eval_ms=2.5,
            policy_hitl_ms=1500.0,
            policy_total_ms=1502.5,
            request_id="req123",
            session_id="sess456",
            hitl_outcome="user_allowed",
        )

        # Assert
        assert event.backend_id == "test-server"
        assert len(event.matched_rules) == 2
        assert event.matched_rules[0].id == "rule1"
        assert event.matched_rules[0].description == "Block sensitive files"
        assert event.side_effects == ["FS_READ"]
        assert event.hitl_outcome == "user_allowed"
        assert event.policy_hitl_ms == 1500.0

    def test_backend_id_field_exists(self) -> None:
        """Should have backend_id field for multi-server setups."""
        # Act
        event = DecisionEvent(
            decision="allow",
            final_rule="test",
            mcp_method="tools/call",
            backend_id="backend-1",
            policy_version="v1",
            request_id="req123",
            policy_eval_ms=1.0,
            policy_total_ms=1.0,
        )

        # Assert
        assert event.backend_id == "backend-1"

    def test_rejects_invalid_decision(self) -> None:
        """Should reject invalid decision values."""
        # Act & Assert
        with pytest.raises(ValueError):
            DecisionEvent(
                decision="invalid",  # type: ignore
                final_rule="test",
                mcp_method="tools/call",
                backend_id="test-server",
                policy_version="v1",
                request_id="req123",
                policy_eval_ms=1.0,
                policy_total_ms=1.0,
            )

    def test_rejects_extra_fields(self) -> None:
        """Should reject extra fields (extra='forbid')."""
        # Act & Assert
        with pytest.raises(ValueError):
            DecisionEvent(
                decision="allow",
                final_rule="test",
                mcp_method="tools/call",
                backend_id="test-server",
                policy_version="v1",
                request_id="req123",
                policy_eval_ms=1.0,
                policy_total_ms=1.0,
                unknown_field="value",  # type: ignore
            )

    def test_time_is_optional(self) -> None:
        """time field should be None by default (added by formatter)."""
        # Act
        event = DecisionEvent(
            decision="allow",
            final_rule="test",
            mcp_method="tools/call",
            backend_id="test-server",
            policy_version="v1",
            request_id="req123",
            policy_eval_ms=1.0,
            policy_total_ms=1.0,
        )

        # Assert
        assert event.time is None

    def test_model_dump_excludes_none(self) -> None:
        """model_dump with exclude_none should omit None fields."""
        # Arrange
        event = DecisionEvent(
            decision="allow",
            final_rule="test",
            mcp_method="tools/call",
            backend_id="test-server",
            policy_version="v1",
            request_id="req123",
            policy_eval_ms=1.0,
            policy_total_ms=1.0,
        )

        # Act
        data = event.model_dump(exclude_none=True)

        # Assert - optional fields should be excluded
        assert "tool_name" not in data
        assert "path" not in data
        assert "subject_id" not in data
        # Required fields should be present
        assert "backend_id" in data
        assert "policy_version" in data
        assert "request_id" in data


# =============================================================================
# PolicyEnforcementMiddleware Tests
# =============================================================================


class TestPolicyEnforcementMiddleware:
    """Tests for PolicyEnforcementMiddleware.

    These tests verify the core decision enforcement logic:
    - ALLOW → request proceeds
    - DENY → PermissionDeniedError raised
    - HITL → depends on user response
    - Discovery bypass → request proceeds without policy evaluation
    - Context build error → fail-secure (deny)
    """

    @pytest.fixture
    def mock_policy(self) -> MagicMock:
        """Create mock PolicyConfig."""
        return MagicMock()

    @pytest.fixture
    def mock_hitl_config(self) -> HITLConfig:
        """Create HITLConfig for tests."""
        return HITLConfig(timeout_seconds=30)

    @pytest.fixture
    def mock_identity_provider(self) -> MagicMock:
        """Create mock IdentityProvider with async get_identity."""
        provider = MagicMock()
        # get_identity is now async
        provider.get_identity = AsyncMock(return_value=MagicMock(subject_id="test_user"))
        return provider

    @pytest.fixture
    def mock_logger(self) -> MagicMock:
        """Create mock logger."""
        return MagicMock(spec=logging.Logger)

    @pytest.fixture
    def mock_middleware_context(self) -> MagicMock:
        """Create mock MiddlewareContext for tools/call."""
        context = MagicMock()
        context.method = "tools/call"
        context.message = MagicMock()
        context.message.model_dump.return_value = {
            "name": "read_file",
            "arguments": {"path": "/test/file.txt"},
        }
        return context

    @pytest.fixture
    def mock_discovery_context(self) -> MagicMock:
        """Create mock MiddlewareContext for discovery method."""
        context = MagicMock()
        context.method = "tools/list"
        context.message = MagicMock()
        context.message.model_dump.return_value = {}
        return context

    @pytest.fixture
    def middleware(
        self,
        mock_policy: MagicMock,
        mock_hitl_config: HITLConfig,
        mock_identity_provider: MagicMock,
        mock_logger: MagicMock,
    ) -> PolicyEnforcementMiddleware:
        """Create middleware instance with mocked dependencies."""
        return PolicyEnforcementMiddleware(
            policy=mock_policy,
            hitl_config=mock_hitl_config,
            protected_dirs=(),  # Empty for tests - no paths protected
            identity_provider=mock_identity_provider,
            backend_id="test-server",
            logger=mock_logger,
            shutdown_callback=lambda reason: None,  # No-op for tests
            policy_version="v1",
        )

    @pytest.mark.asyncio
    async def test_allow_decision_calls_next(
        self,
        middleware: PolicyEnforcementMiddleware,
        mock_middleware_context: MagicMock,
    ) -> None:
        """ALLOW decision should call next middleware and return result."""
        # Arrange
        call_next = AsyncMock(return_value={"result": "success"})

        with patch.object(middleware._engine, "evaluate", return_value=Decision.ALLOW):
            with patch("mcp_acp.pep.middleware.get_request_id", return_value="req123"):
                with patch("mcp_acp.pep.middleware.get_session_id", return_value="sess456"):
                    # Act
                    result = await middleware.on_message(mock_middleware_context, call_next)

        # Assert
        call_next.assert_called_once_with(mock_middleware_context)
        assert result == {"result": "success"}

    @pytest.mark.asyncio
    async def test_deny_decision_raises_permission_denied(
        self,
        middleware: PolicyEnforcementMiddleware,
        mock_middleware_context: MagicMock,
    ) -> None:
        """DENY decision should raise PermissionDeniedError."""
        # Arrange
        call_next = AsyncMock()

        with patch.object(middleware._engine, "evaluate", return_value=Decision.DENY):
            with patch.object(middleware._engine, "get_matching_rules", return_value=[]):
                with patch("mcp_acp.pep.middleware.get_request_id", return_value="req123"):
                    with patch(
                        "mcp_acp.pep.middleware.get_session_id",
                        return_value="sess456",
                    ):
                        # Act & Assert
                        with pytest.raises(PermissionDeniedError) as exc_info:
                            await middleware.on_message(mock_middleware_context, call_next)

        # Assert
        call_next.assert_not_called()
        assert exc_info.value.decision == Decision.DENY
        assert "Policy denied" in exc_info.value.message

    @pytest.mark.asyncio
    async def test_hitl_user_allowed_calls_next(
        self,
        middleware: PolicyEnforcementMiddleware,
        mock_middleware_context: MagicMock,
    ) -> None:
        """HITL with USER_ALLOWED should call next middleware."""
        # Arrange
        call_next = AsyncMock(return_value={"result": "success"})
        hitl_result = HITLResult(outcome=HITLOutcome.USER_ALLOWED, response_time_ms=1500.0)

        with patch.object(middleware._engine, "evaluate", return_value=Decision.HITL):
            with patch.object(
                middleware._hitl_handler,
                "request_approval",
                new_callable=AsyncMock,
                return_value=hitl_result,
            ):
                with patch("mcp_acp.pep.middleware.get_request_id", return_value="req123"):
                    with patch(
                        "mcp_acp.pep.middleware.get_session_id",
                        return_value="sess456",
                    ):
                        # Act
                        result = await middleware.on_message(mock_middleware_context, call_next)

        # Assert
        call_next.assert_called_once()
        assert result == {"result": "success"}

    @pytest.mark.asyncio
    async def test_hitl_user_denied_raises_permission_denied(
        self,
        middleware: PolicyEnforcementMiddleware,
        mock_middleware_context: MagicMock,
    ) -> None:
        """HITL with USER_DENIED should raise PermissionDeniedError."""
        # Arrange
        call_next = AsyncMock()
        hitl_result = HITLResult(outcome=HITLOutcome.USER_DENIED, response_time_ms=500.0)

        with patch.object(middleware._engine, "evaluate", return_value=Decision.HITL):
            with patch.object(
                middleware._hitl_handler,
                "request_approval",
                new_callable=AsyncMock,
                return_value=hitl_result,
            ):
                with patch.object(middleware._engine, "get_matching_rules", return_value=[]):
                    with patch(
                        "mcp_acp.pep.middleware.get_request_id",
                        return_value="req123",
                    ):
                        with patch(
                            "mcp_acp.pep.middleware.get_session_id",
                            return_value="sess456",
                        ):
                            # Act & Assert
                            with pytest.raises(PermissionDeniedError) as exc_info:
                                await middleware.on_message(mock_middleware_context, call_next)

        # Assert
        call_next.assert_not_called()
        assert "User denied" in exc_info.value.message

    @pytest.mark.asyncio
    async def test_hitl_timeout_raises_permission_denied(
        self,
        middleware: PolicyEnforcementMiddleware,
        mock_middleware_context: MagicMock,
    ) -> None:
        """HITL with TIMEOUT should raise PermissionDeniedError."""
        # Arrange
        call_next = AsyncMock()
        hitl_result = HITLResult(outcome=HITLOutcome.TIMEOUT, response_time_ms=30000.0)

        with patch.object(middleware._engine, "evaluate", return_value=Decision.HITL):
            with patch.object(
                middleware._hitl_handler,
                "request_approval",
                new_callable=AsyncMock,
                return_value=hitl_result,
            ):
                with patch.object(middleware._engine, "get_matching_rules", return_value=[]):
                    with patch(
                        "mcp_acp.pep.middleware.get_request_id",
                        return_value="req123",
                    ):
                        with patch(
                            "mcp_acp.pep.middleware.get_session_id",
                            return_value="sess456",
                        ):
                            # Act & Assert
                            with pytest.raises(PermissionDeniedError) as exc_info:
                                await middleware.on_message(mock_middleware_context, call_next)

        # Assert
        call_next.assert_not_called()
        assert "timeout" in exc_info.value.message.lower()

    @pytest.mark.asyncio
    async def test_discovery_bypass_calls_next_without_evaluation(
        self,
        middleware: PolicyEnforcementMiddleware,
        mock_discovery_context: MagicMock,
    ) -> None:
        """Discovery methods should bypass policy and call next."""
        # Arrange
        call_next = AsyncMock(return_value={"tools": []})

        with patch.object(middleware._engine, "evaluate", return_value=Decision.ALLOW) as mock_evaluate:
            with patch("mcp_acp.pep.middleware.get_request_id", return_value="req123"):
                with patch("mcp_acp.pep.middleware.get_session_id", return_value="sess456"):
                    # Act
                    result = await middleware.on_message(mock_discovery_context, call_next)

        # Assert - engine.evaluate is called but returns ALLOW for discovery
        call_next.assert_called_once()
        assert result == {"tools": []}

    @pytest.mark.asyncio
    async def test_context_build_error_raises_permission_denied(
        self,
        middleware: PolicyEnforcementMiddleware,
        mock_middleware_context: MagicMock,
    ) -> None:
        """Context build error should fail-secure with PermissionDeniedError."""
        # Arrange
        call_next = AsyncMock()

        with patch.object(
            middleware,
            "_build_context",
            side_effect=ValueError("Failed to build context"),
        ):
            with patch("mcp_acp.pep.middleware.get_request_id", return_value="req123"):
                with patch("mcp_acp.pep.middleware.get_session_id", return_value="sess456"):
                    # Act & Assert
                    with pytest.raises(PermissionDeniedError) as exc_info:
                        await middleware.on_message(mock_middleware_context, call_next)

        # Assert
        call_next.assert_not_called()
        assert exc_info.value.decision == Decision.DENY
        assert "Internal error" in exc_info.value.message

    @pytest.mark.asyncio
    async def test_decision_is_logged(
        self,
        middleware: PolicyEnforcementMiddleware,
        mock_middleware_context: MagicMock,
        mock_logger: MagicMock,
    ) -> None:
        """Decisions should be logged to the decision logger."""
        # Arrange
        call_next = AsyncMock(return_value={"result": "success"})

        with patch.object(middleware._engine, "evaluate", return_value=Decision.ALLOW):
            with patch("mcp_acp.pep.middleware.get_request_id", return_value="req123"):
                with patch("mcp_acp.pep.middleware.get_session_id", return_value="sess456"):
                    # Act
                    await middleware.on_message(mock_middleware_context, call_next)

        # Assert - logger.info should be called with decision event
        mock_logger.info.assert_called_once()
        logged_data = mock_logger.info.call_args[0][0]
        assert logged_data["decision"] == "allow"
        assert logged_data["mcp_method"] == "tools/call"

    @pytest.mark.asyncio
    async def test_client_name_extracted_from_initialize(
        self,
        middleware: PolicyEnforcementMiddleware,
    ) -> None:
        """Client name should be extracted and cached from initialize request."""
        # Arrange
        context = MagicMock()
        context.method = "initialize"
        context.message = MagicMock()
        context.message.params = MagicMock()
        context.message.params.clientInfo = MagicMock()
        context.message.params.clientInfo.name = "TestClient"
        context.message.params.clientInfo.version = "1.0.0"
        context.message.model_dump.return_value = {}

        call_next = AsyncMock(return_value={})

        with patch.object(middleware._engine, "evaluate", return_value=Decision.ALLOW):
            with patch("mcp_acp.pep.middleware.get_request_id", return_value="req123"):
                with patch("mcp_acp.pep.middleware.get_session_id", return_value="sess456"):
                    # Act
                    await middleware.on_message(context, call_next)

        # Assert
        assert middleware._client_name == "TestClient"


# =============================================================================
# Protected Path Tests
# =============================================================================


class TestProtectedPaths:
    """Tests for built-in protected path enforcement."""

    def test_is_protected_path_returns_false_for_none(self) -> None:
        """None path should not be protected."""
        from mcp_acp.pdp.engine import PolicyEngine
        from mcp_acp.pdp.policy import create_default_policy

        engine = PolicyEngine(
            create_default_policy(),
            protected_dirs=("/protected/dir",),
        )
        assert engine.is_protected_path(None) is False

    def test_is_protected_path_returns_false_for_empty_protected_dirs(self) -> None:
        """No protected dirs means nothing is protected."""
        from mcp_acp.pdp.engine import PolicyEngine
        from mcp_acp.pdp.policy import create_default_policy

        engine = PolicyEngine(
            create_default_policy(),
            protected_dirs=(),
        )
        assert engine.is_protected_path("/any/path") is False

    def test_is_protected_path_detects_exact_match(self, tmp_path: Any) -> None:
        """Exact match on protected dir should be detected."""
        from mcp_acp.pdp.engine import PolicyEngine
        from mcp_acp.pdp.policy import create_default_policy

        protected_dir = tmp_path / "protected"
        protected_dir.mkdir()

        engine = PolicyEngine(
            create_default_policy(),
            protected_dirs=(str(protected_dir),),
        )
        assert engine.is_protected_path(str(protected_dir)) is True

    def test_is_protected_path_detects_nested_path(self, tmp_path: Any) -> None:
        """Path inside protected dir should be detected."""
        from mcp_acp.pdp.engine import PolicyEngine
        from mcp_acp.pdp.policy import create_default_policy

        protected_dir = tmp_path / "protected"
        protected_dir.mkdir()
        nested_file = protected_dir / "config" / "policy.json"

        engine = PolicyEngine(
            create_default_policy(),
            protected_dirs=(str(protected_dir),),
        )
        assert engine.is_protected_path(str(nested_file)) is True

    def test_is_protected_path_allows_outside_path(self, tmp_path: Any) -> None:
        """Path outside protected dir should not be detected."""
        from mcp_acp.pdp.engine import PolicyEngine
        from mcp_acp.pdp.policy import create_default_policy

        protected_dir = tmp_path / "protected"
        protected_dir.mkdir()
        outside_file = tmp_path / "other" / "file.txt"

        engine = PolicyEngine(
            create_default_policy(),
            protected_dirs=(str(protected_dir),),
        )
        assert engine.is_protected_path(str(outside_file)) is False

    def test_is_protected_path_rejects_similar_prefix(self, tmp_path: Any) -> None:
        """Path with similar prefix should NOT be protected.

        /protected/dir_extra should not match /protected/dir
        This prevents false positives from simple startswith() matching.
        """
        from mcp_acp.pdp.engine import PolicyEngine
        from mcp_acp.pdp.policy import create_default_policy

        protected_dir = tmp_path / "config"
        protected_dir.mkdir()

        # Similar name but NOT under protected dir
        similar_dir = tmp_path / "config_backup"
        similar_dir.mkdir()
        (similar_dir / "policy.json").touch()

        engine = PolicyEngine(
            create_default_policy(),
            protected_dirs=(str(protected_dir),),
        )
        # This should NOT be protected - different directory
        assert engine.is_protected_path(str(similar_dir / "policy.json")) is False

    def test_is_protected_path_resolves_symlinks(self, tmp_path: Any) -> None:
        """Symlink pointing to protected dir should be detected."""
        import os

        from mcp_acp.pdp.engine import PolicyEngine
        from mcp_acp.pdp.policy import create_default_policy

        protected_dir = tmp_path / "protected"
        protected_dir.mkdir()
        (protected_dir / "secret.txt").touch()

        symlink = tmp_path / "sneaky_link"
        symlink.symlink_to(protected_dir)

        engine = PolicyEngine(
            create_default_policy(),
            protected_dirs=(str(protected_dir),),
        )
        # Access via symlink should still be detected as protected
        assert engine.is_protected_path(str(symlink / "secret.txt")) is True

    def test_evaluate_denies_protected_path(self, tmp_path: Any) -> None:
        """evaluate() should return DENY for protected paths."""
        from unittest.mock import MagicMock

        from mcp_acp.context import ActionCategory
        from mcp_acp.pdp.decision import Decision
        from mcp_acp.pdp.engine import PolicyEngine
        from mcp_acp.pdp.policy import create_default_policy

        protected_dir = tmp_path / "protected"
        protected_dir.mkdir()
        protected_file = protected_dir / "policy.json"

        engine = PolicyEngine(
            create_default_policy(),
            protected_dirs=(str(protected_dir),),
        )

        # Create mock context with protected path
        context = MagicMock()
        context.action.category = ActionCategory.ACTION
        context.resource.resource.path = str(protected_file)

        result = engine.evaluate(context)
        assert result == Decision.DENY

    def test_evaluate_allows_non_protected_path(self, tmp_path: Any) -> None:
        """evaluate() should evaluate policy for non-protected paths."""
        from unittest.mock import MagicMock

        from mcp_acp.context import ActionCategory
        from mcp_acp.pdp.decision import Decision
        from mcp_acp.pdp.engine import PolicyEngine
        from mcp_acp.pdp.policy import PolicyConfig, PolicyRule, RuleConditions

        protected_dir = tmp_path / "protected"
        protected_dir.mkdir()
        other_file = tmp_path / "other" / "file.txt"

        # Create policy that allows everything
        policy = PolicyConfig(
            version="1",
            default_action="deny",
            rules=[
                PolicyRule(
                    id="allow-all",
                    effect="allow",
                    conditions=RuleConditions(path_pattern="**"),
                ),
            ],
        )

        engine = PolicyEngine(
            policy,
            protected_dirs=(str(protected_dir),),
        )

        # Create mock context with non-protected path
        context = MagicMock()
        context.action.category = ActionCategory.ACTION
        context.resource.resource.path = str(other_file)
        context.resource.tool = None
        context.resource.server.id = "test"
        context.resource.type.value = "tool"
        context.action.mcp_method = "tools/call"
        context.subject.id = "user"

        result = engine.evaluate(context)
        assert result == Decision.ALLOW


# =============================================================================
# Approval Caching Tests
# =============================================================================


class TestApprovalCaching:
    """Tests for HITL approval caching in middleware."""

    @pytest.fixture
    def mock_policy_with_caching(self) -> MagicMock:
        """Create mock PolicyConfig."""
        return MagicMock()

    @pytest.fixture
    def mock_hitl_config_with_caching(self) -> HITLConfig:
        """Create HITLConfig with caching settings.

        Note: cache_side_effects has moved to per-rule policy configuration.
        """
        return HITLConfig(
            timeout_seconds=30,
            approval_ttl_seconds=600,
        )

    @pytest.fixture
    def mock_identity_provider(self) -> MagicMock:
        """Create mock IdentityProvider."""
        provider = MagicMock()
        provider.get_identity = AsyncMock(return_value=MagicMock(subject_id="test_user"))
        return provider

    @pytest.fixture
    def mock_logger(self) -> MagicMock:
        """Create mock logger."""
        return MagicMock(spec=logging.Logger)

    @pytest.fixture
    def mock_middleware_context(self) -> MagicMock:
        """Create mock MiddlewareContext."""
        context = MagicMock()
        context.method = "tools/call"
        context.message = MagicMock()
        context.message.model_dump.return_value = {
            "name": "list_files",
            "arguments": {"path": "/test"},
        }
        return context

    @pytest.fixture
    def middleware_with_caching(
        self,
        mock_policy_with_caching: MagicMock,
        mock_hitl_config_with_caching: HITLConfig,
        mock_identity_provider: MagicMock,
        mock_logger: MagicMock,
    ) -> PolicyEnforcementMiddleware:
        """Create middleware with caching enabled."""
        return PolicyEnforcementMiddleware(
            policy=mock_policy_with_caching,
            hitl_config=mock_hitl_config_with_caching,
            protected_dirs=(),
            identity_provider=mock_identity_provider,
            backend_id="test-server",
            logger=mock_logger,
            shutdown_callback=lambda reason: None,  # No-op for tests
            policy_version="v1",
        )

    def test_approval_store_property_exists(
        self,
        middleware_with_caching: PolicyEnforcementMiddleware,
    ) -> None:
        """Middleware should expose approval_store property."""
        from mcp_acp.pep.approval_store import ApprovalStore

        assert hasattr(middleware_with_caching, "approval_store")
        assert isinstance(middleware_with_caching.approval_store, ApprovalStore)

    def test_approval_store_uses_config_ttl(
        self,
        middleware_with_caching: PolicyEnforcementMiddleware,
    ) -> None:
        """Approval store should use TTL from policy config."""
        assert middleware_with_caching.approval_store.ttl_seconds == 600

    @pytest.mark.asyncio
    async def test_cached_approval_skips_hitl_dialog(
        self,
        middleware_with_caching: PolicyEnforcementMiddleware,
        mock_middleware_context: MagicMock,
    ) -> None:
        """Cached approval should skip HITL dialog and allow request."""
        # Arrange
        call_next = AsyncMock(return_value={"result": "success"})

        # Mock tool
        mock_tool = MagicMock()
        mock_tool.name = "list_files"
        mock_tool.side_effects = None

        # Mock decision context
        mock_decision_context = MagicMock()
        mock_decision_context.resource.tool = mock_tool
        mock_decision_context.resource.resource.path = "/test"
        mock_decision_context.resource.resource.uri = None
        mock_decision_context.resource.resource.scheme = None
        mock_decision_context.resource.resource.source_path = None
        mock_decision_context.resource.resource.dest_path = None
        mock_decision_context.subject.id = "test_user"
        mock_decision_context.action.mcp_method = "tools/call"
        mock_decision_context.action.category = MagicMock()
        mock_decision_context.environment.request_id = "req123"
        mock_decision_context.environment.session_id = "sess456"

        # Pre-populate cache
        middleware_with_caching.approval_store.store(
            subject_id="test_user",
            tool_name="list_files",
            path="/test",
            request_id="prev_req",
        )

        with patch.object(
            middleware_with_caching,
            "_build_context",
            new_callable=AsyncMock,
            return_value=mock_decision_context,
        ):
            with patch.object(middleware_with_caching._engine, "evaluate", return_value=Decision.HITL):
                with patch.object(middleware_with_caching._engine, "get_matching_rules", return_value=[]):
                    with patch.object(
                        middleware_with_caching._hitl_handler,
                        "request_approval",
                        new_callable=AsyncMock,
                    ) as mock_hitl:
                        with patch("mcp_acp.pep.middleware.get_request_id", return_value="req123"):
                            with patch(
                                "mcp_acp.pep.middleware.get_session_id",
                                return_value="sess456",
                            ):
                                # Act
                                result = await middleware_with_caching.on_message(
                                    mock_middleware_context, call_next
                                )

        # Assert - HITL dialog NOT called (cached approval used)
        mock_hitl.assert_not_called()
        call_next.assert_called_once()
        assert result == {"result": "success"}

    @pytest.mark.asyncio
    async def test_no_cache_hit_shows_dialog(
        self,
        middleware_with_caching: PolicyEnforcementMiddleware,
        mock_middleware_context: MagicMock,
    ) -> None:
        """Without cached approval, HITL dialog should be shown."""
        # Arrange
        call_next = AsyncMock(return_value={"result": "success"})
        hitl_result = HITLResult(outcome=HITLOutcome.USER_ALLOWED, response_time_ms=1500.0)

        # Mock tool
        mock_tool = MagicMock()
        mock_tool.name = "list_files"
        mock_tool.side_effects = None

        # Mock decision context
        mock_decision_context = MagicMock()
        mock_decision_context.resource.tool = mock_tool
        mock_decision_context.resource.resource.path = "/test"
        mock_decision_context.resource.resource.uri = None
        mock_decision_context.resource.resource.scheme = None
        mock_decision_context.resource.resource.source_path = None
        mock_decision_context.resource.resource.dest_path = None
        mock_decision_context.subject.id = "test_user"
        mock_decision_context.action.mcp_method = "tools/call"
        mock_decision_context.action.category = MagicMock()
        mock_decision_context.environment.request_id = "req123"
        mock_decision_context.environment.session_id = "sess456"

        with patch.object(
            middleware_with_caching,
            "_build_context",
            new_callable=AsyncMock,
            return_value=mock_decision_context,
        ):
            with patch.object(middleware_with_caching._engine, "evaluate", return_value=Decision.HITL):
                with patch.object(middleware_with_caching._engine, "get_matching_rules", return_value=[]):
                    with patch.object(
                        middleware_with_caching._hitl_handler,
                        "request_approval",
                        new_callable=AsyncMock,
                        return_value=hitl_result,
                    ) as mock_hitl:
                        with patch("mcp_acp.pep.middleware.get_request_id", return_value="req123"):
                            with patch(
                                "mcp_acp.pep.middleware.get_session_id",
                                return_value="sess456",
                            ):
                                # Act
                                result = await middleware_with_caching.on_message(
                                    mock_middleware_context, call_next
                                )

        # Assert - HITL dialog called
        mock_hitl.assert_called_once()
        call_next.assert_called_once()

    @pytest.mark.asyncio
    async def test_approval_stored_after_user_allows_no_side_effects(
        self,
        middleware_with_caching: PolicyEnforcementMiddleware,
        mock_middleware_context: MagicMock,
    ) -> None:
        """After user allows, approval should be cached for tools without side effects."""
        # Arrange
        call_next = AsyncMock(return_value={"result": "success"})
        hitl_result = HITLResult(outcome=HITLOutcome.USER_ALLOWED, response_time_ms=1500.0)

        # Tool with no side effects (should be cached)
        # Note: side_effects=[] means "no side effects" (cacheable)
        # side_effects=None means "unknown" (not cacheable for security)
        mock_tool = MagicMock()
        mock_tool.name = "list_files"
        mock_tool.side_effects = []

        # Mock decision context with tool that has no side effects
        mock_decision_context = MagicMock()
        mock_decision_context.resource.tool = mock_tool
        mock_decision_context.resource.resource.path = "/test"
        mock_decision_context.resource.resource.uri = None
        mock_decision_context.resource.resource.scheme = None
        mock_decision_context.resource.resource.source_path = None
        mock_decision_context.resource.resource.dest_path = None
        mock_decision_context.subject.id = "test_user"
        mock_decision_context.action.mcp_method = "tools/call"
        mock_decision_context.action.category = MagicMock()
        mock_decision_context.environment.request_id = "req123"
        mock_decision_context.environment.session_id = "sess456"

        assert middleware_with_caching.approval_store.count == 0

        with patch.object(
            middleware_with_caching,
            "_build_context",
            new_callable=AsyncMock,
            return_value=mock_decision_context,
        ):
            with patch.object(middleware_with_caching._engine, "evaluate", return_value=Decision.HITL):
                with patch.object(middleware_with_caching._engine, "get_matching_rules", return_value=[]):
                    with patch.object(
                        middleware_with_caching._hitl_handler,
                        "request_approval",
                        new_callable=AsyncMock,
                        return_value=hitl_result,
                    ):
                        with patch("mcp_acp.pep.middleware.get_request_id", return_value="req123"):
                            with patch(
                                "mcp_acp.pep.middleware.get_session_id",
                                return_value="sess456",
                            ):
                                # Act
                                await middleware_with_caching.on_message(mock_middleware_context, call_next)

        # Assert - approval was cached (tool had no side effects)
        assert middleware_with_caching.approval_store.count == 1

    @pytest.mark.asyncio
    async def test_approval_not_stored_for_side_effect_tools(
        self,
        mock_policy_with_caching: MagicMock,
        mock_hitl_config_with_caching: HITLConfig,
        mock_identity_provider: MagicMock,
        mock_logger: MagicMock,
    ) -> None:
        """Approvals for tools with side effects should NOT be cached by default."""
        from mcp_acp.context.resource import SideEffect

        # Create middleware
        middleware = PolicyEnforcementMiddleware(
            policy=mock_policy_with_caching,
            hitl_config=mock_hitl_config_with_caching,
            protected_dirs=(),
            identity_provider=mock_identity_provider,
            backend_id="test-server",
            logger=mock_logger,
            shutdown_callback=lambda reason: None,  # No-op for tests
            policy_version="v1",
        )

        # Arrange
        call_next = AsyncMock(return_value={"result": "success"})
        hitl_result = HITLResult(outcome=HITLOutcome.USER_ALLOWED, response_time_ms=1500.0)

        # Create mock context for tool with side effects
        mock_context = MagicMock()
        mock_context.method = "tools/call"
        mock_context.message = MagicMock()
        mock_context.message.model_dump.return_value = {
            "name": "write_file",
            "arguments": {"path": "/test/file.txt"},
        }

        # Mock tool with side effects
        mock_tool = MagicMock()
        mock_tool.name = "write_file"
        mock_tool.side_effects = frozenset({SideEffect.FS_WRITE})

        # Mock decision context
        mock_decision_context = MagicMock()
        mock_decision_context.resource.tool = mock_tool
        mock_decision_context.resource.resource.path = "/test/file.txt"
        mock_decision_context.resource.resource.uri = None
        mock_decision_context.resource.resource.scheme = None
        mock_decision_context.resource.resource.source_path = None
        mock_decision_context.resource.resource.dest_path = None
        mock_decision_context.subject.id = "test_user"
        mock_decision_context.action.mcp_method = "tools/call"
        mock_decision_context.action.category = MagicMock()
        mock_decision_context.environment.request_id = "req123"
        mock_decision_context.environment.session_id = "sess456"

        assert middleware.approval_store.count == 0

        with patch.object(
            middleware, "_build_context", new_callable=AsyncMock, return_value=mock_decision_context
        ):
            with patch.object(middleware._engine, "evaluate", return_value=Decision.HITL):
                with patch.object(middleware._engine, "get_matching_rules", return_value=[]):
                    with patch.object(
                        middleware._hitl_handler,
                        "request_approval",
                        new_callable=AsyncMock,
                        return_value=hitl_result,
                    ):
                        with patch("mcp_acp.pep.middleware.get_request_id", return_value="req123"):
                            with patch(
                                "mcp_acp.pep.middleware.get_session_id",
                                return_value="sess456",
                            ):
                                # Act
                                await middleware.on_message(mock_context, call_next)

        # Assert - approval was NOT cached (tool has side effects)
        assert middleware.approval_store.count == 0

    @pytest.mark.asyncio
    async def test_configurable_side_effects_can_be_cached(
        self,
        mock_identity_provider: MagicMock,
        mock_logger: MagicMock,
    ) -> None:
        """When cache_side_effects is configured on a rule, those effects can be cached."""
        from mcp_acp.context.resource import SideEffect
        from mcp_acp.pdp.engine import MatchedRule

        # Create policy and HITLConfig (cache_side_effects now per-rule, not in config)
        mock_policy = MagicMock()
        hitl_config = HITLConfig(
            timeout_seconds=30,
            approval_ttl_seconds=600,
        )

        # Create middleware
        middleware = PolicyEnforcementMiddleware(
            policy=mock_policy,
            hitl_config=hitl_config,
            protected_dirs=(),
            identity_provider=mock_identity_provider,
            backend_id="test-server",
            logger=mock_logger,
            shutdown_callback=lambda reason: None,  # No-op for tests
            policy_version="v1",
        )

        # Arrange
        call_next = AsyncMock(return_value={"result": "success"})
        hitl_result = HITLResult(outcome=HITLOutcome.USER_ALLOWED, response_time_ms=1500.0)

        # Create mock context
        mock_context = MagicMock()
        mock_context.method = "tools/call"
        mock_context.message = MagicMock()
        mock_context.message.model_dump.return_value = {
            "name": "read_file",
            "arguments": {"path": "/test/file.txt"},
        }

        # Mock tool with FS_READ side effect (allowed to cache via rule)
        mock_tool = MagicMock()
        mock_tool.name = "read_file"
        mock_tool.side_effects = frozenset({SideEffect.FS_READ})

        # Mock decision context
        mock_decision_context = MagicMock()
        mock_decision_context.resource.tool = mock_tool
        mock_decision_context.resource.resource.path = "/test/file.txt"
        mock_decision_context.resource.resource.uri = None
        mock_decision_context.resource.resource.scheme = None
        mock_decision_context.resource.resource.source_path = None
        mock_decision_context.resource.resource.dest_path = None
        mock_decision_context.subject.id = "test_user"
        mock_decision_context.action.mcp_method = "tools/call"
        mock_decision_context.action.category = MagicMock()
        mock_decision_context.environment.request_id = "req123"
        mock_decision_context.environment.session_id = "sess456"

        # Create a MatchedRule with cache_side_effects allowing FS_READ
        matched_rule = MatchedRule(
            id="hitl-rule-1",
            description="Allow read_file with HITL",
            effect="hitl",
            specificity=100,
            cache_side_effects=[SideEffect.FS_READ],
        )

        assert middleware.approval_store.count == 0

        with patch.object(
            middleware, "_build_context", new_callable=AsyncMock, return_value=mock_decision_context
        ):
            with patch.object(middleware._engine, "evaluate", return_value=Decision.HITL):
                with patch.object(middleware._engine, "get_matching_rules", return_value=[matched_rule]):
                    with patch.object(
                        middleware._hitl_handler,
                        "request_approval",
                        new_callable=AsyncMock,
                        return_value=hitl_result,
                    ):
                        with patch("mcp_acp.pep.middleware.get_request_id", return_value="req123"):
                            with patch(
                                "mcp_acp.pep.middleware.get_session_id",
                                return_value="sess456",
                            ):
                                # Act
                                await middleware.on_message(mock_context, call_next)

        # Assert - approval WAS cached (FS_READ is allowed via rule's cache_side_effects)
        assert middleware.approval_store.count == 1

    @pytest.mark.asyncio
    async def test_user_allowed_once_does_not_cache(
        self,
        middleware_with_caching: PolicyEnforcementMiddleware,
        mock_middleware_context: MagicMock,
    ) -> None:
        """USER_ALLOWED_ONCE should allow but NOT cache the approval."""
        # Arrange
        call_next = AsyncMock(return_value={"result": "success"})
        # User clicked "Allow once" instead of "Allow (cached)"
        hitl_result = HITLResult(outcome=HITLOutcome.USER_ALLOWED_ONCE, response_time_ms=1500.0)

        # Tool with no side effects (would normally be cached)
        mock_tool = MagicMock()
        mock_tool.name = "list_files"
        mock_tool.side_effects = None

        # Mock decision context
        mock_decision_context = MagicMock()
        mock_decision_context.resource.tool = mock_tool
        mock_decision_context.resource.resource.path = "/test"
        mock_decision_context.resource.resource.uri = None
        mock_decision_context.resource.resource.scheme = None
        mock_decision_context.resource.resource.source_path = None
        mock_decision_context.resource.resource.dest_path = None
        mock_decision_context.subject.id = "test_user"
        mock_decision_context.action.mcp_method = "tools/call"
        mock_decision_context.action.category = MagicMock()
        mock_decision_context.environment.request_id = "req123"
        mock_decision_context.environment.session_id = "sess456"

        assert middleware_with_caching.approval_store.count == 0

        with patch.object(
            middleware_with_caching,
            "_build_context",
            new_callable=AsyncMock,
            return_value=mock_decision_context,
        ):
            with patch.object(middleware_with_caching._engine, "evaluate", return_value=Decision.HITL):
                with patch.object(middleware_with_caching._engine, "get_matching_rules", return_value=[]):
                    with patch.object(
                        middleware_with_caching._hitl_handler,
                        "request_approval",
                        new_callable=AsyncMock,
                        return_value=hitl_result,
                    ):
                        with patch("mcp_acp.pep.middleware.get_request_id", return_value="req123"):
                            with patch(
                                "mcp_acp.pep.middleware.get_session_id",
                                return_value="sess456",
                            ):
                                # Act
                                result = await middleware_with_caching.on_message(
                                    mock_middleware_context, call_next
                                )

        # Assert - request succeeded but approval NOT cached
        call_next.assert_called_once()
        assert result == {"result": "success"}
        assert middleware_with_caching.approval_store.count == 0  # NOT cached
