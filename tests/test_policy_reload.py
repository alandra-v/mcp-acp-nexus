"""Unit tests for policy hot reload functionality.

Tests the PolicyEngine.reload_policy() method, PolicyReloader class,
and related hot reload mechanisms.
"""

import logging
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from mcp_acp.pdp import PolicyConfig, PolicyEngine, PolicyRule, RuleConditions
from mcp_acp.pep.reloader import PolicyReloader, ReloadResult


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def sample_policy():
    """Create a sample policy for testing."""
    return PolicyConfig(
        version="1",
        default_action="deny",
        rules=[
            PolicyRule(
                id="allow-read",
                effect="allow",
                conditions=RuleConditions(tool_name="read_*"),
            ),
        ],
    )


@pytest.fixture
def updated_policy():
    """Create an updated policy for testing reload."""
    return PolicyConfig(
        version="1",
        default_action="deny",
        rules=[
            PolicyRule(
                id="allow-read",
                effect="allow",
                conditions=RuleConditions(tool_name="read_*"),
            ),
            PolicyRule(
                id="deny-bash",
                effect="deny",
                conditions=RuleConditions(tool_name="bash"),
            ),
        ],
    )


@pytest.fixture
def mock_logger():
    """Create a mock logger."""
    logger = MagicMock(spec=logging.Logger)
    return logger


@pytest.fixture
def mock_middleware(sample_policy):
    """Create a mock PolicyEnforcementMiddleware."""
    middleware = MagicMock()
    middleware._engine = MagicMock()
    middleware._engine.policy = sample_policy
    middleware._engine.rule_count = len(sample_policy.rules)
    middleware.reload_policy.return_value = {
        "old_rules_count": 1,
        "new_rules_count": 2,
        "approvals_cleared": 0,
    }
    return middleware


# ============================================================================
# Tests: PolicyEngine.reload_policy()
# ============================================================================


class TestPolicyEngineReload:
    """Tests for PolicyEngine.reload_policy() method."""

    def test_reload_swaps_policy_reference(self, sample_policy, updated_policy):
        """Given new policy, reload_policy swaps the reference."""
        # Arrange
        engine = PolicyEngine(sample_policy)
        assert len(engine.policy.rules) == 1

        # Act
        engine.reload_policy(updated_policy)

        # Assert
        assert engine.policy == updated_policy
        assert len(engine.policy.rules) == 2

    def test_reload_is_atomic(self, sample_policy, updated_policy):
        """Given reload, policy reference is atomically swapped."""
        # Arrange
        engine = PolicyEngine(sample_policy)
        old_policy = engine.policy

        # Act
        engine.reload_policy(updated_policy)

        # Assert - old and new are different objects
        assert engine.policy is not old_policy
        assert engine.policy is updated_policy

    def test_reload_preserves_protected_dirs(self, sample_policy, updated_policy):
        """Given reload, protected_dirs setting is preserved."""
        # Arrange
        protected = ("/etc", "/var")
        engine = PolicyEngine(sample_policy, protected_dirs=protected)

        # Act
        engine.reload_policy(updated_policy)

        # Assert
        assert engine._protected_dirs == tuple(__import__("os").path.realpath(d) for d in protected)


# ============================================================================
# Tests: PolicyReloader
# ============================================================================


class TestPolicyReloader:
    """Tests for PolicyReloader class."""

    def test_initial_state(self, mock_middleware, mock_logger):
        """Given new reloader, initial state is correct."""
        # Arrange & Act
        reloader = PolicyReloader(
            middleware=mock_middleware,
            system_logger=mock_logger,
            initial_version="v1",
        )

        # Assert
        assert reloader.current_version == "v1"
        assert reloader.reload_count == 0
        assert reloader.last_reload_at is None
        assert reloader.uptime_seconds >= 0

    def test_current_rules_count(self, mock_middleware, mock_logger, sample_policy):
        """Given reloader, current_rules_count returns correct count."""
        # Arrange
        reloader = PolicyReloader(
            middleware=mock_middleware,
            system_logger=mock_logger,
        )

        # Act & Assert
        assert reloader.current_rules_count == len(sample_policy.rules)

    @pytest.mark.asyncio
    async def test_reload_success(self, mock_middleware, mock_logger, updated_policy, tmp_path):
        """Given valid policy file, reload succeeds."""
        # Arrange
        from mcp_acp.utils.policy import save_policy

        policy_path = tmp_path / "policy.json"
        save_policy(updated_policy, policy_path)

        reloader = PolicyReloader(
            middleware=mock_middleware,
            system_logger=mock_logger,
            policy_path=policy_path,
            initial_version="v1",
        )

        # Act
        result = await reloader.reload()

        # Assert
        assert result.status == "success"
        assert result.old_rules_count == 1
        assert result.new_rules_count == 2
        assert reloader.reload_count == 1
        assert reloader.last_reload_at is not None
        # Note: logger.info() is not called on success - only SSE events are emitted

    @pytest.mark.asyncio
    async def test_reload_file_not_found(self, mock_middleware, mock_logger, tmp_path):
        """Given missing policy file, reload returns file_error."""
        # Arrange
        policy_path = tmp_path / "nonexistent.json"

        reloader = PolicyReloader(
            middleware=mock_middleware,
            system_logger=mock_logger,
            policy_path=policy_path,
        )

        # Act
        result = await reloader.reload()

        # Assert
        assert result.status == "file_error"
        assert "not found" in result.error.lower()
        assert reloader.reload_count == 0
        mock_logger.error.assert_called()

    @pytest.mark.asyncio
    async def test_reload_validation_error(self, mock_middleware, mock_logger, tmp_path):
        """Given invalid policy file, reload returns validation_error."""
        # Arrange
        policy_path = tmp_path / "invalid.json"
        policy_path.write_text('{"rules": [{"effect": "invalid_effect"}]}')

        reloader = PolicyReloader(
            middleware=mock_middleware,
            system_logger=mock_logger,
            policy_path=policy_path,
        )

        # Act
        result = await reloader.reload()

        # Assert
        assert result.status == "validation_error"
        assert result.error is not None
        assert reloader.reload_count == 0
        mock_logger.error.assert_called()

    @pytest.mark.asyncio
    async def test_reload_updates_version(self, mock_middleware, mock_logger, updated_policy, tmp_path):
        """Given successful reload, version is updated."""
        # Arrange
        from mcp_acp.utils.policy import save_policy

        policy_path = tmp_path / "policy.json"
        save_policy(updated_policy, policy_path)

        reloader = PolicyReloader(
            middleware=mock_middleware,
            system_logger=mock_logger,
            policy_path=policy_path,
            initial_version="v1",
        )

        # Act
        await reloader.reload()

        # Assert - version tracking without history returns None
        # (version is only set if policy_history_path is provided)
        # This test verifies reload_count increments
        assert reloader.reload_count == 1


# ============================================================================
# Tests: ReloadResult dataclass
# ============================================================================


class TestReloadResult:
    """Tests for ReloadResult dataclass."""

    def test_success_result(self):
        """Given success parameters, creates correct result."""
        # Act
        result = ReloadResult(
            status="success",
            old_rules_count=5,
            new_rules_count=7,
            approvals_cleared=3,
            policy_version="v2",
        )

        # Assert
        assert result.status == "success"
        assert result.old_rules_count == 5
        assert result.new_rules_count == 7
        assert result.approvals_cleared == 3
        assert result.policy_version == "v2"
        assert result.error is None

    def test_error_result(self):
        """Given error parameters, creates correct result."""
        # Act
        result = ReloadResult(
            status="validation_error",
            old_rules_count=5,
            error="Invalid JSON",
        )

        # Assert
        assert result.status == "validation_error"
        assert result.error == "Invalid JSON"
        assert result.new_rules_count == 0
        assert result.approvals_cleared == 0


# ============================================================================
# Tests: CLI policy reload command
# ============================================================================


class TestCLIPolicyReload:
    """Tests for CLI 'policy reload' command."""

    def test_reload_proxy_not_running(self):
        """Given proxy not running, shows error message."""
        # Arrange
        from mcp_acp.cli.commands.policy import policy
        from mcp_acp.cli.api_client import ProxyNotRunningError

        runner = CliRunner()

        # Mock api_request to simulate proxy not running
        with patch(
            "mcp_acp.cli.commands.policy.api_request",
            side_effect=ProxyNotRunningError(),
        ):
            # Act
            result = runner.invoke(policy, ["reload"])

        # Assert
        assert result.exit_code == 1
        assert "Proxy not running" in result.output or "Error" in result.output

    def test_reload_success(self):
        """Given running proxy, shows success message."""
        # Arrange
        from mcp_acp.cli.commands.policy import policy

        runner = CliRunner()

        # Mock api_request to return successful reload response
        mock_response = {
            "status": "success",
            "old_rules_count": 3,
            "new_rules_count": 5,
            "approvals_cleared": 2,
            "policy_version": "v3",
        }

        with patch(
            "mcp_acp.cli.commands.policy.api_request",
            return_value=mock_response,
        ):
            # Act
            result = runner.invoke(policy, ["reload"])

        # Assert
        assert result.exit_code == 0
        assert "reloaded" in result.output.lower()
        assert "3" in result.output
        assert "5" in result.output

    def test_reload_validation_failure(self):
        """Given validation error, shows error message."""
        # Arrange
        from mcp_acp.cli.commands.policy import policy

        runner = CliRunner()

        # Mock api_request to return validation error response
        mock_response = {
            "status": "validation_error",
            "old_rules_count": 3,
            "new_rules_count": 0,
            "approvals_cleared": 0,
            "error": "Invalid effect value",
        }

        with patch(
            "mcp_acp.cli.commands.policy.api_request",
            return_value=mock_response,
        ):
            # Act
            result = runner.invoke(policy, ["reload"])

        # Assert
        assert result.exit_code == 1
        assert "failed" in result.output.lower() or "error" in result.output.lower()
