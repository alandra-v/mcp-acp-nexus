"""Unit tests for approvals command.

Tests CLI behavior using Click's CliRunner for isolated, fast testing.
Tests use the AAA pattern (Arrange-Act-Assert) for clarity.
"""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from mcp_acp.cli import cli
from mcp_acp.cli.api_client import APIError, ProxyNotRunningError


@pytest.fixture
def runner() -> CliRunner:
    """Create a CLI runner for testing."""
    return CliRunner()


@pytest.fixture
def mock_cache_response() -> dict:
    """Return a typical cached approvals API response."""
    return {
        "count": 2,
        "ttl_seconds": 600,
        "approvals": [
            {
                "tool_name": "bash",
                "path": "/usr/bin/ls",
                "subject_id": "alice@example.com",
                "expires_in_seconds": 300,
            },
            {
                "tool_name": "read_file",
                "path": "/etc/passwd",
                "subject_id": "alice@example.com",
                "expires_in_seconds": 120,
            },
        ],
    }


@pytest.fixture
def mock_empty_cache_response() -> dict:
    """Return an empty cache response."""
    return {
        "count": 0,
        "ttl_seconds": 600,
        "approvals": [],
    }


class TestApprovalsCacheCommand:
    """Tests for approvals cache command."""

    def test_cache_shows_cached_approvals(self, runner: CliRunner, mock_cache_response: dict) -> None:
        """Given cached approvals, shows them with details."""
        # Arrange
        with patch(
            "mcp_acp.cli.commands.approvals.api_request",
            return_value=mock_cache_response,
        ):
            # Act
            result = runner.invoke(cli, ["approvals", "cache"])

        # Assert
        assert result.exit_code == 0
        assert "Cached approvals: 2" in result.output
        assert "bash" in result.output
        assert "read_file" in result.output

    def test_cache_shows_tool_paths(self, runner: CliRunner, mock_cache_response: dict) -> None:
        """Given cached approvals with paths, shows path info."""
        # Arrange
        with patch(
            "mcp_acp.cli.commands.approvals.api_request",
            return_value=mock_cache_response,
        ):
            # Act
            result = runner.invoke(cli, ["approvals", "cache"])

        # Assert
        assert result.exit_code == 0
        assert "Path:" in result.output
        assert "/usr/bin/ls" in result.output

    def test_cache_shows_expiry_time(self, runner: CliRunner, mock_cache_response: dict) -> None:
        """Given cached approvals, shows time until expiry."""
        # Arrange
        with patch(
            "mcp_acp.cli.commands.approvals.api_request",
            return_value=mock_cache_response,
        ):
            # Act
            result = runner.invoke(cli, ["approvals", "cache"])

        # Assert
        assert result.exit_code == 0
        assert "Expires in:" in result.output
        assert "5.0m" in result.output  # 300 seconds
        assert "2.0m" in result.output  # 120 seconds

    def test_cache_shows_entry_numbers(self, runner: CliRunner, mock_cache_response: dict) -> None:
        """Given cached approvals, shows numbered entries."""
        # Arrange
        with patch(
            "mcp_acp.cli.commands.approvals.api_request",
            return_value=mock_cache_response,
        ):
            # Act
            result = runner.invoke(cli, ["approvals", "cache"])

        # Assert
        assert result.exit_code == 0
        assert "[1]" in result.output
        assert "[2]" in result.output

    def test_cache_empty(self, runner: CliRunner, mock_empty_cache_response: dict) -> None:
        """Given empty cache, shows appropriate message."""
        # Arrange
        with patch(
            "mcp_acp.cli.commands.approvals.api_request",
            return_value=mock_empty_cache_response,
        ):
            # Act
            result = runner.invoke(cli, ["approvals", "cache"])

        # Assert
        assert result.exit_code == 0
        assert "No cached approvals" in result.output

    def test_cache_proxy_not_running(self, runner: CliRunner) -> None:
        """Given proxy not running, shows error."""
        # Arrange
        with patch(
            "mcp_acp.cli.commands.approvals.api_request",
            side_effect=ProxyNotRunningError(),
        ):
            # Act
            result = runner.invoke(cli, ["approvals", "cache"])

        # Assert
        assert result.exit_code == 1
        assert "not running" in result.output.lower()


class TestApprovalsCacheJsonOutput:
    """Tests for approvals cache --json flag."""

    def test_cache_json_output(self, runner: CliRunner, mock_cache_response: dict) -> None:
        """Given --json flag, outputs valid JSON."""
        # Arrange
        with patch(
            "mcp_acp.cli.commands.approvals.api_request",
            return_value=mock_cache_response,
        ):
            # Act
            result = runner.invoke(cli, ["approvals", "cache", "--json"])

        # Assert
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "count" in data
        assert "approvals" in data
        assert data["count"] == 2

    def test_cache_json_preserves_all_fields(self, runner: CliRunner, mock_cache_response: dict) -> None:
        """Given --json flag, preserves all approval fields."""
        # Arrange
        with patch(
            "mcp_acp.cli.commands.approvals.api_request",
            return_value=mock_cache_response,
        ):
            # Act
            result = runner.invoke(cli, ["approvals", "cache", "--json"])

        # Assert
        data = json.loads(result.output)
        approval = data["approvals"][0]
        assert "tool_name" in approval
        assert "path" in approval
        assert "subject_id" in approval
        assert "expires_in_seconds" in approval


class TestApprovalsClearCommand:
    """Tests for approvals clear command."""

    def test_clear_requires_flag(self, runner: CliRunner) -> None:
        """Given no flags, shows error."""
        # Act
        result = runner.invoke(cli, ["approvals", "clear"])

        # Assert
        assert result.exit_code == 1
        assert "--all" in result.output or "--entry" in result.output

    def test_clear_rejects_both_flags(self, runner: CliRunner) -> None:
        """Given both --all and --entry, shows error."""
        # Act
        result = runner.invoke(cli, ["approvals", "clear", "--all", "--entry=1"])

        # Assert
        assert result.exit_code == 1
        assert "Cannot use both" in result.output

    def test_clear_all_with_confirmation(self, runner: CliRunner, mock_cache_response: dict) -> None:
        """Given --all and confirmation, clears all approvals."""
        # Arrange
        with patch("mcp_acp.cli.commands.approvals.api_request") as mock_api:
            mock_api.side_effect = [
                mock_cache_response,  # GET for current cache
                {"cleared": 2},  # DELETE response
            ]

            # Act - confirm with 'y'
            result = runner.invoke(cli, ["approvals", "clear", "--all"], input="y\n")

        # Assert
        assert result.exit_code == 0
        assert "Cleared 2" in result.output

    def test_clear_all_cancelled(self, runner: CliRunner, mock_cache_response: dict) -> None:
        """Given --all but declined confirmation, cancels."""
        # Arrange
        with patch(
            "mcp_acp.cli.commands.approvals.api_request",
            return_value=mock_cache_response,
        ):
            # Act - decline with 'n'
            result = runner.invoke(cli, ["approvals", "clear", "--all"], input="n\n")

        # Assert
        assert result.exit_code == 0
        assert "Cancelled" in result.output

    def test_clear_all_with_default_yes(self, runner: CliRunner, mock_cache_response: dict) -> None:
        """Given --all and Enter (default yes), clears cache."""
        # Arrange
        with patch("mcp_acp.cli.commands.approvals.api_request") as mock_api:
            mock_api.side_effect = [
                mock_cache_response,
                {"cleared": 2},
            ]

            # Act - Enter accepts default (yes)
            result = runner.invoke(cli, ["approvals", "clear", "--all"], input="\n")

        # Assert
        assert result.exit_code == 0
        assert "Cleared 2" in result.output

    def test_clear_entry_valid_number(self, runner: CliRunner, mock_cache_response: dict) -> None:
        """Given valid --entry number and confirmation, clears that entry."""
        # Arrange
        with patch("mcp_acp.cli.commands.approvals.api_request") as mock_api:
            mock_api.side_effect = [
                mock_cache_response,
                {},  # DELETE response
            ]

            # Act - Enter accepts default (yes)
            result = runner.invoke(cli, ["approvals", "clear", "--entry=1"], input="\n")

        # Assert
        assert result.exit_code == 0
        assert "Cleared cached approval for 'bash'" in result.output

    def test_clear_entry_invalid_number_too_high(self, runner: CliRunner, mock_cache_response: dict) -> None:
        """Given --entry number too high, shows error."""
        # Arrange
        with patch(
            "mcp_acp.cli.commands.approvals.api_request",
            return_value=mock_cache_response,
        ):
            # Act
            result = runner.invoke(cli, ["approvals", "clear", "--entry=10"])

        # Assert
        assert result.exit_code == 1
        assert "Invalid entry" in result.output
        assert "1-2" in result.output

    def test_clear_entry_invalid_number_zero(self, runner: CliRunner, mock_cache_response: dict) -> None:
        """Given --entry=0, shows error."""
        # Arrange
        with patch(
            "mcp_acp.cli.commands.approvals.api_request",
            return_value=mock_cache_response,
        ):
            # Act
            result = runner.invoke(cli, ["approvals", "clear", "--entry=0"])

        # Assert
        assert result.exit_code == 1
        assert "Invalid entry" in result.output

    def test_clear_empty_cache(self, runner: CliRunner, mock_empty_cache_response: dict) -> None:
        """Given empty cache, shows appropriate message."""
        # Arrange
        with patch(
            "mcp_acp.cli.commands.approvals.api_request",
            return_value=mock_empty_cache_response,
        ):
            # Act
            result = runner.invoke(cli, ["approvals", "clear", "--all"])

        # Assert
        assert result.exit_code == 0
        assert "No cached approvals to clear" in result.output

    def test_clear_proxy_not_running(self, runner: CliRunner) -> None:
        """Given proxy not running, shows error."""
        # Arrange
        with patch(
            "mcp_acp.cli.commands.approvals.api_request",
            side_effect=ProxyNotRunningError(),
        ):
            # Act
            result = runner.invoke(cli, ["approvals", "clear", "--all"])

        # Assert
        assert result.exit_code == 1
        assert "not running" in result.output.lower()


class TestApprovalsHelp:
    """Tests for approvals command help."""

    def test_approvals_help_shows_subcommands(self, runner: CliRunner) -> None:
        """Given approvals --help, shows available subcommands."""
        # Act
        result = runner.invoke(cli, ["approvals", "--help"])

        # Assert
        assert result.exit_code == 0
        assert "cache" in result.output
        assert "clear" in result.output

    def test_approvals_clear_help_shows_options(self, runner: CliRunner) -> None:
        """Given approvals clear --help, shows options."""
        # Act
        result = runner.invoke(cli, ["approvals", "clear", "--help"])

        # Assert
        assert result.exit_code == 0
        assert "--all" in result.output
        assert "--entry" in result.output
