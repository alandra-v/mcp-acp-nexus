"""Unit tests for sessions command.

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
def mock_sessions_response() -> list:
    """Return a typical sessions API response."""
    return [
        {
            "session_id": "sess-abc123def456",
            "user_id": "alice@example.com",
            "started_at": "2024-01-15T10:30:00Z",
        },
        {
            "session_id": "sess-xyz789ghi012",
            "user_id": "bob@example.com",
            "started_at": "2024-01-15T11:45:00Z",
        },
    ]


class TestSessionsListCommand:
    """Tests for sessions list command."""

    def test_sessions_list_shows_active_sessions(
        self, runner: CliRunner, mock_sessions_response: list
    ) -> None:
        """Given active sessions, shows session list."""
        # Arrange
        with patch(
            "mcp_acp.cli.commands.sessions.api_request",
            return_value=mock_sessions_response,
        ):
            # Act
            result = runner.invoke(cli, ["sessions", "list", "--proxy", "test"])

        # Assert
        assert result.exit_code == 0
        assert "Active sessions: 2" in result.output
        assert "alice@example.com" in result.output
        assert "bob@example.com" in result.output

    def test_sessions_list_shows_timestamps(self, runner: CliRunner, mock_sessions_response: list) -> None:
        """Given sessions with timestamps, formats them nicely."""
        # Arrange
        with patch(
            "mcp_acp.cli.commands.sessions.api_request",
            return_value=mock_sessions_response,
        ):
            # Act
            result = runner.invoke(cli, ["sessions", "list", "--proxy", "test"])

        # Assert
        assert result.exit_code == 0
        assert "Started:" in result.output
        # Should format as readable date
        assert "2024-01-15" in result.output

    def test_sessions_list_truncates_long_ids(self, runner: CliRunner, mock_sessions_response: list) -> None:
        """Given long session IDs, truncates for display."""
        # Arrange
        with patch(
            "mcp_acp.cli.commands.sessions.api_request",
            return_value=mock_sessions_response,
        ):
            # Act
            result = runner.invoke(cli, ["sessions", "list", "--proxy", "test"])

        # Assert
        assert result.exit_code == 0
        # Long ID should be truncated with ...
        assert "sess-abc123d..." in result.output

    def test_sessions_list_empty(self, runner: CliRunner) -> None:
        """Given no active sessions, shows appropriate message."""
        # Arrange
        with patch(
            "mcp_acp.cli.commands.sessions.api_request",
            return_value=[],
        ):
            # Act
            result = runner.invoke(cli, ["sessions", "list", "--proxy", "test"])

        # Assert
        assert result.exit_code == 0
        assert "No active sessions" in result.output

    def test_sessions_list_proxy_not_running(self, runner: CliRunner) -> None:
        """Given proxy not running, shows error."""
        # Arrange
        with patch(
            "mcp_acp.cli.commands.sessions.api_request",
            side_effect=ProxyNotRunningError("test"),
        ):
            # Act
            result = runner.invoke(cli, ["sessions", "list", "--proxy", "test"])

        # Assert
        assert result.exit_code == 1
        assert "not running" in result.output.lower()

    def test_sessions_list_api_error(self, runner: CliRunner) -> None:
        """Given API error, shows error message."""
        # Arrange
        with patch(
            "mcp_acp.cli.commands.sessions.api_request",
            side_effect=APIError("Unauthorized", status_code=401),
        ):
            # Act
            result = runner.invoke(cli, ["sessions", "list", "--proxy", "test"])

        # Assert
        assert result.exit_code == 1
        assert "401" in result.output

    def test_sessions_list_requires_proxy_flag(self, runner: CliRunner) -> None:
        """Given no --proxy flag, shows error."""
        # Act
        result = runner.invoke(cli, ["sessions", "list"])

        # Assert
        assert result.exit_code == 2  # Click exits with 2 for missing required option


class TestSessionsListJsonOutput:
    """Tests for sessions list --json flag."""

    def test_sessions_list_json_output(self, runner: CliRunner, mock_sessions_response: list) -> None:
        """Given --json flag, outputs valid JSON array."""
        # Arrange
        with patch(
            "mcp_acp.cli.commands.sessions.api_request",
            return_value=mock_sessions_response,
        ):
            # Act
            result = runner.invoke(cli, ["sessions", "list", "--proxy", "test", "--json"])

        # Assert
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert len(data) == 2

    def test_sessions_list_json_preserves_all_fields(
        self, runner: CliRunner, mock_sessions_response: list
    ) -> None:
        """Given --json flag, preserves all session fields."""
        # Arrange
        with patch(
            "mcp_acp.cli.commands.sessions.api_request",
            return_value=mock_sessions_response,
        ):
            # Act
            result = runner.invoke(cli, ["sessions", "list", "--proxy", "test", "--json"])

        # Assert
        data = json.loads(result.output)
        session = data[0]
        assert "session_id" in session
        assert "user_id" in session
        assert "started_at" in session
        # Full ID, not truncated
        assert session["session_id"] == "sess-abc123def456"

    def test_sessions_list_json_empty_array(self, runner: CliRunner) -> None:
        """Given no sessions and --json flag, outputs empty array."""
        # Arrange
        with patch(
            "mcp_acp.cli.commands.sessions.api_request",
            return_value=[],
        ):
            # Act
            result = runner.invoke(cli, ["sessions", "list", "--proxy", "test", "--json"])

        # Assert
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data == []


class TestSessionsHelp:
    """Tests for sessions command help."""

    def test_sessions_help_shows_subcommands(self, runner: CliRunner) -> None:
        """Given sessions --help, shows available subcommands."""
        # Act
        result = runner.invoke(cli, ["sessions", "--help"])

        # Assert
        assert result.exit_code == 0
        assert "list" in result.output

    def test_sessions_list_help_shows_options(self, runner: CliRunner) -> None:
        """Given sessions list --help, shows options."""
        # Act
        result = runner.invoke(cli, ["sessions", "list", "--help"])

        # Assert
        assert result.exit_code == 0
        assert "--json" in result.output
