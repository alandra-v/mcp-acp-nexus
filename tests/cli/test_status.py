"""Unit tests for status command.

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
def mock_status_response() -> dict:
    """Return a typical status API response."""
    return {
        "running": True,
        "uptime_seconds": 3725,
        "policy_version": "1.0.0",
        "policy_rules_count": 5,
        "reload_count": 2,
        "last_reload_at": "2024-01-15T10:30:00Z",
    }


@pytest.fixture
def mock_sessions_response() -> list:
    """Return a typical sessions API response."""
    return [
        {"session_id": "sess-123", "user_id": "user@example.com"},
        {"session_id": "sess-456", "user_id": "user@example.com"},
    ]


class TestStatusCommand:
    """Tests for status command."""

    def test_status_shows_running_proxy(
        self, runner: CliRunner, mock_status_response: dict, mock_sessions_response: list
    ):
        """Given running proxy, shows status information."""
        # Arrange
        with patch("mcp_acp.cli.commands.status.api_request") as mock_api:
            mock_api.side_effect = [mock_status_response, mock_sessions_response]

            # Act
            result = runner.invoke(cli, ["status"])

        # Assert
        assert result.exit_code == 0
        assert "Running" in result.output
        assert "Uptime" in result.output

    def test_status_shows_policy_info(
        self, runner: CliRunner, mock_status_response: dict, mock_sessions_response: list
    ):
        """Given running proxy, shows policy information."""
        # Arrange
        with patch("mcp_acp.cli.commands.status.api_request") as mock_api:
            mock_api.side_effect = [mock_status_response, mock_sessions_response]

            # Act
            result = runner.invoke(cli, ["status"])

        # Assert
        assert result.exit_code == 0
        assert "Policy" in result.output
        assert "Rules: 5" in result.output

    def test_status_shows_session_count(
        self, runner: CliRunner, mock_status_response: dict, mock_sessions_response: list
    ):
        """Given running proxy with sessions, shows session count."""
        # Arrange
        with patch("mcp_acp.cli.commands.status.api_request") as mock_api:
            mock_api.side_effect = [mock_status_response, mock_sessions_response]

            # Act
            result = runner.invoke(cli, ["status"])

        # Assert
        assert result.exit_code == 0
        assert "Sessions" in result.output
        assert "Active: 2" in result.output

    def test_status_proxy_not_running(self, runner: CliRunner):
        """Given proxy not running, shows error."""
        # Arrange
        with patch(
            "mcp_acp.cli.commands.status.api_request",
            side_effect=ProxyNotRunningError(),
        ):
            # Act
            result = runner.invoke(cli, ["status"])

        # Assert
        assert result.exit_code == 1
        assert "not running" in result.output.lower()

    def test_status_api_error(self, runner: CliRunner):
        """Given API error, shows error message."""
        # Arrange
        with patch(
            "mcp_acp.cli.commands.status.api_request",
            side_effect=APIError("Connection refused"),
        ):
            # Act
            result = runner.invoke(cli, ["status"])

        # Assert
        assert result.exit_code == 1
        assert "Connection refused" in result.output


class TestStatusJsonOutput:
    """Tests for status --json flag."""

    def test_status_json_output_structure(
        self, runner: CliRunner, mock_status_response: dict, mock_sessions_response: list
    ):
        """Given --json flag, outputs valid JSON."""
        # Arrange
        with patch("mcp_acp.cli.commands.status.api_request") as mock_api:
            mock_api.side_effect = [mock_status_response, mock_sessions_response]

            # Act
            result = runner.invoke(cli, ["status", "--json"])

        # Assert
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "running" in data
        assert "uptime_seconds" in data
        assert "policy" in data
        assert "auth_sessions" in data

    def test_status_json_includes_policy_details(
        self, runner: CliRunner, mock_status_response: dict, mock_sessions_response: list
    ):
        """Given --json flag, includes policy details."""
        # Arrange
        with patch("mcp_acp.cli.commands.status.api_request") as mock_api:
            mock_api.side_effect = [mock_status_response, mock_sessions_response]

            # Act
            result = runner.invoke(cli, ["status", "--json"])

        # Assert
        data = json.loads(result.output)
        assert data["policy"]["rules_count"] == 5
        assert data["policy"]["reload_count"] == 2

    def test_status_json_includes_session_count(
        self, runner: CliRunner, mock_status_response: dict, mock_sessions_response: list
    ):
        """Given --json flag, includes auth session count."""
        # Arrange
        with patch("mcp_acp.cli.commands.status.api_request") as mock_api:
            mock_api.side_effect = [mock_status_response, mock_sessions_response]

            # Act
            result = runner.invoke(cli, ["status", "--json"])

        # Assert
        data = json.loads(result.output)
        assert data["auth_sessions"]["active_count"] == 2


class TestStatusUptimeFormatting:
    """Tests for uptime display formatting."""

    @pytest.mark.parametrize(
        "uptime_seconds,expected_text",
        [
            (30, "30 seconds"),
            (90, "1.5 minutes"),
            (3600, "1.0 hours"),
            (7200, "2.0 hours"),
            (90000, "1.0 days"),
        ],
    )
    def test_uptime_formatting(
        self,
        runner: CliRunner,
        uptime_seconds: int,
        expected_text: str,
    ):
        """Given various uptimes, formats appropriately."""
        # Arrange
        status_response = {
            "running": True,
            "uptime_seconds": uptime_seconds,
        }

        with patch("mcp_acp.cli.commands.status.api_request") as mock_api:
            mock_api.side_effect = [status_response, []]

            # Act
            result = runner.invoke(cli, ["status"])

        # Assert
        assert result.exit_code == 0
        assert expected_text in result.output


class TestStatusSessionsErrorHandling:
    """Tests for graceful handling of sessions endpoint errors."""

    def test_status_continues_when_sessions_fails(self, runner: CliRunner, mock_status_response: dict):
        """Given sessions endpoint error, still shows status."""

        # Arrange
        def api_side_effect(method, endpoint):
            if "sessions" in endpoint:
                raise APIError("Sessions unavailable")
            return mock_status_response

        with patch(
            "mcp_acp.cli.commands.status.api_request",
            side_effect=api_side_effect,
        ):
            # Act
            result = runner.invoke(cli, ["status"])

        # Assert
        assert result.exit_code == 0
        assert "Running" in result.output
        assert "Active: 0" in result.output  # Falls back to 0
