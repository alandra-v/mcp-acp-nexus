"""Unit tests for logs command.

Tests CLI behavior using Click's CliRunner for isolated, fast testing.
Tests use the AAA pattern (Arrange-Act-Assert) for clarity.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from mcp_acp.cli import cli


@pytest.fixture
def runner() -> CliRunner:
    """Create a CLI runner for testing."""
    return CliRunner()


@pytest.fixture
def sample_decisions_log() -> str:
    """Return sample decision log entries."""
    entries = [
        {
            "time": "2024-01-15T10:30:00Z",
            "decision": "allow",
            "tool_name": "read_file",
            "final_rule": "rule-1",
        },
        {
            "time": "2024-01-15T10:30:05Z",
            "decision": "deny",
            "tool_name": "bash",
            "final_rule": "rule-2",
        },
        {
            "time": "2024-01-15T10:30:10Z",
            "decision": "hitl",
            "tool_name": "write_file",
            "final_rule": "rule-3",
        },
    ]
    return "\n".join(json.dumps(e) for e in entries)


@pytest.fixture
def sample_system_log() -> str:
    """Return sample system log entries."""
    entries = [
        {
            "time": "2024-01-15T10:30:00Z",
            "level": "INFO",
            "message": "Proxy started",
        },
        {
            "time": "2024-01-15T10:30:05Z",
            "level": "WARNING",
            "message": "Rate limit approaching",
        },
        {
            "time": "2024-01-15T10:30:10Z",
            "level": "ERROR",
            "message": "Connection failed",
        },
    ]
    return "\n".join(json.dumps(e) for e in entries)


@pytest.fixture
def mock_config() -> MagicMock:
    """Create a mock config object."""
    config = MagicMock()
    config.logging.log_dir = "/tmp/test-logs"
    return config


class TestLogsShowCommand:
    """Tests for logs show command (JSON output)."""

    def test_show_outputs_jsonl(
        self, runner: CliRunner, sample_decisions_log: str, mock_config: MagicMock
    ) -> None:
        """Given log file exists, outputs JSONL."""
        # Arrange
        with runner.isolated_filesystem() as tmpdir:
            log_path = Path(tmpdir) / "decisions.jsonl"
            log_path.write_text(sample_decisions_log)

            with patch(
                "mcp_acp.cli.commands.logs.load_config_or_exit",
                return_value=mock_config,
            ):
                with patch(
                    "mcp_acp.cli.commands.logs._get_log_path",
                    return_value=log_path,
                ):
                    # Act
                    result = runner.invoke(cli, ["logs", "show", "--type=decisions"])

        # Assert
        assert result.exit_code == 0
        lines = [l for l in result.output.strip().split("\n") if l]
        assert len(lines) == 3
        # Each line should be valid JSON
        for line in lines:
            data = json.loads(line)
            assert "decision" in data

    def test_show_respects_limit(
        self, runner: CliRunner, sample_decisions_log: str, mock_config: MagicMock
    ) -> None:
        """Given --limit flag, shows only that many entries."""
        # Arrange
        with runner.isolated_filesystem() as tmpdir:
            log_path = Path(tmpdir) / "decisions.jsonl"
            log_path.write_text(sample_decisions_log)

            with patch(
                "mcp_acp.cli.commands.logs.load_config_or_exit",
                return_value=mock_config,
            ):
                with patch(
                    "mcp_acp.cli.commands.logs._get_log_path",
                    return_value=log_path,
                ):
                    # Act
                    result = runner.invoke(cli, ["logs", "show", "--type=decisions", "--limit=1"])

        # Assert
        assert result.exit_code == 0
        lines = [l for l in result.output.strip().split("\n") if l]
        assert len(lines) == 1

    def test_show_missing_log_file(self, runner: CliRunner, mock_config: MagicMock) -> None:
        """Given missing log file, shows JSON error."""
        # Arrange
        with runner.isolated_filesystem() as tmpdir:
            log_path = Path(tmpdir) / "nonexistent.jsonl"

            with patch(
                "mcp_acp.cli.commands.logs.load_config_or_exit",
                return_value=mock_config,
            ):
                with patch(
                    "mcp_acp.cli.commands.logs._get_log_path",
                    return_value=log_path,
                ):
                    # Act
                    result = runner.invoke(cli, ["logs", "show", "--type=decisions"])

        # Assert
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "error" in data

    def test_show_empty_log_file(self, runner: CliRunner, mock_config: MagicMock) -> None:
        """Given empty log file, shows JSON with empty entries."""
        # Arrange
        with runner.isolated_filesystem() as tmpdir:
            log_path = Path(tmpdir) / "decisions.jsonl"
            log_path.write_text("")

            with patch(
                "mcp_acp.cli.commands.logs.load_config_or_exit",
                return_value=mock_config,
            ):
                with patch(
                    "mcp_acp.cli.commands.logs._get_log_path",
                    return_value=log_path,
                ):
                    # Act
                    result = runner.invoke(cli, ["logs", "show", "--type=decisions"])

        # Assert
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["entries"] == []

    def test_show_missing_config(self, runner: CliRunner) -> None:
        """Given missing config file, shows error."""
        # Arrange
        import click

        with runner.isolated_filesystem():
            with patch(
                "mcp_acp.cli.commands.logs.load_config_or_exit",
                side_effect=click.ClickException(
                    "Configuration not found at nonexistent.json\nRun 'mcp-acp init' to create configuration."
                ),
            ):
                # Act
                result = runner.invoke(cli, ["logs", "show", "--type=decisions"])

        # Assert
        assert result.exit_code == 1
        assert "not found" in result.output.lower() or "Configuration" in result.output

    def test_show_requires_type_flag(self, runner: CliRunner) -> None:
        """Given no --type flag, shows error."""
        # Act
        result = runner.invoke(cli, ["logs", "show"])

        # Assert
        assert result.exit_code == 2  # Click error for missing required option
        assert "--type" in result.output


class TestLogsListCommand:
    """Tests for logs list command."""

    def test_list_shows_available_types(self, runner: CliRunner, mock_config: MagicMock) -> None:
        """Given config, shows all log types."""
        # Arrange
        with runner.isolated_filesystem() as tmpdir:
            with patch(
                "mcp_acp.cli.commands.logs.load_config_or_exit",
                return_value=mock_config,
            ):
                with patch(
                    "mcp_acp.cli.commands.logs.get_decisions_log_path",
                    return_value=Path(tmpdir) / "decisions.jsonl",
                ):
                    with patch(
                        "mcp_acp.cli.commands.logs.get_audit_log_path",
                        return_value=Path(tmpdir) / "operations.jsonl",
                    ):
                        with patch(
                            "mcp_acp.cli.commands.logs.get_auth_log_path",
                            return_value=Path(tmpdir) / "auth.jsonl",
                        ):
                            with patch(
                                "mcp_acp.cli.commands.logs.get_system_log_path",
                                return_value=Path(tmpdir) / "system.jsonl",
                            ):
                                # Act
                                result = runner.invoke(cli, ["logs", "list"])

        # Assert
        assert result.exit_code == 0
        assert "decisions" in result.output
        assert "operations" in result.output
        assert "auth" in result.output
        assert "system" in result.output


class TestLogsTailCommand:
    """Tests for logs tail command."""

    def test_tail_requires_type_flag(self, runner: CliRunner) -> None:
        """Given no --type flag, shows error."""
        # Act
        result = runner.invoke(cli, ["logs", "tail"])

        # Assert
        assert result.exit_code == 2  # Click error for missing required option
        assert "--type" in result.output

    def test_tail_help_shows_options(self, runner: CliRunner) -> None:
        """Given logs tail --help, shows options."""
        # Act
        result = runner.invoke(cli, ["logs", "tail", "--help"])

        # Assert
        assert result.exit_code == 0
        assert "--type" in result.output


class TestLogsHelp:
    """Tests for logs command help."""

    def test_logs_help_shows_subcommands(self, runner: CliRunner) -> None:
        """Given logs --help, shows available subcommands."""
        # Act
        result = runner.invoke(cli, ["logs", "--help"])

        # Assert
        assert result.exit_code == 0
        assert "show" in result.output
        assert "tail" in result.output
        assert "list" in result.output

    def test_logs_show_help_shows_options(self, runner: CliRunner) -> None:
        """Given logs show --help, shows options."""
        # Act
        result = runner.invoke(cli, ["logs", "show", "--help"])

        # Assert
        assert result.exit_code == 0
        assert "--type" in result.output
        assert "--limit" in result.output


class TestLogsTypeValidation:
    """Tests for log type validation."""

    def test_show_invalid_type_shows_error(self, runner: CliRunner) -> None:
        """Given invalid log type, shows error."""
        # Act
        result = runner.invoke(cli, ["logs", "show", "--type=invalid"])

        # Assert
        assert result.exit_code == 2
        assert "invalid" in result.output.lower()

    @pytest.mark.parametrize("log_type", ["decisions", "operations", "auth", "system"])
    def test_show_valid_types_accepted(
        self, runner: CliRunner, log_type: str, mock_config: MagicMock
    ) -> None:
        """Given valid log types, command proceeds."""
        # Arrange
        with runner.isolated_filesystem() as tmpdir:
            log_path = Path(tmpdir) / f"{log_type}.jsonl"
            log_path.write_text("")

            with patch(
                "mcp_acp.cli.commands.logs.load_config_or_exit",
                return_value=mock_config,
            ):
                with patch(
                    "mcp_acp.cli.commands.logs._get_log_path",
                    return_value=log_path,
                ):
                    # Act
                    result = runner.invoke(cli, ["logs", "show", f"--type={log_type}"])

        # Assert - should not fail due to invalid type
        assert result.exit_code == 0
