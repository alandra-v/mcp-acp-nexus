"""Unit tests for CLI commands.

Tests CLI behavior using Click's CliRunner for isolated, fast testing.
Tests use the AAA pattern (Arrange-Act-Assert) for clarity.
"""

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from mcp_acp.cli import cli


@pytest.fixture
def runner() -> CliRunner:
    """Create a CLI runner for testing."""
    return CliRunner()


@pytest.fixture
def valid_config() -> dict:
    """Return a minimal valid configuration."""
    return {
        "logging": {"log_dir": "/tmp/test-logs", "log_level": "INFO"},
        "backend": {
            "server_name": "test-server",
            "stdio": {"command": "echo", "args": ["test"]},
        },
        "auth": {
            "oidc": {
                "issuer": "https://test.auth0.com",
                "client_id": "test-client-id",
                "audience": "https://test-api.example.com",
            }
        },
    }


from typing import Generator


@pytest.fixture
def isolated_config(runner: CliRunner, valid_config: dict) -> Generator[tuple[Path, dict], None, None]:
    """Create an isolated filesystem with a valid config file."""
    with runner.isolated_filesystem() as tmpdir:
        config_path = Path(tmpdir) / "config.json"
        config_path.write_text(json.dumps(valid_config, indent=2))
        yield config_path, valid_config


class TestVersion:
    """Tests for --version flag."""

    def test_version_flag_shows_version(self, runner: CliRunner) -> None:
        """Given --version flag, returns version string."""
        # Act
        result = runner.invoke(cli, ["--version"])

        # Assert
        assert result.exit_code == 0
        assert "mcp-acp" in result.output

    def test_short_version_flag(self, runner: CliRunner) -> None:
        """Given -v flag, returns version string."""
        # Act
        result = runner.invoke(cli, ["-v"])

        # Assert
        assert result.exit_code == 0
        assert "mcp-acp" in result.output


class TestHelp:
    """Tests for help output."""

    def test_root_help_shows_commands(self, runner: CliRunner) -> None:
        """Given --help, shows available commands."""
        # Act
        result = runner.invoke(cli, ["--help"])

        # Assert
        assert result.exit_code == 0
        assert "init" in result.output
        assert "start" in result.output
        assert "config" in result.output

    def test_config_help_shows_subcommands(self, runner: CliRunner) -> None:
        """Given config --help, shows subcommands."""
        # Act
        result = runner.invoke(cli, ["config", "--help"])

        # Assert
        assert result.exit_code == 0
        assert "show" in result.output
        assert "path" in result.output
        assert "edit" in result.output


class TestConfigPath:
    """Tests for config path command."""

    def test_config_path_returns_path(self, runner: CliRunner) -> None:
        """Given config path command, returns a path string."""
        # Act
        result = runner.invoke(cli, ["config", "path"])

        # Assert
        assert result.exit_code == 0
        assert "mcp-acp" in result.output


class TestConfigEdit:
    """Tests for config edit command."""

    def test_edit_missing_config_shows_error(self, runner: CliRunner) -> None:
        """Given no config file exists, shows helpful error."""
        # Arrange
        with runner.isolated_filesystem():
            with patch(
                "mcp_acp.cli.commands.config.get_config_path",
                return_value=Path("nonexistent.json"),
            ):
                # Act
                result = runner.invoke(cli, ["config", "edit"])

        # Assert
        assert result.exit_code == 1
        assert "not found" in result.output.lower()
        assert "init" in result.output  # Suggests running init

    def test_edit_cancelled_when_no_changes(self, runner: CliRunner, valid_config: dict) -> None:
        """Given user saves without changes, exits gracefully."""
        # Arrange
        with runner.isolated_filesystem() as tmpdir:
            config_path = Path(tmpdir) / "config.json"
            config_path.write_text(json.dumps(valid_config, indent=2))

            # Load config to get the exact content that will be shown in editor
            # (model_dump adds default fields like proxy.name)
            from mcp_acp.config import AppConfig

            loaded = AppConfig.load_from_files(config_path)
            editor_content = json.dumps(loaded.model_dump(), indent=2)

            with patch(
                "mcp_acp.cli.commands.config.get_config_path",
                return_value=config_path,
            ):
                # Mock click.edit to return unchanged content (exact same as shown)
                with patch("click.edit", return_value=editor_content):
                    with patch("click.pause"):  # Skip "Press Enter" prompt
                        # Act
                        result = runner.invoke(cli, ["config", "edit"])

        # Assert
        assert result.exit_code == 0
        assert "No changes made" in result.output

    def test_edit_cancelled_when_user_quits(self, runner: CliRunner, valid_config: dict) -> None:
        """Given user quits editor without saving, exits gracefully."""
        # Arrange
        with runner.isolated_filesystem() as tmpdir:
            config_path = Path(tmpdir) / "config.json"
            config_path.write_text(json.dumps(valid_config, indent=2))

            with patch(
                "mcp_acp.cli.commands.config.get_config_path",
                return_value=config_path,
            ):
                # Mock click.edit to return None (user quit)
                with patch("click.edit", return_value=None):
                    with patch("click.pause"):
                        # Act
                        result = runner.invoke(cli, ["config", "edit"])

        # Assert
        assert result.exit_code == 0
        assert "cancelled" in result.output.lower()

    @pytest.mark.parametrize(
        "invalid_json,expected_error",
        [
            ("{ invalid }", "Invalid JSON"),
            ('{"unclosed": "brace"', "Invalid JSON"),
            ("not json at all", "Invalid JSON"),
        ],
    )
    def test_edit_invalid_json_shows_error(
        self,
        runner: CliRunner,
        valid_config: dict,
        invalid_json: str,
        expected_error: str,
    ) -> None:
        """Given invalid JSON, shows error and offers re-edit."""
        # Arrange
        with runner.isolated_filesystem() as tmpdir:
            config_path = Path(tmpdir) / "config.json"
            config_path.write_text(json.dumps(valid_config, indent=2))

            with patch(
                "mcp_acp.cli.commands.config.get_config_path",
                return_value=config_path,
            ):
                with patch("click.edit", return_value=invalid_json):
                    with patch("click.pause"):
                        # Act - user declines re-edit
                        result = runner.invoke(cli, ["config", "edit"], input="n\n")

        # Assert
        assert result.exit_code == 1
        assert expected_error in result.output

    @pytest.mark.parametrize(
        "invalid_value,expected_error",
        [
            ({"logging": {"log_dir": "/tmp", "log_level": "INVALID"}}, "log_level"),
            ({"logging": {"log_dir": "", "log_level": "INFO"}}, "log_dir"),  # Empty string fails min_length
        ],
    )
    def test_edit_invalid_field_shows_error(
        self,
        runner: CliRunner,
        valid_config: dict,
        invalid_value: dict,
        expected_error: str,
    ) -> None:
        """Given valid JSON with invalid field values, shows validation error."""
        # Arrange - use valid_config fixture which includes auth
        with runner.isolated_filesystem() as tmpdir:
            config_path = Path(tmpdir) / "config.json"
            config_path.write_text(json.dumps(valid_config, indent=2))

            # Merge invalid values
            edited = {**valid_config, **invalid_value}
            edited_json = json.dumps(edited, indent=2)

            with patch(
                "mcp_acp.cli.commands.config.get_config_path",
                return_value=config_path,
            ):
                with patch("click.edit", return_value=edited_json):
                    with patch("click.pause"):
                        # Act - user declines re-edit
                        result = runner.invoke(cli, ["config", "edit"], input="n\n")

        # Assert
        assert result.exit_code == 1
        assert expected_error in result.output.lower()

    def test_edit_preserves_user_formatting(self, runner: CliRunner, valid_config: dict) -> None:
        """Given valid edit, preserves user's JSON formatting."""
        # Arrange
        with runner.isolated_filesystem() as tmpdir:
            config_path = Path(tmpdir) / "config.json"
            config_path.write_text(json.dumps(valid_config, indent=2))

            # User adds extra spacing and changes a value
            edited_config = valid_config.copy()
            edited_config["logging"] = {**valid_config["logging"], "log_level": "DEBUG"}
            # Custom formatting with extra newlines
            user_formatted = json.dumps(edited_config, indent=4)  # 4-space indent

            with patch(
                "mcp_acp.cli.commands.config.get_config_path",
                return_value=config_path,
            ):
                with patch(
                    "mcp_acp.cli.commands.config.get_config_history_path",
                    return_value=Path(tmpdir) / "history.jsonl",
                ):
                    with patch("click.edit", return_value=user_formatted):
                        with patch("click.pause"):
                            # Act
                            result = runner.invoke(cli, ["config", "edit"])

            # Assert
            assert result.exit_code == 0
            saved_content = config_path.read_text()
            # Should preserve 4-space indent, not reformat to 2-space
            assert "    " in saved_content  # 4-space indent preserved

    def test_edit_creates_backup_before_save(self, runner: CliRunner, valid_config: dict) -> None:
        """Given successful edit, backup is created then removed."""
        # Arrange
        with runner.isolated_filesystem() as tmpdir:
            config_path = Path(tmpdir) / "config.json"
            config_path.write_text(json.dumps(valid_config, indent=2))
            backup_path = config_path.with_suffix(".json.bak")

            edited_config = {**valid_config}
            edited_config["logging"]["log_level"] = "DEBUG"
            edited_json = json.dumps(edited_config, indent=2)

            with patch(
                "mcp_acp.cli.commands.config.get_config_path",
                return_value=config_path,
            ):
                with patch(
                    "mcp_acp.cli.commands.config.get_config_history_path",
                    return_value=Path(tmpdir) / "history.jsonl",
                ):
                    with patch("click.edit", return_value=edited_json):
                        with patch("click.pause"):
                            # Act
                            result = runner.invoke(cli, ["config", "edit"])

            # Assert
            assert result.exit_code == 0
            # Backup should be removed after successful save
            assert not backup_path.exists()


class TestStartCorruptConfig:
    """Tests for start command handling of corrupt configs."""

    def test_start_corrupt_json_shows_error(self, runner: CliRunner) -> None:
        """Given corrupt JSON config, shows clear error."""
        # Arrange
        with runner.isolated_filesystem() as tmpdir:
            config_path = Path(tmpdir) / "config.json"
            config_path.write_text("{ not valid json }")

            with (
                patch(
                    "mcp_acp.cli.commands.start.get_config_path",
                    return_value=config_path,
                ),
                patch("mcp_acp.cli.commands.start.show_startup_error_popup"),
            ):
                # Act
                result = runner.invoke(cli, ["start"])

        # Assert
        assert result.exit_code == 1
        assert "Invalid" in result.output

    def test_start_corrupt_json_with_backup_shows_restore_hint(self, runner: CliRunner) -> None:
        """Given corrupt config with backup file, shows restore command."""
        # Arrange
        with runner.isolated_filesystem() as tmpdir:
            config_path = Path(tmpdir) / "config.json"
            backup_path = config_path.with_suffix(".json.bak")

            config_path.write_text("{ corrupt }")
            backup_path.write_text('{"valid": "backup"}')

            with (
                patch(
                    "mcp_acp.cli.commands.start.get_config_path",
                    return_value=config_path,
                ),
                patch("mcp_acp.cli.commands.start.show_startup_error_popup"),
            ):
                # Act
                result = runner.invoke(cli, ["start"])

        # Assert
        assert result.exit_code == 1
        assert "backup" in result.output.lower()
        assert "restore" in result.output.lower() or "cp" in result.output

    def test_start_invalid_field_no_backup_hint(self, runner: CliRunner) -> None:
        """Given valid JSON with invalid field (not corrupt), no backup hint."""
        # Arrange
        invalid_config = {
            "logging": {"log_dir": "/tmp", "log_level": "INVALID"},
            "backend": {"server_name": "test"},
        }

        with runner.isolated_filesystem() as tmpdir:
            config_path = Path(tmpdir) / "config.json"
            backup_path = config_path.with_suffix(".json.bak")

            config_path.write_text(json.dumps(invalid_config))
            backup_path.write_text('{"some": "backup"}')  # Backup exists

            with (
                patch(
                    "mcp_acp.cli.commands.start.get_config_path",
                    return_value=config_path,
                ),
                patch("mcp_acp.cli.commands.start.show_startup_error_popup"),
            ):
                # Act
                result = runner.invoke(cli, ["start"])

        # Assert
        assert result.exit_code == 1
        # Should NOT show backup hint for validation errors (not corruption)
        assert "backup" not in result.output.lower()


class TestInitCommand:
    """Tests for init command."""

    def test_init_non_interactive_missing_log_dir_shows_error(self, runner: CliRunner) -> None:
        """Given --non-interactive without --log-dir, shows error."""
        # Arrange - use isolated filesystem to avoid existing file conflicts
        with runner.isolated_filesystem() as tmpdir:
            config_path = Path(tmpdir) / "config.json"
            policy_path = Path(tmpdir) / "policy.json"

            with patch(
                "mcp_acp.cli.commands.init.get_config_path",
                return_value=config_path,
            ):
                with patch(
                    "mcp_acp.cli.commands.init.get_policy_path",
                    return_value=policy_path,
                ):
                    # Act
                    result = runner.invoke(
                        cli,
                        [
                            "init",
                            "--non-interactive",
                            "--server-name",
                            "test",
                            "--connection-type",
                            "stdio",
                            "--command",
                            "echo",
                            "--args",
                            "test",
                        ],
                    )

        # Assert
        assert result.exit_code == 1
        assert "--log-dir" in result.output.lower() or "log-dir" in result.output.lower()

    def test_init_non_interactive_missing_server_name_shows_error(self, runner: CliRunner) -> None:
        """Given --non-interactive without --server-name, shows error."""
        # Arrange - use isolated filesystem to avoid existing file conflicts
        with runner.isolated_filesystem() as tmpdir:
            config_path = Path(tmpdir) / "config.json"
            policy_path = Path(tmpdir) / "policy.json"
            log_dir = Path(tmpdir) / "logs"

            with patch(
                "mcp_acp.cli.commands.init.get_config_path",
                return_value=config_path,
            ):
                with patch(
                    "mcp_acp.cli.commands.init.get_policy_path",
                    return_value=policy_path,
                ):
                    # Act
                    result = runner.invoke(
                        cli,
                        [
                            "init",
                            "--non-interactive",
                            "--log-dir",
                            str(log_dir),
                            "--connection-type",
                            "stdio",
                            "--command",
                            "echo",
                            "--args",
                            "test",
                        ],
                    )

        # Assert
        assert result.exit_code == 1
        assert "--server-name" in result.output.lower() or "server-name" in result.output.lower()

    def test_init_non_interactive_missing_connection_type_shows_error(self, runner: CliRunner) -> None:
        """Given --non-interactive without --connection-type, shows error."""
        # Arrange - use isolated filesystem to avoid existing file conflicts
        with runner.isolated_filesystem() as tmpdir:
            config_path = Path(tmpdir) / "config.json"
            policy_path = Path(tmpdir) / "policy.json"
            log_dir = Path(tmpdir) / "logs"

            with patch(
                "mcp_acp.cli.commands.init.get_config_path",
                return_value=config_path,
            ):
                with patch(
                    "mcp_acp.cli.commands.init.get_policy_path",
                    return_value=policy_path,
                ):
                    # Act
                    result = runner.invoke(
                        cli,
                        [
                            "init",
                            "--non-interactive",
                            "--log-dir",
                            str(log_dir),
                            "--server-name",
                            "test",
                        ],
                    )

        # Assert
        assert result.exit_code == 1
        assert "--connection-type" in result.output.lower() or "connection-type" in result.output.lower()

    def test_init_non_interactive_stdio_missing_command_shows_error(self, runner: CliRunner) -> None:
        """Given stdio connection without --command, shows error."""
        # Arrange - use isolated filesystem to avoid existing file conflicts
        with runner.isolated_filesystem() as tmpdir:
            config_path = Path(tmpdir) / "config.json"
            policy_path = Path(tmpdir) / "policy.json"
            log_dir = Path(tmpdir) / "logs"

            with patch(
                "mcp_acp.cli.commands.init.get_config_path",
                return_value=config_path,
            ):
                with patch(
                    "mcp_acp.cli.commands.init.get_policy_path",
                    return_value=policy_path,
                ):
                    # Act
                    result = runner.invoke(
                        cli,
                        [
                            "init",
                            "--non-interactive",
                            "--log-dir",
                            str(log_dir),
                            "--server-name",
                            "test",
                            "--connection-type",
                            "stdio",
                            "--args",
                            "test",
                            # OIDC flags (required for Zero Trust)
                            "--oidc-issuer",
                            "https://test.auth0.com",
                            "--oidc-client-id",
                            "test-client",
                            "--oidc-audience",
                            "https://api.example.com",
                        ],
                    )

        # Assert
        assert result.exit_code == 1
        assert "--command" in result.output.lower() or "command" in result.output.lower()

    def test_init_non_interactive_http_missing_url_shows_error(self, runner: CliRunner) -> None:
        """Given http connection without --url, shows error."""
        # Arrange - use isolated filesystem to avoid existing file conflicts
        with runner.isolated_filesystem() as tmpdir:
            config_path = Path(tmpdir) / "config.json"
            policy_path = Path(tmpdir) / "policy.json"
            log_dir = Path(tmpdir) / "logs"

            with patch(
                "mcp_acp.cli.commands.init.get_config_path",
                return_value=config_path,
            ):
                with patch(
                    "mcp_acp.cli.commands.init.get_policy_path",
                    return_value=policy_path,
                ):
                    # Act
                    result = runner.invoke(
                        cli,
                        [
                            "init",
                            "--non-interactive",
                            "--log-dir",
                            str(log_dir),
                            "--server-name",
                            "test",
                            "--connection-type",
                            "http",
                            # OIDC flags (required for Zero Trust)
                            "--oidc-issuer",
                            "https://test.auth0.com",
                            "--oidc-client-id",
                            "test-client",
                            "--oidc-audience",
                            "https://api.example.com",
                        ],
                    )

        # Assert
        assert result.exit_code == 1
        assert "--url" in result.output.lower() or "url" in result.output.lower()

    def test_init_non_interactive_stdio_creates_config(self, runner: CliRunner) -> None:
        """Given valid stdio flags, creates config file."""
        # Arrange
        with runner.isolated_filesystem() as tmpdir:
            config_path = Path(tmpdir) / "config.json"
            policy_path = Path(tmpdir) / "policy.json"
            log_dir = Path(tmpdir) / "logs"

            with patch(
                "mcp_acp.cli.commands.init.get_config_path",
                return_value=config_path,
            ):
                with patch(
                    "mcp_acp.cli.commands.init.get_policy_path",
                    return_value=policy_path,
                ):
                    # Act
                    result = runner.invoke(
                        cli,
                        [
                            "init",
                            "--non-interactive",
                            "--log-dir",
                            str(log_dir),
                            "--server-name",
                            "test-server",
                            "--connection-type",
                            "stdio",
                            "--command",
                            "echo",
                            "--args",
                            "arg1,arg2",
                            # OIDC flags (required for Zero Trust)
                            "--oidc-issuer",
                            "https://test.auth0.com",
                            "--oidc-client-id",
                            "test-client",
                            "--oidc-audience",
                            "https://api.example.com",
                        ],
                    )

            # Assert
            assert result.exit_code == 0
            assert config_path.exists()
            assert policy_path.exists()

            # Verify config content
            import json

            config = json.loads(config_path.read_text())
            assert config["backend"]["server_name"] == "test-server"
            assert config["backend"]["stdio"]["command"] == "echo"
            assert config["backend"]["stdio"]["args"] == ["arg1", "arg2"]
            assert config["auth"]["oidc"]["issuer"] == "https://test.auth0.com"

    def test_init_non_interactive_http_creates_config(self, runner: CliRunner) -> None:
        """Given valid http flags, creates config file."""
        # Arrange
        with runner.isolated_filesystem() as tmpdir:
            config_path = Path(tmpdir) / "config.json"
            policy_path = Path(tmpdir) / "policy.json"
            log_dir = Path(tmpdir) / "logs"

            with patch(
                "mcp_acp.cli.commands.init.get_config_path",
                return_value=config_path,
            ):
                with patch(
                    "mcp_acp.cli.commands.init.get_policy_path",
                    return_value=policy_path,
                ):
                    with patch(
                        "mcp_acp.cli.commands.init.check_http_health",
                        side_effect=ConnectionError("Server offline"),
                    ):
                        # Act
                        result = runner.invoke(
                            cli,
                            [
                                "init",
                                "--non-interactive",
                                "--log-dir",
                                str(log_dir),
                                "--server-name",
                                "test-server",
                                "--connection-type",
                                "http",
                                "--url",
                                "http://localhost:3000/mcp",
                                "--timeout",
                                "60",
                                # OIDC flags (required for Zero Trust)
                                "--oidc-issuer",
                                "https://test.auth0.com",
                                "--oidc-client-id",
                                "test-client",
                                "--oidc-audience",
                                "https://api.example.com",
                            ],
                        )

            # Assert
            assert result.exit_code == 0
            assert config_path.exists()

            # Verify config content
            import json

            config = json.loads(config_path.read_text())
            assert config["backend"]["server_name"] == "test-server"
            assert config["backend"]["http"]["url"] == "http://localhost:3000/mcp"
            assert config["backend"]["http"]["timeout"] == 60
            assert config["auth"]["oidc"]["issuer"] == "https://test.auth0.com"

    def test_init_existing_files_without_force_fails(self, runner: CliRunner) -> None:
        """Given existing files without --force in non-interactive mode, fails."""
        # Arrange
        with runner.isolated_filesystem() as tmpdir:
            config_path = Path(tmpdir) / "config.json"
            config_path.write_text("{}")

            with patch(
                "mcp_acp.cli.commands.init.get_config_path",
                return_value=config_path,
            ):
                with patch(
                    "mcp_acp.cli.commands.init.get_policy_path",
                    return_value=Path(tmpdir) / "policy.json",
                ):
                    # Act
                    result = runner.invoke(
                        cli,
                        [
                            "init",
                            "--non-interactive",
                            "--log-dir",
                            "/tmp/test",
                            "--server-name",
                            "test",
                            "--connection-type",
                            "stdio",
                            "--command",
                            "echo",
                            "--args",
                            "test",
                            # OIDC flags (required for Zero Trust)
                            "--oidc-issuer",
                            "https://test.auth0.com",
                            "--oidc-client-id",
                            "test-client",
                            "--oidc-audience",
                            "https://api.example.com",
                        ],
                    )

        # Assert
        assert result.exit_code == 1
        assert "--force" in result.output.lower() or "exist" in result.output.lower()

    def test_init_existing_files_with_force_succeeds(self, runner: CliRunner) -> None:
        """Given existing files with --force, overwrites successfully."""
        # Arrange
        with runner.isolated_filesystem() as tmpdir:
            config_path = Path(tmpdir) / "config.json"
            policy_path = Path(tmpdir) / "policy.json"
            # Create both files to avoid hitting the upgrade path (config-only scenario)
            config_path.write_text('{"old": "config"}')
            policy_path.write_text('{"old": "policy"}')
            log_dir = Path(tmpdir) / "logs"

            with patch(
                "mcp_acp.cli.commands.init.get_config_path",
                return_value=config_path,
            ):
                with patch(
                    "mcp_acp.cli.commands.init.get_policy_path",
                    return_value=policy_path,
                ):
                    # Act
                    result = runner.invoke(
                        cli,
                        [
                            "init",
                            "--non-interactive",
                            "--force",
                            "--log-dir",
                            str(log_dir),
                            "--server-name",
                            "new-server",
                            "--connection-type",
                            "stdio",
                            "--command",
                            "echo",
                            "--args",
                            "test",
                            # OIDC flags (required for Zero Trust)
                            "--oidc-issuer",
                            "https://test.auth0.com",
                            "--oidc-client-id",
                            "test-client",
                            "--oidc-audience",
                            "https://api.example.com",
                        ],
                    )

            # Assert
            assert result.exit_code == 0

            import json

            config = json.loads(config_path.read_text())
            assert config["backend"]["server_name"] == "new-server"
            assert config["auth"]["oidc"]["issuer"] == "https://test.auth0.com"

    def test_init_non_interactive_partial_mtls_shows_error(self, runner: CliRunner) -> None:
        """Given partial mTLS config (1-2 of 3 options), shows error."""
        # Arrange
        with runner.isolated_filesystem() as tmpdir:
            config_path = Path(tmpdir) / "config.json"
            policy_path = Path(tmpdir) / "policy.json"

            with patch(
                "mcp_acp.cli.commands.init.get_config_path",
                return_value=config_path,
            ):
                with patch(
                    "mcp_acp.cli.commands.init.get_policy_path",
                    return_value=policy_path,
                ):
                    # Act
                    result = runner.invoke(
                        cli,
                        [
                            "init",
                            "--non-interactive",
                            "--log-dir",
                            str(tmpdir),
                            "--server-name",
                            "test-server",
                            "--connection-type",
                            "http",
                            "--url",
                            "http://localhost:3000/mcp",
                            "--oidc-issuer",
                            "https://test.auth0.com",
                            "--oidc-client-id",
                            "test-client",
                            "--oidc-audience",
                            "https://api.example.com",
                            "--mtls-cert",
                            "/path/to/cert.pem",
                            # Missing --mtls-key and --mtls-ca
                        ],
                    )

        # Assert
        assert result.exit_code == 1
        assert "mTLS requires all three options" in result.output

    def test_init_non_interactive_invalid_url_format_shows_error(self, runner: CliRunner) -> None:
        """Given invalid URL format, shows clear error before health check."""
        # Arrange
        with runner.isolated_filesystem() as tmpdir:
            config_path = Path(tmpdir) / "config.json"
            policy_path = Path(tmpdir) / "policy.json"

            with patch(
                "mcp_acp.cli.commands.init.get_config_path",
                return_value=config_path,
            ):
                with patch(
                    "mcp_acp.cli.commands.init.get_policy_path",
                    return_value=policy_path,
                ):
                    # Act
                    result = runner.invoke(
                        cli,
                        [
                            "init",
                            "--non-interactive",
                            "--log-dir",
                            str(tmpdir),
                            "--server-name",
                            "test-server",
                            "--connection-type",
                            "http",
                            "--url",
                            "not-a-valid-url",  # Invalid format
                            "--oidc-issuer",
                            "https://test.auth0.com",
                            "--oidc-client-id",
                            "test-client",
                            "--oidc-audience",
                            "https://api.example.com",
                        ],
                    )

        # Assert
        assert result.exit_code == 1
        assert "--url must start with http:// or https://" in result.output


class TestConfigShow:
    """Tests for config show command."""

    def test_show_missing_config_shows_error(self, runner: CliRunner) -> None:
        """Given no config file, shows helpful error."""
        # Arrange
        with runner.isolated_filesystem():
            with patch(
                "mcp_acp.cli.commands.config.get_config_path",
                return_value=Path("nonexistent.json"),
            ):
                # Act
                result = runner.invoke(cli, ["config", "show"])

        # Assert
        assert result.exit_code == 1

    def test_show_displays_config_sections(self, runner: CliRunner, valid_config: dict) -> None:
        """Given valid config, displays all sections."""
        # Arrange
        with runner.isolated_filesystem() as tmpdir:
            config_path = Path(tmpdir) / "config.json"
            config_path.write_text(json.dumps(valid_config, indent=2))

            with patch(
                "mcp_acp.cli.commands.config.get_config_path",
                return_value=config_path,
            ):
                # Act
                result = runner.invoke(cli, ["config", "show"])

        # Assert
        assert result.exit_code == 0
        assert "Logging" in result.output
        assert "Backend" in result.output
        assert "test-server" in result.output


class TestAuthHelp:
    """Tests for auth command help."""

    def test_auth_help_shows_subcommands(self, runner: CliRunner) -> None:
        """Given auth --help, shows subcommands."""
        # Act
        result = runner.invoke(cli, ["auth", "--help"])

        # Assert
        assert result.exit_code == 0
        assert "login" in result.output
        assert "logout" in result.output
        assert "status" in result.output

    def test_root_help_shows_auth_command(self, runner: CliRunner) -> None:
        """Given --help, shows auth command."""
        # Act
        result = runner.invoke(cli, ["--help"])

        # Assert
        assert result.exit_code == 0
        assert "auth" in result.output


class TestAuthLogin:
    """Tests for auth login command."""

    def test_login_no_config_shows_error(self, runner: CliRunner) -> None:
        """Given no config file, shows helpful error."""
        # Arrange
        import click

        with runner.isolated_filesystem():
            with patch(
                "mcp_acp.cli.commands.auth.load_config_or_exit",
                side_effect=click.ClickException(
                    "Configuration not found at nonexistent.json\nRun 'mcp-acp init' to create configuration."
                ),
            ):
                # Act
                result = runner.invoke(cli, ["auth", "login"])

        # Assert
        assert result.exit_code == 1
        assert "not found" in result.output.lower() or "configuration" in result.output.lower()
        assert "init" in result.output  # Suggests running init

    def test_login_no_oidc_config_shows_error(self, runner: CliRunner) -> None:
        """Given config without OIDC settings, shows error."""
        # Arrange - mock config without auth section
        from unittest.mock import MagicMock

        mock_config = MagicMock()
        mock_config.auth = None

        with runner.isolated_filesystem():
            with patch(
                "mcp_acp.cli.commands.auth.load_config_or_exit",
                return_value=mock_config,
            ):
                # Act
                result = runner.invoke(cli, ["auth", "login"])

        # Assert
        assert result.exit_code == 1
        assert "not configured" in result.output.lower() or "oidc" in result.output.lower()


class TestAuthLogout:
    """Tests for auth logout command."""

    def test_logout_no_config_shows_error(self, runner: CliRunner) -> None:
        """Given no config file, shows helpful error."""
        # Arrange
        import click

        with runner.isolated_filesystem():
            with patch(
                "mcp_acp.cli.commands.auth.load_config_or_exit",
                side_effect=click.ClickException(
                    "Configuration not found at nonexistent.json\nRun 'mcp-acp init' to create configuration."
                ),
            ):
                # Act
                result = runner.invoke(cli, ["auth", "logout"])

        # Assert
        assert result.exit_code == 1
        assert "not found" in result.output.lower() or "configuration" in result.output.lower()

    def test_logout_no_credentials_shows_message(self, runner: CliRunner, valid_config: dict) -> None:
        """Given no stored credentials, shows appropriate message."""
        # Arrange
        from unittest.mock import MagicMock

        mock_config = MagicMock()
        mock_config.auth = MagicMock()
        mock_config.auth.oidc = MagicMock()

        with runner.isolated_filesystem():
            # Mock storage to return no credentials
            mock_storage = patch("mcp_acp.cli.commands.auth.create_token_storage")

            with patch(
                "mcp_acp.cli.commands.auth.load_config_or_exit",
                return_value=mock_config,
            ):
                with mock_storage as storage_mock:
                    storage_instance = storage_mock.return_value
                    storage_instance.exists.return_value = False

                    # Act
                    result = runner.invoke(cli, ["auth", "logout"])

        # Assert
        assert result.exit_code == 0
        assert "no stored credentials" in result.output.lower()


class TestAuthStatus:
    """Tests for auth status command."""

    def test_status_no_config_shows_error(self, runner: CliRunner) -> None:
        """Given no config file, shows helpful error."""
        # Arrange
        import click

        with runner.isolated_filesystem():
            with patch(
                "mcp_acp.cli.commands.auth.load_config_or_exit",
                side_effect=click.ClickException(
                    "Configuration not found at nonexistent.json\nRun 'mcp-acp init' to create configuration."
                ),
            ):
                # Act
                result = runner.invoke(cli, ["auth", "status"])

        # Assert
        assert result.exit_code == 1
        assert "not found" in result.output.lower() or "configuration" in result.output.lower()

    def test_status_no_oidc_config_shows_not_configured(self, runner: CliRunner) -> None:
        """Given config without OIDC settings, shows not configured."""
        # Arrange - mock config without auth section
        from unittest.mock import MagicMock

        mock_config = MagicMock()
        mock_config.auth = None

        with runner.isolated_filesystem():
            with patch(
                "mcp_acp.cli.commands.auth.load_config_or_exit",
                return_value=mock_config,
            ):
                # Act
                result = runner.invoke(cli, ["auth", "status"])

        # Assert
        assert result.exit_code == 0
        assert "not configured" in result.output.lower()

    def test_status_not_authenticated(self, runner: CliRunner, valid_config: dict) -> None:
        """Given no stored token, shows not authenticated."""
        # Arrange
        from unittest.mock import MagicMock

        mock_config = MagicMock()
        mock_config.auth = MagicMock()
        mock_config.auth.oidc = MagicMock()
        mock_config.auth.oidc.issuer = "https://test.auth0.com"
        mock_config.auth.oidc.client_id = "test-client-id"
        mock_config.auth.oidc.audience = "https://test-api.example.com"
        mock_config.auth.mtls = None

        with runner.isolated_filesystem():
            with patch(
                "mcp_acp.cli.commands.auth.load_config_or_exit",
                return_value=mock_config,
            ):
                with patch("mcp_acp.cli.commands.auth.create_token_storage") as storage_mock:
                    storage_instance = storage_mock.return_value
                    storage_instance.exists.return_value = False

                    with patch(
                        "mcp_acp.cli.commands.auth.get_token_storage_info",
                        return_value={"backend": "keychain"},
                    ):
                        # Act
                        result = runner.invoke(cli, ["auth", "status"])

        # Assert
        assert result.exit_code == 0
        assert "not authenticated" in result.output.lower()
        assert "login" in result.output.lower()  # Suggests running login
