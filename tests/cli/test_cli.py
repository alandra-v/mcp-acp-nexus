"""Unit tests for CLI commands.

Tests CLI behavior using Click's CliRunner for isolated, fast testing.
Tests use the AAA pattern (Arrange-Act-Assert) for clarity.
"""

import json
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
from click.testing import CliRunner

from mcp_acp.cli import cli


@pytest.fixture
def runner() -> CliRunner:
    """Create a CLI runner for testing."""
    return CliRunner()


@pytest.fixture
def valid_manager_config() -> dict:
    """Return a minimal valid manager configuration."""
    return {
        "ui_port": 8765,
        "log_dir": "/tmp/test-logs",
        "log_level": "INFO",
        "auth": {
            "oidc": {
                "issuer": "https://test.auth0.com",
                "client_id": "test-client-id",
                "audience": "https://test-api.example.com",
            }
        },
    }


@pytest.fixture
def valid_proxy_config() -> dict:
    """Return a minimal valid proxy configuration."""
    return {
        "proxy_id": "px_12345678:test-server",
        "created_at": "2024-01-01T00:00:00Z",
        "backend": {
            "server_name": "test-server",
            "transport": "stdio",
            "stdio": {"command": "echo", "args": ["test"]},
        },
        "hitl": {
            "timeout_seconds": 60,
            "approval_ttl_seconds": 600,
        },
    }


from typing import Generator


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

    def test_config_path_returns_paths(self, runner: CliRunner) -> None:
        """Given config path command, returns manager path and shows proxies."""
        # Act
        result = runner.invoke(cli, ["config", "path"])

        # Assert
        assert result.exit_code == 0
        assert "Manager" in result.output

    def test_config_path_manager_flag(self, runner: CliRunner) -> None:
        """Given config path --manager, returns manager path."""
        # Act
        result = runner.invoke(cli, ["config", "path", "--manager"])

        # Assert
        assert result.exit_code == 0
        assert "mcp-acp" in result.output or "manager" in result.output.lower()


class TestConfigShow:
    """Tests for config show command."""

    def test_show_without_flag_shows_error(self, runner: CliRunner) -> None:
        """Given config show without flag, shows error."""
        # Act
        result = runner.invoke(cli, ["config", "show"])

        # Assert
        assert result.exit_code == 1
        assert "--manager" in result.output or "--proxy" in result.output

    def test_show_manager_missing_config_shows_error(self, runner: CliRunner) -> None:
        """Given no manager config file, shows helpful error."""
        # Arrange
        with runner.isolated_filesystem():
            with patch(
                "mcp_acp.cli.commands.config.get_manager_config_path",
                return_value=Path("nonexistent.json"),
            ):
                # Act
                result = runner.invoke(cli, ["config", "show", "--manager"])

        # Assert
        assert result.exit_code == 1
        assert "not found" in result.output.lower()
        assert "init" in result.output.lower()

    def test_show_manager_displays_config(self, runner: CliRunner, valid_manager_config: dict) -> None:
        """Given valid manager config, displays it."""
        # Arrange
        with runner.isolated_filesystem() as tmpdir:
            config_path = Path(tmpdir) / "manager.json"
            config_path.write_text(json.dumps(valid_manager_config, indent=2))

            with patch(
                "mcp_acp.cli.commands.config.get_manager_config_path",
                return_value=config_path,
            ):
                # Act
                result = runner.invoke(cli, ["config", "show", "--manager"])

        # Assert
        assert result.exit_code == 0
        assert "Manager Configuration" in result.output
        assert "8765" in result.output  # ui_port


class TestConfigEdit:
    """Tests for config edit command."""

    def test_edit_without_flag_shows_error(self, runner: CliRunner) -> None:
        """Given config edit without flag, shows error."""
        # Act
        result = runner.invoke(cli, ["config", "edit"])

        # Assert
        assert result.exit_code == 1
        assert "--manager" in result.output or "--proxy" in result.output

    def test_edit_manager_missing_config_shows_error(self, runner: CliRunner) -> None:
        """Given no manager config file, shows helpful error."""
        # Arrange
        with runner.isolated_filesystem():
            with patch(
                "mcp_acp.cli.commands.config.get_manager_config_path",
                return_value=Path("nonexistent.json"),
            ):
                # Act
                result = runner.invoke(cli, ["config", "edit", "--manager"])

        # Assert
        assert result.exit_code == 1
        assert "not found" in result.output.lower()
        assert "init" in result.output.lower()


class TestConfigValidate:
    """Tests for config validate command."""

    def test_validate_all_shows_results(self, runner: CliRunner, valid_manager_config: dict) -> None:
        """Given config validate, validates manager and proxies."""
        # Arrange
        with runner.isolated_filesystem() as tmpdir:
            manager_path = Path(tmpdir) / "manager.json"
            manager_path.write_text(json.dumps(valid_manager_config, indent=2))

            with patch(
                "mcp_acp.cli.commands.config.get_manager_config_path",
                return_value=manager_path,
            ):
                with patch(
                    "mcp_acp.cli.commands.config.list_configured_proxies",
                    return_value=[],
                ):
                    # Act
                    result = runner.invoke(cli, ["config", "validate"])

        # Assert
        assert result.exit_code == 0
        assert "valid" in result.output.lower()


class TestStartCommand:
    """Tests for start command."""

    def test_start_no_proxy_shows_available(self, runner: CliRunner) -> None:
        """Given start without --proxy, shows available proxies."""
        # Arrange - patch where the function is imported (start.py module level)
        with patch(
            "mcp_acp.cli.commands.start.list_configured_proxies",
            return_value=["test-proxy"],
        ):
            # Act
            result = runner.invoke(cli, ["start"])

        # Assert
        assert result.exit_code == 1
        assert "test-proxy" in result.output
        assert "--proxy" in result.output

    def test_start_no_proxies_shows_help(self, runner: CliRunner) -> None:
        """Given no proxies configured, shows helpful message."""
        # Arrange - patch where the function is imported (start.py module level)
        with patch(
            "mcp_acp.cli.commands.start.list_configured_proxies",
            return_value=[],
        ):
            # Act
            result = runner.invoke(cli, ["start"])

        # Assert
        assert result.exit_code == 1
        assert "No proxies configured" in result.output or "proxy add" in result.output


class TestInitCommand:
    """Tests for init command.

    The init command creates manager.json with auth config (OIDC, log_level).
    mTLS is now per-proxy, configured in 'proxy add'.
    """

    def test_init_non_interactive_missing_oidc_issuer_shows_error(self, runner: CliRunner) -> None:
        """Given --non-interactive without --oidc-issuer, shows error."""
        with runner.isolated_filesystem() as tmpdir:
            manager_path = Path(tmpdir) / "manager.json"

            with patch(
                "mcp_acp.cli.commands.init.get_manager_config_path",
                return_value=manager_path,
            ):
                result = runner.invoke(
                    cli,
                    [
                        "init",
                        "--non-interactive",
                        "--oidc-client-id",
                        "test-client",
                        "--oidc-audience",
                        "https://api.example.com",
                    ],
                )

        assert result.exit_code == 1
        assert "--oidc-issuer" in result.output.lower()

    def test_init_non_interactive_missing_oidc_client_id_shows_error(self, runner: CliRunner) -> None:
        """Given --non-interactive without --oidc-client-id, shows error."""
        with runner.isolated_filesystem() as tmpdir:
            manager_path = Path(tmpdir) / "manager.json"

            with patch(
                "mcp_acp.cli.commands.init.get_manager_config_path",
                return_value=manager_path,
            ):
                result = runner.invoke(
                    cli,
                    [
                        "init",
                        "--non-interactive",
                        "--oidc-issuer",
                        "https://test.auth0.com",
                        "--oidc-audience",
                        "https://api.example.com",
                    ],
                )

        assert result.exit_code == 1
        assert "--oidc-client-id" in result.output.lower()

    def test_init_non_interactive_missing_oidc_audience_shows_error(self, runner: CliRunner) -> None:
        """Given --non-interactive without --oidc-audience, shows error."""
        with runner.isolated_filesystem() as tmpdir:
            manager_path = Path(tmpdir) / "manager.json"

            with patch(
                "mcp_acp.cli.commands.init.get_manager_config_path",
                return_value=manager_path,
            ):
                result = runner.invoke(
                    cli,
                    [
                        "init",
                        "--non-interactive",
                        "--oidc-issuer",
                        "https://test.auth0.com",
                        "--oidc-client-id",
                        "test-client",
                    ],
                )

        assert result.exit_code == 1
        assert "--oidc-audience" in result.output.lower()

    def test_init_non_interactive_invalid_oidc_issuer_shows_error(self, runner: CliRunner) -> None:
        """Given --oidc-issuer without https://, shows error."""
        with runner.isolated_filesystem() as tmpdir:
            manager_path = Path(tmpdir) / "manager.json"

            with patch(
                "mcp_acp.cli.commands.init.get_manager_config_path",
                return_value=manager_path,
            ):
                result = runner.invoke(
                    cli,
                    [
                        "init",
                        "--non-interactive",
                        "--oidc-issuer",
                        "http://test.auth0.com",  # Should be https
                        "--oidc-client-id",
                        "test-client",
                        "--oidc-audience",
                        "https://api.example.com",
                    ],
                )

        assert result.exit_code == 1
        assert "https://" in result.output.lower()

    def test_init_non_interactive_creates_manager_config(self, runner: CliRunner) -> None:
        """Given valid OIDC flags, creates manager.json."""
        with runner.isolated_filesystem() as tmpdir:
            manager_path = Path(tmpdir) / "manager.json"

            # Patch in both modules: init.py (for path display) and manager/config.py (for save)
            with patch(
                "mcp_acp.cli.commands.init.get_manager_config_path",
                return_value=manager_path,
            ):
                with patch(
                    "mcp_acp.manager.config.get_manager_config_path",
                    return_value=manager_path,
                ):
                    result = runner.invoke(
                        cli,
                        [
                            "init",
                            "--non-interactive",
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
            assert manager_path.exists()

            # Verify config content
            import json

            config = json.loads(manager_path.read_text())
            assert config["auth"]["oidc"]["issuer"] == "https://test.auth0.com"
            assert config["auth"]["oidc"]["client_id"] == "test-client"
            assert config["auth"]["oidc"]["audience"] == "https://api.example.com"
            assert config["log_level"] == "INFO"  # Default

    def test_init_non_interactive_with_log_level(self, runner: CliRunner) -> None:
        """Given --log-level DEBUG, saves DEBUG in config."""
        with runner.isolated_filesystem() as tmpdir:
            manager_path = Path(tmpdir) / "manager.json"

            with patch(
                "mcp_acp.cli.commands.init.get_manager_config_path",
                return_value=manager_path,
            ):
                with patch(
                    "mcp_acp.manager.config.get_manager_config_path",
                    return_value=manager_path,
                ):
                    result = runner.invoke(
                        cli,
                        [
                            "init",
                            "--non-interactive",
                            "--oidc-issuer",
                            "https://test.auth0.com",
                            "--oidc-client-id",
                            "test-client",
                            "--oidc-audience",
                            "https://api.example.com",
                            "--log-level",
                            "DEBUG",
                        ],
                    )

            assert result.exit_code == 0
            import json

            config = json.loads(manager_path.read_text())
            assert config["log_level"] == "DEBUG"

    def test_init_existing_file_without_force_fails(self, runner: CliRunner) -> None:
        """Given existing config without --force in non-interactive mode, fails."""
        with runner.isolated_filesystem() as tmpdir:
            manager_path = Path(tmpdir) / "manager.json"
            manager_path.write_text("{}")

            with patch(
                "mcp_acp.cli.commands.init.get_manager_config_path",
                return_value=manager_path,
            ):
                result = runner.invoke(
                    cli,
                    [
                        "init",
                        "--non-interactive",
                        "--oidc-issuer",
                        "https://test.auth0.com",
                        "--oidc-client-id",
                        "test-client",
                        "--oidc-audience",
                        "https://api.example.com",
                    ],
                )

        assert result.exit_code == 1
        assert "--force" in result.output.lower() or "exist" in result.output.lower()

    def test_init_existing_file_with_force_succeeds(self, runner: CliRunner) -> None:
        """Given existing config with --force, overwrites successfully."""
        with runner.isolated_filesystem() as tmpdir:
            manager_path = Path(tmpdir) / "manager.json"
            manager_path.write_text('{"old": "config"}')

            with patch(
                "mcp_acp.cli.commands.init.get_manager_config_path",
                return_value=manager_path,
            ):
                with patch(
                    "mcp_acp.manager.config.get_manager_config_path",
                    return_value=manager_path,
                ):
                    result = runner.invoke(
                        cli,
                        [
                            "init",
                            "--non-interactive",
                            "--force",
                            "--oidc-issuer",
                            "https://new.auth0.com",
                            "--oidc-client-id",
                            "new-client",
                            "--oidc-audience",
                            "https://new-api.example.com",
                        ],
                    )

            assert result.exit_code == 0
            import json

            config = json.loads(manager_path.read_text())
            assert config["auth"]["oidc"]["issuer"] == "https://new.auth0.com"

    def test_init_shows_next_steps(self, runner: CliRunner) -> None:
        """After successful init, shows auth login and proxy add instructions."""
        with runner.isolated_filesystem() as tmpdir:
            manager_path = Path(tmpdir) / "manager.json"

            with patch(
                "mcp_acp.cli.commands.init.get_manager_config_path",
                return_value=manager_path,
            ):
                result = runner.invoke(
                    cli,
                    [
                        "init",
                        "--non-interactive",
                        "--oidc-issuer",
                        "https://test.auth0.com",
                        "--oidc-client-id",
                        "test-client",
                        "--oidc-audience",
                        "https://api.example.com",
                    ],
                )

        assert result.exit_code == 0
        assert "auth login" in result.output
        assert "proxy add" in result.output


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
                "mcp_acp.cli.commands.auth.load_manager_config_or_exit",
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
        # Arrange - load_manager_config_or_exit raises when auth is None
        import click

        with runner.isolated_filesystem():
            with patch(
                "mcp_acp.cli.commands.auth.load_manager_config_or_exit",
                side_effect=click.ClickException(
                    "Authentication not configured.\nRun 'mcp-acp init' to configure OIDC authentication."
                ),
            ):
                # Act
                result = runner.invoke(cli, ["auth", "login"])

        # Assert
        assert result.exit_code == 1
        assert "not configured" in result.output.lower()


class TestAuthLogout:
    """Tests for auth logout command."""

    def test_logout_no_config_shows_error(self, runner: CliRunner) -> None:
        """Given no config file, shows helpful error."""
        # Arrange
        import click

        with runner.isolated_filesystem():
            with patch(
                "mcp_acp.cli.commands.auth.load_manager_config_or_exit",
                side_effect=click.ClickException(
                    "Configuration not found at nonexistent.json\nRun 'mcp-acp init' to create configuration."
                ),
            ):
                # Act
                result = runner.invoke(cli, ["auth", "logout"])

        # Assert
        assert result.exit_code == 1
        assert "not found" in result.output.lower() or "configuration" in result.output.lower()

    def test_logout_no_credentials_shows_message(self, runner: CliRunner) -> None:
        """Given no stored credentials, shows appropriate message."""
        # Arrange
        mock_config = MagicMock()
        mock_config.auth = MagicMock()
        mock_config.auth.oidc = MagicMock()

        with runner.isolated_filesystem():
            # Mock storage to return no credentials
            mock_storage = patch("mcp_acp.cli.commands.auth.create_token_storage")

            with patch(
                "mcp_acp.cli.commands.auth.load_manager_config_or_exit",
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
                "mcp_acp.cli.commands.auth.load_manager_config_or_exit",
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
        # Arrange - load_manager_config_or_exit raises when auth is None
        import click

        with runner.isolated_filesystem():
            with patch(
                "mcp_acp.cli.commands.auth.load_manager_config_or_exit",
                side_effect=click.ClickException(
                    "Authentication not configured.\nRun 'mcp-acp init' to configure OIDC authentication."
                ),
            ):
                # Act
                result = runner.invoke(cli, ["auth", "status"])

        # Assert
        assert result.exit_code == 1
        assert "not configured" in result.output.lower()

    def test_status_not_authenticated(self, runner: CliRunner) -> None:
        """Given no stored token, shows not authenticated."""
        # Arrange
        mock_config = MagicMock()
        mock_config.auth = MagicMock()
        mock_config.auth.oidc = MagicMock()
        mock_config.auth.oidc.issuer = "https://test.auth0.com"
        mock_config.auth.oidc.client_id = "test-client-id"
        mock_config.auth.oidc.audience = "https://test-api.example.com"

        with runner.isolated_filesystem():
            with patch(
                "mcp_acp.cli.commands.auth.load_manager_config_or_exit",
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
