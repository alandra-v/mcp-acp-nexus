"""Tests for proxy CLI commands."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from mcp_acp.cli.commands.proxy import proxy
from mcp_acp.cli.commands.start import start
from mcp_acp.config import (
    BackendConfig,
    HITLConfig,
    PerProxyConfig,
    StdioTransportConfig,
    save_proxy_config,
)
from mcp_acp.config import AuthConfig, OIDCConfig
from mcp_acp.manager.config import (
    ManagerConfig,
    save_manager_config,
)


@pytest.fixture
def cli_runner() -> CliRunner:
    """Create a CLI runner for testing."""
    return CliRunner()


@pytest.fixture
def temp_config_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Set up temporary config directory."""
    config_dir = tmp_path / "config"
    config_dir.mkdir()

    # Patch get_app_dir in the modules that import it
    monkeypatch.setattr(
        "mcp_acp.manager.config.get_app_dir",
        lambda: config_dir,
    )
    monkeypatch.setattr(
        "mcp_acp.utils.file_helpers.get_app_dir",
        lambda: config_dir,
    )
    monkeypatch.setattr(
        "mcp_acp.manager.deletion.get_app_dir",
        lambda: config_dir,
    )

    return config_dir


@pytest.fixture
def manager_config(temp_config_dir: Path) -> Path:
    """Create a manager.json file with auth configured."""
    manager_path = temp_config_dir / "manager.json"
    config = ManagerConfig(
        auth=AuthConfig(
            oidc=OIDCConfig(
                issuer="https://test.auth0.com",
                client_id="test-client-id",
                audience="test-audience",
            ),
        ),
    )
    save_manager_config(config)
    return manager_path


@pytest.fixture
def mock_http_health(monkeypatch: pytest.MonkeyPatch) -> None:
    """Mock HTTP health check to avoid network calls."""
    monkeypatch.setattr(
        "mcp_acp.cli.commands.proxy.check_http_health",
        lambda url, timeout: None,  # Success - no exception
    )


@pytest.fixture
def sample_proxy(temp_config_dir: Path) -> tuple[str, PerProxyConfig]:
    """Create a sample proxy config."""
    name = "filesystem"
    config = PerProxyConfig(
        proxy_id="px_a1b2c3d4:filesystem-server",
        created_at="2024-01-15T10:30:00Z",
        backend=BackendConfig(
            server_name="Filesystem Server",
            transport="stdio",
            stdio=StdioTransportConfig(
                command="npx",
                args=["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
            ),
        ),
        hitl=HITLConfig(),
    )
    save_proxy_config(name, config)
    return name, config


class TestProxyAdd:
    """Tests for 'proxy add' command."""

    def test_add_without_manager_config(
        self,
        cli_runner: CliRunner,
        temp_config_dir: Path,
    ) -> None:
        """Should error if manager.json doesn't exist."""
        result = cli_runner.invoke(proxy, ["add", "--name", "test"])
        assert result.exit_code == 1
        assert "Not initialized" in result.output

    def test_add_invalid_name(
        self,
        cli_runner: CliRunner,
        temp_config_dir: Path,
        manager_config: Path,
    ) -> None:
        """Should error for invalid proxy name."""
        result = cli_runner.invoke(proxy, ["add", "--name", "_invalid"])
        assert result.exit_code == 1
        assert "cannot start with" in result.output

    def test_add_reserved_name(
        self,
        cli_runner: CliRunner,
        temp_config_dir: Path,
        manager_config: Path,
    ) -> None:
        """Should error for reserved name."""
        result = cli_runner.invoke(proxy, ["add", "--name", "manager"])
        assert result.exit_code == 1
        assert "reserved name" in result.output

    def test_add_duplicate_name(
        self,
        cli_runner: CliRunner,
        temp_config_dir: Path,
        manager_config: Path,
        sample_proxy: tuple[str, PerProxyConfig],
    ) -> None:
        """Should error for duplicate name."""
        name, _ = sample_proxy
        result = cli_runner.invoke(proxy, ["add", "--name", name])
        assert result.exit_code == 1
        assert "already exists" in result.output

    def test_add_non_interactive(
        self,
        cli_runner: CliRunner,
        temp_config_dir: Path,
        manager_config: Path,
    ) -> None:
        """Should create proxy with all flags provided."""
        result = cli_runner.invoke(
            proxy,
            [
                "add",
                "--name",
                "myproxy",
                "--server-name",
                "My Server",
                "--connection-type",
                "stdio",
                "--command",
                "node",
                "--args",
                "server.js,--port,3000",
                "--yes",
            ],
        )
        assert result.exit_code == 0
        assert "Created proxy config" in result.output
        assert "Created default policy" in result.output
        assert "myproxy" in result.output

        # Verify files were created
        config_path = temp_config_dir / "proxies" / "myproxy" / "config.json"
        policy_path = temp_config_dir / "proxies" / "myproxy" / "policy.json"
        assert config_path.exists()
        assert policy_path.exists()

    def test_add_http_connection(
        self,
        cli_runner: CliRunner,
        temp_config_dir: Path,
        manager_config: Path,
        mock_http_health: None,
    ) -> None:
        """Should create proxy with HTTP connection."""
        result = cli_runner.invoke(
            proxy,
            [
                "add",
                "--name",
                "httpproxy",
                "--server-name",
                "HTTP Server",
                "--connection-type",
                "http",
                "--url",
                "http://localhost:3000/mcp",
                "--yes",
            ],
            input="n\n",  # Answer "no" to API key prompt
        )
        assert result.exit_code == 0
        assert "Created proxy config" in result.output

    def test_add_auto_connections(
        self,
        cli_runner: CliRunner,
        temp_config_dir: Path,
        manager_config: Path,
        mock_http_health: None,
    ) -> None:
        """Should create proxy with auto connection type (tries HTTP, falls back to STDIO)."""
        result = cli_runner.invoke(
            proxy,
            [
                "add",
                "--name",
                "autoproxy",
                "--server-name",
                "Dual Server",
                "--connection-type",
                "auto",
                "--command",
                "node",
                "--args",
                "server.js",
                "--url",
                "http://localhost:3000/mcp",
                "--yes",
            ],
            input="n\n",  # Answer "no" to API key prompt
        )
        assert result.exit_code == 0
        assert "Created proxy config" in result.output

    def test_add_http_with_api_key(
        self,
        cli_runner: CliRunner,
        temp_config_dir: Path,
        manager_config: Path,
        mock_http_health: None,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Should store API key via --api-key option."""
        # Mock keyring to avoid system keychain access during tests
        saved_credentials: dict[str, str] = {}

        def mock_save(self: object, credential: str) -> None:
            saved_credentials["credential"] = credential

        monkeypatch.setattr(
            "mcp_acp.security.credential_storage.BackendCredentialStorage.save",
            mock_save,
        )

        result = cli_runner.invoke(
            proxy,
            [
                "add",
                "--name",
                "apiproxy",
                "--server-name",
                "API Server",
                "--connection-type",
                "http",
                "--url",
                "http://localhost:3000/mcp",
                "--api-key",
                "sk-test-key-12345",
                "--yes",
            ],
        )
        assert result.exit_code == 0
        assert "Created proxy config" in result.output
        assert "API key stored" in result.output
        assert saved_credentials.get("credential") == "sk-test-key-12345"

    def test_add_http_invalid_url(
        self,
        cli_runner: CliRunner,
        temp_config_dir: Path,
        manager_config: Path,
    ) -> None:
        """Should error for invalid HTTP URL."""
        result = cli_runner.invoke(
            proxy,
            [
                "add",
                "--name",
                "badurl",
                "--server-name",
                "Bad URL Server",
                "--connection-type",
                "http",
                "--url",
                "not-a-valid-url",
            ],
        )
        assert result.exit_code == 1
        assert "Invalid URL" in result.output

    def test_add_http_missing_scheme(
        self,
        cli_runner: CliRunner,
        temp_config_dir: Path,
        manager_config: Path,
    ) -> None:
        """Should error for URL missing http/https scheme."""
        result = cli_runner.invoke(
            proxy,
            [
                "add",
                "--name",
                "noscheme",
                "--server-name",
                "No Scheme Server",
                "--connection-type",
                "http",
                "--url",
                "localhost:3000/mcp",
            ],
        )
        assert result.exit_code == 1
        assert "Invalid URL" in result.output
        assert "http://" in result.output or "https://" in result.output


class TestProxyDelete:
    """Tests for 'proxy delete' command."""

    def test_delete_existing_proxy(
        self,
        cli_runner: CliRunner,
        temp_config_dir: Path,
        sample_proxy: tuple[str, PerProxyConfig],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Should archive proxy and show summary."""
        name, _ = sample_proxy

        # Mock credential storage
        monkeypatch.setattr(
            "mcp_acp.security.credential_storage.BackendCredentialStorage",
            type("MockCred", (), {"__init__": lambda s, n: None, "delete": lambda s: None}),
        )
        # Mock log dir to not exist (no logs to archive)
        monkeypatch.setattr(
            "mcp_acp.manager.deletion.get_proxy_log_dir",
            lambda n: temp_config_dir / "nonexistent_logs" / n,
        )
        # Mock socket path to not exist
        monkeypatch.setattr(
            "mcp_acp.manager.deletion.get_proxy_socket_path",
            lambda n: temp_config_dir / "nonexistent_socket" / f"proxy_{n}.sock",
        )
        # Mock _is_proxy_running to return False
        monkeypatch.setattr(
            "mcp_acp.cli.commands.proxy._is_proxy_running",
            lambda n: False,
        )

        result = cli_runner.invoke(proxy, ["delete", "--proxy", name, "--yes"])
        assert result.exit_code == 0
        assert "deleted" in result.output.lower()
        assert "Config + policy" in result.output

        # Verify config directory was removed
        config_path = temp_config_dir / "proxies" / name
        assert not config_path.exists()

        # Verify archive was created
        archive_dir = temp_config_dir / "archive"
        assert archive_dir.exists()
        archives = list(archive_dir.iterdir())
        assert len(archives) == 1
        assert archives[0].name.startswith(name + "_")

    def test_delete_nonexistent_proxy(
        self,
        cli_runner: CliRunner,
        temp_config_dir: Path,
    ) -> None:
        """Should error for nonexistent proxy."""
        result = cli_runner.invoke(proxy, ["delete", "--proxy", "nonexistent", "--yes"])
        assert result.exit_code == 1
        assert "not found" in result.output.lower()

    def test_delete_with_purge(
        self,
        cli_runner: CliRunner,
        temp_config_dir: Path,
        sample_proxy: tuple[str, PerProxyConfig],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Should permanently delete with --purge flag."""
        name, _ = sample_proxy

        monkeypatch.setattr(
            "mcp_acp.security.credential_storage.BackendCredentialStorage",
            type("MockCred", (), {"__init__": lambda s, n: None, "delete": lambda s: None}),
        )
        monkeypatch.setattr(
            "mcp_acp.manager.deletion.get_proxy_log_dir",
            lambda n: temp_config_dir / "nonexistent_logs" / n,
        )
        monkeypatch.setattr(
            "mcp_acp.manager.deletion.get_proxy_socket_path",
            lambda n: temp_config_dir / "nonexistent_socket" / f"proxy_{n}.sock",
        )
        monkeypatch.setattr(
            "mcp_acp.cli.commands.proxy._is_proxy_running",
            lambda n: False,
        )

        result = cli_runner.invoke(proxy, ["delete", "--proxy", name, "--purge", "--yes"])
        assert result.exit_code == 0
        assert "deleted" in result.output.lower()

        # Verify no archive was created
        archive_dir = temp_config_dir / "archive"
        assert not archive_dir.exists()

    def test_delete_with_yes_skips_confirm(
        self,
        cli_runner: CliRunner,
        temp_config_dir: Path,
        sample_proxy: tuple[str, PerProxyConfig],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Should skip confirmation with --yes flag."""
        name, _ = sample_proxy

        monkeypatch.setattr(
            "mcp_acp.security.credential_storage.BackendCredentialStorage",
            type("MockCred", (), {"__init__": lambda s, n: None, "delete": lambda s: None}),
        )
        monkeypatch.setattr(
            "mcp_acp.manager.deletion.get_proxy_log_dir",
            lambda n: temp_config_dir / "nonexistent_logs" / n,
        )
        monkeypatch.setattr(
            "mcp_acp.manager.deletion.get_proxy_socket_path",
            lambda n: temp_config_dir / "nonexistent_socket" / f"proxy_{n}.sock",
        )
        monkeypatch.setattr(
            "mcp_acp.cli.commands.proxy._is_proxy_running",
            lambda n: False,
        )

        result = cli_runner.invoke(proxy, ["delete", "--proxy", name, "-y"])
        assert result.exit_code == 0

    def test_delete_running_proxy_refused(
        self,
        cli_runner: CliRunner,
        temp_config_dir: Path,
        sample_proxy: tuple[str, PerProxyConfig],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Should refuse deletion of running proxy."""
        name, _ = sample_proxy

        monkeypatch.setattr(
            "mcp_acp.cli.commands.proxy._is_proxy_running",
            lambda n: True,
        )

        result = cli_runner.invoke(proxy, ["delete", "--proxy", name, "--yes"])
        assert result.exit_code == 1
        assert "currently running" in result.output


class TestProxyList:
    """Tests for 'proxy list' command."""

    def test_list_active_proxies(
        self,
        cli_runner: CliRunner,
        temp_config_dir: Path,
        sample_proxy: tuple[str, PerProxyConfig],
    ) -> None:
        """Should list configured proxies."""
        result = cli_runner.invoke(proxy, ["list"])
        assert result.exit_code == 0
        assert "filesystem" in result.output

    def test_list_deleted_proxies_empty(
        self,
        cli_runner: CliRunner,
        temp_config_dir: Path,
    ) -> None:
        """Should show message when no archived proxies."""
        result = cli_runner.invoke(proxy, ["list", "--deleted"])
        assert result.exit_code == 0
        assert "No archived proxies" in result.output

    def test_list_deleted_proxies(
        self,
        cli_runner: CliRunner,
        temp_config_dir: Path,
        sample_proxy: tuple[str, PerProxyConfig],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Should list archived proxies after deletion."""
        name, _ = sample_proxy

        monkeypatch.setattr(
            "mcp_acp.security.credential_storage.BackendCredentialStorage",
            type("MockCred", (), {"__init__": lambda s, n: None, "delete": lambda s: None}),
        )
        monkeypatch.setattr(
            "mcp_acp.manager.deletion.get_proxy_log_dir",
            lambda n: temp_config_dir / "nonexistent_logs" / n,
        )
        monkeypatch.setattr(
            "mcp_acp.manager.deletion.get_proxy_socket_path",
            lambda n: temp_config_dir / "nonexistent_socket" / f"proxy_{n}.sock",
        )
        monkeypatch.setattr(
            "mcp_acp.cli.commands.proxy._is_proxy_running",
            lambda n: False,
        )

        # Delete the proxy first
        cli_runner.invoke(proxy, ["delete", "--proxy", name, "--yes"])

        # List deleted
        result = cli_runner.invoke(proxy, ["list", "--deleted"])
        assert result.exit_code == 0
        assert "filesystem_" in result.output


class TestStartWithProxy:
    """Tests for 'start --proxy' command."""

    def test_start_without_manager_config(
        self,
        cli_runner: CliRunner,
        temp_config_dir: Path,
    ) -> None:
        """Should error if manager.json doesn't exist."""
        result = cli_runner.invoke(start, ["--proxy", "test"])
        assert result.exit_code == 1
        assert "not found" in result.output.lower()

    def test_start_proxy_not_found(
        self,
        cli_runner: CliRunner,
        temp_config_dir: Path,
        manager_config: Path,
    ) -> None:
        """Should error if proxy doesn't exist."""
        result = cli_runner.invoke(start, ["--proxy", "nonexistent"])
        assert result.exit_code == 1
        assert "not found" in result.output.lower()
