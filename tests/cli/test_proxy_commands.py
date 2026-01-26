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

    return config_dir


@pytest.fixture
def manager_config(temp_config_dir: Path) -> Path:
    """Create a manager.json file."""
    manager_path = temp_config_dir / "manager.json"
    config = ManagerConfig()
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


class TestProxyList:
    """Tests for 'proxy list' command."""

    def test_empty_list(
        self,
        cli_runner: CliRunner,
        temp_config_dir: Path,
    ) -> None:
        """Should show message when no proxies configured."""
        result = cli_runner.invoke(proxy, ["list"])
        assert result.exit_code == 0
        assert "No proxies configured" in result.output

    def test_list_with_proxies(
        self,
        cli_runner: CliRunner,
        temp_config_dir: Path,
        sample_proxy: tuple[str, PerProxyConfig],
    ) -> None:
        """Should list configured proxies."""
        name, config = sample_proxy

        result = cli_runner.invoke(proxy, ["list"])
        assert result.exit_code == 0
        assert name in result.output
        assert "Filesystem Server" in result.output
        assert "stdio" in result.output

    def test_list_shows_running_status(
        self,
        cli_runner: CliRunner,
        temp_config_dir: Path,
        sample_proxy: tuple[str, PerProxyConfig],
    ) -> None:
        """Should show running status for proxies."""
        name, config = sample_proxy

        # Proxy is not running (no socket)
        result = cli_runner.invoke(proxy, ["list"])
        assert result.exit_code == 0
        assert "not running" in result.output
        assert "0 running" in result.output or "1 proxies configured, 0 running" in result.output


class TestProxyShow:
    """Tests for 'proxy show' command."""

    def test_show_nonexistent(
        self,
        cli_runner: CliRunner,
        temp_config_dir: Path,
    ) -> None:
        """Should error for nonexistent proxy."""
        result = cli_runner.invoke(proxy, ["show", "nonexistent"])
        assert result.exit_code == 1
        assert "not found" in result.output

    def test_show_existing(
        self,
        cli_runner: CliRunner,
        temp_config_dir: Path,
        sample_proxy: tuple[str, PerProxyConfig],
    ) -> None:
        """Should show proxy details."""
        name, config = sample_proxy

        result = cli_runner.invoke(proxy, ["show", name])
        assert result.exit_code == 0
        assert f"Proxy: {name}" in result.output
        assert config.proxy_id in result.output
        assert "Filesystem Server" in result.output
        assert "npx" in result.output

    def test_show_includes_running_status(
        self,
        cli_runner: CliRunner,
        temp_config_dir: Path,
        sample_proxy: tuple[str, PerProxyConfig],
    ) -> None:
        """Should show running status."""
        name, config = sample_proxy

        result = cli_runner.invoke(proxy, ["show", name])
        assert result.exit_code == 0
        # Proxy is not running (no socket)
        assert "not running" in result.output or "Status:" in result.output


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
            ],
            input="n\n",  # Answer "no" to API key prompt
        )
        assert result.exit_code == 0
        assert "Created proxy config" in result.output

    def test_add_both_connections(
        self,
        cli_runner: CliRunner,
        temp_config_dir: Path,
        manager_config: Path,
        mock_http_health: None,
    ) -> None:
        """Should create proxy with both connection types."""
        result = cli_runner.invoke(
            proxy,
            [
                "add",
                "--name",
                "bothproxy",
                "--server-name",
                "Dual Server",
                "--connection-type",
                "both",
                "--command",
                "node",
                "--args",
                "server.js",
                "--url",
                "http://localhost:3000/mcp",
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
