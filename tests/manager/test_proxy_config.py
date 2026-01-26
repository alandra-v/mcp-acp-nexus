"""Tests for multi-proxy configuration helpers.

Tests proxy name validation, path helpers, and ID generation.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from mcp_acp.config import (
    PerProxyConfig,
    BackendConfig,
    StdioTransportConfig,
    generate_instance_id,
    generate_proxy_id,
    sanitize_backend_name,
)
from mcp_acp.constants import RUNTIME_DIR, get_proxy_socket_path
from mcp_acp.manager.config import (
    RESERVED_PROXY_NAMES,
    get_proxies_dir,
    get_proxy_config_dir,
    get_proxy_config_path,
    get_proxy_log_dir,
    get_proxy_policy_path,
    list_configured_proxies,
    validate_proxy_name,
)


class TestValidateProxyName:
    """Tests for validate_proxy_name()."""

    def test_valid_names(self) -> None:
        """Valid names should not raise."""
        valid_names = [
            "filesystem",
            "github",
            "my-proxy",
            "proxy_1",
            "A1",
            "a",
            "proxy-with-many-parts",
            "UPPERCASE",
            "MixedCase123",
        ]
        for name in valid_names:
            validate_proxy_name(name)  # Should not raise

    def test_empty_name_raises(self) -> None:
        """Empty name should raise ValueError."""
        with pytest.raises(ValueError, match="cannot be empty"):
            validate_proxy_name("")

    def test_too_long_raises(self) -> None:
        """Name over 64 chars should raise."""
        with pytest.raises(ValueError, match="too long"):
            validate_proxy_name("a" * 65)

    def test_starts_with_underscore_raises(self) -> None:
        """Name starting with underscore should raise."""
        with pytest.raises(ValueError, match="cannot start with '_'"):
            validate_proxy_name("_hidden")

    def test_starts_with_dot_raises(self) -> None:
        """Name starting with dot should raise."""
        with pytest.raises(ValueError, match="cannot start with"):
            validate_proxy_name(".hidden")

    def test_reserved_names_raise(self) -> None:
        """Reserved names should raise."""
        for name in RESERVED_PROXY_NAMES:
            with pytest.raises(ValueError, match="reserved name"):
                validate_proxy_name(name)
            # Also test case-insensitive
            with pytest.raises(ValueError, match="reserved name"):
                validate_proxy_name(name.upper())

    def test_invalid_characters_raise(self) -> None:
        """Names with invalid characters should raise."""
        invalid_names = [
            "my proxy",  # space
            "proxy.name",  # dot
            "proxy@name",  # special char
            "proxy/name",  # slash
            "-startsdash",  # starts with dash
        ]
        for name in invalid_names:
            with pytest.raises(ValueError, match="Invalid proxy name"):
                validate_proxy_name(name)


class TestSanitizeBackendName:
    """Tests for sanitize_backend_name()."""

    def test_simple_name(self) -> None:
        """Simple name should be lowercased."""
        assert sanitize_backend_name("Filesystem") == "filesystem"

    def test_spaces_replaced(self) -> None:
        """Spaces should be replaced with hyphens."""
        assert sanitize_backend_name("My Server") == "my-server"

    def test_special_chars_removed(self) -> None:
        """Special characters should be removed."""
        assert sanitize_backend_name("Server@v2!") == "serverv2"

    def test_multiple_spaces_collapsed(self) -> None:
        """Multiple spaces become single hyphen."""
        assert sanitize_backend_name("My   Server") == "my-server"

    def test_leading_trailing_hyphens_stripped(self) -> None:
        """Leading/trailing hyphens should be stripped."""
        assert sanitize_backend_name(" Server ") == "server"
        assert sanitize_backend_name("--server--") == "server"

    def test_empty_result_becomes_backend(self) -> None:
        """If result would be empty, return 'backend'."""
        assert sanitize_backend_name("@#$%") == "backend"

    def test_complex_name(self) -> None:
        """Complex name should be fully sanitized."""
        assert sanitize_backend_name("My Filesystem Server (v2)") == "my-filesystem-server-v2"


class TestGenerateProxyId:
    """Tests for generate_proxy_id()."""

    def test_format(self) -> None:
        """ID should match expected format."""
        proxy_id = generate_proxy_id("Filesystem Server")
        assert re.match(r"^px_[a-f0-9]{8}:filesystem-server$", proxy_id)

    def test_unique(self) -> None:
        """Each call should generate unique ID."""
        id1 = generate_proxy_id("Server")
        id2 = generate_proxy_id("Server")
        assert id1 != id2

    def test_sanitizes_backend_name(self) -> None:
        """Backend name should be sanitized in ID."""
        proxy_id = generate_proxy_id("My Cool Server!")
        assert ":my-cool-server" in proxy_id


class TestGenerateInstanceId:
    """Tests for generate_instance_id()."""

    def test_format(self) -> None:
        """Instance ID should match expected format."""
        proxy_id = "px_a1b2c3d4:filesystem-server"
        instance_id = generate_instance_id(proxy_id)
        assert re.match(r"^a1b2c3d4_[a-f0-9]{8}$", instance_id)

    def test_includes_proxy_uuid(self) -> None:
        """Instance ID should include proxy's UUID prefix."""
        proxy_id = "px_deadbeef:backend"
        instance_id = generate_instance_id(proxy_id)
        assert instance_id.startswith("deadbeef_")

    def test_unique(self) -> None:
        """Each call should generate unique instance ID."""
        proxy_id = "px_a1b2c3d4:backend"
        id1 = generate_instance_id(proxy_id)
        id2 = generate_instance_id(proxy_id)
        assert id1 != id2


class TestProxyPathHelpers:
    """Tests for proxy path helper functions."""

    def test_get_proxies_dir(self) -> None:
        """Should return proxies subdirectory of config dir."""
        proxies_dir = get_proxies_dir()
        assert proxies_dir.name == "proxies"

    def test_get_proxy_config_dir(self) -> None:
        """Should return named subdirectory of proxies dir."""
        config_dir = get_proxy_config_dir("filesystem")
        assert config_dir.name == "filesystem"
        assert config_dir.parent.name == "proxies"

    def test_get_proxy_config_path(self) -> None:
        """Should return config.json in proxy dir."""
        config_path = get_proxy_config_path("filesystem")
        assert config_path.name == "config.json"
        assert config_path.parent.name == "filesystem"

    def test_get_proxy_policy_path(self) -> None:
        """Should return policy.json in proxy dir."""
        policy_path = get_proxy_policy_path("filesystem")
        assert policy_path.name == "policy.json"
        assert policy_path.parent.name == "filesystem"

    def test_get_proxy_log_dir(self) -> None:
        """Should return log directory for proxy."""
        log_dir = get_proxy_log_dir("filesystem")
        assert log_dir.name == "filesystem"
        assert "proxies" in str(log_dir)

    def test_get_proxy_socket_path(self) -> None:
        """Should return socket path for proxy."""
        socket_path = get_proxy_socket_path("filesystem")
        assert socket_path.name == "proxy_filesystem.sock"
        assert socket_path.parent == RUNTIME_DIR


class TestListConfiguredProxies:
    """Tests for list_configured_proxies()."""

    def test_returns_empty_if_no_dir(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Should return empty list if proxies dir doesn't exist."""
        monkeypatch.setattr("mcp_acp.manager.config.get_proxies_dir", lambda: tmp_path / "nonexistent")
        assert list_configured_proxies() == []

    def test_returns_directory_names(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Should return names of subdirectories."""
        proxies_dir = tmp_path / "proxies"
        proxies_dir.mkdir()
        (proxies_dir / "filesystem").mkdir()
        (proxies_dir / "github").mkdir()
        (proxies_dir / ".hidden").mkdir()  # Should be excluded

        monkeypatch.setattr("mcp_acp.manager.config.get_proxies_dir", lambda: proxies_dir)

        result = list_configured_proxies()
        assert result == ["filesystem", "github"]

    def test_ignores_files(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Should only return directories, not files."""
        proxies_dir = tmp_path / "proxies"
        proxies_dir.mkdir()
        (proxies_dir / "filesystem").mkdir()
        (proxies_dir / "some_file.txt").touch()

        monkeypatch.setattr("mcp_acp.manager.config.get_proxies_dir", lambda: proxies_dir)

        result = list_configured_proxies()
        assert result == ["filesystem"]


class TestPerProxyConfig:
    """Tests for PerProxyConfig model."""

    def test_valid_config(self) -> None:
        """Valid config should validate."""
        config = PerProxyConfig(
            proxy_id="px_a1b2c3d4:filesystem-server",
            created_at="2024-01-15T10:30:00Z",
            backend=BackendConfig(
                server_name="Filesystem Server",
                transport="stdio",
                stdio=StdioTransportConfig(command="node", args=["server.js"]),
            ),
        )
        assert config.proxy_id == "px_a1b2c3d4:filesystem-server"

    def test_invalid_proxy_id_rejected(self) -> None:
        """Invalid proxy_id format should be rejected."""
        with pytest.raises(ValueError):
            PerProxyConfig(
                proxy_id="invalid",  # Wrong format
                created_at="2024-01-15T10:30:00Z",
                backend=BackendConfig(
                    server_name="Server",
                    transport="stdio",
                    stdio=StdioTransportConfig(command="node"),
                ),
            )

    def test_hitl_has_default(self) -> None:
        """HITL config should have sensible defaults."""
        config = PerProxyConfig(
            proxy_id="px_a1b2c3d4:backend",
            created_at="2024-01-15T10:30:00Z",
            backend=BackendConfig(
                server_name="Server",
                transport="stdio",
                stdio=StdioTransportConfig(command="node"),
            ),
        )
        assert config.hitl.timeout_seconds > 0
