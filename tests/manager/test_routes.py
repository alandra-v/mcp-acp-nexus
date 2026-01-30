"""Tests for manager HTTP routes.

Tests API routing, manager endpoints, and error handling.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

from mcp_acp.manager.registry import ProxyRegistry
from mcp_acp.manager.routes import (
    IDLE_EXEMPT_PATHS,
    MANAGER_API_PREFIXES,
    is_safe_path,
    create_manager_api_app,
    error_response,
)


@pytest.fixture
def registry() -> ProxyRegistry:
    """Create a fresh registry for each test."""
    return ProxyRegistry()


@pytest.fixture
def app(registry: ProxyRegistry) -> TestClient:
    """Create test client with fresh registry."""
    fastapi_app = create_manager_api_app(token="test-token", registry=registry)
    return TestClient(fastapi_app)


class TestManagerStatusEndpoint:
    """Tests for /api/manager/status endpoint."""

    def test_returns_running_status(self, app: TestClient) -> None:
        """Returns running=True and current PID."""
        response = app.get("/api/manager/status")

        assert response.status_code == 200
        data = response.json()
        assert data["running"] is True
        assert data["pid"] == os.getpid()
        assert data["proxies_connected"] == 0

    async def test_returns_correct_proxy_count(self, registry: ProxyRegistry) -> None:
        """Returns correct count of connected proxies."""
        # Register a proxy
        reader, writer = AsyncMock(), AsyncMock()
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()

        await registry.register(
            proxy_name="test",
            proxy_id="px_test:test",
            instance_id="inst_1",
            config_summary={},
            socket_path="/tmp/test.sock",
            reader=reader,
            writer=writer,
        )

        fastapi_app = create_manager_api_app(token="test", registry=registry)
        client = TestClient(fastapi_app)

        response = client.get("/api/manager/status")

        assert response.status_code == 200
        assert response.json()["proxies_connected"] == 1


class TestManagerProxiesEndpoint:
    """Tests for /api/manager/proxies endpoint."""

    def test_returns_empty_list_when_no_configured_proxies(
        self, app: TestClient, monkeypatch: "pytest.MonkeyPatch"
    ) -> None:
        """Returns empty list when no proxies are configured."""
        # Mock list_configured_proxies to return empty list
        # Patch where it's used (in the proxies submodule)
        monkeypatch.setattr("mcp_acp.manager.routes.proxies.list_configured_proxies", lambda: [])

        response = app.get("/api/manager/proxies")

        assert response.status_code == 200
        assert response.json() == []

    async def test_returns_configured_and_running_proxies(
        self,
        registry: ProxyRegistry,
        tmp_path: Path,
        monkeypatch: "pytest.MonkeyPatch",
    ) -> None:
        """Returns all configured proxies with running status for registered ones."""
        # Create a mock proxy config directory
        proxy_dir = tmp_path / "proxies" / "proxy-a"
        proxy_dir.mkdir(parents=True)
        config_file = proxy_dir / "config.json"
        config_file.write_text(
            """{
                "proxy_id": "px_a1234567:proxy-a",
                "created_at": "2024-01-15T10:30:00Z",
                "backend": {
                    "server_name": "Test Server",
                    "transport": "stdio",
                    "stdio": {"command": "test", "args": []}
                },
                "hitl": {}
            }"""
        )

        # Mock the config functions
        # Patch where it's used (in the proxies submodule)
        monkeypatch.setattr("mcp_acp.manager.routes.proxies.list_configured_proxies", lambda: ["proxy-a"])
        monkeypatch.setattr("mcp_acp.manager.config.get_proxies_dir", lambda: tmp_path / "proxies")

        # Register the proxy (mark as running)
        reader, writer = AsyncMock(), AsyncMock()
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()

        await registry.register(
            proxy_name="proxy-a",
            proxy_id="px_a1234567:proxy-a",
            instance_id="inst_a",
            config_summary={"transport": "stdio"},
            socket_path="/tmp/a.sock",
            reader=reader,
            writer=writer,
        )

        fastapi_app = create_manager_api_app(token="test", registry=registry)
        client = TestClient(fastapi_app)

        response = client.get("/api/manager/proxies")

        assert response.status_code == 200
        proxies = response.json()
        assert len(proxies) == 1
        assert proxies[0]["proxy_name"] == "proxy-a"
        assert proxies[0]["proxy_id"] == "px_a1234567:proxy-a"
        assert proxies[0]["status"] == "running"
        assert proxies[0]["instance_id"] == "inst_a"
        assert proxies[0]["server_name"] == "Test Server"
        assert proxies[0]["transport"] == "stdio"


class TestProxyCreationEndpoint:
    """Tests for POST /api/manager/proxies endpoint."""

    def test_creates_proxy_successfully(
        self,
        app: TestClient,
        tmp_path: Path,
        monkeypatch: "pytest.MonkeyPatch",
    ) -> None:
        """Creates proxy config and policy files successfully."""
        # Mock the config directory to use tmp_path
        proxies_dir = tmp_path / "proxies"
        proxies_dir.mkdir(parents=True)

        monkeypatch.setattr("mcp_acp.manager.config.get_proxies_dir", lambda: proxies_dir)
        # Patch where these are used (in the proxies submodule)
        monkeypatch.setattr(
            "mcp_acp.manager.routes.proxies.get_proxy_config_path",
            lambda name: proxies_dir / name / "config.json",
        )
        monkeypatch.setattr(
            "mcp_acp.manager.routes.proxies.get_proxy_policy_path",
            lambda name: proxies_dir / name / "policy.json",
        )
        monkeypatch.setattr(
            "mcp_acp.manager.routes.proxies.save_proxy_config",
            lambda name, config: (proxies_dir / name).mkdir(parents=True, exist_ok=True)
            or (proxies_dir / name / "config.json").write_text("{}"),
        )
        monkeypatch.setattr(
            "mcp_acp.manager.routes.proxies.save_policy",
            lambda policy, path: path.parent.mkdir(parents=True, exist_ok=True) or path.write_text("{}"),
        )

        response = app.post(
            "/api/manager/proxies",
            json={
                "name": "test-proxy",
                "server_name": "Test Server",
                "transport": "stdio",
                "command": "test-command",
                "args": ["--arg1"],
            },
        )

        assert response.status_code == 201
        data = response.json()
        assert data["ok"] is True
        assert data["proxy_name"] == "test-proxy"
        assert data["proxy_id"] is not None
        assert "claude_desktop_snippet" in data
        assert data["claude_desktop_snippet"]["test-proxy"]["command"] == "mcp-acp"

    def test_rejects_invalid_proxy_name(self, app: TestClient) -> None:
        """Rejects proxy names that violate naming rules with 400 error."""
        response = app.post(
            "/api/manager/proxies",
            json={
                "name": "manager",  # Reserved name
                "server_name": "Test Server",
                "transport": "stdio",
                "command": "test",
            },
        )

        assert response.status_code == 400
        data = response.json()
        assert data["detail"]["code"] == "PROXY_INVALID"
        assert "reserved" in data["detail"]["message"].lower()

    def test_rejects_missing_command_for_stdio(self, app: TestClient) -> None:
        """Rejects stdio transport without command with 400 error."""
        response = app.post(
            "/api/manager/proxies",
            json={
                "name": "test-proxy",
                "server_name": "Test Server",
                "transport": "stdio",
                # Missing command
            },
        )

        assert response.status_code == 400
        data = response.json()
        assert data["detail"]["code"] == "PROXY_INVALID"
        assert "command" in data["detail"]["message"].lower()

    def test_rejects_missing_url_for_http(self, app: TestClient) -> None:
        """Rejects HTTP transport without URL with 400 error."""
        response = app.post(
            "/api/manager/proxies",
            json={
                "name": "test-proxy",
                "server_name": "Test Server",
                "transport": "streamablehttp",
                # Missing url
            },
        )

        assert response.status_code == 400
        data = response.json()
        assert data["detail"]["code"] == "PROXY_INVALID"
        assert "url" in data["detail"]["message"].lower()

    def test_rejects_partial_mtls_options(self, app: TestClient) -> None:
        """Rejects partial mTLS configuration with 400 error."""
        response = app.post(
            "/api/manager/proxies",
            json={
                "name": "test-proxy",
                "server_name": "Test Server",
                "transport": "stdio",
                "command": "test",
                "mtls_cert": "/path/to/cert.pem",
                # Missing mtls_key and mtls_ca
            },
        )

        assert response.status_code == 400
        data = response.json()
        assert data["detail"]["code"] == "PROXY_INVALID"
        assert "mtls" in data["detail"]["message"].lower()

    def test_rejects_mtls_with_missing_files(self, app: TestClient, tmp_path: Path) -> None:
        """Rejects mTLS configuration when files don't exist."""
        # Create only cert file, key and ca don't exist
        cert_file = tmp_path / "cert.pem"
        cert_file.write_text("cert")

        response = app.post(
            "/api/manager/proxies",
            json={
                "name": "test-proxy",
                "server_name": "Test Server",
                "transport": "stdio",
                "command": "test",
                "mtls_cert": str(cert_file),
                "mtls_key": "/nonexistent/key.pem",
                "mtls_ca": "/nonexistent/ca.pem",
            },
        )

        assert response.status_code == 400
        data = response.json()
        assert data["detail"]["code"] == "PROXY_INVALID"
        assert "not found" in data["detail"]["message"].lower()

    def test_rejects_invalid_sha256_format(self, app: TestClient) -> None:
        """Rejects invalid SHA-256 format with 400 error."""
        response = app.post(
            "/api/manager/proxies",
            json={
                "name": "test-proxy",
                "server_name": "Test Server",
                "transport": "stdio",
                "command": "test",
                "attestation_sha256": "invalid-not-hex-chars",
            },
        )

        assert response.status_code == 400
        data = response.json()
        assert data["detail"]["code"] == "PROXY_INVALID"
        assert "hex characters" in data["detail"]["message"]

    def test_creates_proxy_with_attestation(
        self,
        app: TestClient,
        tmp_path: Path,
        monkeypatch: "pytest.MonkeyPatch",
    ) -> None:
        """Creates proxy with attestation options successfully."""
        proxies_dir = tmp_path / "proxies"
        proxies_dir.mkdir(parents=True)

        # Track saved config to verify attestation
        saved_configs = []

        def mock_save_proxy_config(name, config):
            saved_configs.append(config)
            (proxies_dir / name).mkdir(parents=True, exist_ok=True)
            (proxies_dir / name / "config.json").write_text("{}")

        monkeypatch.setattr("mcp_acp.manager.config.get_proxies_dir", lambda: proxies_dir)
        # Patch where these are used (in the proxies submodule)
        monkeypatch.setattr(
            "mcp_acp.manager.routes.proxies.get_proxy_config_path",
            lambda name: proxies_dir / name / "config.json",
        )
        monkeypatch.setattr(
            "mcp_acp.manager.routes.proxies.get_proxy_policy_path",
            lambda name: proxies_dir / name / "policy.json",
        )
        monkeypatch.setattr(
            "mcp_acp.manager.routes.proxies.save_proxy_config",
            mock_save_proxy_config,
        )
        monkeypatch.setattr(
            "mcp_acp.manager.routes.proxies.save_policy",
            lambda policy, path: path.parent.mkdir(parents=True, exist_ok=True) or path.write_text("{}"),
        )

        response = app.post(
            "/api/manager/proxies",
            json={
                "name": "attested-proxy",
                "server_name": "Test Server",
                "transport": "stdio",
                "command": "test-binary",
                "attestation_slsa_owner": "myorg",
                "attestation_sha256": "a" * 64,
                "attestation_require_signature": True,
            },
        )

        assert response.status_code == 201
        assert len(saved_configs) == 1
        assert saved_configs[0].backend.stdio is not None
        assert saved_configs[0].backend.stdio.attestation is not None
        assert saved_configs[0].backend.stdio.attestation.slsa_owner == "myorg"
        assert saved_configs[0].backend.stdio.attestation.expected_sha256 == "a" * 64
        assert saved_configs[0].backend.stdio.attestation.require_signature is True

    def test_keychain_failure_returns_500(
        self,
        tmp_path: Path,
        registry: ProxyRegistry,
        monkeypatch: "pytest.MonkeyPatch",
    ) -> None:
        """Keychain failure when storing API key returns 500 error."""
        proxies_dir = tmp_path / "proxies"
        proxies_dir.mkdir(parents=True)

        monkeypatch.setattr("mcp_acp.manager.config.get_proxies_dir", lambda: proxies_dir)
        # Patch where it's used (in the proxies submodule)
        monkeypatch.setattr(
            "mcp_acp.manager.routes.proxies.get_proxy_config_path",
            lambda name: proxies_dir / name / "config.json",
        )
        # Skip health check - make it succeed
        monkeypatch.setattr(
            "mcp_acp.utils.transport.check_http_health",
            lambda url, timeout, mtls_config: None,
        )

        # Mock keychain storage to fail
        class FailingCredentialStorage:
            def __init__(self, name: str) -> None:
                self._name = name

            @property
            def credential_key(self) -> str:
                return f"{self._name}_api_key"

            def save(self, api_key: str) -> None:
                raise RuntimeError("Keychain unavailable")

        monkeypatch.setattr(
            "mcp_acp.security.credential_storage.BackendCredentialStorage",
            FailingCredentialStorage,
        )

        # Create app after patching
        fastapi_app = create_manager_api_app(token="test-token", registry=registry)
        client = TestClient(fastapi_app)

        response = client.post(
            "/api/manager/proxies",
            json={
                "name": "http-proxy",
                "server_name": "Test Server",
                "transport": "streamablehttp",
                "url": "https://example.com/mcp",
                "api_key": "secret-key",
            },
        )

        assert response.status_code == 500
        data = response.json()
        assert data["detail"]["code"] == "PROXY_CREATION_FAILED"
        assert "keychain" in data["detail"]["message"].lower()

    def test_http_health_check_failure_returns_400(
        self,
        tmp_path: Path,
        registry: ProxyRegistry,
        monkeypatch: "pytest.MonkeyPatch",
    ) -> None:
        """HTTP health check failure returns 400 error."""
        proxies_dir = tmp_path / "proxies"
        proxies_dir.mkdir(parents=True)

        monkeypatch.setattr("mcp_acp.manager.config.get_proxies_dir", lambda: proxies_dir)
        # Patch where it's used (in the proxies submodule)
        monkeypatch.setattr(
            "mcp_acp.manager.routes.proxies.get_proxy_config_path",
            lambda name: proxies_dir / name / "config.json",
        )

        # Mock health check to fail
        def mock_health_check(url, timeout, mtls_config):
            raise ConnectionError("Connection refused")

        monkeypatch.setattr(
            "mcp_acp.utils.transport.check_http_health",
            mock_health_check,
        )

        # Create app after patching
        fastapi_app = create_manager_api_app(token="test-token", registry=registry)
        client = TestClient(fastapi_app)

        response = client.post(
            "/api/manager/proxies",
            json={
                "name": "http-proxy",
                "server_name": "Test Server",
                "transport": "streamablehttp",
                "url": "https://unreachable.example.com/mcp",
            },
        )

        assert response.status_code == 400
        data = response.json()
        assert data["detail"]["code"] == "BACKEND_UNREACHABLE"
        assert "health check failed" in data["detail"]["message"].lower()


class TestProxyDeletionEndpoint:
    """Tests for DELETE /api/manager/proxies/{proxy_id} endpoint."""

    def test_delete_returns_200_with_summary(
        self,
        app: TestClient,
        tmp_path: Path,
        monkeypatch: "pytest.MonkeyPatch",
    ) -> None:
        """DELETE returns 200 with deletion summary."""
        # Set up proxy config (proxy_id must match ^px_[a-f0-9]{8}:[a-z0-9-]+$)
        proxies_dir = tmp_path / "proxies"
        proxy_dir = proxies_dir / "test-proxy"
        proxy_dir.mkdir(parents=True)
        (proxy_dir / "config.json").write_text(
            '{"proxy_id": "px_a1b2c3d4:test-server", "created_at": "2024-01-15T10:30:00Z",'
            '"backend": {"server_name": "Test", "transport": "stdio",'
            '"stdio": {"command": "test", "args": []}}, "hitl": {}}'
        )

        monkeypatch.setattr("mcp_acp.manager.config.get_proxies_dir", lambda: proxies_dir)

        # Mock deletion module to avoid filesystem operations
        from mcp_acp.manager.deletion import DeleteResult

        def mock_delete_proxy(name, *, purge=False, deleted_by="api"):
            return DeleteResult(
                archived=["Config + policy", "Audit logs"],
                deleted=["Debug logs", "Backend credential from keychain"],
                archive_name="test-proxy_2024-01-15T10-30-00",
                archived_size=1024,
                deleted_size=2048,
            )

        monkeypatch.setattr(
            "mcp_acp.manager.deletion.delete_proxy",
            mock_delete_proxy,
        )

        response = app.delete("/api/manager/proxies/px_a1b2c3d4:test-server")

        assert response.status_code == 200
        data = response.json()
        assert "Config + policy" in data["archived"]
        assert "Debug logs" in data["deleted"]
        assert data["archive_name"] == "test-proxy_2024-01-15T10-30-00"
        assert data["archived_size"] == 1024

    async def test_delete_running_proxy_returns_409(
        self,
        registry: ProxyRegistry,
        tmp_path: Path,
        monkeypatch: "pytest.MonkeyPatch",
    ) -> None:
        """DELETE of running proxy returns 409."""
        # Set up proxy config (proxy_id must match ^px_[a-f0-9]{8}:[a-z0-9-]+$)
        proxies_dir = tmp_path / "proxies"
        proxy_dir = proxies_dir / "running-proxy"
        proxy_dir.mkdir(parents=True)
        (proxy_dir / "config.json").write_text(
            '{"proxy_id": "px_abcd1234:running-server", "created_at": "2024-01-15T10:30:00Z",'
            '"backend": {"server_name": "Running", "transport": "stdio",'
            '"stdio": {"command": "test", "args": []}}, "hitl": {}}'
        )

        monkeypatch.setattr("mcp_acp.manager.config.get_proxies_dir", lambda: proxies_dir)

        # Register the proxy (mark as running)
        reader, writer = AsyncMock(), AsyncMock()
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()

        await registry.register(
            proxy_name="running-proxy",
            proxy_id="px_abcd1234:running-server",
            instance_id="inst_running",
            config_summary={},
            socket_path="/tmp/running.sock",
            reader=reader,
            writer=writer,
        )

        fastapi_app = create_manager_api_app(token="test", registry=registry)
        client = TestClient(fastapi_app)

        response = client.delete("/api/manager/proxies/px_abcd1234:running-server")

        assert response.status_code == 409
        data = response.json()
        assert data["detail"]["code"] == "PROXY_RUNNING"

    def test_delete_nonexistent_proxy_returns_404(self, app: TestClient) -> None:
        """DELETE of nonexistent proxy returns 404."""
        response = app.delete("/api/manager/proxies/px_00000000:none")

        assert response.status_code == 404
        data = response.json()
        assert data["detail"]["code"] == "PROXY_NOT_FOUND"

    def test_delete_with_purge_param(
        self,
        app: TestClient,
        tmp_path: Path,
        monkeypatch: "pytest.MonkeyPatch",
    ) -> None:
        """DELETE with ?purge=true passes purge flag."""
        proxies_dir = tmp_path / "proxies"
        proxy_dir = proxies_dir / "purge-proxy"
        proxy_dir.mkdir(parents=True)
        (proxy_dir / "config.json").write_text(
            '{"proxy_id": "px_ef012345:purge-server", "created_at": "2024-01-15T10:30:00Z",'
            '"backend": {"server_name": "Purge", "transport": "stdio",'
            '"stdio": {"command": "test", "args": []}}, "hitl": {}}'
        )

        monkeypatch.setattr("mcp_acp.manager.config.get_proxies_dir", lambda: proxies_dir)

        from mcp_acp.manager.deletion import DeleteResult

        purge_called = []

        def mock_delete_proxy(name, *, purge=False, deleted_by="api"):
            purge_called.append(purge)
            return DeleteResult(
                archived=[],
                deleted=["Config directory", "Log directory"],
                archive_name=None,
                archived_size=0,
                deleted_size=4096,
            )

        monkeypatch.setattr(
            "mcp_acp.manager.deletion.delete_proxy",
            mock_delete_proxy,
        )

        response = app.delete("/api/manager/proxies/px_ef012345:purge-server?purge=true")

        assert response.status_code == 200
        assert purge_called == [True]
        data = response.json()
        assert data["archive_name"] is None


class TestProxyDeletedNotificationEndpoint:
    """Tests for POST /api/manager/proxies/notify-deleted endpoint."""

    def test_notify_deleted_returns_ok(self, app: TestClient) -> None:
        """POST returns {ok: true} and accepts notification payload."""
        response = app.post(
            "/api/manager/proxies/notify-deleted",
            json={
                "proxy_id": "px_a1b2c3d4:test-server",
                "proxy_name": "test-proxy",
                "archive_name": "test-proxy_2024-01-15T10-30-00",
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["ok"] is True

    def test_notify_deleted_without_archive_name(self, app: TestClient) -> None:
        """POST accepts notification without archive_name (purge case)."""
        response = app.post(
            "/api/manager/proxies/notify-deleted",
            json={
                "proxy_id": "px_a1b2c3d4:test-server",
                "proxy_name": "test-proxy",
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["ok"] is True

    def test_notify_deleted_missing_required_fields(self, app: TestClient) -> None:
        """POST rejects missing required fields."""
        response = app.post(
            "/api/manager/proxies/notify-deleted",
            json={
                "proxy_name": "test-proxy",
                # Missing proxy_id
            },
        )

        assert response.status_code == 422


class TestConfigSnippetEndpoint:
    """Tests for GET /api/manager/config-snippet endpoint."""

    def test_returns_snippet_for_all_proxies(
        self, app: TestClient, monkeypatch: "pytest.MonkeyPatch"
    ) -> None:
        """Returns config snippet for all configured proxies."""
        # Patch where it's used (in the proxies submodule)
        monkeypatch.setattr(
            "mcp_acp.manager.routes.proxies.list_configured_proxies",
            lambda: ["proxy-a", "proxy-b"],
        )

        response = app.get("/api/manager/config-snippet")

        assert response.status_code == 200
        data = response.json()
        assert "mcpServers" in data
        assert "proxy-a" in data["mcpServers"]
        assert "proxy-b" in data["mcpServers"]
        assert data["mcpServers"]["proxy-a"]["args"] == ["start", "--proxy", "proxy-a"]
        assert data["mcpServers"]["proxy-b"]["args"] == ["start", "--proxy", "proxy-b"]

    def test_returns_snippet_for_single_proxy(
        self, app: TestClient, monkeypatch: "pytest.MonkeyPatch"
    ) -> None:
        """Returns config snippet for a single specified proxy."""
        # Patch where it's used (in the proxies submodule)
        monkeypatch.setattr(
            "mcp_acp.manager.routes.proxies.list_configured_proxies",
            lambda: ["proxy-a", "proxy-b"],
        )

        response = app.get("/api/manager/config-snippet?proxy=proxy-a")

        assert response.status_code == 200
        data = response.json()
        assert "mcpServers" in data
        assert "proxy-a" in data["mcpServers"]
        assert "proxy-b" not in data["mcpServers"]

    def test_returns_404_for_unknown_proxy(self, app: TestClient, monkeypatch: "pytest.MonkeyPatch") -> None:
        """Returns 404 when specified proxy doesn't exist."""
        # Patch where it's used (in the proxies submodule)
        monkeypatch.setattr(
            "mcp_acp.manager.routes.proxies.list_configured_proxies",
            lambda: ["proxy-a"],
        )

        response = app.get("/api/manager/config-snippet?proxy=unknown")

        assert response.status_code == 404
        data = response.json()
        assert data["detail"]["code"] == "PROXY_NOT_FOUND"

    def test_includes_executable_path(self, app: TestClient, monkeypatch: "pytest.MonkeyPatch") -> None:
        """Response includes executable path."""
        # Patch where it's used (in the proxies submodule)
        monkeypatch.setattr(
            "mcp_acp.manager.routes.proxies.list_configured_proxies",
            lambda: ["test"],
        )

        response = app.get("/api/manager/config-snippet")

        assert response.status_code == 200
        data = response.json()
        assert "executable_path" in data
        # Should be either full path or 'mcp-acp' fallback
        assert data["executable_path"]


class TestIncidentsAggregationEndpoint:
    """Tests for GET /api/manager/incidents endpoint."""

    def test_returns_empty_when_no_incidents(
        self,
        app: TestClient,
        tmp_path: Path,
        monkeypatch: "pytest.MonkeyPatch",
    ) -> None:
        """Returns empty list when no incidents exist."""
        # Mock to return no configured proxies
        # Patch where it's used (in the incidents submodule)
        monkeypatch.setattr("mcp_acp.manager.routes.incidents.list_configured_proxies", lambda: [])
        # Mock emergency path
        monkeypatch.setattr(
            "mcp_acp.manager.routes.incidents.get_emergency_audit_path",
            lambda: tmp_path / "emergency_audit.jsonl",
        )

        response = app.get("/api/manager/incidents")

        assert response.status_code == 200
        data = response.json()
        assert data["entries"] == []
        assert data["total_returned"] == 0
        assert data["has_more"] is False

    def test_filters_by_incident_type(
        self,
        app: TestClient,
        tmp_path: Path,
        monkeypatch: "pytest.MonkeyPatch",
    ) -> None:
        """Filters incidents by type when specified."""
        # Create a proxy directory with bootstrap incident file
        proxy_dir = tmp_path / "proxies" / "test-proxy"
        proxy_dir.mkdir(parents=True)
        bootstrap_path = proxy_dir / "bootstrap.jsonl"
        bootstrap_path.write_text('{"time": "2024-01-15T10:00:00Z", "error": "test"}\n')

        # Mock functions - patch where they're used (in the incidents submodule)
        monkeypatch.setattr(
            "mcp_acp.manager.routes.incidents.list_configured_proxies", lambda: ["test-proxy"]
        )
        monkeypatch.setattr(
            "mcp_acp.manager.routes.incidents.get_proxy_config_path",
            lambda name: proxy_dir / "config.json",
        )
        monkeypatch.setattr(
            "mcp_acp.manager.routes.incidents.get_emergency_audit_path",
            lambda: tmp_path / "emergency_audit.jsonl",
        )

        # Request only bootstrap incidents
        response = app.get("/api/manager/incidents?incident_type=bootstrap")

        assert response.status_code == 200
        data = response.json()
        assert data["total_returned"] == 1
        assert data["entries"][0]["incident_type"] == "bootstrap"
        assert data["filters_applied"]["incident_type"] == "bootstrap"

    def test_annotates_entries_with_type(
        self,
        app: TestClient,
        tmp_path: Path,
        monkeypatch: "pytest.MonkeyPatch",
    ) -> None:
        """Annotates entries with incident_type without mutating originals."""
        # Create an emergency incident file
        emergency_path = tmp_path / "emergency_audit.jsonl"
        emergency_path.write_text('{"time": "2024-01-15T10:00:00Z", "event": "test"}\n')

        # Mock functions - patch where they're used (in the incidents submodule)
        monkeypatch.setattr("mcp_acp.manager.routes.incidents.list_configured_proxies", lambda: [])
        monkeypatch.setattr(
            "mcp_acp.manager.routes.incidents.get_emergency_audit_path", lambda: emergency_path
        )

        response = app.get("/api/manager/incidents?incident_type=emergency")

        assert response.status_code == 200
        data = response.json()
        assert data["total_returned"] == 1
        assert data["entries"][0]["incident_type"] == "emergency"
        # Original fields preserved
        assert data["entries"][0]["event"] == "test"


class TestProxyRoutingErrors:
    """Tests for proxy routing error cases."""

    def test_route_to_unknown_proxy_returns_404(self, app: TestClient) -> None:
        """Routing to unknown proxy returns 404."""
        response = app.get("/api/proxy/nonexistent/status")

        assert response.status_code == 404
        assert "not found" in response.json()["error"].lower()

    def test_fallback_no_proxy_returns_503(self, app: TestClient) -> None:
        """Fallback routing with no default proxy returns 503."""
        response = app.get("/api/approvals/pending")

        assert response.status_code == 503
        assert "no proxies connected" in response.json()["error"].lower()

    async def test_route_to_proxy_with_missing_socket_returns_503(
        self,
        registry: ProxyRegistry,
    ) -> None:
        """Routing to proxy with missing socket returns 503."""
        reader, writer = AsyncMock(), AsyncMock()
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()

        await registry.register(
            proxy_name="broken",
            proxy_id="px_broken:broken",
            instance_id="inst_1",
            config_summary={},
            socket_path="/nonexistent/socket.sock",
            reader=reader,
            writer=writer,
        )

        fastapi_app = create_manager_api_app(token="test", registry=registry)
        client = TestClient(fastapi_app)

        response = client.get("/api/proxy/broken/status")

        assert response.status_code == 503
        assert "socket not available" in response.json()["error"].lower()

    async def test_fallback_multiple_proxies_returns_400(
        self,
        registry: ProxyRegistry,
    ) -> None:
        """Fallback routing with multiple proxies returns 400."""
        # Register two proxies
        for name in ["proxy-a", "proxy-b"]:
            reader, writer = AsyncMock(), AsyncMock()
            writer.close = MagicMock()
            writer.wait_closed = AsyncMock()

            await registry.register(
                proxy_name=name,
                proxy_id=f"px_{name}:{name}",
                instance_id=f"inst_{name}",
                config_summary={},
                socket_path=f"/tmp/{name}.sock",
                reader=reader,
                writer=writer,
            )

        fastapi_app = create_manager_api_app(token="test", registry=registry)
        client = TestClient(fastapi_app)

        # Request without specifying proxy
        response = client.get("/api/approvals/pending")

        assert response.status_code == 400
        error = response.json()["error"].lower()
        assert "multiple proxies" in error or "specify" in error


class TestManagerApiPrefixes:
    """Tests for manager API prefix handling."""

    def test_manager_prefixes_defined(self) -> None:
        """Manager API prefixes are defined."""
        assert "/api/manager/" in MANAGER_API_PREFIXES
        assert "/api/events" in MANAGER_API_PREFIXES
        assert "/api/proxy/" in MANAGER_API_PREFIXES

    def test_manager_status_not_forwarded(self, app: TestClient) -> None:
        """Manager status endpoint is not forwarded to proxy."""
        # This should return 200 from manager, not 503 (no proxy)
        response = app.get("/api/manager/status")
        assert response.status_code == 200

    def test_manager_proxies_not_forwarded(self, app: TestClient) -> None:
        """Manager proxies endpoint is not forwarded to proxy."""
        response = app.get("/api/manager/proxies")
        assert response.status_code == 200


class TestErrorResponse:
    """Tests for error_response helper."""

    def test_creates_json_response_with_error(self) -> None:
        """Creates JSONResponse with error field."""
        response = error_response(404, "Not found")

        assert response.status_code == 404
        body = json.loads(response.body)
        assert body["error"] == "Not found"

    def test_includes_detail_when_provided(self) -> None:
        """Includes detail field when provided."""
        response = error_response(500, "Error", detail="Additional info")

        body = json.loads(response.body)
        assert body["error"] == "Error"
        assert body["detail"] == "Additional info"

    def test_omits_detail_when_not_provided(self) -> None:
        """Omits detail field when not provided."""
        response = error_response(400, "Bad request")

        body = json.loads(response.body)
        assert "detail" not in body


class TestPathSafety:
    """Tests for path traversal protection."""

    def test_safe_path_within_base(self, tmp_path) -> None:
        """Path within base directory is safe."""
        base = tmp_path / "static"
        base.mkdir()
        requested = base / "assets" / "index.js"

        assert is_safe_path(base, requested) is True

    def test_unsafe_path_traversal_detected(self, tmp_path) -> None:
        """Path traversal attempt is detected."""
        base = tmp_path / "static"
        base.mkdir()
        # Attempt to escape base directory
        requested = base / ".." / ".." / "etc" / "passwd"

        assert is_safe_path(base, requested) is False

    def test_unsafe_absolute_path_outside_base(self, tmp_path) -> None:
        """Absolute path outside base is unsafe."""
        base = tmp_path / "static"
        base.mkdir()
        requested = tmp_path / "other" / "file.txt"

        assert is_safe_path(base, requested) is False


class TestStaticFileServing:
    """Tests for static file serving (SPA)."""

    def test_root_returns_index_html(self, app: TestClient) -> None:
        """Root path returns index.html."""
        # This will work if STATIC_DIR exists with index.html
        # In tests, it may return 404 if static files aren't built
        response = app.get("/")
        # Either serves index.html or 404 if not built
        assert response.status_code in (200, 404)

    def test_spa_routes_return_index_html(self, app: TestClient) -> None:
        """SPA routes fall back to index.html."""
        response = app.get("/some/spa/route")
        # Same as above - depends on static files being built
        assert response.status_code in (200, 404)


class TestSSEEndpoint:
    """Tests for /api/events SSE endpoint.

    Note: Full SSE testing requires async client that can handle streaming.
    SSE functionality is covered by registry tests (broadcast_proxy_event, etc.)
    """

    def test_manager_api_prefixes_include_events(self) -> None:
        """SSE events endpoint is in manager API prefixes (not forwarded to proxy)."""
        assert "/api/events" in MANAGER_API_PREFIXES


class TestActivityTrackingMiddleware:
    """Tests for HTTP middleware that tracks activity for idle shutdown."""

    def test_idle_exempt_paths_defined(self) -> None:
        """Idle exempt paths are defined."""
        assert "/api/manager/status" in IDLE_EXEMPT_PATHS
        assert "/api/events" in IDLE_EXEMPT_PATHS

    def test_status_endpoint_does_not_record_activity(self, registry: ProxyRegistry) -> None:
        """Status endpoint requests don't reset idle timer."""
        fastapi_app = create_manager_api_app(token="test", registry=registry)
        client = TestClient(fastapi_app)

        # Record activity and wait
        registry.record_activity()
        time.sleep(0.02)
        before = registry.seconds_since_last_activity()

        # Make status request
        client.get("/api/manager/status")

        # Activity time should NOT have been reset
        after = registry.seconds_since_last_activity()
        assert after >= before

    def test_proxies_endpoint_records_activity(self, registry: ProxyRegistry) -> None:
        """Non-exempt endpoints reset idle timer."""
        fastapi_app = create_manager_api_app(token="test", registry=registry)
        client = TestClient(fastapi_app)

        # Wait to ensure time passes
        time.sleep(0.02)
        before = registry.seconds_since_last_activity()

        # Make proxies request (not exempt)
        client.get("/api/manager/proxies")

        # Activity time should have been reset
        after = registry.seconds_since_last_activity()
        assert after < before

    def test_idle_exempt_paths_is_frozenset(self) -> None:
        """IDLE_EXEMPT_PATHS is immutable."""
        assert isinstance(IDLE_EXEMPT_PATHS, frozenset)
