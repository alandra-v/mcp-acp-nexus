"""Unit tests for config API routes.

Tests the configuration management endpoints.
Uses AAA pattern (Arrange-Act-Assert) for clarity.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from mcp_acp.api.routes.config import _build_config_response, router
from mcp_acp.api.schemas import (
    AuthConfigResponse,
    BackendConfigResponse,
    ConfigResponse,
    ConfigUpdateRequest,
    LoggingConfigResponse,
    LoggingConfigUpdate,
    MTLSConfigResponse,
    OIDCConfigResponse,
    ProxyConfigResponse,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def mock_config() -> MagicMock:
    """Create a mock AppConfig with auth and transport configs."""
    config = MagicMock()
    config.backend.server_name = "test-server"
    config.backend.transport = "stdio"

    # STDIO transport config
    config.backend.stdio = MagicMock()
    config.backend.stdio.command = "npx"
    config.backend.stdio.args = ["-y", "@modelcontextprotocol/server"]
    config.backend.stdio.attestation = None

    # HTTP transport config (None for STDIO-only)
    config.backend.http = None

    config.logging.log_dir = "/tmp/logs"
    config.logging.log_level = "INFO"
    config.logging.include_payloads = False
    config.proxy.name = "test-proxy"

    # Auth config with OIDC
    config.auth = MagicMock()
    config.auth.oidc = MagicMock()
    config.auth.oidc.issuer = "https://auth.example.com"
    config.auth.oidc.client_id = "test-client-id"
    config.auth.oidc.audience = "test-audience"
    config.auth.oidc.scopes = ["openid", "profile"]

    # mTLS is per-proxy, stored at config.mtls (not config.auth.mtls)
    config.mtls = None

    # HITL config
    config.hitl = MagicMock()
    config.hitl.timeout_seconds = 60
    config.hitl.default_on_timeout = "deny"
    config.hitl.approval_ttl_seconds = 600
    # Note: cache_side_effects has moved to per-rule policy configuration

    return config


@pytest.fixture
def mock_config_no_auth() -> MagicMock:
    """Create a mock AppConfig without auth."""
    config = MagicMock()
    config.backend.server_name = "test-server"
    config.backend.transport = "stdio"
    config.backend.stdio = MagicMock()
    config.backend.stdio.command = "npx"
    config.backend.stdio.args = []
    config.backend.stdio.attestation = None
    config.backend.http = None
    config.logging.log_dir = "/tmp/logs"
    config.logging.log_level = "INFO"
    config.logging.include_payloads = False
    config.proxy.name = "test-proxy"
    config.auth = None

    # HITL config
    config.hitl = MagicMock()
    config.hitl.timeout_seconds = 60
    config.hitl.default_on_timeout = "deny"
    config.hitl.approval_ttl_seconds = 600
    # Note: cache_side_effects has moved to per-rule policy configuration

    return config


@pytest.fixture
def app(mock_config: MagicMock) -> FastAPI:
    """Create a test FastAPI app with config router and mocked state."""
    app = FastAPI()
    app.include_router(router, prefix="/api/config")
    # Set app.state.config for dependency injection
    app.state.config = mock_config
    return app


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    """Create a test client."""
    return TestClient(app)


# =============================================================================
# Tests: GET /api/config
# =============================================================================


class TestGetConfig:
    """Tests for GET /api/config endpoint."""

    def test_returns_config_with_auth(self, client: TestClient, mock_config: MagicMock) -> None:
        """Given config with auth, returns full config details."""
        # Arrange
        with (
            patch(
                "mcp_acp.api.routes.config.get_proxy_config_path",
                return_value=Path("/config/app.json"),
            ),
            patch(
                "mcp_acp.api.routes.config.get_proxy_log_dir",
                return_value=Path("/tmp/logs"),
            ),
        ):
            # Act
            response = client.get("/api/config")

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["backend"]["server_name"] == "test-server"
        assert data["backend"]["transport"] == "stdio"
        assert data["backend"]["stdio"]["command"] == "npx"
        assert data["logging"]["log_dir"] == "/tmp/logs"
        assert data["auth"]["oidc"]["issuer"] == "https://auth.example.com"
        assert data["auth"]["oidc"]["client_id"] == "test-client-id"
        assert data["auth"]["mtls"] is None
        assert data["requires_restart_for_changes"] is True

    def test_returns_config_without_auth(self, mock_config_no_auth: MagicMock) -> None:
        """Given config without auth, returns null auth."""
        # Arrange
        app = FastAPI()
        app.include_router(router, prefix="/api/config")
        app.state.config = mock_config_no_auth
        client = TestClient(app)

        with patch(
            "mcp_acp.api.routes.config.get_proxy_config_path",
            return_value=Path("/config/app.json"),
        ):
            # Act
            response = client.get("/api/config")

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["auth"] is None

    def test_returns_full_transport_details(self, client: TestClient, mock_config: MagicMock) -> None:
        """Config response includes full transport configuration."""
        # Arrange
        with patch(
            "mcp_acp.api.routes.config.get_proxy_config_path",
            return_value=Path("/config/app.json"),
        ):
            # Act
            response = client.get("/api/config")

        # Assert
        data = response.json()
        assert data["backend"]["stdio"]["command"] == "npx"
        assert data["backend"]["stdio"]["args"] == ["-y", "@modelcontextprotocol/server"]
        assert data["backend"]["http"] is None


# =============================================================================
# Tests: PUT /api/config
# =============================================================================


class TestUpdateConfig:
    """Tests for PUT /api/config endpoint."""

    def test_updates_logging_config(self, client: TestClient, tmp_path: Path) -> None:
        """Given logging updates, saves and returns updated config."""
        # Arrange
        mock_config = MagicMock()
        mock_config.model_dump.return_value = {
            "backend": {
                "server_name": "test",
                "transport": "stdio",
                "stdio": {"command": "npx", "args": []},
                "http": None,
            },
            "logging": {"log_dir": "/tmp/logs", "log_level": "INFO", "include_payloads": False},
            "proxy": {"name": "test"},
            "auth": None,
        }
        mock_config.save_to_file = MagicMock()

        # Configure new_config mock for response building
        new_config = MagicMock()
        new_config.backend.server_name = "test"
        new_config.backend.transport = "stdio"
        new_config.backend.stdio = MagicMock()
        new_config.backend.stdio.command = "npx"
        new_config.backend.stdio.args = []
        new_config.backend.stdio.attestation = None
        new_config.backend.http = None
        new_config.logging.log_dir = "/tmp/logs"
        new_config.logging.log_level = "DEBUG"
        new_config.logging.include_payloads = True
        new_config.proxy.name = "test"
        new_config.auth = None
        new_config.hitl = MagicMock()
        new_config.hitl.timeout_seconds = 60
        new_config.hitl.default_on_timeout = "deny"
        new_config.hitl.approval_ttl_seconds = 600
        # Note: cache_side_effects has moved to per-rule policy configuration
        new_config.save_to_file = MagicMock()

        config_path = tmp_path / "config.json"
        mock_per_proxy = MagicMock()

        with patch("mcp_acp.api.routes.config.load_proxy_config", return_value=mock_per_proxy):
            with patch("mcp_acp.api.routes.config.build_app_config_from_per_proxy", return_value=mock_config):
                with patch("mcp_acp.config.AppConfig.model_validate", return_value=new_config):
                    with patch("mcp_acp.api.routes.config.PerProxyConfig", return_value=MagicMock()):
                        with patch("mcp_acp.api.routes.config.save_proxy_config"):
                            with patch(
                                "mcp_acp.api.routes.config.get_proxy_config_path",
                                return_value=config_path,
                            ):
                                # Act
                                response = client.put(
                                    "/api/config",
                                    json={"logging": {"log_level": "DEBUG", "include_payloads": True}},
                                )

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert "Restart the client" in data["message"]

    def test_returns_404_when_config_missing(self, client: TestClient, tmp_path: Path) -> None:
        """Given missing config file, returns 404."""
        # Arrange
        with patch(
            "mcp_acp.api.routes.config.load_proxy_config",
            side_effect=FileNotFoundError,
        ):
            with patch(
                "mcp_acp.api.routes.config.get_proxy_config_path",
                return_value=tmp_path / "missing.json",
            ):
                # Act
                response = client.put("/api/config", json={"logging": {"log_level": "DEBUG"}})

        # Assert
        assert response.status_code == 404

    def test_empty_update_is_valid(self, client: TestClient, tmp_path: Path) -> None:
        """Given empty update, returns current config."""
        # Arrange
        mock_config = MagicMock()
        mock_config.model_dump.return_value = {
            "backend": {
                "server_name": "test",
                "transport": "stdio",
                "stdio": {"command": "npx", "args": []},
                "http": None,
            },
            "logging": {"log_dir": "/tmp", "log_level": "INFO", "include_payloads": False},
            "proxy": {"name": "test"},
            "auth": None,
        }
        mock_config.save_to_file = MagicMock()
        mock_config.backend.server_name = "test"
        mock_config.backend.transport = "stdio"
        mock_config.backend.stdio = MagicMock()
        mock_config.backend.stdio.command = "npx"
        mock_config.backend.stdio.args = []
        mock_config.backend.stdio.attestation = None
        mock_config.backend.http = None
        mock_config.logging.log_dir = "/tmp"
        mock_config.logging.log_level = "INFO"
        mock_config.logging.include_payloads = False
        mock_config.proxy.name = "test"
        mock_config.auth = None
        mock_config.hitl = MagicMock()
        mock_config.hitl.timeout_seconds = 60
        mock_config.hitl.default_on_timeout = "deny"
        mock_config.hitl.approval_ttl_seconds = 600
        # Note: cache_side_effects has moved to per-rule policy configuration

        mock_per_proxy = MagicMock()

        with patch("mcp_acp.api.routes.config.load_proxy_config", return_value=mock_per_proxy):
            with patch("mcp_acp.api.routes.config.build_app_config_from_per_proxy", return_value=mock_config):
                with patch("mcp_acp.config.AppConfig.model_validate", return_value=mock_config):
                    with patch("mcp_acp.api.routes.config.PerProxyConfig", return_value=MagicMock()):
                        with patch("mcp_acp.api.routes.config.save_proxy_config"):
                            with patch(
                                "mcp_acp.api.routes.config.get_proxy_config_path",
                                return_value=tmp_path / "config.json",
                            ):
                                # Act
                                response = client.put("/api/config", json={})

        # Assert
        assert response.status_code == 200


# =============================================================================
# Tests: Helper Functions
# =============================================================================


class TestBuildConfigResponse:
    """Tests for _build_config_response helper."""

    def test_builds_response_with_auth(self, mock_config: MagicMock) -> None:
        """Given config with auth, builds complete response."""
        # Arrange
        with patch(
            "mcp_acp.api.routes.config.get_proxy_config_path",
            return_value=Path("/test/config.json"),
        ):
            # Act
            response = _build_config_response(mock_config)

        # Assert
        assert isinstance(response, ConfigResponse)
        assert response.backend.server_name == "test-server"
        assert response.logging.log_level == "INFO"
        assert response.auth is not None
        assert response.auth.oidc is not None
        assert response.auth.oidc.issuer == "https://auth.example.com"
        assert response.config_path == "/test/config.json"

    def test_builds_response_without_auth(self, mock_config_no_auth: MagicMock) -> None:
        """Given config without auth, builds response with null auth."""
        # Arrange
        with patch(
            "mcp_acp.api.routes.config.get_proxy_config_path",
            return_value=Path("/test/config.json"),
        ):
            # Act
            response = _build_config_response(mock_config_no_auth)

        # Assert
        assert response.auth is None

    def test_includes_mtls_when_present(self, mock_config: MagicMock) -> None:
        """Given config with mTLS (per-proxy), includes full mTLS details in auth response."""
        # Arrange - mTLS is per-proxy at config.mtls, not config.auth.mtls
        mock_config.mtls = MagicMock()
        mock_config.mtls.client_cert_path = "/path/to/cert.pem"
        mock_config.mtls.client_key_path = "/path/to/key.pem"
        mock_config.mtls.ca_bundle_path = "/path/to/ca.pem"

        with patch(
            "mcp_acp.api.routes.config.get_proxy_config_path",
            return_value=Path("/test/config.json"),
        ):
            # Act
            response = _build_config_response(mock_config)

        # Assert - mTLS is included in auth response (API schema nests it there)
        assert response.auth is not None
        assert response.auth.mtls is not None
        assert response.auth.mtls.client_cert_path == "/path/to/cert.pem"

    def test_includes_http_transport_when_present(self, mock_config: MagicMock) -> None:
        """Given config with HTTP transport, includes full HTTP details."""
        # Arrange
        mock_config.backend.http = MagicMock()
        mock_config.backend.http.url = "http://localhost:3010/mcp"
        mock_config.backend.http.timeout = 60

        with patch(
            "mcp_acp.api.routes.config.get_proxy_config_path",
            return_value=Path("/test/config.json"),
        ):
            # Act
            response = _build_config_response(mock_config)

        # Assert
        assert response.backend.http is not None
        assert response.backend.http.url == "http://localhost:3010/mcp"
        assert response.backend.http.timeout == 60


# =============================================================================
# Tests: Response Models
# =============================================================================


class TestResponseModels:
    """Tests for response model serialization."""

    def test_backend_config_response(self) -> None:
        """BackendConfigResponse serializes correctly."""
        # Act
        response = BackendConfigResponse(
            server_name="test-server",
            transport="stdio",
        )
        data = response.model_dump()

        # Assert
        assert data["server_name"] == "test-server"
        assert data["transport"] == "stdio"

    def test_logging_config_response(self) -> None:
        """LoggingConfigResponse serializes correctly."""
        # Act
        response = LoggingConfigResponse(
            log_dir="/var/log",
            log_level="DEBUG",
            include_payloads=True,
        )
        data = response.model_dump()

        # Assert
        assert data["log_dir"] == "/var/log"
        assert data["include_payloads"] is True

    def test_auth_config_response_with_oidc(self) -> None:
        """AuthConfigResponse serializes correctly with OIDC."""
        # Act
        oidc = OIDCConfigResponse(
            issuer="https://auth.example.com",
            client_id="test-client",
            audience="test-api",
            scopes=["openid", "profile"],
        )
        response = AuthConfigResponse(oidc=oidc, mtls=None)
        data = response.model_dump()

        # Assert
        assert data["oidc"]["issuer"] == "https://auth.example.com"
        assert data["oidc"]["scopes"] == ["openid", "profile"]
        assert data["mtls"] is None

    def test_auth_config_response_with_mtls(self) -> None:
        """AuthConfigResponse serializes correctly with mTLS."""
        # Act
        mtls = MTLSConfigResponse(
            client_cert_path="/path/to/cert.pem",
            client_key_path="/path/to/key.pem",
            ca_bundle_path="/path/to/ca.pem",
        )
        response = AuthConfigResponse(oidc=None, mtls=mtls)
        data = response.model_dump()

        # Assert
        assert data["oidc"] is None
        assert data["mtls"]["client_cert_path"] == "/path/to/cert.pem"

    def test_proxy_config_response(self) -> None:
        """ProxyConfigResponse serializes correctly."""
        # Act
        response = ProxyConfigResponse(name="my-proxy")
        data = response.model_dump()

        # Assert
        assert data["name"] == "my-proxy"


# =============================================================================
# Tests: Update Models
# =============================================================================


class TestUpdateModels:
    """Tests for update model validation."""

    def test_logging_update_partial(self) -> None:
        """LoggingConfigUpdate allows partial updates."""
        # Act
        update = LoggingConfigUpdate(log_level="DEBUG")

        # Assert
        assert update.log_level == "DEBUG"
        assert update.log_dir is None
        assert update.include_payloads is None

    def test_config_update_request_empty(self) -> None:
        """ConfigUpdateRequest allows empty update."""
        # Act
        update = ConfigUpdateRequest()

        # Assert
        assert update.logging is None
        assert update.backend is None

    def test_config_update_request_with_logging(self) -> None:
        """ConfigUpdateRequest with logging updates."""
        # Act
        update = ConfigUpdateRequest(logging=LoggingConfigUpdate(log_level="DEBUG", include_payloads=True))

        # Assert
        assert update.logging is not None
        assert update.logging.log_level == "DEBUG"
