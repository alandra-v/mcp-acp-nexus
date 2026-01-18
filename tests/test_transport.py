"""Tests for transport utilities.

Tests use the AAA pattern (Arrange-Act-Assert) for clarity.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx
import pytest
from fastmcp.client.transports import StdioTransport, StreamableHttpTransport

from mcp_acp.config import BackendConfig, HttpTransportConfig, MTLSConfig, StdioTransportConfig
from mcp_acp.utils.transport import (
    USER_AGENT,
    SSLCertificateError,
    SSLHandshakeError,
    _check_certificate_expiry,
    _validate_certificates,
    create_backend_transport,
    create_httpx_client_factory,
    create_mtls_client_factory,
)


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def stdio_config() -> StdioTransportConfig:
    return StdioTransportConfig(command="echo", args=["hello"])


@pytest.fixture
def http_config() -> HttpTransportConfig:
    return HttpTransportConfig(url="http://localhost:3000/mcp")


@pytest.fixture
def https_config() -> HttpTransportConfig:
    """HTTPS config for mTLS tests."""
    return HttpTransportConfig(url="https://localhost:3000/mcp")


@pytest.fixture
def backend_stdio_only(stdio_config: StdioTransportConfig) -> BackendConfig:
    return BackendConfig(server_name="test", transport="auto", stdio=stdio_config)


@pytest.fixture
def backend_http_only(http_config: HttpTransportConfig) -> BackendConfig:
    return BackendConfig(server_name="test", transport="auto", http=http_config)


@pytest.fixture
def backend_both(stdio_config: StdioTransportConfig, http_config: HttpTransportConfig) -> BackendConfig:
    return BackendConfig(server_name="test", transport="auto", stdio=stdio_config, http=http_config)


# ============================================================================
# Tests: Explicit Transport Selection
# ============================================================================


class TestExplicitTransport:
    """Tests for explicit transport selection."""

    def test_explicit_stdio_returns_stdio(self, stdio_config: StdioTransportConfig):
        # Arrange
        config = BackendConfig(server_name="test", transport="stdio", stdio=stdio_config)

        # Act
        transport, transport_type = create_backend_transport(config)

        # Assert
        assert isinstance(transport, StdioTransport)
        assert transport_type == "stdio"

    def test_explicit_stdio_without_config_raises(self):
        # Arrange
        config = BackendConfig(server_name="test", transport="stdio", stdio=None)

        # Act & Assert
        with pytest.raises(ValueError, match="stdio configuration is missing"):
            create_backend_transport(config)

    def test_explicit_http_returns_http_when_reachable(self, http_config: HttpTransportConfig):
        # Arrange
        config = BackendConfig(server_name="test", transport="streamablehttp", http=http_config)

        # Act
        with patch("mcp_acp.utils.transport.check_http_health"):
            transport, transport_type = create_backend_transport(config)

        # Assert
        assert isinstance(transport, StreamableHttpTransport)
        assert transport_type == "streamablehttp"

    def test_explicit_http_without_config_raises(self):
        # Arrange
        config = BackendConfig(server_name="test", transport="streamablehttp", http=None)

        # Act & Assert
        with pytest.raises(ValueError, match="http configuration is missing"):
            create_backend_transport(config)

    def test_explicit_http_raises_when_unreachable(self, http_config: HttpTransportConfig):
        """Explicit HTTP selection fails after retries when unreachable."""
        # Arrange
        config = BackendConfig(server_name="test", transport="streamablehttp", http=http_config)

        # Act & Assert - raises TimeoutError after exhausting retries
        with patch(
            "mcp_acp.utils.transport.check_http_health",
            side_effect=ConnectionError("refused"),
        ):
            with pytest.raises(TimeoutError, match="not reachable after"):
                create_backend_transport(config)

    def test_explicit_http_raises_on_timeout(self, http_config: HttpTransportConfig):
        """Explicit HTTP selection fails on timeout (no fallback)."""
        # Arrange
        config = BackendConfig(server_name="test", transport="streamablehttp", http=http_config)

        # Act & Assert
        with patch(
            "mcp_acp.utils.transport.check_http_health",
            side_effect=TimeoutError("timed out"),
        ):
            with pytest.raises(TimeoutError):
                create_backend_transport(config)

    def test_explicit_https_without_mtls_suggests_mtls(self, https_config: HttpTransportConfig):
        """HTTPS without mTLS config suggests mTLS when connection fails."""
        # Arrange
        config = BackendConfig(server_name="test", transport="streamablehttp", http=https_config)

        # Act & Assert - should raise ConnectionError with mTLS hint
        with patch(
            "mcp_acp.utils.transport.check_http_health",
            side_effect=ConnectionError("connection reset"),
        ):
            with pytest.raises(ConnectionError, match="mTLS"):
                create_backend_transport(config)

    def test_ssl_handshake_error_not_retried(self, https_config: HttpTransportConfig):
        """SSL handshake errors fail immediately without retry."""
        # Arrange
        config = BackendConfig(server_name="test", transport="streamablehttp", http=https_config)
        mock = MagicMock(side_effect=SSLHandshakeError("handshake failed"))

        # Act & Assert - should raise immediately, mock called only once
        with patch("mcp_acp.utils.transport.check_http_health", mock):
            with pytest.raises(SSLHandshakeError, match="handshake failed"):
                create_backend_transport(config)

        # Verify no retries (only 1 call)
        assert mock.call_count == 1

    def test_ssl_certificate_error_not_retried(self, https_config: HttpTransportConfig):
        """SSL certificate errors fail immediately without retry."""
        # Arrange
        config = BackendConfig(server_name="test", transport="streamablehttp", http=https_config)
        mock = MagicMock(side_effect=SSLCertificateError("cert validation failed"))

        # Act & Assert - should raise immediately, mock called only once
        with patch("mcp_acp.utils.transport.check_http_health", mock):
            with pytest.raises(SSLCertificateError, match="cert validation failed"):
                create_backend_transport(config)

        # Verify no retries (only 1 call)
        assert mock.call_count == 1


# ============================================================================
# Tests: Auto-detect Transport
# ============================================================================


class TestAutoDetect:
    """Tests for auto-detect transport selection."""

    def test_stdio_only_returns_stdio(self, backend_stdio_only: BackendConfig):
        # Act
        transport, transport_type = create_backend_transport(backend_stdio_only)

        # Assert
        assert isinstance(transport, StdioTransport)
        assert transport_type == "stdio"

    def test_http_only_returns_http_when_reachable(self, backend_http_only: BackendConfig):
        # Act
        with patch("mcp_acp.utils.transport.check_http_health"):
            transport, transport_type = create_backend_transport(backend_http_only)

        # Assert
        assert isinstance(transport, StreamableHttpTransport)
        assert transport_type == "streamablehttp"

    def test_http_only_raises_when_unreachable(self, backend_http_only: BackendConfig):
        """HTTP-only config fails after retries when unreachable."""
        # Act & Assert - raises TimeoutError after exhausting retries
        with patch(
            "mcp_acp.utils.transport.check_http_health",
            side_effect=ConnectionError("refused"),
        ):
            with pytest.raises(TimeoutError, match="not reachable after"):
                create_backend_transport(backend_http_only)

    def test_http_only_raises_on_timeout(self, backend_http_only: BackendConfig):
        # Act & Assert
        with patch(
            "mcp_acp.utils.transport.check_http_health",
            side_effect=TimeoutError("timed out"),
        ):
            with pytest.raises(TimeoutError):
                create_backend_transport(backend_http_only)

    def test_both_prefers_http_when_reachable(self, backend_both: BackendConfig):
        # Act
        with patch("mcp_acp.utils.transport.check_http_health"):
            transport, transport_type = create_backend_transport(backend_both)

        # Assert
        assert isinstance(transport, StreamableHttpTransport)
        assert transport_type == "streamablehttp"

    def test_both_falls_back_to_stdio_when_http_unreachable(self, backend_both: BackendConfig):
        # Act
        with patch(
            "mcp_acp.utils.transport.check_http_health",
            side_effect=ConnectionError("refused"),
        ):
            transport, transport_type = create_backend_transport(backend_both)

        # Assert
        assert isinstance(transport, StdioTransport)
        assert transport_type == "stdio"

    def test_neither_configured_raises(self):
        # Arrange - transport="auto" but no stdio or http config
        config = BackendConfig(server_name="test", transport="auto")

        # Act & Assert
        with pytest.raises(ValueError, match="No transport configured"):
            create_backend_transport(config)

    def test_both_falls_back_to_stdio_on_timeout(self, backend_both: BackendConfig):
        """Auto-detect falls back to STDIO when HTTP times out."""
        # Act
        with patch(
            "mcp_acp.utils.transport.check_http_health",
            side_effect=TimeoutError("timed out"),
        ):
            transport, transport_type = create_backend_transport(backend_both)

        # Assert
        assert isinstance(transport, StdioTransport)
        assert transport_type == "stdio"


# ============================================================================
# Tests: Transport Creation
# ============================================================================


class TestTransportCreation:
    """Tests for transport object creation."""

    def test_stdio_transport_has_correct_command(self, stdio_config: StdioTransportConfig):
        # Arrange
        config = BackendConfig(server_name="test", transport="stdio", stdio=stdio_config)

        # Act
        transport, _ = create_backend_transport(config)

        # Assert
        assert transport.command == "echo"
        assert transport.args == ["hello"]

    def test_http_transport_has_correct_url(self, http_config: HttpTransportConfig):
        # Arrange
        config = BackendConfig(server_name="test", transport="streamablehttp", http=http_config)

        # Act
        with patch("mcp_acp.utils.transport.check_http_health"):
            transport, _ = create_backend_transport(config)

        # Assert
        assert transport.url == "http://localhost:3000/mcp"


# ============================================================================
# Tests: mTLS Client Factory
# ============================================================================


class TestMTLSClientFactory:
    """Tests for mTLS client factory creation."""

    @pytest.fixture
    def cert_files(self, tmp_path: Path) -> dict[str, Path]:
        """Create temporary certificate files with valid PEM content."""
        # Create minimal valid PEM files (content doesn't matter for path tests)
        cert_path = tmp_path / "client.pem"
        key_path = tmp_path / "client-key.pem"
        ca_path = tmp_path / "ca-bundle.pem"

        cert_path.write_text("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----")
        key_path.write_text("-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----")
        ca_path.write_text("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----")

        return {"cert": cert_path, "key": key_path, "ca": ca_path}

    @pytest.fixture
    def mtls_config(self, cert_files: dict[str, Path]) -> MTLSConfig:
        """Create MTLSConfig with valid paths."""
        return MTLSConfig(
            client_cert_path=str(cert_files["cert"]),
            client_key_path=str(cert_files["key"]),
            ca_bundle_path=str(cert_files["ca"]),
        )

    def test_create_factory_returns_callable(self, mtls_config: MTLSConfig, cert_files: dict[str, Path]):
        """Factory creation succeeds with valid certificate paths."""
        # Act - skip actual SSL validation since test certs are not real
        with patch("mcp_acp.security.mtls._validate_certificates"):
            factory = create_mtls_client_factory(mtls_config)

        # Assert
        assert callable(factory)

    def test_factory_creates_httpx_client(self, mtls_config: MTLSConfig, cert_files: dict[str, Path]):
        """Factory returns httpx.AsyncClient with correct configuration."""
        # Act - mock validation, ssl context, and httpx client creation
        mock_ssl_ctx = MagicMock()
        with (
            patch("mcp_acp.security.mtls._validate_certificates"),
            patch("mcp_acp.security.mtls.ssl.create_default_context", return_value=mock_ssl_ctx),
            patch("mcp_acp.security.mtls.httpx.AsyncClient") as mock_client_cls,
        ):
            factory = create_mtls_client_factory(mtls_config)
            factory()

        # Assert
        mock_client_cls.assert_called_once()
        # Verify ssl context was passed as verify param
        call_kwargs = mock_client_cls.call_args[1]
        assert "verify" in call_kwargs
        assert call_kwargs["verify"] == mock_ssl_ctx
        # Verify ssl context had cert chain loaded
        mock_ssl_ctx.load_cert_chain.assert_called_once()

    def test_create_factory_missing_cert_raises(self, tmp_path: Path):
        """FileNotFoundError when client certificate doesn't exist."""
        # Arrange
        key_path = tmp_path / "client-key.pem"
        ca_path = tmp_path / "ca-bundle.pem"
        key_path.write_text("key")
        ca_path.write_text("ca")

        config = MTLSConfig(
            client_cert_path=str(tmp_path / "missing.pem"),
            client_key_path=str(key_path),
            ca_bundle_path=str(ca_path),
        )

        # Act & Assert
        with pytest.raises(FileNotFoundError, match="client certificate not found"):
            create_mtls_client_factory(config)

    def test_create_factory_missing_key_raises(self, tmp_path: Path):
        """FileNotFoundError when client key doesn't exist."""
        # Arrange
        cert_path = tmp_path / "client.pem"
        ca_path = tmp_path / "ca-bundle.pem"
        cert_path.write_text("cert")
        ca_path.write_text("ca")

        config = MTLSConfig(
            client_cert_path=str(cert_path),
            client_key_path=str(tmp_path / "missing-key.pem"),
            ca_bundle_path=str(ca_path),
        )

        # Act & Assert
        with pytest.raises(FileNotFoundError, match="client key not found"):
            create_mtls_client_factory(config)

    def test_create_factory_missing_ca_raises(self, tmp_path: Path):
        """FileNotFoundError when CA bundle doesn't exist."""
        # Arrange
        cert_path = tmp_path / "client.pem"
        key_path = tmp_path / "client-key.pem"
        cert_path.write_text("cert")
        key_path.write_text("key")

        config = MTLSConfig(
            client_cert_path=str(cert_path),
            client_key_path=str(key_path),
            ca_bundle_path=str(tmp_path / "missing-ca.pem"),
        )

        # Act & Assert
        with pytest.raises(FileNotFoundError, match="CA bundle not found"):
            create_mtls_client_factory(config)

    def test_create_factory_expands_tilde_paths(self, tmp_path: Path, monkeypatch):
        """Factory expands ~ in certificate paths."""
        # Arrange - mock home directory
        monkeypatch.setenv("HOME", str(tmp_path))

        cert_path = tmp_path / "client.pem"
        key_path = tmp_path / "client-key.pem"
        ca_path = tmp_path / "ca-bundle.pem"
        cert_path.write_text("cert")
        key_path.write_text("key")
        ca_path.write_text("ca")

        config = MTLSConfig(
            client_cert_path="~/client.pem",
            client_key_path="~/client-key.pem",
            ca_bundle_path="~/ca-bundle.pem",
        )

        # Act - skip validation
        with patch("mcp_acp.security.mtls._validate_certificates"):
            factory = create_mtls_client_factory(config)

        # Assert
        assert callable(factory)


# ============================================================================
# Tests: mTLS Transport Integration
# ============================================================================


class TestTransportWithMTLS:
    """Tests for transport creation with mTLS."""

    @pytest.fixture
    def mtls_config(self, tmp_path: Path) -> MTLSConfig:
        """Create MTLSConfig with valid paths."""
        cert_path = tmp_path / "client.pem"
        key_path = tmp_path / "client-key.pem"
        ca_path = tmp_path / "ca-bundle.pem"
        cert_path.write_text("cert")
        key_path.write_text("key")
        ca_path.write_text("ca")

        return MTLSConfig(
            client_cert_path=str(cert_path),
            client_key_path=str(key_path),
            ca_bundle_path=str(ca_path),
        )

    def test_http_transport_with_mtls_has_factory(
        self, https_config: HttpTransportConfig, mtls_config: MTLSConfig
    ):
        """StreamableHttpTransport created with client factory when mTLS configured."""
        # Arrange - must use https:// for mTLS to be applied
        config = BackendConfig(server_name="test", transport="streamablehttp", http=https_config)

        # Act
        with (
            patch("mcp_acp.utils.transport.check_http_health"),
            patch("mcp_acp.security.mtls._validate_certificates"),
        ):
            transport, transport_type = create_backend_transport(config, mtls_config)

        # Assert
        assert isinstance(transport, StreamableHttpTransport)
        assert transport_type == "streamablehttp"
        # Verify factory was set
        assert transport.httpx_client_factory is not None

    def test_http_transport_without_mtls_has_user_agent_factory(self, http_config: HttpTransportConfig):
        """StreamableHttpTransport always has factory for User-Agent header."""
        # Arrange
        config = BackendConfig(server_name="test", transport="streamablehttp", http=http_config)

        # Act
        with patch("mcp_acp.utils.transport.check_http_health"):
            transport, _ = create_backend_transport(config, mtls_config=None)

        # Assert - factory is always set (for User-Agent), even without mTLS
        assert isinstance(transport, StreamableHttpTransport)
        assert transport.httpx_client_factory is not None

    def test_stdio_transport_ignores_mtls(self, stdio_config: StdioTransportConfig, mtls_config: MTLSConfig):
        """STDIO transport ignores mTLS configuration."""
        # Arrange
        config = BackendConfig(server_name="test", transport="stdio", stdio=stdio_config)

        # Act - mTLS config is passed but should be ignored
        transport, transport_type = create_backend_transport(config, mtls_config)

        # Assert
        assert isinstance(transport, StdioTransport)
        assert transport_type == "stdio"

    def test_health_check_receives_mtls_config(
        self, http_config: HttpTransportConfig, mtls_config: MTLSConfig
    ):
        """Health check is called with mTLS config."""
        # Arrange
        config = BackendConfig(server_name="test", transport="streamablehttp", http=http_config)

        # Act
        with (
            patch("mcp_acp.utils.transport.check_http_health") as mock_health,
            patch("mcp_acp.security.mtls._validate_certificates"),
        ):
            create_backend_transport(config, mtls_config)

        # Assert - health check received mtls_config
        mock_health.assert_called_once()
        call_args = mock_health.call_args
        assert call_args[0][0] == http_config.url  # URL
        assert call_args[0][2] == mtls_config  # mtls_config (3rd positional arg)


# ============================================================================
# Tests: User-Agent Header
# ============================================================================


class TestUserAgentHeader:
    """Tests for User-Agent header in HTTP client factory."""

    def test_user_agent_format(self):
        """User-Agent follows expected format."""
        # Assert - format is "mcp-acp/{version}"
        assert USER_AGENT.startswith("mcp-acp/")
        # Version should be present (e.g., "0.1.0")
        version_part = USER_AGENT.split("/")[1]
        assert len(version_part) > 0

    @pytest.mark.asyncio
    async def test_factory_without_mtls_includes_user_agent(self):
        """Factory without mTLS includes User-Agent header."""
        # Arrange
        factory = create_httpx_client_factory(mtls_config=None, url="http://localhost:3000")

        # Act
        client = factory()

        # Assert
        assert client.headers.get("User-Agent") == USER_AGENT
        await client.aclose()

    @pytest.mark.asyncio
    async def test_factory_with_mtls_includes_user_agent(self, tmp_path: Path):
        """Factory with mTLS includes User-Agent header."""
        # Arrange - create mTLS config with valid paths
        cert_path = tmp_path / "client.pem"
        key_path = tmp_path / "client-key.pem"
        ca_path = tmp_path / "ca-bundle.pem"
        cert_path.write_text("cert")
        key_path.write_text("key")
        ca_path.write_text("ca")

        mtls_config = MTLSConfig(
            client_cert_path=str(cert_path),
            client_key_path=str(key_path),
            ca_bundle_path=str(ca_path),
        )

        # Act - mock both certificate validations (create_mtls_client_factory calls _validate_certificates)
        with (
            patch("mcp_acp.utils.transport.create_mtls_client_factory") as mock_mtls,
            patch("mcp_acp.security.mtls._validate_certificates"),
        ):
            # Mock the mTLS factory to return a simple client factory
            mock_mtls.return_value = lambda headers=None, timeout=None, auth=None: httpx.AsyncClient(
                headers=headers, timeout=timeout, auth=auth
            )
            factory = create_httpx_client_factory(mtls_config=mtls_config, url="https://localhost:3000")
            client = factory()

        # Assert
        assert client.headers.get("User-Agent") == USER_AGENT
        await client.aclose()

    @pytest.mark.asyncio
    async def test_factory_merges_custom_headers_with_user_agent(self):
        """Factory merges custom headers with User-Agent."""
        # Arrange
        factory = create_httpx_client_factory(mtls_config=None, url="http://localhost:3000")
        custom_headers = {"X-Custom-Header": "test-value"}

        # Act
        client = factory(headers=custom_headers)

        # Assert - both headers present
        assert client.headers.get("User-Agent") == USER_AGENT
        assert client.headers.get("X-Custom-Header") == "test-value"
        await client.aclose()

    @pytest.mark.asyncio
    async def test_custom_user_agent_overrides_default(self):
        """Custom User-Agent in headers overrides default."""
        # Arrange
        factory = create_httpx_client_factory(mtls_config=None, url="http://localhost:3000")
        custom_headers = {"User-Agent": "custom-agent/1.0"}

        # Act
        client = factory(headers=custom_headers)

        # Assert - custom User-Agent takes precedence
        assert client.headers.get("User-Agent") == "custom-agent/1.0"
        await client.aclose()
