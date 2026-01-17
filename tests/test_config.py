"""Tests for configuration models and load/save behavior."""

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from mcp_acp.config import (
    AppConfig,
    AuthConfig,
    BackendConfig,
    HttpTransportConfig,
    LoggingConfig,
    OIDCConfig,
    StdioTransportConfig,
)


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def valid_oidc_config() -> OIDCConfig:
    """Valid OIDC configuration for tests."""
    return OIDCConfig(
        issuer="https://test.auth0.com",
        client_id="test-client-id",
        audience="https://test-api.example.com",
    )


@pytest.fixture
def valid_auth_config(valid_oidc_config: OIDCConfig) -> AuthConfig:
    """Valid auth configuration for tests."""
    return AuthConfig(oidc=valid_oidc_config)


@pytest.fixture
def valid_config_dict() -> dict:
    """Minimal valid configuration."""
    return {
        "logging": {"log_dir": "/tmp/logs"},
        "backend": {
            "server_name": "test-server",
            "transport": "stdio",
            "stdio": {"command": "echo"},
        },
        "auth": {
            "oidc": {
                "issuer": "https://test.auth0.com",
                "client_id": "test-client-id",
                "audience": "https://test-api.example.com",
            }
        },
    }


@pytest.fixture
def config_file(tmp_path: Path, valid_config_dict: dict) -> Path:
    """Write valid config to temp file and return path."""
    path = tmp_path / "config.json"
    path.write_text(json.dumps(valid_config_dict))
    return path


# ============================================================================
# LoggingConfig Validation
# ============================================================================


class TestLoggingConfig:
    """LoggingConfig validation tests."""

    def test_accepts_debug_level(self):
        # Act
        config = LoggingConfig(log_dir="/tmp", log_level="DEBUG")

        # Assert
        assert config.log_level == "DEBUG"

    def test_accepts_info_level(self):
        # Act
        config = LoggingConfig(log_dir="/tmp", log_level="INFO")

        # Assert
        assert config.log_level == "INFO"

    def test_defaults_to_info_level(self):
        # Act
        config = LoggingConfig(log_dir="/tmp")

        # Assert
        assert config.log_level == "INFO"

    @pytest.mark.parametrize("invalid_level", ["WARNING", "ERROR", "TRACE", "warn", ""])
    def test_rejects_invalid_log_level(self, invalid_level: str):
        # Act & Assert
        with pytest.raises(ValidationError):
            LoggingConfig(log_dir="/tmp", log_level=invalid_level)

    def test_requires_log_dir(self):
        # Act & Assert
        with pytest.raises(ValidationError):
            LoggingConfig()


# ============================================================================
# HttpTransportConfig Validation
# ============================================================================


class TestHttpTransportConfig:
    """HttpTransportConfig validation tests."""

    def test_accepts_valid_timeout(self):
        # Act
        config = HttpTransportConfig(url="http://localhost:3000/mcp", timeout=60)

        # Assert
        assert config.timeout == 60

    def test_defaults_timeout_to_30(self):
        # Act
        config = HttpTransportConfig(url="http://localhost:3000/mcp")

        # Assert
        assert config.timeout == 30

    def test_accepts_minimum_timeout(self):
        # Act
        config = HttpTransportConfig(url="http://localhost:3000/mcp", timeout=1)

        # Assert
        assert config.timeout == 1

    def test_accepts_maximum_timeout(self):
        # Act
        config = HttpTransportConfig(url="http://localhost:3000/mcp", timeout=300)

        # Assert
        assert config.timeout == 300

    @pytest.mark.parametrize("invalid_timeout", [0, -1, -100, 301, 1000])
    def test_rejects_invalid_timeout(self, invalid_timeout: int):
        # Act & Assert
        with pytest.raises(ValidationError):
            HttpTransportConfig(url="http://localhost:3000/mcp", timeout=invalid_timeout)


# ============================================================================
# BackendConfig Validation
# ============================================================================


class TestBackendConfig:
    """BackendConfig validation tests."""

    def test_accepts_stdio_transport(self):
        # Act
        config = BackendConfig(
            server_name="test",
            transport="stdio",
            stdio=StdioTransportConfig(command="echo"),
        )

        # Assert
        assert config.transport == "stdio"

    def test_accepts_streamablehttp_transport(self):
        # Act
        config = BackendConfig(
            server_name="test",
            transport="streamablehttp",
            http=HttpTransportConfig(url="http://localhost:3000/mcp"),
        )

        # Assert
        assert config.transport == "streamablehttp"

    def test_accepts_auto_detect_transport(self):
        # Act - transport="auto" means auto-detect at runtime
        config = BackendConfig(
            server_name="test",
            transport="auto",
            stdio=StdioTransportConfig(command="echo"),
            http=HttpTransportConfig(url="http://localhost:3000/mcp"),
        )

        # Assert
        assert config.transport == "auto"
        assert config.stdio is not None
        assert config.http is not None

    def test_defaults_to_auto_transport(self):
        # Act - transport defaults to "auto" if not specified
        config = BackendConfig(
            server_name="test",
            stdio=StdioTransportConfig(command="echo"),
        )

        # Assert
        assert config.transport == "auto"

    @pytest.mark.parametrize("invalid_transport", ["http", "sse", "grpc", ""])
    def test_rejects_invalid_transport(self, invalid_transport: str):
        # Act & Assert
        with pytest.raises(ValidationError):
            BackendConfig(
                server_name="test",
                transport=invalid_transport,
                stdio=StdioTransportConfig(command="echo"),
            )

    def test_allows_optional_transport_configs(self):
        # Transport configs are optional at model level
        # (runtime validation happens in validate_transport_config)
        config = BackendConfig(server_name="test", transport="stdio")

        # Assert - model allows it, validation is runtime concern
        assert config.transport == "stdio"
        assert config.stdio is None


# ============================================================================
# AppConfig Validation
# ============================================================================


class TestAppConfig:
    """AppConfig validation tests."""

    def test_validates_from_dict(self, valid_config_dict: dict):
        # Act
        config = AppConfig.model_validate(valid_config_dict)

        # Assert
        assert config.backend.server_name == "test-server"

    def test_requires_logging_section(self, valid_auth_config: AuthConfig):
        # Act & Assert
        with pytest.raises(ValidationError):
            AppConfig(
                backend=BackendConfig(
                    server_name="test",
                    transport="stdio",
                    stdio=StdioTransportConfig(command="echo"),
                ),
                auth=valid_auth_config,
            )

    def test_requires_backend_section(self, valid_auth_config: AuthConfig):
        # Act & Assert
        with pytest.raises(ValidationError):
            AppConfig(
                logging=LoggingConfig(log_dir="/tmp"),
                auth=valid_auth_config,
            )

    def test_auth_is_optional_for_development(self):
        # Auth is optional for development (falls back to LocalIdentityProvider)
        # Production deployments should always have auth configured
        config = AppConfig(
            logging=LoggingConfig(log_dir="/tmp"),
            backend=BackendConfig(
                server_name="test",
                transport="stdio",
                stdio=StdioTransportConfig(command="echo"),
            ),
        )
        # Assert auth defaults to None
        assert config.auth is None

    def test_defaults_proxy_name(self, valid_auth_config: AuthConfig):
        # Act
        config = AppConfig(
            logging=LoggingConfig(log_dir="/tmp"),
            backend=BackendConfig(
                server_name="test",
                transport="stdio",
                stdio=StdioTransportConfig(command="echo"),
            ),
            auth=valid_auth_config,
        )

        # Assert
        assert config.proxy.name == "mcp-acp-nexus"


# ============================================================================
# AppConfig.load_from_files
# ============================================================================


class TestLoadFromFiles:
    """AppConfig.load_from_files() tests."""

    def test_loads_valid_config(self, config_file: Path):
        # Act
        config = AppConfig.load_from_files(config_file)

        # Assert
        assert config.backend.server_name == "test-server"

    def test_raises_file_not_found(self, tmp_path: Path):
        # Arrange
        missing_path = tmp_path / "missing.json"

        # Act & Assert
        with pytest.raises(FileNotFoundError):
            AppConfig.load_from_files(missing_path)

    def test_raises_value_error_for_invalid_json(self, tmp_path: Path):
        # Arrange
        bad_json = tmp_path / "bad.json"
        bad_json.write_text("{not valid json")

        # Act & Assert
        with pytest.raises(ValueError, match="Invalid JSON"):
            AppConfig.load_from_files(bad_json)

    def test_raises_value_error_for_missing_field(self, tmp_path: Path):
        # Arrange
        incomplete = tmp_path / "incomplete.json"
        incomplete.write_text('{"logging": {"log_dir": "/tmp"}}')

        # Act & Assert
        with pytest.raises(ValueError, match="backend"):
            AppConfig.load_from_files(incomplete)

    def test_raises_value_error_for_invalid_field(self, tmp_path: Path):
        # Arrange
        bad_value = tmp_path / "bad_value.json"
        bad_value.write_text(
            json.dumps(
                {
                    "logging": {"log_dir": "/tmp", "log_level": "INVALID"},
                    "backend": {
                        "server_name": "test",
                        "transport": "stdio",
                        "stdio": {"command": "echo"},
                    },
                }
            )
        )

        # Act & Assert
        with pytest.raises(ValueError, match="log_level"):
            AppConfig.load_from_files(bad_value)


# ============================================================================
# AppConfig.save_to_file
# ============================================================================


class TestSaveToFile:
    """AppConfig.save_to_file() tests."""

    def test_creates_parent_directories(self, tmp_path: Path, valid_config_dict: dict):
        # Arrange
        config = AppConfig.model_validate(valid_config_dict)
        nested_path = tmp_path / "a" / "b" / "config.json"

        # Act
        config.save_to_file(nested_path)

        # Assert
        assert nested_path.exists()

    def test_writes_loadable_json(self, tmp_path: Path, valid_config_dict: dict):
        # Arrange
        config = AppConfig.model_validate(valid_config_dict)
        path = tmp_path / "config.json"

        # Act
        config.save_to_file(path)
        loaded = AppConfig.load_from_files(path)

        # Assert
        assert loaded.backend.server_name == config.backend.server_name


# ============================================================================
# Config Helpers
# ============================================================================


class TestConfigHelpers:
    """Config helper function tests."""

    def test_get_log_dir_appends_mcp_acp_logs(self, valid_config_dict: dict):
        # Arrange
        from mcp_acp.utils.config import get_log_dir

        config = AppConfig.model_validate(valid_config_dict)

        # Act
        result = get_log_dir(config)

        # Assert
        assert result.name == "mcp_acp_logs"

    @pytest.mark.parametrize(
        "helper_name,expected_file",
        [
            ("get_client_log_path", "client_wire.jsonl"),
            ("get_backend_log_path", "backend_wire.jsonl"),
            ("get_system_log_path", "system.jsonl"),
            ("get_config_history_path", "config_history.jsonl"),
            ("get_audit_log_path", "operations.jsonl"),
        ],
    )
    def test_log_path_helpers_return_correct_filename(
        self, valid_config_dict: dict, helper_name: str, expected_file: str
    ):
        # Arrange
        from mcp_acp.utils import config as config_module

        config = AppConfig.model_validate(valid_config_dict)
        helper = getattr(config_module, helper_name)

        # Act
        result = helper(config)

        # Assert
        assert result.name == expected_file

    def test_checksum_is_deterministic(self, tmp_path: Path):
        # Arrange
        from mcp_acp.utils.config import compute_config_checksum

        path = tmp_path / "test.json"
        path.write_text('{"key": "value"}')

        # Act
        checksum1 = compute_config_checksum(path)
        checksum2 = compute_config_checksum(path)

        # Assert
        assert checksum1 == checksum2

    def test_checksum_changes_with_content(self, tmp_path: Path):
        # Arrange
        from mcp_acp.utils.config import compute_config_checksum

        path = tmp_path / "test.json"

        # Act
        path.write_text('{"v": 1}')
        checksum1 = compute_config_checksum(path)
        path.write_text('{"v": 2}')
        checksum2 = compute_config_checksum(path)

        # Assert
        assert checksum1 != checksum2

    def test_ensure_directories_creates_log_structure_info_level(
        self, tmp_path: Path, valid_config_dict: dict
    ):
        """INFO level creates audit and system dirs, but NOT debug dir."""
        from mcp_acp.utils.config import ensure_directories

        valid_config_dict["logging"]["log_dir"] = str(tmp_path)
        valid_config_dict["logging"]["log_level"] = "INFO"
        config = AppConfig.model_validate(valid_config_dict)

        ensure_directories(config)

        assert (tmp_path / "mcp_acp_logs" / "audit").is_dir()
        assert (tmp_path / "mcp_acp_logs" / "system").is_dir()
        assert not (tmp_path / "mcp_acp_logs" / "debug").exists()

    def test_ensure_directories_creates_debug_dir_when_debug_level(
        self, tmp_path: Path, valid_config_dict: dict
    ):
        """DEBUG level creates all dirs including debug."""
        from mcp_acp.utils.config import ensure_directories

        valid_config_dict["logging"]["log_dir"] = str(tmp_path)
        valid_config_dict["logging"]["log_level"] = "DEBUG"
        config = AppConfig.model_validate(valid_config_dict)

        ensure_directories(config)

        assert (tmp_path / "mcp_acp_logs" / "audit").is_dir()
        assert (tmp_path / "mcp_acp_logs" / "system").is_dir()
        assert (tmp_path / "mcp_acp_logs" / "debug").is_dir()
