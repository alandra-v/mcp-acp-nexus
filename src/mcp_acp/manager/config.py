"""Manager configuration for mcp-acp.

Defines configuration model for the manager daemon.
Config is stored at the OS-appropriate location alongside proxy config.

Example usage:
    # Load from config file (creates default if not exists)
    config = load_manager_config()

    # Save configuration
    save_manager_config(config)
"""

from __future__ import annotations

__all__ = [
    "ManagerConfig",
    "RESERVED_PROXY_NAMES",
    "get_manager_config_path",
    "get_manager_log_dir",
    "get_manager_system_log_path",
    "get_proxies_dir",
    "get_proxy_config_dir",
    "get_proxy_config_path",
    "get_proxy_log_dir",
    "get_proxy_policy_path",
    "list_configured_proxies",
    "load_manager_config",
    "load_manager_config_strict",
    "save_manager_config",
    "validate_proxy_name",
]

import json
import logging
import re
import sys
from pathlib import Path

from pydantic import BaseModel, Field, ValidationError

from mcp_acp.config import AuthConfig
from mcp_acp.constants import APP_NAME, DEFAULT_API_PORT
from mcp_acp.utils.file_helpers import get_app_dir, set_secure_permissions

_logger = logging.getLogger(f"{APP_NAME}.manager.config")


def _get_platform_log_dir() -> str:
    """Get platform-appropriate base log directory following OS conventions.

    Returns:
        Platform-specific base log directory path (unexpanded).
        mcp-acp logs go in <base>/mcp-acp/manager/ and <base>/mcp-acp/proxies/.

    Platform conventions:
        - macOS: ~/Library/Logs (Apple standard, integrates with Console.app)
        - Linux: ~/.local/state (XDG Base Directory Specification for logs/state)
        - Windows: ~/AppData/Local (standard for app data)
    """
    if sys.platform == "darwin":
        return "~/Library/Logs"
    elif sys.platform == "win32":
        return "~/AppData/Local"
    else:
        # Linux/Unix: XDG_STATE_HOME is for logs, history, state
        # Falls back to ~/.local/state per XDG spec
        import os

        return os.environ.get("XDG_STATE_HOME", "~/.local/state")


# Default base log directory (platform-specific, follows OS conventions)
DEFAULT_MANAGER_LOG_DIR = _get_platform_log_dir()


class ManagerConfig(BaseModel):
    """Manager daemon configuration.

    Attributes:
        ui_port: HTTP port for web UI (default: 8765).
        log_dir: Base directory for logs. Platform-specific default:
            - macOS: ~/Library/Logs
            - Linux: $XDG_STATE_HOME (~/.local/state)
            Manager logs stored in <log_dir>/mcp-acp/manager/.
        auth: Authentication configuration (OIDC only).
            Shared across all proxies. Required for multi-proxy mode.
            Note: mTLS is per-proxy, configured via 'mcp-acp proxy add'.
    """

    ui_port: int = Field(
        default=DEFAULT_API_PORT,
        ge=1024,
        le=65535,
        description="HTTP port for web UI",
    )
    log_dir: str = Field(
        default=DEFAULT_MANAGER_LOG_DIR,
        min_length=1,
        description="Base directory for all logs (manager and proxies)",
    )
    auth: AuthConfig | None = Field(
        default=None,
        description="Authentication configuration (OIDC only). mTLS is per-proxy.",
    )

    model_config = {"extra": "ignore"}  # Ignore unknown fields for forward compat


def get_manager_config_path() -> Path:
    """Get the full path to the manager config file.

    Returns:
        Path to manager.json in the config directory.
    """
    return get_app_dir() / "manager.json"


def get_manager_log_dir(config: ManagerConfig) -> Path:
    """Get manager log directory.

    Args:
        config: Manager configuration.

    Returns:
        Path: Log directory path (<log_dir>/mcp-acp/manager/).
    """
    return Path(config.log_dir).expanduser() / APP_NAME / "manager"


def get_manager_system_log_path(config: ManagerConfig) -> Path:
    """Get full path to manager system log file.

    Args:
        config: Manager configuration.

    Returns:
        Path: Full path to manager/system.jsonl.
    """
    return get_manager_log_dir(config) / "system.jsonl"


def load_manager_config() -> ManagerConfig:
    """Load manager configuration from file.

    If the config file doesn't exist, returns default configuration.
    Invalid JSON or validation errors return default config with a warning.

    Returns:
        ManagerConfig: Loaded or default configuration.
    """
    config_path = get_manager_config_path()

    if not config_path.exists():
        return ManagerConfig()

    try:
        with config_path.open(encoding="utf-8") as f:
            data = json.load(f)
        return ManagerConfig.model_validate(data)
    except json.JSONDecodeError as e:
        _logger.warning(
            {
                "event": "config_invalid_json",
                "message": f"Invalid JSON in manager config, using defaults: {e}",
                "error_type": type(e).__name__,
                "error_message": str(e),
                "details": {"config_path": str(config_path)},
            }
        )
        return ManagerConfig()
    except ValidationError as e:
        _logger.warning(
            {
                "event": "config_validation_failed",
                "message": f"Invalid manager config values, using defaults: {e}",
                "error_type": type(e).__name__,
                "error_message": str(e),
                "details": {"config_path": str(config_path)},
            }
        )
        return ManagerConfig()
    except OSError as e:
        # Covers all file I/O errors including PermissionError (subclass of OSError)
        _logger.warning(
            {
                "event": "config_read_failed",
                "message": f"Failed to read manager config file, using defaults: {e}",
                "error_type": type(e).__name__,
                "error_message": str(e),
                "details": {"config_path": str(config_path)},
            }
        )
        return ManagerConfig()


def load_manager_config_strict() -> ManagerConfig:
    """Load manager configuration, raising on any error.

    Unlike load_manager_config(), this function raises ConfigurationError
    for missing files, missing auth, invalid JSON, or validation errors.
    Used by the manager daemon to enforce valid config at startup.

    Returns:
        ManagerConfig: Validated configuration.

    Raises:
        ConfigurationError: If config is missing, invalid, or lacks auth.
    """
    from mcp_acp.exceptions import ConfigurationError

    config_path = get_manager_config_path()

    if not config_path.exists():
        raise ConfigurationError("Not initialized. Run 'mcp-acp init' to configure.")

    try:
        with config_path.open(encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        raise ConfigurationError(f"Invalid JSON in {config_path}: {e}") from e
    except OSError as e:
        raise ConfigurationError(f"Cannot read {config_path}: {e}") from e

    try:
        config = ManagerConfig.model_validate(data)
    except ValidationError as e:
        raise ConfigurationError(f"Invalid config in {config_path}: {e}") from e

    if config.auth is None:
        raise ConfigurationError(
            f"Auth not configured in {config_path}.\n"
            "Add 'auth' section or run 'mcp-acp init --force' to reconfigure."
        )

    return config


def save_manager_config(config: ManagerConfig) -> None:
    """Save manager configuration to file.

    Creates the config directory if it doesn't exist.
    Sets secure file permissions (0600).

    Args:
        config: Manager configuration to save.

    Raises:
        OSError: If unable to write config file.
    """
    config_path = get_manager_config_path()

    # Ensure config directory exists
    config_path.parent.mkdir(parents=True, exist_ok=True)

    # Write config with pretty formatting
    with config_path.open("w", encoding="utf-8") as f:
        json.dump(config.model_dump(), f, indent=2)
        f.write("\n")  # Trailing newline

    # Set secure permissions (owner read/write only)
    set_secure_permissions(config_path)


# Proxy name validation
RESERVED_PROXY_NAMES = frozenset({"manager", "all", "default"})
_PROXY_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]*$")
_PROXY_NAME_MAX_LENGTH = 64


def validate_proxy_name(name: str) -> None:
    """Validate proxy name for use as directory and identifier.

    Rules:
    - 1-64 characters
    - Must start with alphanumeric
    - Only alphanumeric, hyphens, underscores (no dots)
    - Cannot be a reserved name
    - Cannot start with '_' or '.'

    Args:
        name: Proxy name to validate.

    Raises:
        ValueError: If name is invalid, with descriptive message.
    """
    if not name:
        raise ValueError("Proxy name cannot be empty.")

    if len(name) > _PROXY_NAME_MAX_LENGTH:
        raise ValueError(f"Proxy name too long (max {_PROXY_NAME_MAX_LENGTH} characters).")

    if name.startswith("_") or name.startswith("."):
        raise ValueError("Proxy name cannot start with '_' or '.'")

    if name.lower() in RESERVED_PROXY_NAMES:
        raise ValueError(f"'{name}' is a reserved name. Choose a different name.")

    if not _PROXY_NAME_PATTERN.match(name):
        raise ValueError(
            f"Invalid proxy name '{name}'. "
            "Use letters, numbers, hyphens, underscores. "
            "Must start with letter or number."
        )


# =============================================================================
# Proxy Path Helpers (Multi-Proxy Support)
# =============================================================================


def get_proxies_dir() -> Path:
    """Get directory containing all proxy configurations.

    Returns:
        Path to proxies directory (<config_dir>/proxies/).
    """
    return get_app_dir() / "proxies"


def get_proxy_config_dir(name: str) -> Path:
    """Get directory for a specific proxy's configuration.

    Args:
        name: Proxy name (validated separately).

    Returns:
        Path to proxy's config directory (<config_dir>/proxies/{name}/).
    """
    return get_proxies_dir() / name


def get_proxy_config_path(name: str) -> Path:
    """Get path to a proxy's config file.

    Args:
        name: Proxy name.

    Returns:
        Path to config.json (<config_dir>/proxies/{name}/config.json).
    """
    return get_proxy_config_dir(name) / "config.json"


def get_proxy_policy_path(name: str) -> Path:
    """Get path to a proxy's policy file.

    Args:
        name: Proxy name.

    Returns:
        Path to policy.json (<config_dir>/proxies/{name}/policy.json).
    """
    return get_proxy_config_dir(name) / "policy.json"


def get_proxy_log_dir(name: str, config: ManagerConfig | None = None) -> Path:
    """Get log directory for a specific proxy.

    Args:
        name: Proxy name.
        config: Manager config (uses default log_dir if None).

    Returns:
        Path to proxy's log directory (<log_dir>/mcp-acp/proxies/{name}/).
    """
    if config is None:
        base_log_dir = DEFAULT_MANAGER_LOG_DIR
    else:
        base_log_dir = config.log_dir
    return Path(base_log_dir).expanduser() / APP_NAME / "proxies" / name


def list_configured_proxies() -> list[str]:
    """List all configured proxy names.

    Returns:
        Sorted list of proxy names (directory names under proxies/).
        Empty list if proxies directory doesn't exist.
    """
    proxies_dir = get_proxies_dir()
    if not proxies_dir.exists():
        return []

    return sorted(d.name for d in proxies_dir.iterdir() if d.is_dir() and not d.name.startswith("."))
