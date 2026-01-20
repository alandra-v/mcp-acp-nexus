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
    "get_manager_config_path",
    "get_manager_log_dir",
    "get_manager_system_log_path",
    "load_manager_config",
    "save_manager_config",
]

import json
import logging
import sys
from pathlib import Path

from pydantic import BaseModel, Field

from mcp_acp.constants import DEFAULT_API_PORT
from mcp_acp.utils.file_helpers import get_app_dir, set_secure_permissions

_logger = logging.getLogger(__name__)


def _get_default_log_dir() -> str:
    """Get platform-appropriate default log directory.

    Returns:
        Default log directory path (unexpanded).
    """
    if sys.platform == "darwin":
        return "~/Library/Logs"
    elif sys.platform == "win32":
        # Windows: use AppData/Local
        return "~/AppData/Local"
    else:
        # Linux/Unix: use ~/.local/share
        return "~/.local/share"


# Default log directory for manager (platform-specific)
DEFAULT_MANAGER_LOG_DIR = _get_default_log_dir()


class ManagerConfig(BaseModel):
    """Manager daemon configuration.

    Attributes:
        ui_port: HTTP port for web UI (default: 8765).
        log_dir: Directory for manager logs. Defaults to ~/Library/Logs.
            Manager logs are stored in <log_dir>/mcp_acp_logs/manager/.
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
        description="Directory for manager logs",
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
        Path: Log directory path (<log_dir>/mcp_acp_logs/manager/).
    """
    return Path(config.log_dir).expanduser() / "mcp_acp_logs" / "manager"


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
        _logger.debug("Manager config not found, using defaults: %s", config_path)
        return ManagerConfig()

    try:
        with config_path.open(encoding="utf-8") as f:
            data = json.load(f)
        return ManagerConfig.model_validate(data)
    except json.JSONDecodeError as e:
        _logger.warning("Invalid JSON in manager config, using defaults: %s", e)
        return ManagerConfig()
    except Exception as e:
        _logger.warning("Failed to load manager config, using defaults: %s", e)
        return ManagerConfig()


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

    _logger.debug("Saved manager config: %s", config_path)
