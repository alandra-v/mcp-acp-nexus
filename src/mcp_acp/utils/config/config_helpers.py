"""Helper functions for configuration management.

Simple utility functions for working with configuration objects.
For config history logging, see utils/history_logging/.
"""

from __future__ import annotations

__all__ = [
    "compute_config_checksum",
    "ensure_directories",
    "get_audit_log_path",
    "get_auth_log_path",
    "get_backend_log_path",
    "get_client_log_path",
    "get_config_dir",
    "get_config_history_path",
    "get_config_path",
    "get_decisions_log_path",
    "get_log_dir",
    "get_policy_history_path",
    "get_system_log_path",
]

from pathlib import Path
from typing import TYPE_CHECKING

from mcp_acp.utils.file_helpers import (
    compute_file_checksum,
    get_app_dir,
    set_secure_permissions,
)

if TYPE_CHECKING:
    from mcp_acp.config import AppConfig


def get_config_dir() -> Path:
    """Get the OS-appropriate config directory.

    Uses click.get_app_dir() which returns:
    - macOS: ~/Library/Application Support/mcp-acp
    - Linux: ~/.config/mcp-acp (XDG compliant)
    - Windows: C:\\Users\\<user>\\AppData\\Roaming\\mcp-acp

    Returns:
        Path to the config directory.
    """
    return get_app_dir()


def get_config_path() -> Path:
    """Get the full path to the config file.

    Returns:
        Path to mcp_acp_config.json in the config directory.
    """
    return get_config_dir() / "mcp_acp_config.json"


def get_log_dir(config: "AppConfig") -> Path:
    """Get log directory (always <config.logging.log_dir>/mcp_acp_logs/).

    Args:
        config: Application configuration.

    Returns:
        Path: Log directory path (<log_dir>/mcp_acp_logs/).
    """
    return Path(config.logging.log_dir).expanduser() / "mcp_acp_logs"


def get_client_log_path(config: "AppConfig") -> Path:
    """Get full path to client wire log file.

    Args:
        config: Application configuration.

    Returns:
        Path: Full path to logs/debug/client_wire.jsonl.
    """
    return get_log_dir(config) / "debug" / "client_wire.jsonl"


def get_backend_log_path(config: "AppConfig") -> Path:
    """Get full path to backend wire log file.

    Args:
        config: Application configuration.

    Returns:
        Path: Full path to logs/debug/backend_wire.jsonl.
    """
    return get_log_dir(config) / "debug" / "backend_wire.jsonl"


def get_system_log_path(config: "AppConfig") -> Path:
    """Get full path to system log file.

    Args:
        config: Application configuration.

    Returns:
        Path: Full path to logs/system/system.jsonl.
    """
    return get_log_dir(config) / "system" / "system.jsonl"


def get_config_history_path(config: "AppConfig") -> Path:
    """Get full path to config history log file.

    Args:
        config: Application configuration.

    Returns:
        Path: Full path to logs/system/config_history.jsonl.
    """
    return get_log_dir(config) / "system" / "config_history.jsonl"


def get_policy_history_path(config: "AppConfig") -> Path:
    """Get full path to policy history log file.

    Args:
        config: Application configuration.

    Returns:
        Path: Full path to logs/system/policy_history.jsonl.
    """
    return get_log_dir(config) / "system" / "policy_history.jsonl"


def get_audit_log_path(config: "AppConfig") -> Path:
    """Get full path to audit operations log file.

    Args:
        config: Application configuration.

    Returns:
        Path: Full path to logs/audit/operations.jsonl.
    """
    return get_log_dir(config) / "audit" / "operations.jsonl"


def get_decisions_log_path(config: "AppConfig") -> Path:
    """Get full path to policy decisions log file.

    Args:
        config: Application configuration.

    Returns:
        Path: Full path to logs/audit/decisions.jsonl.
    """
    return get_log_dir(config) / "audit" / "decisions.jsonl"


def get_auth_log_path(config: "AppConfig") -> Path:
    """Get full path to authentication audit log file.

    Args:
        config: Application configuration.

    Returns:
        Path: Full path to logs/audit/auth.jsonl.
    """
    return get_log_dir(config) / "audit" / "auth.jsonl"


def compute_config_checksum(config_path: Path) -> str:
    """Compute SHA256 checksum of config file content.

    Used for integrity verification and detecting manual edits.

    Args:
        config_path: Path to the configuration file.

    Returns:
        str: Checksum in format "sha256:<hex_digest>".

    Raises:
        FileNotFoundError: If config file doesn't exist.
        OSError: If config file cannot be read.
    """
    return compute_file_checksum(config_path)


def ensure_directories(config: "AppConfig") -> None:
    """Create log directories if they don't exist.

    Creates the standard log directory structure:
        <log_dir>/
        └── mcp_acp_logs/
            ├── audit/
            ├── debug/    (only if log_level == DEBUG)
            └── system/

    Note: Config directory is created by AppConfig.save_to_file().

    Sets secure permissions (0o700) on Unix systems.

    Args:
        config: Application configuration.
    """
    log_base = Path(config.logging.log_dir).expanduser()
    log_dir = log_base / "mcp_acp_logs"
    audit_dir = log_dir / "audit"
    system_dir = log_dir / "system"

    # Directories to create (debug only when enabled)
    dirs_to_create = [log_base, log_dir, audit_dir, system_dir]

    # Only create debug directory if DEBUG logging is enabled
    if config.logging.log_level == "DEBUG":
        debug_dir = log_dir / "debug"
        dirs_to_create.append(debug_dir)

    # Create log directories with secure permissions
    for directory in dirs_to_create:
        directory.mkdir(parents=True, exist_ok=True)
        set_secure_permissions(directory, is_directory=True)
