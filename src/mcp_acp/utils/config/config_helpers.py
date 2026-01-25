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
    "get_decisions_log_path",
    "get_log_dir",
    "get_policy_history_path",
    "get_system_log_path",
]

from pathlib import Path

from platformdirs import user_log_dir

from mcp_acp.constants import APP_NAME
from mcp_acp.utils.file_helpers import (
    compute_file_checksum,
    get_app_dir,
    set_secure_permissions,
)


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


def get_log_dir(proxy_name: str, log_dir: str | None = None) -> Path:
    """Get proxy log directory (<log_dir>/mcp-acp/proxies/<proxy_name>/).

    Args:
        proxy_name: Name of the proxy.
        log_dir: Base log directory. If None, uses platform default.

    Returns:
        Path: Log directory path (<log_dir>/mcp-acp/proxies/<proxy_name>/).
    """
    base = Path(log_dir).expanduser() if log_dir else Path(user_log_dir(APP_NAME))
    return base / APP_NAME / "proxies" / proxy_name


def get_client_log_path(proxy_name: str, log_dir: str | None = None) -> Path:
    """Get full path to client wire log file.

    Args:
        proxy_name: Name of the proxy.
        log_dir: Base log directory. If None, uses platform default.

    Returns:
        Path: Full path to logs/debug/client_wire.jsonl.
    """
    return get_log_dir(proxy_name, log_dir) / "debug" / "client_wire.jsonl"


def get_backend_log_path(proxy_name: str, log_dir: str | None = None) -> Path:
    """Get full path to backend wire log file.

    Args:
        proxy_name: Name of the proxy.
        log_dir: Base log directory. If None, uses platform default.

    Returns:
        Path: Full path to logs/debug/backend_wire.jsonl.
    """
    return get_log_dir(proxy_name, log_dir) / "debug" / "backend_wire.jsonl"


def get_system_log_path(proxy_name: str, log_dir: str | None = None) -> Path:
    """Get full path to system log file.

    Args:
        proxy_name: Name of the proxy.
        log_dir: Base log directory. If None, uses platform default.

    Returns:
        Path: Full path to logs/system/system.jsonl.
    """
    return get_log_dir(proxy_name, log_dir) / "system" / "system.jsonl"


def get_config_history_path(proxy_name: str, log_dir: str | None = None) -> Path:
    """Get full path to config history log file.

    Args:
        proxy_name: Name of the proxy.
        log_dir: Base log directory. If None, uses platform default.

    Returns:
        Path: Full path to logs/system/config_history.jsonl.
    """
    return get_log_dir(proxy_name, log_dir) / "system" / "config_history.jsonl"


def get_policy_history_path(proxy_name: str, log_dir: str | None = None) -> Path:
    """Get full path to policy history log file.

    Args:
        proxy_name: Name of the proxy.
        log_dir: Base log directory. If None, uses platform default.

    Returns:
        Path: Full path to logs/system/policy_history.jsonl.
    """
    return get_log_dir(proxy_name, log_dir) / "system" / "policy_history.jsonl"


def get_audit_log_path(proxy_name: str, log_dir: str | None = None) -> Path:
    """Get full path to audit operations log file.

    Args:
        proxy_name: Name of the proxy.
        log_dir: Base log directory. If None, uses platform default.

    Returns:
        Path: Full path to logs/audit/operations.jsonl.
    """
    return get_log_dir(proxy_name, log_dir) / "audit" / "operations.jsonl"


def get_decisions_log_path(proxy_name: str, log_dir: str | None = None) -> Path:
    """Get full path to policy decisions log file.

    Args:
        proxy_name: Name of the proxy.
        log_dir: Base log directory. If None, uses platform default.

    Returns:
        Path: Full path to logs/audit/decisions.jsonl.
    """
    return get_log_dir(proxy_name, log_dir) / "audit" / "decisions.jsonl"


def get_auth_log_path(proxy_name: str, log_dir: str | None = None) -> Path:
    """Get full path to authentication audit log file.

    Args:
        proxy_name: Name of the proxy.
        log_dir: Base log directory. If None, uses platform default.

    Returns:
        Path: Full path to logs/audit/auth.jsonl.
    """
    return get_log_dir(proxy_name, log_dir) / "audit" / "auth.jsonl"


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


def ensure_directories(
    proxy_name: str,
    log_dir: str | None = None,
    log_level: str = "INFO",
) -> None:
    """Create log directories if they don't exist.

    Creates the standard log directory structure:
        <log_dir>/
        └── mcp-acp/
            └── proxies/
                └── <proxy_name>/
                    ├── audit/
                    ├── debug/    (only if log_level == DEBUG)
                    └── system/

    Note: Config directory is created by AppConfig.save_to_file().

    Sets secure permissions (0o700) on Unix systems.

    Args:
        proxy_name: Name of the proxy.
        log_dir: Base log directory. If None, uses platform default.
        log_level: Log level (DEBUG enables debug directory).
    """
    log_base = Path(log_dir).expanduser() if log_dir else Path(user_log_dir(APP_NAME))
    mcp_acp_dir = log_base / APP_NAME
    proxies_dir = mcp_acp_dir / "proxies"
    proxy_dir = proxies_dir / proxy_name
    audit_dir = proxy_dir / "audit"
    system_dir = proxy_dir / "system"

    # Directories to create (debug only when enabled)
    dirs_to_create = [log_base, mcp_acp_dir, proxies_dir, proxy_dir, audit_dir, system_dir]

    # Only create debug directory if DEBUG logging is enabled
    if log_level == "DEBUG":
        debug_dir = proxy_dir / "debug"
        dirs_to_create.append(debug_dir)

    # Create log directories with secure permissions
    for directory in dirs_to_create:
        directory.mkdir(parents=True, exist_ok=True)
        set_secure_permissions(directory, is_directory=True)
