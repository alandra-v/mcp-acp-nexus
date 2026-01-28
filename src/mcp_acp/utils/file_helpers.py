"""Shared file utilities for mcp-acp.

Provides common utilities used by config, policy, and history logging:
- get_app_dir: OS-appropriate application directory
- compute_file_checksum: SHA256 checksum for file integrity
- set_secure_permissions: Secure file/directory permissions
- scan_backup_files: Scan for .broken.TIMESTAMP.jsonl backup files
- VersionInfo, get_next_version, get_last_version_info: History versioning
- get_history_logger: Cached JSONL logger for history files
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import sys
from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple, TypeVar

import click
from pydantic import BaseModel, ValidationError

from mcp_acp.constants import APP_NAME, INITIAL_VERSION
from mcp_acp.utils.logging.logger_setup import setup_jsonl_logger

if TYPE_CHECKING:
    from mcp_acp.security.integrity.integrity_state import IntegrityStateManager

# Type variable for Pydantic models
T = TypeVar("T", bound=BaseModel)

__all__ = [
    # App directory
    "get_app_dir",
    # File operations
    "compute_file_checksum",
    "set_secure_permissions",
    "require_file_exists",
    "load_validated_json",
    # Backup file scanning
    "BackupFile",
    "scan_backup_files",
    # History versioning
    "VersionInfo",
    "get_next_version",
    "get_last_version_info",
    "get_history_logger",
]

# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

# Bytes to read when finding last line in history file
_HISTORY_CHUNK_SIZE = 4096

# Pattern for backup files: decisions.broken.2025-01-28_123456.jsonl
_BACKUP_FILE_PATTERN = re.compile(r"^(.+)\.broken\.(\d{4}-\d{2}-\d{2}_\d{6})\.jsonl$")


# -----------------------------------------------------------------------------
# Backup file scanning
# -----------------------------------------------------------------------------


class BackupFile(NamedTuple):
    """Information about a backup log file (.broken.TIMESTAMP.jsonl)."""

    filename: str
    path: str  # Relative path from log directory
    size_bytes: int
    timestamp: str  # Extracted from filename (e.g., "2025-01-28_123456")


def scan_backup_files(log_path: Path, log_dir: Path | None = None) -> list[BackupFile]:
    """Scan for backup files (.broken.TIMESTAMP.jsonl) for a log file.

    Backup files are created by the audit repair process when a hash chain
    is broken. They have the format: <original>.broken.<timestamp>.jsonl

    Args:
        log_path: Path to the original log file (e.g., audit/decisions.jsonl).
        log_dir: Base log directory for computing relative paths. If None,
                 uses log_path.parent.parent.

    Returns:
        List of BackupFile sorted by timestamp (newest first).
    """
    if not log_path.parent.exists():
        return []

    base_name = log_path.stem  # e.g., "decisions"
    base_dir = log_dir if log_dir else log_path.parent.parent
    backups: list[BackupFile] = []

    for file_path in log_path.parent.iterdir():
        if not file_path.is_file():
            continue

        match = _BACKUP_FILE_PATTERN.match(file_path.name)
        if match and match.group(1) == base_name:
            timestamp = match.group(2)
            try:
                size = file_path.stat().st_size
                # Compute relative path from base directory
                try:
                    rel_path = str(file_path.relative_to(base_dir))
                except ValueError:
                    rel_path = file_path.name

                backups.append(
                    BackupFile(
                        filename=file_path.name,
                        path=rel_path,
                        size_bytes=size,
                        timestamp=timestamp,
                    )
                )
            except OSError:
                continue  # Skip files we can't stat

    # Sort by timestamp (newest first)
    backups.sort(key=lambda b: b.timestamp, reverse=True)
    return backups


def get_app_dir() -> Path:
    """Get the OS-appropriate application directory.

    Uses click.get_app_dir() which returns:
    - macOS: ~/Library/Application Support/mcp-acp
    - Linux: ~/.config/mcp-acp (XDG compliant)
    - Windows: C:\\Users\\<user>\\AppData\\Roaming\\mcp-acp

    Returns:
        Path to the application directory.
    """
    return Path(click.get_app_dir(APP_NAME))


def compute_file_checksum(file_path: Path) -> str:
    """Compute SHA256 checksum of file content.

    Used for integrity verification and detecting manual edits.

    Args:
        file_path: Path to the file.

    Returns:
        str: Checksum in format "sha256:<hex_digest>".

    Raises:
        FileNotFoundError: If file doesn't exist.
        OSError: If file cannot be read.
    """
    with open(file_path, "rb") as f:
        content = f.read()
    digest = hashlib.sha256(content).hexdigest()
    return f"sha256:{digest}"


def set_secure_permissions(path: Path, *, is_directory: bool = False) -> None:
    """Set secure permissions on file or directory.

    Sets permissions to restrict access to owner only:
    - Directory: 0o700 (rwx------)
    - File: 0o600 (rw-------)

    Does nothing on Windows. Silently ignores permission errors
    (some systems don't allow permission changes).

    Args:
        path: Path to file or directory.
        is_directory: If True, use directory permissions (0o700).
    """
    if sys.platform == "win32":
        return

    try:
        mode = 0o700 if is_directory else 0o600
        path.chmod(mode)
    except OSError:
        pass  # Permission changes might fail on some systems


def require_file_exists(
    file_path: Path,
    file_type: str = "file",
    init_hint: bool = True,
) -> None:
    """Raise FileNotFoundError with helpful message if file doesn't exist.

    Args:
        file_path: Path to check.
        file_type: Description for error message (e.g., "configuration", "policy").
        init_hint: If True, suggest running 'mcp-acp init'.

    Raises:
        FileNotFoundError: If file doesn't exist.
    """
    if file_path.exists():
        return

    hint = f"\nRun 'mcp-acp init' to create a {file_type} file." if init_hint else ""
    raise FileNotFoundError(f"{file_type.capitalize()} file not found at {file_path}.{hint}")


def load_validated_json(
    file_path: Path,
    model_class: type[T],
    file_type: str = "file",
    recovery_hint: str | None = None,
    encoding: str | None = None,
) -> T:
    """Load JSON file and validate against Pydantic model.

    Combines file reading, JSON parsing, and Pydantic validation with
    consistent error messages.

    Args:
        file_path: Path to JSON file.
        model_class: Pydantic model class to validate against.
        file_type: Description for error messages (e.g., "config", "policy").
        recovery_hint: Optional hint appended to validation errors.
        encoding: File encoding. If None, uses system default.

    Returns:
        Validated Pydantic model instance.

    Raises:
        ValueError: If JSON is invalid or validation fails.
    """
    try:
        with open(file_path, "r", encoding=encoding) as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in {file_type} file {file_path}: {e}") from e
    except OSError as e:
        raise ValueError(f"Could not read {file_type} file {file_path}: {e}") from e

    try:
        return model_class.model_validate(data)
    except ValidationError as e:
        errors = []
        for error in e.errors():
            loc_parts = error["loc"]
            loc = ".".join(str(x) for x in loc_parts)
            msg = error["msg"]

            # For rules errors, add context (rule ID or tool_name) to help identify
            context = ""
            if len(loc_parts) >= 2 and loc_parts[0] == "rules" and isinstance(loc_parts[1], int):
                rule_index = loc_parts[1]
                rules = data.get("rules", [])
                if 0 <= rule_index < len(rules):
                    rule = rules[rule_index]
                    rule_id = rule.get("id")
                    tool = rule.get("conditions", {}).get("tool_name")
                    if rule_id:
                        context = f" (rule id: {rule_id})"
                    elif tool:
                        context = f" (rule for tool: {tool})"
                    else:
                        context = f" (rule #{rule_index + 1})"

            errors.append(f"  - {loc}{context}: {msg}")

        hint = f"\n\n{recovery_hint}" if recovery_hint else ""
        raise ValueError(
            f"Invalid {file_type} configuration in {file_path}:\n" + "\n".join(errors) + hint
        ) from e


# -----------------------------------------------------------------------------
# History versioning utilities (moved from history_logging/base.py)
# -----------------------------------------------------------------------------

# Cache of logger instances per history path
_logger_cache: dict[Path, logging.Logger] = {}


class VersionInfo(NamedTuple):
    """Version and checksum from last history entry."""

    version: str | None
    checksum: str | None


def get_next_version(current_version: str | None) -> str:
    """Compute next version number.

    Args:
        current_version: Current version (e.g., "v1") or None.

    Returns:
        str: Next version (e.g., "v2"). Returns "v1" if current is None.
    """
    if current_version is None:
        return INITIAL_VERSION

    # Extract number from "vN" format
    try:
        num = int(current_version.lstrip("v"))
        return f"v{num + 1}"
    except ValueError:
        return INITIAL_VERSION


def get_last_version_info(
    history_path: Path,
    version_field: str = "config_version",
) -> VersionInfo:
    """Get version and checksum from last history entry.

    Reads the last line of a JSONL history file to extract the most recent
    version and checksum. Used to determine next version number and detect
    manual edits.

    Args:
        history_path: Path to history JSONL file.
        version_field: Name of the version field (e.g., "config_version" or "policy_version").

    Returns:
        VersionInfo with (version, checksum) or (None, None) if no history.
    """
    if not history_path.exists():
        return VersionInfo(None, None)

    try:
        with open(history_path, "rb") as f:
            # Seek to end and read backwards to find last line
            f.seek(0, 2)  # End of file
            size = f.tell()
            if size == 0:
                return VersionInfo(None, None)

            # Read last chunk (should contain last entry)
            chunk_size = min(_HISTORY_CHUNK_SIZE, size)
            f.seek(-chunk_size, 2)
            lines = f.read().decode("utf-8").strip().split("\n")

            if not lines:
                return VersionInfo(None, None)

            last_entry = json.loads(lines[-1])
            return VersionInfo(
                last_entry.get(version_field),
                last_entry.get("checksum"),
            )
    except (json.JSONDecodeError, OSError, KeyError):
        return VersionInfo(None, None)


def get_history_logger(
    history_path: Path,
    logger_name: str,
    state_manager: "IntegrityStateManager | None" = None,
    log_dir: Path | None = None,
) -> logging.Logger:
    """Get or create a logger for the given history path.

    Uses a cache to avoid creating duplicate loggers for the same path.
    When state_manager is provided, uses HashChainFormatter for tamper-evident
    logging. Otherwise uses ISO8601Formatter.

    Args:
        history_path: Path to history JSONL file.
        logger_name: Name for the logger (e.g., "mcp-acp.config.history").
        state_manager: Optional IntegrityStateManager for hash chain support.
        log_dir: Base log directory for computing relative file key.
                 Required when state_manager is provided.

    Returns:
        logging.Logger: Configured logger instance for history logging.
    """
    if history_path not in _logger_cache:
        logger = setup_jsonl_logger(
            logger_name,
            history_path,
            logging.INFO,
        )

        # If state_manager provided, swap formatter to HashChainFormatter
        if state_manager is not None and log_dir is not None:
            from mcp_acp.security.integrity.hash_chain import HashChainFormatter

            # Find the file handler
            for handler in logger.handlers:
                if isinstance(handler, logging.FileHandler):
                    # Compute relative file key
                    try:
                        file_key = str(history_path.relative_to(log_dir))
                    except ValueError:
                        file_key = history_path.name

                    formatter = HashChainFormatter(
                        state_manager=state_manager,
                        log_file_key=file_key,
                        log_path=history_path,
                    )
                    handler.setFormatter(formatter)
                    break

        _logger_cache[history_path] = logger

    return _logger_cache[history_path]
