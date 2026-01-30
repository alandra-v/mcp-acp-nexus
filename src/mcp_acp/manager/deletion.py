"""Proxy deletion logic (soft delete, purge, and archive management).

Provides the shared deletion logic used by both CLI and API endpoints.
Soft delete archives config and audit/system logs to ~/.mcp-acp/archive/,
while permanently deleting debug logs and socket files.

Design goals:
- Preserve audit trail (Zero Trust compliance)
- Transparent behavior (user knows exactly what happens)
- Recoverable by default (soft delete unless explicitly purged)
- Unified archive location for discoverability
"""

from __future__ import annotations

__all__ = [
    "DeleteResult",
    "PurgeResult",
    "delete_proxy",
    "get_archive_dir",
    "get_archived_proxy_dir",
    "list_archived_proxies",
    "purge_archived_proxy",
]

import json
import logging
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from mcp_acp.constants import CRASH_BREADCRUMB_FILENAME, get_proxy_socket_path
from mcp_acp.manager.config import (
    get_proxy_config_dir,
    get_proxy_log_dir,
)
from mcp_acp.security.integrity.integrity_state import IntegrityStateManager
from mcp_acp.utils.file_helpers import get_app_dir

_logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class DeleteResult:
    """Result of a proxy deletion operation."""

    archived: list[str] = field(default_factory=list)
    deleted: list[str] = field(default_factory=list)
    archive_name: str | None = None
    archived_size: int = 0
    deleted_size: int = 0


@dataclass(frozen=True, slots=True)
class PurgeResult:
    """Result of a proxy archive purge operation."""

    archive_name: str = ""
    purged_size: int = 0


def get_archive_dir() -> Path:
    """Get unified archive directory."""
    return get_app_dir() / "archive"


def get_archived_proxy_dir(archive_name: str) -> Path:
    """Get directory for a specific archived proxy."""
    return get_archive_dir() / archive_name


def list_archived_proxies() -> list[str]:
    """List all archive folder names."""
    archive_dir = get_archive_dir()
    if not archive_dir.exists():
        return []
    return sorted(d.name for d in archive_dir.iterdir() if d.is_dir())


def delete_proxy(
    name: str,
    *,
    purge: bool = False,
    deleted_by: str = "cli",
) -> DeleteResult:
    """Delete a proxy, archiving config and audit logs.

    Callers must check if proxy is running before calling this function.
    Credential deletion is the last non-recoverable step.

    Args:
        name: Proxy name.
        purge: If True, skip archiving and delete everything.
        deleted_by: Who initiated deletion ("cli" or "api").

    Returns:
        DeleteResult with lists of archived and deleted items.
    """
    now = datetime.now(timezone.utc)
    timestamp = now.strftime("%Y-%m-%dT%H-%M-%S")
    archive_name = f"{name}_{timestamp}"

    proxy_dir = get_proxy_config_dir(name)
    logs_dir = get_proxy_log_dir(name)

    archived: list[str] = []
    deleted: list[str] = []
    archived_size = 0
    deleted_size = 0

    if purge:
        # Hard delete everything
        if proxy_dir.exists():
            deleted_size += _dir_size(proxy_dir)
            shutil.rmtree(proxy_dir)
            deleted.append("Config directory")
        if logs_dir.exists():
            deleted_size += _dir_size(logs_dir)
            shutil.rmtree(logs_dir)
            deleted.append("Log directory")
        # Delete stale socket file
        socket_path = get_proxy_socket_path(name)
        if socket_path.exists():
            socket_path.unlink()
            deleted.append("Socket file")
        archive_name_result = None
    else:
        # Soft delete: archive to unified archive directory
        archive_root = get_archived_proxy_dir(archive_name)
        archive_config_dir = archive_root / "config"
        archive_logs_dir = archive_root / "logs"

        archive_root.mkdir(parents=True, exist_ok=True)

        # 1. Archive config dir (includes config.json, policy.json, bootstrap.jsonl)
        if proxy_dir.exists():
            shutil.copytree(proxy_dir, archive_config_dir)
            archived_size += _dir_size(archive_config_dir)
            archived.append("Config + policy")

        # 2. Archive audit and system log subdirectories
        for log_type in ["audit", "system"]:
            src = logs_dir / log_type
            if src.exists():
                dst = archive_logs_dir / log_type
                shutil.copytree(src, dst)
                archived_size += _dir_size(dst)
                shutil.rmtree(src)
                archived.append(f"{log_type.title()} logs")

        # 3. Archive log-dir root files: .integrity_state, .last_crash, shutdowns.jsonl
        root_files_to_archive = [
            IntegrityStateManager.STATE_FILE_NAME,  # ".integrity_state"
            CRASH_BREADCRUMB_FILENAME,  # ".last_crash"
            "shutdowns.jsonl",
        ]
        archive_logs_dir.mkdir(parents=True, exist_ok=True)
        for filename in root_files_to_archive:
            src = logs_dir / filename
            if src.exists():
                shutil.copy2(src, archive_logs_dir / filename)
                archived_size += src.stat().st_size
                src.unlink()

        # 4. Delete debug logs (ephemeral, no security value)
        debug_dir = logs_dir / "debug"
        if debug_dir.exists():
            deleted_size += _dir_size(debug_dir)
            shutil.rmtree(debug_dir)
            deleted.append("Debug logs")

        # 5. Clean up empty logs dir
        if logs_dir.exists() and not any(logs_dir.iterdir()):
            logs_dir.rmdir()

        # 6. Delete stale socket file (runtime artifact)
        socket_path = get_proxy_socket_path(name)
        if socket_path.exists():
            socket_path.unlink()
            deleted.append("Socket file")

        # 7. Remove backend credential from keychain (non-recoverable)
        credential_deleted = False
        try:
            from mcp_acp.security.credential_storage import BackendCredentialStorage

            credential_storage = BackendCredentialStorage(name)
            credential_storage.delete()
            credential_deleted = True
        except ImportError:
            credential_deleted = True  # No keychain library = nothing to clean up
        except RuntimeError as e:
            _logger.debug("Credential cleanup for '%s' skipped: %s", name, e)
        deleted.append("Backend credential from keychain")

        # 8. Write metadata.json (machine-readable manifest)
        metadata = {
            "version": 1,
            "original_name": name,
            "deleted_at": now.isoformat(),
            "deleted_by": deleted_by,
            "original_config_path": str(proxy_dir),
            "original_log_path": str(logs_dir),
            "archived": {
                "config": archive_config_dir.exists(),
                "audit_logs": (archive_logs_dir / "audit").exists(),
                "system_logs": (archive_logs_dir / "system").exists(),
                "integrity_state": (archive_logs_dir / IntegrityStateManager.STATE_FILE_NAME).exists(),
                "crash_breadcrumb": (archive_logs_dir / CRASH_BREADCRUMB_FILENAME).exists(),
                "incident_shutdowns": (archive_logs_dir / "shutdowns.jsonl").exists(),
                "incident_bootstrap": (
                    (archive_config_dir / "bootstrap.jsonl").exists()
                    if archive_config_dir.exists()
                    else False
                ),
            },
            "deleted": {
                "debug_logs": "Debug logs" in deleted,
                "debug_logs_size_bytes": deleted_size,
                "socket_file": "Socket file" in deleted,
                "backend_credential": credential_deleted,
            },
        }
        (archive_root / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")

        # 9. Write README.txt (human-readable)
        _write_deletion_readme(archive_root, name, archive_name, now, archived, deleted, deleted_size)

        # 10. Remove original config dir (deferred until metadata is safely written)
        if proxy_dir.exists():
            shutil.rmtree(proxy_dir)

        archive_name_result = archive_name

    # Purge path: remove backend credential last
    if purge:
        try:
            from mcp_acp.security.credential_storage import BackendCredentialStorage

            credential_storage = BackendCredentialStorage(name)
            credential_storage.delete()
        except ImportError:
            pass  # Keychain library not available on this platform
        except RuntimeError as e:
            _logger.debug("Credential cleanup for '%s' skipped: %s", name, e)
        deleted.append("Backend credential from keychain")

    return DeleteResult(
        archived=archived,
        deleted=deleted,
        archive_name=archive_name_result,
        archived_size=archived_size,
        deleted_size=deleted_size,
    )


def purge_archived_proxy(archive_name: str) -> PurgeResult:
    """Permanently delete an archived proxy.

    Args:
        archive_name: Full archive directory name (e.g., "filesystem_2024-01-13T10-30-00").

    Returns:
        PurgeResult with purge details.

    Raises:
        FileNotFoundError: If archive directory doesn't exist.
    """
    archive_dir = get_archived_proxy_dir(archive_name)
    if not archive_dir.exists():
        raise FileNotFoundError(f"Archive '{archive_name}' not found")

    purged_size = _dir_size(archive_dir)
    shutil.rmtree(archive_dir)

    # Clean up empty archive/ parent if no other archives exist
    parent = get_archive_dir()
    if parent.exists() and not any(parent.iterdir()):
        parent.rmdir()

    return PurgeResult(
        archive_name=archive_name,
        purged_size=purged_size,
    )


def _dir_size(path: Path) -> int:
    """Calculate total size of all files in a directory."""
    return sum(f.stat().st_size for f in path.rglob("*") if f.is_file())


def _write_deletion_readme(
    archive_root: Path,
    name: str,
    archive_name: str,
    deleted_at: datetime,
    archived: list[str],
    deleted: list[str],
    deleted_size: int,
) -> None:
    """Write human-readable README.txt to archive directory."""
    from mcp_acp.utils.file_helpers import format_size

    proxy_dir = get_proxy_config_dir(name)

    lines = [
        f"Proxy deleted: {deleted_at.isoformat()}",
        f"Original name: {name}",
        "",
        "What was archived (in this directory):",
    ]

    if "Config + policy" in archived:
        archive_config_dir = archive_root / "config"
        config_files = sorted(f.name for f in archive_config_dir.iterdir() if f.is_file())
        lines.append(f"  - config/    ({', '.join(config_files)})")
    if "Audit logs" in archived:
        lines.append("  - logs/audit/    (audit trail - security logs)")
    if "System logs" in archived:
        lines.append("  - logs/system/   (system logs)")
    if (archive_root / "logs" / ".integrity_state").exists():
        lines.append("  - logs/.integrity_state    (hash chain state)")
    if (archive_root / "logs" / "shutdowns.jsonl").exists():
        lines.append("  - logs/shutdowns.jsonl     (security shutdown history)")

    lines.extend(["", "What was deleted permanently:"])

    if "Debug logs" in deleted:
        lines.append(f"  - Debug logs ({format_size(deleted_size)})")
    if "Socket file" in deleted:
        lines.append(f"  - Socket file (proxy_{name}.sock)")
    lines.append("  - Backend credential from keychain")

    lines.extend(
        [
            "",
            "To restore this proxy:",
            f"  1. Move config/ to {proxy_dir}",
            f"  2. Reconfigure backend credentials: mcp-acp proxy auth set-key --proxy {name}",
            "",
            "To permanently delete:",
            f"  mcp-acp proxy purge {archive_name}",
            "",
        ]
    )

    (archive_root / "README.txt").write_text("\n".join(lines))
