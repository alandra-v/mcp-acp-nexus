"""Log API schemas.

Combines schemas from routes/logs.py and routes/logs/models.py.
"""

from __future__ import annotations

__all__ = [
    # Re-exported from audit schema
    "BackupFileInfo",
    # Log schemas
    "LogFileInfo",
    "LogFolderInfo",
    "LogsMetadataResponse",
    "LogsResponse",
]

from typing import Any

from pydantic import BaseModel

# Re-export BackupFileInfo from audit schema (single source of truth)
from mcp_acp.api.schemas.audit import BackupFileInfo as BackupFileInfo  # noqa: F401


class LogsResponse(BaseModel):
    """Response containing log entries."""

    entries: list[dict[str, Any]]
    total_returned: int
    total_scanned: int
    log_file: str
    has_more: bool
    filters_applied: dict[str, Any]


class LogFileInfo(BaseModel):
    """Information about an available log file."""

    name: str
    path: str
    exists: bool
    size_bytes: int | None
    backups: list[BackupFileInfo] = []


class LogFolderInfo(BaseModel):
    """Information about a log folder."""

    name: str
    files: list[LogFileInfo]


class LogsMetadataResponse(BaseModel):
    """Metadata about available logs and filter options."""

    folders: list[LogFolderInfo]
    debug_enabled: bool
    available_policy_versions: list[str]
    available_config_versions: list[str]
