"""Audit API schemas for integrity verification."""

from __future__ import annotations

__all__ = [
    "BackupFileInfo",
    "AuditFileResult",
    "AuditVerifyResponse",
    "AuditRepairResult",
    "AuditRepairResponse",
]

from pydantic import BaseModel, Field


class BackupFileInfo(BaseModel):
    """Information about a backup log file (.broken.TIMESTAMP.jsonl)."""

    filename: str = Field(description="Backup file name")
    path: str = Field(description="Relative path from log directory")
    size_bytes: int = Field(description="File size in bytes")
    timestamp: str = Field(description="Backup timestamp (e.g., '2025-01-28_123456')")


class AuditFileResult(BaseModel):
    """Verification result for a single audit log file."""

    name: str = Field(description="Log file name (e.g., 'operations', 'decisions')")
    description: str = Field(description="Human-readable description")
    status: str = Field(
        description="Status: 'protected', 'unprotected', 'broken', 'missing', 'empty', 'not_created', 'error'"
    )
    entry_count: int | None = Field(default=None, description="Number of entries in the file")
    last_sequence: int | None = Field(
        default=None, description="Last sequence number if hash chain is present"
    )
    errors: list[str] = Field(default_factory=list, description="Error messages if status is broken/error")
    backups: list[BackupFileInfo] = Field(default_factory=list, description="Backup files for this log")


class AuditVerifyResponse(BaseModel):
    """Response for audit verify endpoint."""

    proxy_name: str = Field(description="Name of the proxy")
    proxy_id: str = Field(description="Stable proxy identifier")
    state_file_present: bool = Field(description="Whether the integrity state file exists")
    files: list[AuditFileResult] = Field(description="Verification results per file")
    total_protected: int = Field(description="Number of files with verified hash chains")
    total_broken: int = Field(description="Number of files with broken integrity")
    total_unprotected: int = Field(description="Number of files without hash chain protection")
    overall_status: str = Field(
        description="'passed' if no broken files, 'failed' if any broken, 'no_files' if nothing to verify"
    )


class AuditRepairResult(BaseModel):
    """Repair result for a single file."""

    name: str = Field(description="Log file name")
    description: str = Field(description="Human-readable description")
    action: str = Field(description="'repaired', 'backed_up', 'skipped', 'no_action', or 'error'")
    message: str = Field(description="Details about the action taken")


class AuditRepairResponse(BaseModel):
    """Response for audit repair endpoint."""

    proxy_name: str = Field(description="Name of the proxy")
    proxy_id: str = Field(description="Stable proxy identifier")
    results: list[AuditRepairResult] = Field(description="Repair results per file")
    success: bool = Field(description="Whether all repairs succeeded")
    message: str = Field(description="Overall repair summary")
