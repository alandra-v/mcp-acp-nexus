"""Audit API schemas for integrity verification and status."""

from __future__ import annotations

from pydantic import BaseModel, Field


class AuditFileStatus(BaseModel):
    """Status of a single audit log file."""

    name: str = Field(description="Log file name (e.g., 'operations', 'decisions')")
    description: str = Field(description="Human-readable description")
    status: str = Field(
        description="Status: 'protected', 'unprotected', 'broken', 'empty', 'not_created', 'error'"
    )
    entry_count: int | None = Field(default=None, description="Number of entries in the file")
    last_sequence: int | None = Field(
        default=None, description="Last sequence number if hash chain is present"
    )
    errors: list[str] = Field(default_factory=list, description="Error messages if status is broken/error")


class AuditStatusResponse(BaseModel):
    """Response for audit status endpoint."""

    proxy_name: str = Field(description="Name of the proxy")
    proxy_id: str = Field(description="Stable proxy identifier")
    state_file_present: bool = Field(description="Whether the integrity state file exists")
    files: list[AuditFileStatus] = Field(description="Status of each audit log file")


class AuditVerifyResult(BaseModel):
    """Verification result for a single file."""

    name: str = Field(description="Log file name")
    description: str = Field(description="Human-readable description")
    status: str = Field(description="'passed', 'failed', or 'skipped'")
    entry_count: int = Field(default=0, description="Number of entries verified")
    errors: list[str] = Field(default_factory=list, description="Error messages if verification failed")


class AuditVerifyResponse(BaseModel):
    """Response for audit verify endpoint."""

    proxy_name: str = Field(description="Name of the proxy")
    proxy_id: str = Field(description="Stable proxy identifier")
    results: list[AuditVerifyResult] = Field(description="Verification results per file")
    total_passed: int = Field(description="Number of files that passed verification")
    total_failed: int = Field(description="Number of files that failed verification")
    total_skipped: int = Field(description="Number of files skipped (not created yet)")
    overall_status: str = Field(
        description="'passed' if all verified files passed, 'failed' if any failed, 'no_files' if nothing to verify"
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
