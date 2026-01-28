"""Audit integrity endpoints."""

from __future__ import annotations

__all__ = ["router", "AUDIT_LOG_FILES"]

import json
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from fastapi import APIRouter

from mcp_acp.api.errors import APIError, ErrorCode
from mcp_acp.api.schemas.audit import (
    AuditFileResult,
    AuditRepairResponse,
    AuditRepairResult,
    AuditVerifyResponse,
    BackupFileInfo,
)
from mcp_acp.manager.config import load_manager_config

from .deps import find_proxy_by_id, get_backup_file_infos

if TYPE_CHECKING:
    from mcp_acp.security.integrity import IntegrityStateManager

router = APIRouter(prefix="/api/manager/proxies", tags=["audit"])

# Timestamp format for backup files
_BACKUP_TIMESTAMP_FORMAT = "%Y-%m-%d_%H%M%S"

# Log files that are protected by hash chains
# CLI name -> (description, internal log_type for get_log_path)
AUDIT_LOG_FILES: dict[str, tuple[str, str]] = {
    "operations": ("Operations audit", "operations"),
    "decisions": ("Policy decisions", "decisions"),
    "auth": ("Authentication events", "auth"),
    "system": ("System logs", "system"),
    "config-history": ("Config change history", "config_history"),
    "policy-history": ("Policy change history", "policy_history"),
}


# ==========================================================================
# Audit Helpers
# ==========================================================================


def _backup_and_reset_file(
    log_path: Path,
    state_manager: "IntegrityStateManager",
    reason: str = "",
) -> AuditRepairResult:
    """Backup a broken/invalid log file and create empty replacement.

    Args:
        log_path: Path to the log file to backup and reset.
        state_manager: IntegrityStateManager to clear state from.
        reason: Optional reason prefix for the message (e.g., "Invalid JSON").

    Returns:
        AuditRepairResult with action and message.
    """
    timestamp = datetime.now().strftime(_BACKUP_TIMESTAMP_FORMAT)
    backup_path = log_path.with_suffix(f".broken.{timestamp}.jsonl")

    try:
        log_path.rename(backup_path)
        log_path.touch()
        state_manager.clear_state_for_file(log_path)

        prefix = f"{reason} - " if reason else ""
        return AuditRepairResult(
            name="",  # Caller sets this
            description="",  # Caller sets this
            action="backed_up",
            message=f"{prefix}Backed up to {backup_path.name}, created fresh file",
        )
    except OSError as e:
        return AuditRepairResult(
            name="",  # Caller sets this
            description="",  # Caller sets this
            action="error",
            message=f"Failed to backup/reset: {e}",
        )


def _build_audit_verify(proxy_name: str, proxy_id: str) -> AuditVerifyResponse:
    """Build audit verification response for a proxy.

    This is the single endpoint for audit integrity - it verifies all files
    and returns comprehensive status including state file presence, per-file
    status with entry counts/sequences, and overall summary.
    """
    from mcp_acp.security.integrity import IntegrityStateManager
    from mcp_acp.security.integrity.hash_chain import verify_file_integrity
    from mcp_acp.utils.config import get_log_dir, get_log_path

    manager_config = load_manager_config()
    log_dir_str = manager_config.log_dir
    log_dir_path = get_log_dir(proxy_name, log_dir_str)

    # Check state file and load state manager
    state_file = log_dir_path / IntegrityStateManager.STATE_FILE_NAME
    state_file_present = state_file.exists()

    state_manager = IntegrityStateManager(log_dir_path)
    state_manager.load_state()

    files: list[AuditFileResult] = []
    total_protected = 0
    total_broken = 0
    total_unprotected = 0

    for file_key, (description, internal_type) in AUDIT_LOG_FILES.items():
        log_path = get_log_path(proxy_name, internal_type, log_dir_str)

        # Scan for backup files (.broken.TIMESTAMP.jsonl)
        backups = get_backup_file_infos(log_path, log_dir_path)

        if not log_path.exists():
            files.append(
                AuditFileResult(
                    name=file_key,
                    description=description,
                    status="not_created",
                    backups=backups,
                )
            )
            continue

        try:
            with log_path.open(encoding="utf-8") as f:
                lines = [line.strip() for line in f if line.strip()]

            if not lines:
                files.append(
                    AuditFileResult(
                        name=file_key,
                        description=description,
                        status="empty",
                        entry_count=0,
                        backups=backups,
                    )
                )
                continue

            # Check last entry for hash chain fields
            last_entry = json.loads(lines[-1])
            if "sequence" in last_entry and "entry_hash" in last_entry:
                # Has hash chain - use unified verification (state + chain check)
                result = verify_file_integrity(
                    log_path,
                    state_manager=state_manager,
                    log_dir=log_dir_path,
                )
                if result.success:
                    files.append(
                        AuditFileResult(
                            name=file_key,
                            description=description,
                            status="protected",
                            entry_count=len(lines),
                            last_sequence=last_entry.get("sequence"),
                            backups=backups,
                        )
                    )
                    total_protected += 1
                else:
                    files.append(
                        AuditFileResult(
                            name=file_key,
                            description=description,
                            status="broken",
                            entry_count=len(lines),
                            last_sequence=last_entry.get("sequence"),
                            errors=result.errors,
                            backups=backups,
                        )
                    )
                    total_broken += 1
            else:
                files.append(
                    AuditFileResult(
                        name=file_key,
                        description=description,
                        status="unprotected",
                        entry_count=len(lines),
                        backups=backups,
                    )
                )
                total_unprotected += 1

        except (json.JSONDecodeError, OSError) as e:
            files.append(
                AuditFileResult(
                    name=file_key,
                    description=description,
                    status="error",
                    errors=[str(e)],
                    backups=backups,
                )
            )
            total_broken += 1

    # Determine overall status
    if total_broken > 0:
        overall_status = "failed"
    elif total_protected > 0:
        overall_status = "passed"
    else:
        overall_status = "no_files"

    return AuditVerifyResponse(
        proxy_name=proxy_name,
        proxy_id=proxy_id,
        state_file_present=state_file_present,
        files=files,
        total_protected=total_protected,
        total_broken=total_broken,
        total_unprotected=total_unprotected,
        overall_status=overall_status,
    )


def _build_audit_repair(proxy_name: str, proxy_id: str) -> AuditRepairResponse:
    """Build audit repair response for a proxy.

    Repairs integrity state for all audit log files. For each file:
    - Missing file: clears stale state if present
    - Empty file: clears stale state if present
    - Unprotected file: no action needed
    - Valid chain: syncs state file to match log
    - Broken chain or invalid JSON: backs up file and creates fresh one

    Args:
        proxy_name: Human-readable proxy name.
        proxy_id: Stable proxy identifier.

    Returns:
        AuditRepairResponse with per-file repair results and overall status.
    """
    from mcp_acp.security.integrity import IntegrityStateManager
    from mcp_acp.security.integrity.hash_chain import verify_chain_from_lines
    from mcp_acp.utils.config import get_log_dir, get_log_path

    manager_config = load_manager_config()
    log_dir_str = manager_config.log_dir
    log_dir_path = get_log_dir(proxy_name, log_dir_str)

    state_manager = IntegrityStateManager(log_dir_path)
    state_manager.load_state()  # Load existing state before repairs
    results: list[AuditRepairResult] = []
    all_success = True

    for file_key, (description, internal_type) in AUDIT_LOG_FILES.items():
        log_path = get_log_path(proxy_name, internal_type, log_dir_str)

        if not log_path.exists():
            # File doesn't exist - clear any stale state
            success, message = state_manager.repair_state_for_file(log_path)
            if success and "cleared" in message.lower():
                results.append(
                    AuditRepairResult(
                        name=file_key,
                        description=description,
                        action="repaired",
                        message=message,
                    )
                )
            else:
                results.append(
                    AuditRepairResult(
                        name=file_key,
                        description=description,
                        action="no_action",
                        message="File not created yet",
                    )
                )
            continue

        try:
            with log_path.open(encoding="utf-8") as f:
                lines = [line.strip() for line in f if line.strip()]

            if not lines:
                # Empty file - clear any stale state
                success, message = state_manager.repair_state_for_file(log_path)
                results.append(
                    AuditRepairResult(
                        name=file_key,
                        description=description,
                        action="repaired" if success else "error",
                        message=message,
                    )
                )
                continue

            # Check if file has hash chain entries
            last_entry = json.loads(lines[-1])
            if "sequence" not in last_entry or "entry_hash" not in last_entry:
                # No hash chain - nothing to repair
                results.append(
                    AuditRepairResult(
                        name=file_key,
                        description=description,
                        action="no_action",
                        message="No hash chain entries (unprotected file)",
                    )
                )
                continue

            # Verify chain integrity
            result = verify_chain_from_lines(lines)

            if result.success:
                # Chain is valid - repair state file to match
                success, message = state_manager.repair_state_for_file(log_path)
                results.append(
                    AuditRepairResult(
                        name=file_key,
                        description=description,
                        action="repaired" if success else "error",
                        message=message,
                    )
                )
                if not success:
                    all_success = False
            else:
                # Chain is broken - backup and reset
                repair_result = _backup_and_reset_file(log_path, state_manager)
                results.append(
                    AuditRepairResult(
                        name=file_key,
                        description=description,
                        action=repair_result.action,
                        message=repair_result.message,
                    )
                )
                if repair_result.action == "error":
                    all_success = False

        except json.JSONDecodeError:
            # File has invalid JSON - treat as broken chain, backup and reset
            repair_result = _backup_and_reset_file(log_path, state_manager, reason="Invalid JSON")
            results.append(
                AuditRepairResult(
                    name=file_key,
                    description=description,
                    action=repair_result.action,
                    message=repair_result.message,
                )
            )
            if repair_result.action == "error":
                all_success = False

        except OSError as e:
            all_success = False
            results.append(
                AuditRepairResult(
                    name=file_key,
                    description=description,
                    action="error",
                    message=f"Failed to read file: {e}",
                )
            )

    return AuditRepairResponse(
        proxy_name=proxy_name,
        proxy_id=proxy_id,
        results=results,
        success=all_success,
        message="All repairs completed" if all_success else "Some repairs failed",
    )


# ==========================================================================
# Audit Endpoints
# ==========================================================================


@router.get("/{proxy_id}/audit/verify", response_model=AuditVerifyResponse)
async def verify_audit_logs(proxy_id: str) -> AuditVerifyResponse:
    """Verify audit log integrity and return comprehensive status.

    This is the single endpoint for audit integrity. It verifies all
    files and returns:
    - State file presence
    - Per-file status (protected, broken, unprotected, empty, not_created, error)
    - Entry counts and last sequence numbers
    - Verification errors for broken files
    - Overall summary (total protected/broken/unprotected)

    Args:
        proxy_id: Stable proxy identifier.

    Returns:
        AuditVerifyResponse with verification results and status.
    """
    result = find_proxy_by_id(proxy_id)
    if result is None:
        raise APIError(
            status_code=404,
            code=ErrorCode.PROXY_NOT_FOUND,
            message=f"Proxy with ID '{proxy_id}' not found",
            details={"proxy_id": proxy_id},
        )

    proxy_name, _ = result
    return _build_audit_verify(proxy_name, proxy_id)


@router.post("/{proxy_id}/audit/repair", response_model=AuditRepairResponse)
async def repair_audit_logs(proxy_id: str) -> AuditRepairResponse:
    """Repair audit log integrity state for a proxy.

    Updates the integrity state file to match actual log files.
    For broken hash chains, backs up the file and creates a fresh one.

    Args:
        proxy_id: Stable proxy identifier.

    Returns:
        AuditRepairResponse with repair results.
    """
    result = find_proxy_by_id(proxy_id)
    if result is None:
        raise APIError(
            status_code=404,
            code=ErrorCode.PROXY_NOT_FOUND,
            message=f"Proxy with ID '{proxy_id}' not found",
            details={"proxy_id": proxy_id},
        )

    proxy_name, _ = result
    return _build_audit_repair(proxy_name, proxy_id)
