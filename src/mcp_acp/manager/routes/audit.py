"""Audit integrity endpoints."""

from __future__ import annotations

__all__ = ["router", "AUDIT_LOG_FILES"]

import json
from datetime import datetime

from fastapi import APIRouter

from mcp_acp.api.errors import APIError, ErrorCode
from mcp_acp.api.schemas.audit import (
    AuditFileStatus,
    AuditRepairResponse,
    AuditRepairResult,
    AuditStatusResponse,
    AuditVerifyResponse,
    AuditVerifyResult,
)
from mcp_acp.manager.config import load_manager_config

from .deps import find_proxy_by_id

router = APIRouter(prefix="/api/manager/proxies", tags=["audit"])

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


def _build_audit_status(proxy_name: str, proxy_id: str) -> AuditStatusResponse:
    """Build audit status response for a proxy."""
    from mcp_acp.security.integrity import IntegrityStateManager
    from mcp_acp.security.integrity.hash_chain import verify_chain_from_lines
    from mcp_acp.utils.config import get_log_dir, get_log_path

    manager_config = load_manager_config()
    log_dir_str = manager_config.log_dir
    log_dir_path = get_log_dir(proxy_name, log_dir_str)

    # Check state file
    state_file = log_dir_path / IntegrityStateManager.STATE_FILE_NAME
    state_file_present = state_file.exists()

    files: list[AuditFileStatus] = []

    for file_key, (description, internal_type) in AUDIT_LOG_FILES.items():
        log_path = get_log_path(proxy_name, internal_type, log_dir_str)

        if not log_path.exists():
            files.append(
                AuditFileStatus(
                    name=file_key,
                    description=description,
                    status="not_created",
                )
            )
            continue

        try:
            with log_path.open(encoding="utf-8") as f:
                lines = [line.strip() for line in f if line.strip()]

            if not lines:
                files.append(
                    AuditFileStatus(
                        name=file_key,
                        description=description,
                        status="empty",
                        entry_count=0,
                    )
                )
                continue

            # Check last entry for hash chain fields
            last_entry = json.loads(lines[-1])
            if "sequence" in last_entry and "entry_hash" in last_entry:
                # Has hash chain - verify integrity
                result = verify_chain_from_lines(lines)
                if result.success:
                    files.append(
                        AuditFileStatus(
                            name=file_key,
                            description=description,
                            status="protected",
                            entry_count=len(lines),
                            last_sequence=last_entry.get("sequence"),
                        )
                    )
                else:
                    files.append(
                        AuditFileStatus(
                            name=file_key,
                            description=description,
                            status="broken",
                            entry_count=len(lines),
                            last_sequence=last_entry.get("sequence"),
                            errors=result.errors,
                        )
                    )
            else:
                files.append(
                    AuditFileStatus(
                        name=file_key,
                        description=description,
                        status="unprotected",
                        entry_count=len(lines),
                    )
                )

        except (json.JSONDecodeError, OSError) as e:
            files.append(
                AuditFileStatus(
                    name=file_key,
                    description=description,
                    status="error",
                    errors=[str(e)],
                )
            )

    return AuditStatusResponse(
        proxy_name=proxy_name,
        proxy_id=proxy_id,
        state_file_present=state_file_present,
        files=files,
    )


def _build_audit_verify(proxy_name: str, proxy_id: str) -> AuditVerifyResponse:
    """Build audit verification response for a proxy."""
    from mcp_acp.security.integrity.hash_chain import verify_chain_from_lines
    from mcp_acp.utils.config import get_log_path

    manager_config = load_manager_config()
    log_dir_str = manager_config.log_dir

    results: list[AuditVerifyResult] = []
    total_passed = 0
    total_failed = 0
    total_skipped = 0

    for file_key, (description, internal_type) in AUDIT_LOG_FILES.items():
        log_path = get_log_path(proxy_name, internal_type, log_dir_str)

        if not log_path.exists():
            results.append(
                AuditVerifyResult(
                    name=file_key,
                    description=description,
                    status="skipped",
                    entry_count=0,
                )
            )
            total_skipped += 1
            continue

        try:
            with log_path.open(encoding="utf-8") as f:
                lines = [line.strip() for line in f if line.strip()]

            if not lines:
                results.append(
                    AuditVerifyResult(
                        name=file_key,
                        description=description,
                        status="skipped",
                        entry_count=0,
                    )
                )
                total_skipped += 1
                continue

            # Verify chain integrity
            result = verify_chain_from_lines(lines)

            if result.success:
                results.append(
                    AuditVerifyResult(
                        name=file_key,
                        description=description,
                        status="passed",
                        entry_count=len(lines),
                    )
                )
                total_passed += 1
            else:
                results.append(
                    AuditVerifyResult(
                        name=file_key,
                        description=description,
                        status="failed",
                        entry_count=len(lines),
                        errors=result.errors,
                    )
                )
                total_failed += 1

        except OSError as e:
            results.append(
                AuditVerifyResult(
                    name=file_key,
                    description=description,
                    status="failed",
                    errors=[f"Failed to read file: {e}"],
                )
            )
            total_failed += 1

    # Determine overall status
    if total_failed > 0:
        overall_status = "failed"
    elif total_passed > 0:
        overall_status = "passed"
    else:
        overall_status = "no_files"

    return AuditVerifyResponse(
        proxy_name=proxy_name,
        proxy_id=proxy_id,
        results=results,
        total_passed=total_passed,
        total_failed=total_failed,
        total_skipped=total_skipped,
        overall_status=overall_status,
    )


def _build_audit_repair(proxy_name: str, proxy_id: str) -> AuditRepairResponse:
    """Build audit repair response for a proxy."""
    from mcp_acp.security.integrity import IntegrityStateManager
    from mcp_acp.security.integrity.hash_chain import verify_chain_from_lines
    from mcp_acp.utils.config import get_log_dir, get_log_path

    manager_config = load_manager_config()
    log_dir_str = manager_config.log_dir
    log_dir_path = get_log_dir(proxy_name, log_dir_str)

    state_manager = IntegrityStateManager(log_dir_path)
    results: list[AuditRepairResult] = []
    all_success = True

    for file_key, (description, internal_type) in AUDIT_LOG_FILES.items():
        log_path = get_log_path(proxy_name, internal_type, log_dir_str)

        if not log_path.exists():
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
                # Empty file - clear any state
                state_manager.clear_state_for_file(log_path)
                results.append(
                    AuditRepairResult(
                        name=file_key,
                        description=description,
                        action="repaired",
                        message="Cleared state for empty file",
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
                state_manager.repair_state_for_file(log_path)
                results.append(
                    AuditRepairResult(
                        name=file_key,
                        description=description,
                        action="repaired",
                        message=f"State synced with {len(lines)} entries",
                    )
                )
            else:
                # Chain is broken - backup and reset
                timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
                backup_path = log_path.with_suffix(f".broken.{timestamp}.jsonl")

                try:
                    log_path.rename(backup_path)
                    log_path.touch()
                    state_manager.clear_state_for_file(log_path)
                    results.append(
                        AuditRepairResult(
                            name=file_key,
                            description=description,
                            action="backed_up",
                            message=f"Backed up to {backup_path.name}, created fresh file",
                        )
                    )
                except OSError as e:
                    all_success = False
                    results.append(
                        AuditRepairResult(
                            name=file_key,
                            description=description,
                            action="error",
                            message=f"Failed to backup/reset: {e}",
                        )
                    )

        except (json.JSONDecodeError, OSError) as e:
            all_success = False
            results.append(
                AuditRepairResult(
                    name=file_key,
                    description=description,
                    action="error",
                    message=f"Failed to process file: {e}",
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


@router.get("/{proxy_id}/audit/status", response_model=AuditStatusResponse)
async def get_audit_status(proxy_id: str) -> AuditStatusResponse:
    """Get audit log integrity status for a proxy.

    Returns status of each audit log file including:
    - Whether hash chain protection is enabled
    - Number of entries
    - Chain integrity status

    Args:
        proxy_id: Stable proxy identifier.

    Returns:
        AuditStatusResponse with file statuses.
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
    return _build_audit_status(proxy_name, proxy_id)


@router.get("/{proxy_id}/audit/verify", response_model=AuditVerifyResponse)
async def verify_audit_logs(proxy_id: str) -> AuditVerifyResponse:
    """Verify audit log hash chain integrity for a proxy.

    Checks that log entries haven't been tampered with, deleted,
    or reordered. Uses cryptographic hash chains for verification.

    Args:
        proxy_id: Stable proxy identifier.

    Returns:
        AuditVerifyResponse with verification results.
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
