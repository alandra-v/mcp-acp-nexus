"""Audit command group for mcp-acp CLI.

Provides audit log management commands including hash chain verification.
"""

from __future__ import annotations

__all__ = ["audit"]

import json
import sys
from datetime import datetime
from pathlib import Path

import click

from mcp_acp.manager.config import list_configured_proxies
from mcp_acp.security.integrity import IntegrityStateManager
from mcp_acp.security.integrity.hash_chain import verify_chain_from_lines
from mcp_acp.utils.cli import (
    load_manager_config_or_exit,
    require_proxy_name,
    validate_proxy_if_provided,
)
from mcp_acp.utils.config import get_log_dir, get_log_path

from ..styling import style_error, style_label, style_success, style_warning

# Exit codes as per plan
EXIT_PASSED = 0
EXIT_FAILED = 1  # Tampering detected
EXIT_UNABLE = 2  # Unable to verify (missing files, etc.)

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


@click.group()
def audit() -> None:
    """Audit log management commands.

    Verify audit log integrity using hash chains.
    """
    pass


@audit.command("verify")
@click.option(
    "--proxy",
    "-p",
    "proxy_name",
    help="Proxy name (optional - verifies all proxies if not specified)",
)
@click.option(
    "--file",
    "-f",
    "log_file",
    type=click.Choice(list(AUDIT_LOG_FILES.keys()) + ["all"]),
    default="all",
    help="Log file to verify (default: all)",
)
def verify(proxy_name: str | None, log_file: str) -> None:
    """Verify audit log integrity and show status.

    Without --proxy, verifies ALL proxies.
    With --proxy, verifies only the specified proxy.

    Performs the same checks as startup verification:
    - Hash chain integrity (entries not tampered/deleted/reordered)
    - State file consistency (inode match, last hash match)

    Shows detailed status including entry counts, sequence numbers,
    and any backup files from previous repairs.

    Exit codes:
      0 - All checks passed
      1 - Tampering detected (hash chain broken or state mismatch)
      2 - Unable to verify (missing files, read errors)
    """
    proxy_name = validate_proxy_if_provided(proxy_name)
    manager_config = load_manager_config_or_exit()
    log_dir_str = manager_config.log_dir

    click.echo()
    click.echo(style_label("Audit Log Integrity Verification"))
    click.echo()

    # Determine which proxies to verify
    if proxy_name:
        proxies_to_verify = [proxy_name]
    else:
        proxies_to_verify = list_configured_proxies()
        if not proxies_to_verify:
            click.echo(style_warning("No proxies configured."))
            click.echo("Run 'mcp-acp proxy add' to create one.")
            sys.exit(EXIT_UNABLE)

    if log_file == "all":
        files_to_verify = list(AUDIT_LOG_FILES.items())
    else:
        if log_file not in AUDIT_LOG_FILES:
            click.echo(style_error(f"Unknown log file: {log_file}"))
            sys.exit(EXIT_UNABLE)
        files_to_verify = [(log_file, AUDIT_LOG_FILES[log_file])]

    total_protected = 0
    total_broken = 0
    total_unprotected = 0
    total_empty = 0

    for pname in proxies_to_verify:
        click.echo(f"Proxy: {pname}")

        # Load state manager for this proxy
        log_dir_path = get_log_dir(pname, log_dir_str)
        state_manager = IntegrityStateManager(log_dir_path)
        try:
            state_manager.load_state()
            state_loaded = True
        except (ValueError, OSError):
            state_loaded = False

        # Show state file status
        state_file = log_dir_path / IntegrityStateManager.STATE_FILE_NAME
        if state_file.exists():
            if state_loaded:
                click.echo(f"  State file: {style_success('present')}")
            else:
                click.echo(f"  State file: {style_error('corrupted')}")
        else:
            click.echo(f"  State file: {style_warning('not found')}")

        click.echo("  Log files:")

        for file_key, (description, internal_type) in files_to_verify:
            log_path = get_log_path(pname, internal_type, log_dir_str)

            if not log_path.exists():
                # Check for stale state
                rel_key = str(log_path.relative_to(log_dir_path))
                if state_loaded and state_manager.has_state_for_file(rel_key):
                    status_str = style_error("MISSING")
                    info = "file deleted but state exists - run audit repair"
                    total_broken += 1
                else:
                    status_str = style_warning("not created")
                    info = ""
                    total_empty += 1
            else:
                # Check if file has hash chain entries and verify integrity
                try:
                    with log_path.open(encoding="utf-8") as f:
                        lines = [line.strip() for line in f if line.strip()]

                    if not lines:
                        # Check for stale state on empty file
                        rel_key = str(log_path.relative_to(log_dir_path))
                        if state_loaded and state_manager.has_state_for_file(rel_key):
                            status_str = style_error("EMPTY")
                            info = "file emptied but state exists - run audit repair"
                            total_broken += 1
                        else:
                            status_str = style_warning("empty")
                            info = "0 entries"
                            total_empty += 1
                    else:
                        # Check last entry for hash chain fields
                        last_entry = json.loads(lines[-1])
                        if "sequence" in last_entry and "entry_hash" in last_entry:
                            # Has hash chain - verify integrity AND state consistency
                            result = verify_chain_from_lines(lines)
                            state_issue = _check_state_consistency(
                                log_path,
                                log_dir_path,
                                state_manager,
                                state_loaded,
                                last_entry_hash=last_entry.get("entry_hash"),
                            )

                            if not result.success:
                                status_str = style_error("BROKEN")
                                info = f"{len(lines)} entries - chain integrity failed"
                                total_broken += 1
                            elif state_issue:
                                status_str = style_error("STATE MISMATCH")
                                info = f"{len(lines)} entries - {state_issue}"
                                total_broken += 1
                            else:
                                status_str = style_success("protected")
                                info = f"{len(lines)} entries, seq #{last_entry.get('sequence', '?')}"
                                total_protected += 1
                        else:
                            status_str = style_warning("unprotected")
                            info = f"{len(lines)} entries (no hash chain)"
                            total_unprotected += 1
                except (json.JSONDecodeError, OSError):
                    status_str = style_error("error reading")
                    info = ""
                    total_broken += 1

            click.echo(f"    {file_key:15} - {status_str}")
            if info:
                click.echo(f"                       {info}")

        click.echo()

    # Summary
    if total_broken == 0:
        if total_protected == 0 and total_unprotected == 0:
            click.echo(style_warning("No log files found to verify."))
            click.echo("Run the proxy to generate audit logs.")
            sys.exit(EXIT_UNABLE)
        else:
            msg = f"All {total_protected} protected file(s) passed integrity check."
            if total_unprotected > 0:
                msg += f" ({total_unprotected} unprotected)"
            if total_empty > 0:
                msg += f" ({total_empty} empty/not created)"
            click.echo(style_success(msg))
            sys.exit(EXIT_PASSED)
    else:
        click.echo(style_error(f"INTEGRITY CHECK FAILED: {total_broken} file(s) have issues"))
        click.echo()
        click.echo("Run 'mcp-acp audit repair --proxy <name>' to fix.")
        sys.exit(EXIT_FAILED)


def _check_state_consistency(
    log_path: Path,
    log_dir_path: Path,
    state_manager: IntegrityStateManager,
    state_loaded: bool,
    last_entry_hash: str | None = None,
) -> str | None:
    """Check if file's inode and last hash match stored state.

    Performs the same checks as startup verification to detect:
    - File replacement (inode changed)
    - Last entry modification (hash mismatch)

    Args:
        log_path: Path to the log file to check.
        log_dir_path: Base log directory for computing relative key.
        state_manager: IntegrityStateManager with loaded state.
        state_loaded: Whether state was successfully loaded.
        last_entry_hash: Hash from last entry (avoids re-reading file).

    Returns:
        Error description if mismatch found, None if state is consistent.
    """
    if not state_loaded:
        return None

    rel_key = str(log_path.relative_to(log_dir_path))
    state = state_manager.get_file_state(rel_key)
    if state is None:
        return None  # No state - OK (first run or new file)

    # Check inode match (detect file replacement)
    try:
        stat = log_path.stat()
    except OSError:
        return "cannot stat file"

    if stat.st_ino != state.last_inode or stat.st_dev != state.last_dev:
        return "inode changed (file was replaced) - run audit repair"

    # Check last entry hash match
    if last_entry_hash and last_entry_hash != state.last_hash:
        return "last hash mismatch - run audit repair"

    return None


def _check_chain_integrity(log_path: Path) -> tuple[bool, list[str]]:
    """Check if a log file's hash chain is internally consistent.

    Args:
        log_path: Path to the log file to verify.

    Returns:
        Tuple of (is_valid, error_messages). Returns (True, []) for empty
        files or files without hash chain entries.
    """
    try:
        with log_path.open(encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]

        if not lines:
            return True, []  # Empty file is valid

        # Check if file has hash chain entries
        try:
            last_entry = json.loads(lines[-1])
            if "sequence" not in last_entry or "entry_hash" not in last_entry:
                return True, []  # No hash chain entries, nothing to verify
        except json.JSONDecodeError:
            return False, ["Last entry is not valid JSON"]

        # Verify chain integrity
        result = verify_chain_from_lines(lines)
        return result.success, result.errors

    except OSError as e:
        return False, [f"Cannot read file: {e}"]


def _backup_and_reset_file(
    log_path: Path,
    state_manager: IntegrityStateManager,
) -> tuple[bool, str]:
    """Backup a broken log file and create empty replacement.

    Renames the broken file with a .broken.{timestamp}.jsonl suffix,
    creates a new empty file, and clears the integrity state.

    Uses rollback on failure: if any step fails after the rename,
    attempts to restore the original file.

    Args:
        log_path: Path to the broken log file.
        state_manager: IntegrityStateManager to clear state from.

    Returns:
        Tuple of (success, message). On success, message includes the
        backup filename. On failure, message describes the error.
    """
    # Generate backup filename with timestamp
    timestamp = datetime.now().strftime(_BACKUP_TIMESTAMP_FORMAT)
    backup_path = log_path.with_suffix(f".broken.{timestamp}.jsonl")

    try:
        # Rename original to backup
        log_path.rename(backup_path)
    except OSError as e:
        return False, f"Failed to backup file: {e}"

    try:
        # Create empty file
        log_path.touch()

        # Clear state for this file using public method
        state_manager.clear_state_for_file(log_path)

        return True, f"Backed up to {backup_path.name}, created fresh file"

    except OSError as e:
        # Rollback: restore original file
        try:
            if log_path.exists():
                log_path.unlink()
            backup_path.rename(log_path)
        except OSError:
            pass  # Best effort rollback
        return False, f"Failed to reset file: {e}"


@audit.command("repair")
@click.option(
    "--proxy",
    "-p",
    "proxy_name",
    required=True,
    help="Proxy name (required - repair operates on one proxy at a time)",
)
@click.option(
    "--file",
    "-f",
    "log_file",
    type=click.Choice(list(AUDIT_LOG_FILES.keys()) + ["all"]),
    default="all",
    help="Log file to repair (default: all)",
)
@click.option(
    "--yes",
    "-y",
    is_flag=True,
    hidden=True,
    help="Skip confirmation prompt (for testing/automation)",
)
def repair(proxy_name: str, log_file: str, yes: bool) -> None:
    """Repair integrity state after crash or verification failure.

    Requires --proxy (dangerous operation, operates on one proxy at a time).

    Updates the .integrity_state file to match the actual log files.
    Use this when:
    - Proxy crashed during a write operation
    - Verification fails with "hash mismatch" errors
    - You've investigated and confirmed logs are not tampered

    If a log file's hash chain is internally broken (e.g., entries deleted),
    backs up the broken file with a .broken.TIMESTAMP.jsonl suffix and creates
    a fresh empty file. Use 'logs list' to see backup files.
    """
    proxy_name = require_proxy_name(proxy_name)
    manager_config = load_manager_config_or_exit()
    log_dir_str = manager_config.log_dir
    log_dir_path = get_log_dir(proxy_name, log_dir_str)

    click.echo()
    click.echo(style_label("Audit Log State Repair"))
    click.echo()

    if log_file == "all":
        files_to_repair = list(AUDIT_LOG_FILES.items())
    else:
        files_to_repair = [(log_file, AUDIT_LOG_FILES[log_file])]

    # Load state manager
    state_manager = IntegrityStateManager(log_dir_path)
    state_manager.load_state()

    repaired = 0
    failed = 0
    reset = 0

    for file_key, (description, internal_type) in files_to_repair:
        log_path = get_log_path(proxy_name, internal_type, log_dir_str)

        if not log_path.exists():
            # File doesn't exist - clear any stale state
            success, message = state_manager.repair_state_for_file(log_path)
            if success and "cleared" in message.lower():
                click.echo(f"  {style_success('✓')} {message}")
                repaired += 1
            continue

        # First check if chain is internally broken
        chain_valid, chain_errors = _check_chain_integrity(log_path)

        if not chain_valid:
            # Chain is broken - offer to backup and reset
            click.echo(f"  {style_error('✗')} {description}: Chain is broken")
            for err in chain_errors[:2]:
                click.echo(f"      {err}")

            click.echo()
            click.echo(f"  The hash chain in {log_path.name} is internally corrupted.")
            click.echo("  This usually means entries were deleted or modified.")
            click.echo()
            click.echo(f"  Repair will: 1) Backup current file with .broken.TIMESTAMP.jsonl suffix")
            click.echo(f"               2) Create a fresh empty log file")
            click.echo()

            if yes or click.confirm(f"  Proceed with backup and reset of {log_path.name}?"):
                success, message = _backup_and_reset_file(log_path, state_manager)
                if success:
                    click.echo(f"  {style_success('✓')} {message}")
                    reset += 1
                else:
                    click.echo(f"  {style_error('✗')} {message}")
                    failed += 1
            else:
                click.echo("  Skipped.")
                failed += 1
        else:
            # Chain is valid - just sync state
            success, message = state_manager.repair_state_for_file(log_path)
            if success:
                click.echo(f"  {style_success('✓')} {message}")
                repaired += 1
            else:
                click.echo(f"  {style_error('✗')} {message}")
                failed += 1

    click.echo()
    total_fixed = repaired + reset
    if failed == 0 and total_fixed > 0:
        msg = f"Repaired {repaired} file(s)"
        if reset > 0:
            msg += f", reset {reset} broken file(s)"
        click.echo(style_success(f"{msg}. Proxy should now start."))
        sys.exit(EXIT_PASSED)
    elif failed > 0:
        click.echo(style_error(f"Failed to repair {failed} file(s). See errors above."))
        sys.exit(EXIT_FAILED)
    else:
        click.echo(style_warning("No files needed repair."))
        sys.exit(EXIT_PASSED)
