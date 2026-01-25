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
from mcp_acp.utils.config import (
    get_audit_log_path,
    get_auth_log_path,
    get_config_history_path,
    get_decisions_log_path,
    get_log_dir,
    get_policy_history_path,
    get_system_log_path,
)

from ..styling import style_error, style_label, style_success, style_warning

# Exit codes as per plan
EXIT_PASSED = 0
EXIT_FAILED = 1  # Tampering detected
EXIT_UNABLE = 2  # Unable to verify (missing files, etc.)

# Log files that are protected by hash chains
AUDIT_LOG_FILES = {
    "operations": ("Operations audit", get_audit_log_path),
    "decisions": ("Policy decisions", get_decisions_log_path),
    "auth": ("Authentication events", get_auth_log_path),
    "system": ("System logs", get_system_log_path),
    "config-history": ("Config change history", get_config_history_path),
    "policy-history": ("Policy change history", get_policy_history_path),
}


def _verify_single_file(
    log_path: Path,
    log_name: str,
) -> tuple[bool, list[str]]:
    """Verify a single log file's hash chain.

    Args:
        log_path: Path to the log file.
        log_name: Human-readable name for the log.

    Returns:
        Tuple of (success, error_messages).
    """
    errors: list[str] = []

    if not log_path.exists():
        return True, []  # File doesn't exist yet - not an error

    # Read all lines from the file
    try:
        with log_path.open(encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
    except OSError as e:
        errors.append(f"Failed to read {log_name}: {e}")
        return False, errors

    if not lines:
        click.echo(f"  {log_name}: empty (no entries to verify)")
        return True, []

    # Count entries with and without hash chain fields
    entries_with_chain = 0
    entries_without_chain = 0

    for line in lines:
        try:
            entry = json.loads(line)
            # Check same fields as verify_chain_from_lines uses
            if "sequence" in entry and "entry_hash" in entry:
                entries_with_chain += 1
            else:
                entries_without_chain += 1
        except (json.JSONDecodeError, TypeError):
            entries_without_chain += 1

    if entries_with_chain == 0:
        click.echo(f"  {log_name}: {len(lines)} entries (legacy format, no hash chain)")
        return True, []  # No chain entries - legacy format, skip verification

    # Verify chain integrity
    result = verify_chain_from_lines(lines)

    if result.success:
        msg = f"  {log_name}: {entries_with_chain} chain entries"
        if entries_without_chain > 0:
            msg += f" + {entries_without_chain} legacy entries"
        msg += " - " + style_success("PASSED")
        click.echo(msg)
        return True, []
    else:
        errors.extend(result.errors)
        click.echo(f"  {log_name}: " + style_error("FAILED"))
        for err in result.errors:
            click.echo(f"    - {err}")
        return False, errors


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
    """Verify audit log hash chain integrity.

    Without --proxy, verifies ALL proxies.
    With --proxy, verifies only the specified proxy.

    Checks that log entries haven't been tampered with, deleted,
    or reordered. Uses cryptographic hash chains for verification.

    Exit codes:
      0 - All checks passed
      1 - Tampering detected (hash chain broken)
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

    total_passed = 0
    total_failed = 0
    total_skipped = 0

    for pname in proxies_to_verify:
        if len(proxies_to_verify) > 1:
            click.echo(f"Proxy: {pname}")

        for file_key, (description, path_fn) in files_to_verify:
            log_path = path_fn(pname, log_dir_str)

            if not log_path.exists():
                click.echo(f"  {description}: " + style_warning("not found (skipped)"))
                total_skipped += 1
                continue

            success, _errors = _verify_single_file(log_path, description)

            if success:
                total_passed += 1
            else:
                total_failed += 1

        if len(proxies_to_verify) > 1:
            click.echo()

    # Summary
    click.echo()
    if total_failed == 0:
        if total_passed == 0:
            click.echo(style_warning("No log files found to verify."))
            click.echo("Run the proxy to generate audit logs.")
            sys.exit(EXIT_UNABLE)
        else:
            click.echo(style_success(f"All {total_passed} verified files passed integrity check."))
            if total_skipped > 0:
                click.echo(f"({total_skipped} files not yet created)")
            sys.exit(EXIT_PASSED)
    else:
        click.echo(style_error(f"INTEGRITY CHECK FAILED: {total_failed} file(s) have issues"))
        click.echo()
        click.echo("Run 'mcp-acp audit repair --proxy <name>' to fix.")
        sys.exit(EXIT_FAILED)


@audit.command("status")
@click.option(
    "--proxy",
    "-p",
    "proxy_name",
    help="Proxy name (optional - shows all proxies if not specified)",
)
def status(proxy_name: str | None) -> None:
    """Show audit log hash chain status.

    Without --proxy, shows status for ALL proxies.
    With --proxy, shows detailed status for a specific proxy.

    Displays which log files have hash chain protection enabled
    and their current state.
    """
    proxy_name = validate_proxy_if_provided(proxy_name)
    manager_config = load_manager_config_or_exit()
    log_dir_str = manager_config.log_dir

    click.echo()
    click.echo(style_label("Audit Log Hash Chain Status"))
    click.echo()

    # Determine which proxies to show
    if proxy_name:
        proxies_to_show = [proxy_name]
    else:
        proxies_to_show = list_configured_proxies()
        if not proxies_to_show:
            click.echo(style_warning("No proxies configured."))
            click.echo("Run 'mcp-acp proxy add' to create one.")
            return

    for pname in proxies_to_show:
        _show_proxy_audit_status(pname, log_dir_str)


def _show_proxy_audit_status(proxy_name: str, log_dir_str: str) -> None:
    """Show audit status for a single proxy."""
    log_dir_path = get_log_dir(proxy_name, log_dir_str)

    click.echo(f"Proxy: {proxy_name}")

    # Check for state file (log_dir_path already includes mcp-acp/proxies/<name>)
    state_file = log_dir_path / IntegrityStateManager.STATE_FILE_NAME
    if state_file.exists():
        click.echo(f"  State file: {style_success('present')}")
    else:
        click.echo(f"  State file: {style_warning('not found')}")

    click.echo("  Log files:")

    for file_key, (description, path_fn) in AUDIT_LOG_FILES.items():
        log_path = path_fn(proxy_name, log_dir_str)

        if not log_path.exists():
            status_str = style_warning("not created")
            info = ""
        else:
            # Check if file has hash chain entries and verify integrity
            try:
                with log_path.open(encoding="utf-8") as f:
                    lines = [line.strip() for line in f if line.strip()]

                if not lines:
                    status_str = style_warning("empty")
                    info = "0 entries"
                else:
                    # Check last entry for hash chain fields
                    last_entry = json.loads(lines[-1])
                    if "sequence" in last_entry and "entry_hash" in last_entry:
                        # Has hash chain - verify integrity
                        result = verify_chain_from_lines(lines)
                        if result.success:
                            status_str = style_success("protected")
                            info = f"{len(lines)} entries, seq #{last_entry.get('sequence', '?')}"
                        else:
                            status_str = style_error("BROKEN")
                            info = f"{len(lines)} entries - chain integrity failed"
                    else:
                        status_str = style_warning("legacy format")
                        info = f"{len(lines)} entries (no hash chain)"
            except (json.JSONDecodeError, OSError):
                status_str = style_error("error reading")
                info = ""

        click.echo(f"    {file_key:15} - {status_str}")
        if info:
            click.echo(f"                       {info}")

    click.echo()


def _check_chain_integrity(log_path: Path) -> tuple[bool, list[str]]:
    """Check if a log file's hash chain is internally consistent.

    Args:
        log_path: Path to the log file to verify.

    Returns:
        Tuple of (is_valid, error_messages). Returns (True, []) for empty
        files or legacy files without hash chain entries.
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
                return True, []  # Legacy format, no chain to verify
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
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
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
    help="Skip confirmation prompt",
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
    offers to backup the broken file and create a fresh one.
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

    for file_key, (description, path_fn) in files_to_repair:
        log_path = path_fn(proxy_name, log_dir_str)

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

            if yes or click.confirm(f"  Backup {log_path.name} and create fresh file?"):
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
