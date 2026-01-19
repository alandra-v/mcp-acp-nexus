"""Audit command group for mcp-acp CLI.

Provides audit log management commands including hash chain verification.
"""

from __future__ import annotations

__all__ = ["audit"]

import json
import sys
from pathlib import Path

import click

from mcp_acp.config import AppConfig
from mcp_acp.security.integrity import IntegrityStateManager
from mcp_acp.security.integrity.hash_chain import verify_chain_from_lines
from mcp_acp.utils.cli import load_config_or_exit
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
    verbose: bool,
) -> tuple[bool, list[str]]:
    """Verify a single log file's hash chain.

    Args:
        log_path: Path to the log file
        log_name: Human-readable name for the log
        verbose: Whether to print verbose output

    Returns:
        Tuple of (success, error_messages)
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
        if verbose:
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
        if verbose:
            click.echo(f"  {log_name}: {len(lines)} entries (no hash chain fields - legacy format)")
        return True, []  # No chain entries - legacy format, skip verification

    # Verify chain integrity
    result = verify_chain_from_lines(lines)

    if result.success:
        if verbose:
            msg = f"  {log_name}: {entries_with_chain} chain entries"
            if entries_without_chain > 0:
                msg += f" + {entries_without_chain} legacy entries"
            msg += " - " + style_success("PASSED")
            click.echo(msg)
        return True, []
    else:
        errors.extend(result.errors)
        if verbose:
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
    "--file",
    "-f",
    "log_file",
    type=click.Choice(list(AUDIT_LOG_FILES.keys()) + ["all"]),
    default="all",
    help="Log file to verify (default: all)",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Show detailed verification output",
)
def verify(log_file: str, verbose: bool) -> None:
    """Verify audit log hash chain integrity.

    Checks that log entries haven't been tampered with, deleted,
    or reordered. Uses cryptographic hash chains for verification.

    Exit codes:
      0 - All checks passed
      1 - Tampering detected (hash chain broken)
      2 - Unable to verify (missing files, read errors)
    """
    config = load_config_or_exit()

    click.echo()
    click.echo(style_label("Audit Log Integrity Verification"))
    click.echo()

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
    all_errors: list[str] = []

    for file_key, (description, path_fn) in files_to_verify:
        log_path = path_fn(config)

        if not log_path.exists():
            if verbose:
                click.echo(f"  {description}: " + style_warning("not found (skipped)"))
            total_skipped += 1
            continue

        success, errors = _verify_single_file(log_path, description, verbose)

        if success:
            total_passed += 1
        else:
            total_failed += 1
            all_errors.extend(errors)

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
        click.echo("Possible causes:")
        click.echo("  - Log entries were manually edited")
        click.echo("  - Log entries were deleted")
        click.echo("  - Log file was replaced")
        click.echo()
        click.echo("This may indicate tampering. Review the errors above.")
        sys.exit(EXIT_FAILED)


@audit.command("status")
def status() -> None:
    """Show audit log hash chain status.

    Displays which log files have hash chain protection enabled
    and their current state.
    """
    config = load_config_or_exit()
    log_dir = get_log_dir(config)

    click.echo()
    click.echo(style_label("Audit Log Hash Chain Status"))
    click.echo()

    # Check for state file (log_dir already includes mcp_acp_logs)
    state_file = log_dir / IntegrityStateManager.STATE_FILE_NAME
    if state_file.exists():
        click.echo(f"State file: {style_success('present')}")
        click.echo(f"  {state_file}")
    else:
        click.echo(f"State file: {style_warning('not found')}")
        click.echo("  Hash chain state will be created on first proxy run.")

    click.echo()
    click.echo("Log files:")

    for file_key, (description, path_fn) in AUDIT_LOG_FILES.items():
        log_path = path_fn(config)

        if not log_path.exists():
            status_str = style_warning("not created")
            info = ""
        else:
            # Check if file has hash chain entries
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
                        status_str = style_success("protected")
                        info = f"{len(lines)} entries, seq #{last_entry.get('sequence', '?')}"
                    else:
                        status_str = style_warning("legacy format")
                        info = f"{len(lines)} entries (no hash chain)"
            except (json.JSONDecodeError, OSError):
                status_str = style_error("error reading")
                info = ""

        click.echo(f"  {file_key:15} - {status_str}")
        if info:
            click.echo(f"                   {info}")

    click.echo()


@audit.command("repair")
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
def repair(log_file: str, yes: bool) -> None:
    """Repair integrity state after crash or verification failure.

    Updates the .integrity_state file to match the actual log files.
    Use this when:
    - Proxy crashed during a write operation
    - Verification fails with "hash mismatch" errors
    - You've investigated and confirmed logs are not tampered

    WARNING: This command trusts the current log file contents.
    Only use after confirming the logs have not been tampered with.
    """
    config = load_config_or_exit()
    log_dir = get_log_dir(config)

    click.echo()
    click.echo(style_label("Audit Log State Repair"))
    click.echo()

    if log_file == "all":
        files_to_repair = list(AUDIT_LOG_FILES.items())
    else:
        files_to_repair = [(log_file, AUDIT_LOG_FILES[log_file])]

    # Show what will be repaired
    click.echo("Files to repair:")
    for file_key, (description, path_fn) in files_to_repair:
        log_path = path_fn(config)
        if log_path.exists():
            click.echo(f"  - {description} ({file_key})")

    click.echo()
    click.echo(style_warning("WARNING: This trusts the current log file contents."))
    click.echo("Only proceed if you've confirmed the logs have not been tampered with.")
    click.echo()

    if not yes:
        if not click.confirm("Proceed with repair?"):
            click.echo("Aborted.")
            sys.exit(EXIT_UNABLE)

    # Load state manager
    state_manager = IntegrityStateManager(log_dir)
    state_manager.load_state()

    repaired = 0
    failed = 0

    for file_key, (description, path_fn) in files_to_repair:
        log_path = path_fn(config)

        if not log_path.exists():
            continue

        success, message = state_manager.repair_state_for_file(log_path)

        if success:
            click.echo(f"  {style_success('✓')} {message}")
            repaired += 1
        else:
            click.echo(f"  {style_error('✗')} {message}")
            failed += 1

    click.echo()
    if failed == 0 and repaired > 0:
        click.echo(style_success(f"Repaired {repaired} file(s). Proxy should now start."))
        sys.exit(EXIT_PASSED)
    elif failed > 0:
        click.echo(style_error(f"Failed to repair {failed} file(s). See errors above."))
        sys.exit(EXIT_FAILED)
    else:
        click.echo(style_warning("No files needed repair."))
        sys.exit(EXIT_PASSED)
