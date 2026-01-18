"""Hash chain formatter for tamper-evident audit logging.

This module provides a logging formatter that adds hash chain fields to each
log entry, enabling detection of:
- Deleted entries (chain breaks)
- Inserted entries (hash mismatch)
- Reordered entries (hash mismatch)
- Modified entries (hash mismatch)

Each entry contains:
- sequence: Monotonically increasing per-file
- prev_hash: SHA-256 hash of previous entry (or "GENESIS" for first)
- entry_hash: SHA-256 hash of this entry (for next entry to reference)

Verification functions:
- verify_chain_integrity(path): Read file and verify, returns tuple
- verify_chain_from_lines(lines): Verify pre-read lines, returns VerificationResult

Security Limitations:
    This is a self-attesting system with NO external attestation. An attacker
    with write access to both log files AND the .integrity_state file can:
    1. Truncate logs (remove entries from end)
    2. Update state file to match the new last entry
    This would be undetected by the hash chain verification.

    Mitigations for high-security environments:
    - Forward logs to remote syslog server (attacker can't modify remote copy)
    - Use append-only filesystem attributes (chattr +a on Linux)
    - Regular external backups of logs to immutable storage
    - Monitor for unexpected log file size decreases
"""

from __future__ import annotations

__all__ = [
    "HashChainFormatter",
    "compute_entry_hash",
    "verify_chain_integrity",
    "verify_chain_from_lines",
]

import hashlib
import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from mcp_acp.security.integrity.integrity_state import VerificationResult

# Display constants
_HASH_DISPLAY_LENGTH = 16  # Characters to show when truncating hashes in error messages

if TYPE_CHECKING:
    from mcp_acp.security.integrity.integrity_state import IntegrityStateManager


def compute_entry_hash(entry: dict[str, Any]) -> str:
    """Compute SHA-256 hash of a log entry.

    The hash is computed over the entire entry EXCEPT the entry_hash field,
    using deterministic JSON serialization (sorted keys, no extra whitespace).

    Args:
        entry: Log entry dictionary.

    Returns:
        SHA-256 hash as hexadecimal string (64 characters).
    """
    # Create a copy without entry_hash for hashing
    entry_for_hash = {k: v for k, v in entry.items() if k != "entry_hash"}

    # Deterministic serialization
    json_str = json.dumps(entry_for_hash, sort_keys=True, separators=(",", ":"))

    return hashlib.sha256(json_str.encode("utf-8")).hexdigest()


class HashChainFormatter(logging.Formatter):
    """Formatter that adds hash chain fields to log entries.

    Extends standard logging formatter to add:
    - time: ISO 8601 timestamp (UTC)
    - sequence: Monotonically increasing entry number
    - prev_hash: SHA-256 hash of previous entry (or "GENESIS")
    - entry_hash: SHA-256 hash of current entry

    Thread-safe via lock for hash chain state updates.

    Usage:
        state_manager = IntegrityStateManager(log_dir)
        formatter = HashChainFormatter(state_manager, "audit/operations.jsonl", log_path)
        handler.setFormatter(formatter)
    """

    def __init__(
        self,
        state_manager: "IntegrityStateManager",
        log_file_key: str,
        log_path: Path,
    ) -> None:
        """Initialize formatter with state manager.

        Args:
            state_manager: Manages chain state persistence.
            log_file_key: Relative path key for this log file (e.g., "audit/operations.jsonl").
            log_path: Absolute path to the log file.
        """
        super().__init__()
        self._state_manager = state_manager
        self._log_file_key = log_file_key
        self._log_path = log_path
        self._lock = threading.Lock()

    def format(self, record: logging.LogRecord) -> str:
        """Format record with hash chain fields.

        Process:
        1. Create ISO 8601 timestamp
        2. Get next sequence number and prev_hash from state
        3. Build entry dict with chain fields
        4. Compute entry_hash (excluding entry_hash field)
        5. Add entry_hash to dict
        6. Update state (new hash, new sequence)
        7. Return JSON string

        Args:
            record: The log record to format.

        Returns:
            JSON-formatted log entry with hash chain fields.
        """
        with self._lock:
            # Create ISO 8601 timestamp with milliseconds in UTC
            timestamp = (
                datetime.fromtimestamp(record.created, tz=timezone.utc)
                .isoformat(timespec="milliseconds")
                .replace("+00:00", "Z")
            )

            # Get chain state
            prev_hash, sequence = self._state_manager.get_chain_state(
                self._log_file_key
            )

            # Handle dict messages (structured logging)
            if isinstance(record.msg, dict):
                log_data = record.msg
            # Handle JSON string messages (backwards compatibility)
            elif isinstance(record.msg, str) and record.msg.startswith("{"):
                try:
                    log_data = json.loads(record.msg)
                except json.JSONDecodeError:
                    log_data = {"message": record.msg}
            # Handle plain string/other messages
            else:
                log_data = {"message": str(record.msg)}

            # Build entry with chain fields
            # Order: time, sequence, prev_hash, then event data, then entry_hash
            log_entry: dict[str, Any] = {
                "time": timestamp,
                "sequence": sequence,
                "prev_hash": prev_hash,
                **log_data,
            }

            # Compute entry hash (before adding entry_hash field)
            entry_hash = compute_entry_hash(log_entry)

            # Add entry_hash
            log_entry["entry_hash"] = entry_hash

            # Update state manager
            self._state_manager.update_chain_state(
                self._log_file_key,
                entry_hash,
                sequence,
                self._log_path,
            )

            return json.dumps(log_entry)


def verify_chain_integrity(
    log_path: Path,
    limit: int | None = None,
) -> tuple[bool, list[str], list[str]]:
    """Verify hash chain integrity of a log file by reading from path.

    Use this when you have a file path and want simple tuple return values.
    For pre-read lines or when you need a VerificationResult object,
    use verify_chain_from_lines() instead.

    Verifies:
    - Each entry's prev_hash matches the previous entry's entry_hash
    - Sequence numbers are monotonically increasing without gaps
    - Timestamps are non-decreasing (warning if regression)

    Entries without hash chain fields (pre-upgrade) are skipped.

    Args:
        log_path: Path to the log file to read and verify.
        limit: Maximum number of entries to verify (None = all).

    Returns:
        Tuple of (success: bool, errors: list[str], warnings: list[str]).
    """
    errors: list[str] = []
    warnings: list[str] = []

    if not log_path.exists():
        errors.append(f"File does not exist: {log_path}")
        return False, errors, warnings

    prev_entry_hash: str | None = None
    prev_sequence: int | None = None
    prev_time: str | None = None
    chain_started = False
    entry_count = 0

    try:
        with log_path.open("r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue

                # Parse entry
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError as e:
                    errors.append(f"Line {line_num}: Invalid JSON: {e}")
                    continue

                # Skip entries without hash chain fields (pre-upgrade)
                if "sequence" not in entry or "entry_hash" not in entry:
                    continue

                chain_started = True
                entry_count += 1

                if limit is not None and entry_count > limit:
                    break

                sequence = entry.get("sequence")
                prev_hash = entry.get("prev_hash")
                entry_hash = entry.get("entry_hash")
                timestamp = entry.get("time")

                # Verify prev_hash matches previous entry's hash
                if prev_entry_hash is not None:
                    if prev_hash is None:
                        errors.append(f"Line {line_num}: Missing prev_hash field")
                    elif prev_hash != prev_entry_hash:
                        errors.append(
                            f"Line {line_num}: Chain break. "
                            f"prev_hash={prev_hash[:_HASH_DISPLAY_LENGTH]}... does not match "
                            f"previous entry_hash={prev_entry_hash[:_HASH_DISPLAY_LENGTH]}..."
                        )
                elif prev_hash is None:
                    errors.append(f"Line {line_num}: Missing prev_hash field")
                elif prev_hash != "GENESIS":
                    errors.append(
                        f"Line {line_num}: First entry should have prev_hash='GENESIS', "
                        f"found '{prev_hash}'"
                    )

                # Verify sequence is monotonic
                if prev_sequence is not None and sequence != prev_sequence + 1:
                    errors.append(
                        f"Line {line_num}: Sequence gap. "
                        f"Expected {prev_sequence + 1}, found {sequence}"
                    )

                # Verify computed hash matches stored hash
                computed_hash = compute_entry_hash(entry)
                if entry_hash is None:
                    errors.append(f"Line {line_num}: Missing entry_hash field")
                elif computed_hash != entry_hash:
                    errors.append(
                        f"Line {line_num}: Entry hash mismatch. "
                        f"Stored={entry_hash[:_HASH_DISPLAY_LENGTH]}..., "
                        f"computed={computed_hash[:_HASH_DISPLAY_LENGTH]}..."
                    )

                # Check time ordering (warning only)
                if prev_time is not None and timestamp is not None and timestamp < prev_time:
                    warnings.append(
                        f"Line {line_num}: Time regression. "
                        f"Current={timestamp}, previous={prev_time}"
                    )

                # Update state for next iteration
                prev_entry_hash = entry_hash
                prev_sequence = sequence
                prev_time = timestamp

    except OSError as e:
        errors.append(f"Cannot read file: {e}")
        return False, errors, warnings

    if not chain_started:
        # No entries with hash chain fields found
        warnings.append("No hash chain entries found (file may be pre-upgrade)")

    return len(errors) == 0, errors, warnings


def verify_chain_from_lines(
    lines: list[str],
    *,
    partial_chain: bool = False,
) -> VerificationResult:
    """Verify hash chain integrity from pre-read lines.

    Use this when you have already read lines from a file (e.g., reading only
    the last N entries for performance) and need a VerificationResult object.
    For verifying directly from a file path with tuple returns, use
    verify_chain_integrity() instead.

    This function is used by:
    - CLI audit verify command (reads file with custom error handling)
    - AuditHealthMonitor (reads only tail of file for efficiency)

    Args:
        lines: List of JSON strings, one per log entry.
        partial_chain: If True, skip GENESIS check for first entry. Use this
            when verifying a subset of entries (e.g., tail of a file) where
            the first entry won't have prev_hash="GENESIS".

    Returns:
        VerificationResult with .success, .errors, and .warnings attributes.
    """
    errors: list[str] = []
    warnings: list[str] = []

    prev_entry_hash: str | None = None
    prev_sequence: int | None = None
    prev_time: str | None = None
    chain_started = False

    for line_num, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            continue

        # Parse entry
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as e:
            errors.append(f"Line {line_num}: Invalid JSON: {e}")
            continue

        # Skip entries without hash chain fields (pre-upgrade)
        if "sequence" not in entry or "entry_hash" not in entry:
            continue

        is_first_chain_entry = not chain_started
        chain_started = True

        sequence = entry.get("sequence")
        prev_hash = entry.get("prev_hash")
        entry_hash = entry.get("entry_hash")
        timestamp = entry.get("time")

        # Verify prev_hash matches previous entry's hash
        if prev_entry_hash is not None:
            if prev_hash is None:
                errors.append(f"Line {line_num}: Missing prev_hash field")
            elif prev_hash != prev_entry_hash:
                errors.append(
                    f"Line {line_num}: Chain break. "
                    f"prev_hash={prev_hash[:_HASH_DISPLAY_LENGTH]}... does not match "
                    f"previous entry_hash={prev_entry_hash[:_HASH_DISPLAY_LENGTH]}..."
                )
        elif prev_hash is None:
            errors.append(f"Line {line_num}: Missing prev_hash field")
        elif not (partial_chain and is_first_chain_entry) and prev_hash != "GENESIS":
            # First entry in full chain should have GENESIS
            # Skip for partial chains (tail verification)
            errors.append(
                f"Line {line_num}: First entry should have prev_hash='GENESIS', "
                f"found '{prev_hash}'"
            )

        # Verify sequence is monotonic
        if prev_sequence is not None and sequence != prev_sequence + 1:
            errors.append(
                f"Line {line_num}: Sequence gap. "
                f"Expected {prev_sequence + 1}, found {sequence}"
            )

        # Verify computed hash matches stored hash
        computed_hash = compute_entry_hash(entry)
        if entry_hash is None:
            errors.append(f"Line {line_num}: Missing entry_hash field")
        elif computed_hash != entry_hash:
            errors.append(
                f"Line {line_num}: Entry hash mismatch. "
                f"Stored={entry_hash[:_HASH_DISPLAY_LENGTH]}..., "
                f"computed={computed_hash[:_HASH_DISPLAY_LENGTH]}..."
            )

        # Check time ordering (warning only)
        if prev_time is not None and timestamp is not None and timestamp < prev_time:
            warnings.append(
                f"Line {line_num}: Time regression. "
                f"Current={timestamp}, previous={prev_time}"
            )

        # Update state for next iteration
        prev_entry_hash = entry_hash
        prev_sequence = sequence
        prev_time = timestamp

    if not chain_started:
        # No entries with hash chain fields found
        warnings.append("No hash chain entries found (file may be pre-upgrade)")

    return VerificationResult(
        success=len(errors) == 0,
        errors=errors,
        warnings=warnings,
    )
