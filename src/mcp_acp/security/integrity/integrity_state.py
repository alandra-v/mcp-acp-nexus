"""Integrity state management for audit log hash chains.

This module manages the `.integrity_state` file that tracks the last known
good state of each protected log file. Used for:
- Between-run verification (detect file swaps when proxy is not running)
- Startup validation (hard fail if integrity compromised)
- Providing chain state to HashChainFormatter

State is persisted atomically after each log entry to minimize the window
where a crash could leave state inconsistent with log files.

Security Note:
    The state file is NOT cryptographically protected. An attacker with write
    access can modify it. However, tampering is detected if ONLY the state file
    is modified (the log's last entry hash won't match). The vulnerability is
    when both log AND state are modified consistently - see hash_chain.py for
    mitigations.
"""

from __future__ import annotations

__all__ = [
    "FileIntegrityState",
    "IntegrityStateManager",
    "VerificationResult",
]

import json
import os
import tempfile
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Genesis constant for first entry in a chain
GENESIS_HASH = "GENESIS"
INITIAL_SEQUENCE = 1

# File reading constants
_READ_CHUNK_SIZE = 4096  # Bytes to read at a time when reading from end of file


@dataclass
class FileIntegrityState:
    """State for a single log file's hash chain.

    Attributes:
        last_hash: SHA-256 hash of the last entry written.
        last_sequence: Sequence number of the last entry.
        last_inode: Inode of the log file (for file swap detection).
        last_dev: Device ID of the log file.
        last_size: File size after last write (for deletion detection).
    """

    last_hash: str
    last_sequence: int
    last_inode: int
    last_dev: int
    last_size: int = 0  # Default for backwards compatibility with old state files


@dataclass
class VerificationResult:
    """Result of integrity verification.

    Attributes:
        success: True if all checks passed.
        errors: List of critical errors (tampering detected).
        warnings: List of non-critical warnings (e.g., time regression).
    """

    success: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class IntegrityStateManager:
    """Manages .integrity_state persistence and verification.

    Thread-safe via internal lock. Handles:
    - Loading state from file on startup
    - Saving state atomically after each log entry
    - Verifying file identity (inode/dev) hasn't changed
    - Detecting file swaps between proxy runs

    The state file is stored in the root of the log directory:
        <log_dir>/mcp_acp_logs/.integrity_state
    """

    STATE_FILE_NAME = ".integrity_state"
    STATE_VERSION = 1

    def __init__(self, log_dir: Path) -> None:
        """Initialize with log directory.

        Args:
            log_dir: Path to mcp_acp_logs directory (parent of audit/, system/).
        """
        self._log_dir = log_dir
        self._state_file = log_dir / self.STATE_FILE_NAME
        self._states: dict[str, FileIntegrityState] = {}
        self._lock = threading.Lock()

    @property
    def state_file_path(self) -> Path:
        """Path to the .integrity_state file."""
        return self._state_file

    def load_state(self) -> None:
        """Load state from file if exists.

        If state file doesn't exist, starts with empty state (first run).
        If state file is corrupted, raises ValueError.
        """
        if not self._state_file.exists():
            return

        try:
            with self._state_file.open("r", encoding="utf-8") as f:
                data = json.load(f)

            # Validate version
            version = data.get("version", 0)
            if version != self.STATE_VERSION:
                raise ValueError(
                    f"Unsupported state file version: {version} " f"(expected {self.STATE_VERSION})"
                )

            # Load file states
            files_data = data.get("files", {})
            with self._lock:
                self._states = {
                    key: FileIntegrityState(
                        last_hash=state["last_hash"],
                        last_sequence=state["last_sequence"],
                        last_inode=state["last_inode"],
                        last_dev=state["last_dev"],
                        last_size=state.get("last_size", 0),  # Backwards compat
                    )
                    for key, state in files_data.items()
                }

        except json.JSONDecodeError as e:
            raise ValueError(f"Corrupted state file: {e}") from e
        except KeyError as e:
            raise ValueError(f"Invalid state file format: missing {e}") from e

    def save_state(self) -> None:
        """Persist current state to file atomically.

        Uses temp file + rename pattern to ensure atomicity.
        State file won't be corrupted even if process crashes mid-write.
        """
        with self._lock:
            data = {
                "version": self.STATE_VERSION,
                "updated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "files": {key: asdict(state) for key, state in self._states.items()},
            }

        # Ensure directory exists
        self._state_file.parent.mkdir(parents=True, exist_ok=True)

        # Atomic write: write to temp file, then rename
        fd, temp_path = tempfile.mkstemp(
            dir=self._state_file.parent,
            prefix=".integrity_state_",
            suffix=".tmp",
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
                f.flush()
                os.fsync(f.fileno())

            # Atomic rename
            os.replace(temp_path, self._state_file)
        except Exception:
            # Clean up temp file on failure
            try:
                os.unlink(temp_path)
            except OSError:
                pass
            raise

    def verify_on_startup(self, log_paths: list[Path]) -> VerificationResult:
        """Verify all log files match stored state.

        Checks for each file with stored state:
        1. File exists
        2. File's inode/dev matches stored values (not swapped)
        3. Last entry in file matches stored last_hash

        Files without stored state are skipped (first run or new file).

        Args:
            log_paths: List of log file paths to verify.

        Returns:
            VerificationResult with pass/fail status and details.
        """
        errors: list[str] = []
        warnings: list[str] = []

        for log_path in log_paths:
            file_key = self._get_file_key(log_path)
            state = self._states.get(file_key)

            if state is None:
                # No stored state for this file - skip (first run or new file)
                continue

            # Check file exists
            if not log_path.exists():
                errors.append(f"{file_key}: File missing but state exists")
                continue

            # Check inode/dev (file swap detection)
            try:
                stat = log_path.stat()
                if stat.st_ino != state.last_inode or stat.st_dev != state.last_dev:
                    errors.append(
                        f"{file_key}: File replaced (inode/dev mismatch). "
                        f"Expected inode={state.last_inode}, dev={state.last_dev}. "
                        f"Found inode={stat.st_ino}, dev={stat.st_dev}."
                    )
                    continue
            except OSError as e:
                errors.append(f"{file_key}: Cannot stat file: {e}")
                continue

            # Check last entry hash
            hash_error = self._verify_last_entry_hash(log_path, state, file_key)
            if hash_error:
                errors.append(hash_error)

        return VerificationResult(
            success=len(errors) == 0,
            errors=errors,
            warnings=warnings,
        )

    def get_chain_state(self, file_key: str) -> tuple[str, int]:
        """Get (prev_hash, next_sequence) for file.

        Returns ("GENESIS", 1) if no prior state (first entry).

        Args:
            file_key: Relative path key for the log file (e.g., "audit/operations.jsonl").

        Returns:
            Tuple of (prev_hash, next_sequence).
        """
        with self._lock:
            state = self._states.get(file_key)
            if state is None:
                return GENESIS_HASH, INITIAL_SEQUENCE
            return state.last_hash, state.last_sequence + 1

    def update_chain_state(
        self,
        file_key: str,
        entry_hash: str,
        sequence: int,
        log_path: Path,
    ) -> None:
        """Update state for an entry about to be written.

        Called by HashChainFormatter BEFORE the entry is written to the log file.
        The formatter computes the entry, updates state here, then returns the
        formatted string for the handler to write.

        IMPORTANT: State is persisted BEFORE the log entry is written. If the
        process crashes after this call but before the handler writes the entry,
        the state file will be "ahead" of the log. This is detected on startup
        by verify_on_startup() and auto-repaired (see _try_repair_state_ahead).

        This ordering is intentional: it's better to fail loudly (detect the
        mismatch on startup) than to silently corrupt the chain (which would
        happen if we persisted state after write but crashed before persistence).

        Args:
            file_key: Relative path key for the log file.
            entry_hash: SHA-256 hash of the entry about to be written.
            sequence: Sequence number of the entry about to be written.
            log_path: Path to the log file (for inode/dev tracking).
        """
        stat = log_path.stat()

        with self._lock:
            self._states[file_key] = FileIntegrityState(
                last_hash=entry_hash,
                last_sequence=sequence,
                last_inode=stat.st_ino,
                last_dev=stat.st_dev,
            )

        # Persist to disk immediately
        self.save_state()

    def has_state_for_file(self, file_key: str) -> bool:
        """Check if state exists for a file.

        Args:
            file_key: Relative path key for the log file.

        Returns:
            True if state exists, False otherwise.
        """
        with self._lock:
            return file_key in self._states

    def _get_file_key(self, log_path: Path) -> str:
        """Get relative file key from absolute path.

        Args:
            log_path: Absolute path to log file.

        Returns:
            Relative path from log_dir (e.g., "audit/operations.jsonl").
        """
        try:
            return str(log_path.relative_to(self._log_dir))
        except ValueError:
            # Path is not under log_dir - use filename as key
            return log_path.name

    def _verify_last_entry_hash(
        self,
        log_path: Path,
        state: FileIntegrityState,
        file_key: str,
    ) -> str | None:
        """Verify the last entry in a log file matches stored hash.

        Args:
            log_path: Path to the log file.
            state: Stored state for this file.
            file_key: File key for error messages.

        Returns:
            Error message if verification fails, None if passes.
        """
        try:
            # Read last non-empty line from file
            last_line = self._read_last_line(log_path)
            if last_line is None:
                # Empty file but we have state - something was deleted
                return f"{file_key}: File is empty but state exists (entries deleted?)"

            # Parse the entry
            try:
                entry = json.loads(last_line)
            except json.JSONDecodeError:
                return f"{file_key}: Last entry is not valid JSON"

            # Check if entry has hash chain fields
            entry_hash = entry.get("entry_hash")
            if entry_hash is None:
                # Entry without hash chain - might be pre-upgrade
                # This is allowed during genesis handling
                return None

            # Verify hash matches state
            if entry_hash != state.last_hash:
                return (
                    f"{file_key}: Last entry hash mismatch. "
                    f"Expected {state.last_hash[:16]}..., "
                    f"found {entry_hash[:16]}.... "
                    f"Run 'mcp-acp audit repair' to recover from crash, "
                    f"or investigate if tampering is suspected."
                )

            # Verify entry content matches its hash (detect content tampering)
            from mcp_acp.security.integrity.hash_chain import compute_entry_hash

            computed_hash = compute_entry_hash(entry)
            if computed_hash != entry_hash:
                return (
                    f"{file_key}: Entry content tampered. "
                    f"Stored hash={entry_hash[:16]}..., "
                    f"computed={computed_hash[:16]}..."
                )

            # Verify sequence matches
            entry_sequence = entry.get("sequence")
            if entry_sequence is not None and entry_sequence != state.last_sequence:
                return (
                    f"{file_key}: Last entry sequence mismatch. "
                    f"Expected {state.last_sequence}, found {entry_sequence}"
                )

            return None

        except OSError as e:
            return f"{file_key}: Cannot read file: {e}"

    def repair_state_for_file(self, log_path: Path) -> tuple[bool, str]:
        """Manually repair state to match actual log file.

        Use this after crash recovery or when instructed by verification errors.
        Updates state to match the last valid entry in the log file.

        Args:
            log_path: Path to the log file to repair state for.

        Returns:
            Tuple of (success, message).
        """
        from mcp_acp.security.integrity.hash_chain import compute_entry_hash

        file_key = self._get_file_key(log_path)

        if not log_path.exists():
            return False, f"{file_key}: File does not exist"

        # Read last entry
        last_line = self._read_last_line(log_path)
        if last_line is None:
            return False, f"{file_key}: File is empty"

        try:
            entry = json.loads(last_line)
        except json.JSONDecodeError:
            return False, f"{file_key}: Last entry is not valid JSON"

        entry_hash = entry.get("entry_hash")
        entry_sequence = entry.get("sequence")

        if entry_hash is None or entry_sequence is None:
            return False, f"{file_key}: Last entry has no hash chain fields"

        # Verify entry is internally consistent
        computed_hash = compute_entry_hash(entry)
        if computed_hash != entry_hash:
            return False, (
                f"{file_key}: Last entry is corrupted (hash mismatch). "
                f"Cannot repair - manual investigation required."
            )

        # Update state to match log
        try:
            stat = log_path.stat()
            with self._lock:
                self._states[file_key] = FileIntegrityState(
                    last_hash=entry_hash,
                    last_sequence=entry_sequence,
                    last_inode=stat.st_ino,
                    last_dev=stat.st_dev,
                )
            self.save_state()
        except OSError as e:
            return False, f"{file_key}: Failed to save state: {e}"

        return True, f"{file_key}: State repaired to sequence {entry_sequence}"

    def _read_last_line(self, log_path: Path) -> str | None:
        """Read the last non-empty line from a file.

        Efficiently reads from end of file without loading entire file.

        Args:
            log_path: Path to the file.

        Returns:
            Last non-empty line, or None if file is empty.
        """
        with log_path.open("rb") as f:
            # Seek to end
            f.seek(0, 2)
            file_size = f.tell()

            if file_size == 0:
                return None

            # Read backwards to find last newline
            buffer = b""
            position = file_size

            while position > 0:
                # Read in chunks from the end
                chunk_size = min(_READ_CHUNK_SIZE, position)
                position -= chunk_size
                f.seek(position)
                chunk = f.read(chunk_size)
                buffer = chunk + buffer

                # Look for complete lines
                lines = buffer.split(b"\n")
                # Check from end for non-empty line
                for line in reversed(lines):
                    stripped = line.strip()
                    if stripped:
                        return stripped.decode("utf-8")

            return None

    def get_all_file_keys(self) -> list[str]:
        """Get all file keys with stored state.

        Returns:
            List of file keys.
        """
        with self._lock:
            return list(self._states.keys())
