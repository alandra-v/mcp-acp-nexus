"""Tests for IntegrityStateManager and related classes."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from mcp_acp.constants import CRASH_BREADCRUMB_FILENAME
from mcp_acp.security.integrity.hash_chain import compute_entry_hash
from mcp_acp.security.integrity.integrity_state import (
    GENESIS_HASH,
    INITIAL_SEQUENCE,
    FileIntegrityState,
    IntegrityStateManager,
    VerificationResult,
)


class TestFileIntegrityState:
    """Tests for FileIntegrityState dataclass."""

    def test_creates_with_all_fields(self) -> None:
        """FileIntegrityState stores all required fields."""
        state = FileIntegrityState(
            last_hash="abc123",
            last_sequence=42,
            last_inode=12345,
            last_dev=67890,
            last_size=1024,
        )

        assert state.last_hash == "abc123"
        assert state.last_sequence == 42
        assert state.last_inode == 12345
        assert state.last_dev == 67890
        assert state.last_size == 1024


class TestVerificationResult:
    """Tests for VerificationResult dataclass."""

    def test_success_result_defaults(self) -> None:
        """Successful result has empty error and warning lists."""
        result = VerificationResult(success=True)

        assert result.success is True
        assert result.errors == []
        assert result.warnings == []

    def test_failure_result_with_errors(self) -> None:
        """Failed result can contain errors."""
        result = VerificationResult(
            success=False,
            errors=["Error 1", "Error 2"],
            warnings=["Warning 1"],
        )

        assert result.success is False
        assert len(result.errors) == 2
        assert len(result.warnings) == 1


class TestIntegrityStateManager:
    """Tests for IntegrityStateManager."""

    @pytest.fixture
    def temp_log_dir(self) -> Path:
        """Create a temporary log directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_dir = Path(tmpdir) / "mcp-acp/proxies/default"
            log_dir.mkdir(parents=True)
            yield log_dir

    @pytest.fixture
    def state_manager(self, temp_log_dir: Path) -> IntegrityStateManager:
        """Create a state manager with temp directory."""
        return IntegrityStateManager(temp_log_dir)

    def test_state_file_path(self, state_manager: IntegrityStateManager, temp_log_dir: Path) -> None:
        """State file path is in log directory."""
        expected = temp_log_dir / ".integrity_state"
        assert state_manager.state_file_path == expected

    def test_get_chain_state_returns_genesis_when_empty(self, state_manager: IntegrityStateManager) -> None:
        """First call to get_chain_state returns GENESIS."""
        prev_hash, sequence = state_manager.get_chain_state("audit/test.jsonl")

        assert prev_hash == GENESIS_HASH
        assert sequence == INITIAL_SEQUENCE

    def test_update_and_get_chain_state(
        self, state_manager: IntegrityStateManager, temp_log_dir: Path
    ) -> None:
        """update_chain_state updates state and get_chain_state retrieves it."""
        # Create a log file for inode tracking
        log_path = temp_log_dir / "audit" / "test.jsonl"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text('{"test": 1}\n')

        # Update state
        state_manager.update_chain_state(
            "audit/test.jsonl",
            entry_hash="hash123",
            sequence=1,
            log_path=log_path,
        )

        # Get state should return updated values
        prev_hash, sequence = state_manager.get_chain_state("audit/test.jsonl")

        assert prev_hash == "hash123"
        assert sequence == 2  # Next sequence

    def test_save_and_load_state(self, state_manager: IntegrityStateManager, temp_log_dir: Path) -> None:
        """State persists across save/load cycle."""
        # Create a log file
        log_path = temp_log_dir / "audit" / "test.jsonl"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text('{"test": 1}\n')

        # Update state
        state_manager.update_chain_state(
            "audit/test.jsonl",
            entry_hash="hash456",
            sequence=5,
            log_path=log_path,
        )

        # Create new state manager and load
        new_manager = IntegrityStateManager(temp_log_dir)
        new_manager.load_state()

        # Should have the same state
        prev_hash, sequence = new_manager.get_chain_state("audit/test.jsonl")
        assert prev_hash == "hash456"
        assert sequence == 6

    def test_load_state_handles_missing_file(self, state_manager: IntegrityStateManager) -> None:
        """load_state works when state file doesn't exist."""
        # Should not raise
        state_manager.load_state()

        # State should be empty (GENESIS)
        prev_hash, sequence = state_manager.get_chain_state("any/file.jsonl")
        assert prev_hash == GENESIS_HASH

    def test_load_state_raises_on_corrupted_json(
        self, state_manager: IntegrityStateManager, temp_log_dir: Path
    ) -> None:
        """load_state raises ValueError on corrupted JSON."""
        state_file = temp_log_dir / ".integrity_state"
        state_file.write_text("not valid json {{{")

        with pytest.raises(ValueError, match="Corrupted state file"):
            state_manager.load_state()

    def test_load_state_raises_on_wrong_version(
        self, state_manager: IntegrityStateManager, temp_log_dir: Path
    ) -> None:
        """load_state raises ValueError on unsupported version."""
        state_file = temp_log_dir / ".integrity_state"
        state_file.write_text(json.dumps({"version": 999, "files": {}}))

        with pytest.raises(ValueError, match="Unsupported state file version"):
            state_manager.load_state()

    def test_save_state_atomic_write(self, state_manager: IntegrityStateManager, temp_log_dir: Path) -> None:
        """save_state writes atomically (no partial writes)."""
        # Create a log file
        log_path = temp_log_dir / "audit" / "test.jsonl"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text('{"test": 1}\n')

        # Update state (triggers save)
        state_manager.update_chain_state(
            "audit/test.jsonl",
            entry_hash="hashABC",
            sequence=10,
            log_path=log_path,
        )

        # State file should exist and be valid JSON
        state_file = temp_log_dir / ".integrity_state"
        assert state_file.exists()

        data = json.loads(state_file.read_text())
        assert data["version"] == 1
        assert "audit/test.jsonl" in data["files"]

    def test_has_state_for_file(self, state_manager: IntegrityStateManager, temp_log_dir: Path) -> None:
        """has_state_for_file returns True after update."""
        log_path = temp_log_dir / "audit" / "test.jsonl"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text('{"test": 1}\n')

        assert state_manager.has_state_for_file("audit/test.jsonl") is False

        state_manager.update_chain_state(
            "audit/test.jsonl",
            entry_hash="hash",
            sequence=1,
            log_path=log_path,
        )

        assert state_manager.has_state_for_file("audit/test.jsonl") is True

    def test_get_all_file_keys(self, state_manager: IntegrityStateManager, temp_log_dir: Path) -> None:
        """get_all_file_keys returns all tracked files."""
        # Create log files
        for name in ["audit/a.jsonl", "audit/b.jsonl", "system/c.jsonl"]:
            log_path = temp_log_dir / name
            log_path.parent.mkdir(parents=True, exist_ok=True)
            log_path.write_text('{"test": 1}\n')
            state_manager.update_chain_state(name, "hash", 1, log_path)

        keys = state_manager.get_all_file_keys()
        assert set(keys) == {"audit/a.jsonl", "audit/b.jsonl", "system/c.jsonl"}


class TestIntegrityStateManagerVerification:
    """Tests for IntegrityStateManager.verify_on_startup()."""

    @pytest.fixture
    def temp_log_dir(self) -> Path:
        """Create a temporary log directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_dir = Path(tmpdir) / "mcp-acp/proxies/default"
            log_dir.mkdir(parents=True)
            yield log_dir

    @pytest.fixture
    def state_manager(self, temp_log_dir: Path) -> IntegrityStateManager:
        """Create a state manager with temp directory."""
        return IntegrityStateManager(temp_log_dir)

    def test_verify_passes_with_no_state(
        self, state_manager: IntegrityStateManager, temp_log_dir: Path
    ) -> None:
        """Verification passes when no state exists (first run)."""
        log_path = temp_log_dir / "audit" / "test.jsonl"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text('{"test": 1}\n')

        result = state_manager.verify_on_startup([log_path])

        assert result.success is True
        assert result.errors == []

    def test_verify_passes_with_valid_state(
        self, state_manager: IntegrityStateManager, temp_log_dir: Path
    ) -> None:
        """Verification passes when file matches stored state."""
        log_path = temp_log_dir / "audit" / "test.jsonl"
        log_path.parent.mkdir(parents=True, exist_ok=True)

        # Build entry and compute real hash
        entry = {
            "time": "2025-01-18T10:00:00.000Z",
            "sequence": 1,
            "prev_hash": "GENESIS",
            "event": "test",
        }
        entry_hash = compute_entry_hash(entry)
        entry["entry_hash"] = entry_hash
        log_path.write_text(json.dumps(entry) + "\n")

        # Store state matching the entry
        state_manager.update_chain_state(
            "audit/test.jsonl",
            entry_hash=entry_hash,
            sequence=1,
            log_path=log_path,
        )

        # Create new manager and verify
        new_manager = IntegrityStateManager(temp_log_dir)
        new_manager.load_state()

        result = new_manager.verify_on_startup([log_path])

        assert result.success is True

    def test_verify_fails_on_missing_file(
        self, state_manager: IntegrityStateManager, temp_log_dir: Path
    ) -> None:
        """Verification fails when file is missing but state exists."""
        log_path = temp_log_dir / "audit" / "test.jsonl"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text('{"test": 1}\n')

        # Store state
        state_manager.update_chain_state(
            "audit/test.jsonl",
            entry_hash="hash",
            sequence=1,
            log_path=log_path,
        )

        # Delete the file
        log_path.unlink()

        # Create new manager and verify
        new_manager = IntegrityStateManager(temp_log_dir)
        new_manager.load_state()

        result = new_manager.verify_on_startup([log_path])

        assert result.success is False
        assert any("missing" in e.lower() for e in result.errors)

    def test_verify_fails_on_file_replacement(
        self, state_manager: IntegrityStateManager, temp_log_dir: Path
    ) -> None:
        """Verification fails when file is replaced (different inode)."""
        log_path = temp_log_dir / "audit" / "test.jsonl"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text('{"original": 1}\n')

        # Store state with original inode
        state_manager.update_chain_state(
            "audit/test.jsonl",
            entry_hash="hash",
            sequence=1,
            log_path=log_path,
        )

        # Guarantee inode mismatch (Linux tmpfs may recycle inodes on unlink+write)
        state_manager._states["audit/test.jsonl"].last_inode += 1
        state_manager.save_state()

        # Replace file (creates new inode)
        log_path.unlink()
        log_path.write_text('{"replacement": 1}\n')

        # Create new manager and verify
        new_manager = IntegrityStateManager(temp_log_dir)
        new_manager.load_state()

        result = new_manager.verify_on_startup([log_path])

        assert result.success is False
        assert any("replaced" in e.lower() or "inode" in e.lower() for e in result.errors)

    def test_verify_fails_on_hash_mismatch(
        self, state_manager: IntegrityStateManager, temp_log_dir: Path
    ) -> None:
        """Verification fails when last entry hash doesn't match state."""
        log_path = temp_log_dir / "audit" / "test.jsonl"
        log_path.parent.mkdir(parents=True, exist_ok=True)

        # Write entry with hash chain fields
        entry = {
            "time": "2025-01-18T10:00:00.000Z",
            "sequence": 1,
            "prev_hash": "GENESIS",
            "event": "test",
            "entry_hash": "wrong_hash",
        }
        log_path.write_text(json.dumps(entry) + "\n")

        # Store state with DIFFERENT hash (simulating tampering)
        stat = log_path.stat()
        state_manager._states["audit/test.jsonl"] = FileIntegrityState(
            last_hash="correct_hash",
            last_sequence=1,
            last_inode=stat.st_ino,
            last_dev=stat.st_dev,
            last_size=stat.st_size,
        )
        state_manager.save_state()

        # Create new manager and verify
        new_manager = IntegrityStateManager(temp_log_dir)
        new_manager.load_state()

        result = new_manager.verify_on_startup([log_path])

        assert result.success is False
        assert any("mismatch" in e.lower() for e in result.errors)

    def test_verify_fails_when_hash_chain_entries_deleted(
        self, state_manager: IntegrityStateManager, temp_log_dir: Path
    ) -> None:
        """Verification fails when state exists but last entry lacks hash chain fields.

        This tests the scenario where an attacker deletes all hash-chained entries,
        leaving only pre-upgrade entries. Since state exists (indicating hash-chained
        entries were previously written), verification should fail.
        """
        log_path = temp_log_dir / "audit" / "test.jsonl"
        log_path.parent.mkdir(parents=True, exist_ok=True)

        # Write entry WITHOUT hash chain fields (simulating pre-upgrade entry)
        entry = {"time": "2025-01-18T10:00:00.000Z", "event": "test"}
        log_path.write_text(json.dumps(entry) + "\n")

        # Store state (indicating hash-chained entries were previously written)
        stat = log_path.stat()
        state_manager._states["audit/test.jsonl"] = FileIntegrityState(
            last_hash="some_hash",
            last_sequence=1,
            last_inode=stat.st_ino,
            last_dev=stat.st_dev,
            last_size=stat.st_size,
        )
        state_manager.save_state()

        # Create new manager and verify
        new_manager = IntegrityStateManager(temp_log_dir)
        new_manager.load_state()

        result = new_manager.verify_on_startup([log_path])

        # Should FAIL because state exists but last entry has no hash chain
        assert result.success is False
        assert any("hash chain protection were deleted" in e.lower() for e in result.errors)

    def test_verify_fails_on_state_ahead_of_log(
        self, state_manager: IntegrityStateManager, temp_log_dir: Path
    ) -> None:
        """Verification fails when state is ahead of log (requires manual repair).

        This simulates the scenario where:
        1. State was saved for sequence N
        2. Process crashed before the log entry was written
        3. Log's last entry is sequence N-1

        Verification should fail and require manual repair via CLI.
        """
        log_path = temp_log_dir / "audit" / "test.jsonl"
        log_path.parent.mkdir(parents=True, exist_ok=True)

        # Write entry with sequence 1 (the "last successfully written" entry)
        entry_1 = {
            "time": "2025-01-18T10:00:00.000Z",
            "sequence": 1,
            "prev_hash": "GENESIS",
            "event": "first_entry",
        }
        entry_1["entry_hash"] = compute_entry_hash(entry_1)
        log_path.write_text(json.dumps(entry_1) + "\n")

        # Store state as if sequence 2 was saved (but entry wasn't written - crash)
        stat = log_path.stat()
        state_manager._states["audit/test.jsonl"] = FileIntegrityState(
            last_hash="hash_for_seq_2_that_never_got_written",
            last_sequence=2,
            last_inode=stat.st_ino,
            last_dev=stat.st_dev,
            last_size=stat.st_size,
        )
        state_manager.save_state()

        # Create new manager and verify - should FAIL (no auto-repair)
        new_manager = IntegrityStateManager(temp_log_dir)
        new_manager.load_state()

        result = new_manager.verify_on_startup([log_path])

        # Should fail - requires manual repair
        assert result.success is False
        assert len(result.errors) == 1
        assert "hash mismatch" in result.errors[0]
        assert "mcp-acp audit repair" in result.errors[0]

    def test_manual_repair_fixes_state_ahead(
        self, state_manager: IntegrityStateManager, temp_log_dir: Path
    ) -> None:
        """Manual repair fixes state-ahead scenario."""
        log_path = temp_log_dir / "audit" / "test.jsonl"
        log_path.parent.mkdir(parents=True, exist_ok=True)

        # Write valid entry
        entry_1 = {
            "time": "2025-01-18T10:00:00.000Z",
            "sequence": 1,
            "prev_hash": "GENESIS",
            "event": "first_entry",
        }
        entry_1["entry_hash"] = compute_entry_hash(entry_1)
        log_path.write_text(json.dumps(entry_1) + "\n")

        # Store state ahead of log
        stat = log_path.stat()
        state_manager._states["audit/test.jsonl"] = FileIntegrityState(
            last_hash="hash_for_seq_2_that_never_got_written",
            last_sequence=2,
            last_inode=stat.st_ino,
            last_dev=stat.st_dev,
            last_size=stat.st_size,
        )
        state_manager.save_state()

        # Manual repair
        success, message = state_manager.repair_state_for_file(log_path)
        assert success is True
        assert "repaired" in message.lower()

        # Verify now passes
        result = state_manager.verify_on_startup([log_path])
        assert result.success is True

        # State matches log
        prev_hash, next_seq = state_manager.get_chain_state("audit/test.jsonl")
        assert prev_hash == entry_1["entry_hash"]
        assert next_seq == 2

    def test_verify_fails_on_genuine_hash_mismatch(
        self, state_manager: IntegrityStateManager, temp_log_dir: Path
    ) -> None:
        """Verification fails when hash mismatch is not a state-ahead scenario.

        This tests that genuine tampering (not a crash recovery scenario) is
        still detected and not incorrectly auto-repaired.
        """
        from mcp_acp.security.integrity.hash_chain import compute_entry_hash

        log_path = temp_log_dir / "audit" / "test.jsonl"
        log_path.parent.mkdir(parents=True, exist_ok=True)

        # Write entry with sequence 5 (simulating mid-log tampering, not crash)
        entry = {
            "time": "2025-01-18T10:00:00.000Z",
            "sequence": 5,
            "prev_hash": "some_prev_hash",
            "event": "tampered_entry",
        }
        entry["entry_hash"] = compute_entry_hash(entry)
        log_path.write_text(json.dumps(entry) + "\n")

        # Store state with same sequence but different hash (tampering scenario)
        stat = log_path.stat()
        state_manager._states["audit/test.jsonl"] = FileIntegrityState(
            last_hash="different_hash_indicating_tampering",
            last_sequence=5,  # Same sequence, different hash = tampering
            last_inode=stat.st_ino,
            last_dev=stat.st_dev,
            last_size=stat.st_size,
        )
        state_manager.save_state()

        # Create new manager and verify - should fail (not auto-repair)
        new_manager = IntegrityStateManager(temp_log_dir)
        new_manager.load_state()

        result = new_manager.verify_on_startup([log_path])

        # Should fail - this is genuine tampering, not recoverable
        assert result.success is False
        assert any("mismatch" in e.lower() for e in result.errors)

    def test_repair_clears_state_for_empty_file(
        self, state_manager: IntegrityStateManager, temp_log_dir: Path
    ) -> None:
        """Repair clears state when file is empty (allows fresh start)."""
        log_path = temp_log_dir / "audit" / "test.jsonl"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text("")  # Empty file

        # Store state (simulating previous hash-chained entries)
        stat = log_path.stat()
        state_manager._states["audit/test.jsonl"] = FileIntegrityState(
            last_hash="some_hash",
            last_sequence=5,
            last_inode=stat.st_ino,
            last_dev=stat.st_dev,
            last_size=stat.st_size,
        )

        # Repair should succeed and clear state
        success, message = state_manager.repair_state_for_file(log_path)
        assert success is True
        assert "cleared" in message.lower()
        assert "audit/test.jsonl" not in state_manager._states

    def test_repair_clears_state_for_file_without_hash_chain(
        self, state_manager: IntegrityStateManager, temp_log_dir: Path
    ) -> None:
        """Repair clears state when file has no hash chain entries."""
        log_path = temp_log_dir / "audit" / "test.jsonl"
        log_path.parent.mkdir(parents=True, exist_ok=True)

        # Write entry without hash chain fields
        entry = {"time": "2025-01-18T10:00:00.000Z", "event": "test"}
        log_path.write_text(json.dumps(entry) + "\n")

        # Store state
        stat = log_path.stat()
        state_manager._states["audit/test.jsonl"] = FileIntegrityState(
            last_hash="some_hash",
            last_sequence=5,
            last_inode=stat.st_ino,
            last_dev=stat.st_dev,
            last_size=stat.st_size,
        )

        # Repair should succeed and clear state
        success, message = state_manager.repair_state_for_file(log_path)
        assert success is True
        assert "cleared" in message.lower()
        assert "audit/test.jsonl" not in state_manager._states

    def test_repair_clears_state_for_missing_file(
        self, state_manager: IntegrityStateManager, temp_log_dir: Path
    ) -> None:
        """Repair clears state when file is missing."""
        log_path = temp_log_dir / "audit" / "missing.jsonl"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        # Don't create the file

        # Store state
        state_manager._states["audit/missing.jsonl"] = FileIntegrityState(
            last_hash="some_hash",
            last_sequence=5,
            last_inode=999,
            last_dev=999,
            last_size=0,
        )

        # Repair should succeed and clear state
        success, message = state_manager.repair_state_for_file(log_path)
        assert success is True
        assert "cleared" in message.lower()
        assert "audit/missing.jsonl" not in state_manager._states


class TestIntegrityStateAutoRepairOnCrash:
    """Tests for auto_repair_on_crash functionality in verify_on_startup()."""

    @pytest.fixture
    def temp_log_dir(self) -> Path:
        """Create a temporary log directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_dir = Path(tmpdir) / "mcp-acp/proxies/default"
            log_dir.mkdir(parents=True)
            yield log_dir

    @pytest.fixture
    def state_manager(self, temp_log_dir: Path) -> IntegrityStateManager:
        """Create a state manager with temp directory."""
        return IntegrityStateManager(temp_log_dir)

    def test_auto_repair_on_crash_with_inode_mismatch(
        self, state_manager: IntegrityStateManager, temp_log_dir: Path
    ) -> None:
        """Auto-repair works when file is recreated after crash."""
        log_path = temp_log_dir / "audit" / "test.jsonl"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text('{"original": 1}\n')

        # Store state with original inode
        state_manager.update_chain_state(
            "audit/test.jsonl",
            entry_hash="hash",
            sequence=1,
            log_path=log_path,
        )

        # Guarantee inode mismatch (Linux tmpfs may recycle inodes on unlink+write)
        state_manager._states["audit/test.jsonl"].last_inode += 1
        state_manager.save_state()

        # Replace file (creates new inode) - simulating crash recovery
        log_path.unlink()
        log_path.write_text("")  # Empty file after crash

        # Create crash breadcrumb to indicate recent crash
        crash_file = temp_log_dir / CRASH_BREADCRUMB_FILENAME
        crash_file.write_text("2025-01-18T10:00:00Z\nfailure_type: audit_failure\n")

        # Create new manager and verify with auto_repair_on_crash=True
        new_manager = IntegrityStateManager(temp_log_dir)
        new_manager.load_state()

        result = new_manager.verify_on_startup([log_path], auto_repair_on_crash=True)

        # Should succeed after auto-repair
        assert result.success is True
        # Should have warnings about auto-repair
        assert any("auto-repair" in w.lower() for w in result.warnings)
        # Crash file should be preserved (needed for incidents page)
        assert crash_file.exists()

    def test_auto_repair_on_crash_with_missing_file(
        self, state_manager: IntegrityStateManager, temp_log_dir: Path
    ) -> None:
        """Auto-repair works when file is missing after crash."""
        log_path = temp_log_dir / "audit" / "test.jsonl"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text('{"test": 1}\n')

        # Store state
        state_manager.update_chain_state(
            "audit/test.jsonl",
            entry_hash="hash",
            sequence=1,
            log_path=log_path,
        )

        # Delete file - simulating it was deleted before crash
        log_path.unlink()

        # Create crash breadcrumb
        crash_file = temp_log_dir / CRASH_BREADCRUMB_FILENAME
        crash_file.write_text("2025-01-18T10:00:00Z\nfailure_type: audit_failure\n")

        # Create new manager and verify with auto_repair_on_crash=True
        new_manager = IntegrityStateManager(temp_log_dir)
        new_manager.load_state()

        result = new_manager.verify_on_startup([log_path], auto_repair_on_crash=True)

        # Should succeed after auto-repair
        assert result.success is True
        # Should have warnings about auto-repair
        assert any("auto-repair" in w.lower() for w in result.warnings)
        # State should be cleared for the missing file
        assert not new_manager.has_state_for_file("audit/test.jsonl")

    def test_auto_repair_disabled_by_default(
        self, state_manager: IntegrityStateManager, temp_log_dir: Path
    ) -> None:
        """Auto-repair is disabled by default (requires explicit opt-in)."""
        log_path = temp_log_dir / "audit" / "test.jsonl"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text('{"original": 1}\n')

        # Store state with original inode
        state_manager.update_chain_state(
            "audit/test.jsonl",
            entry_hash="hash",
            sequence=1,
            log_path=log_path,
        )

        # Guarantee inode mismatch (Linux tmpfs may recycle inodes on unlink+write)
        state_manager._states["audit/test.jsonl"].last_inode += 1
        state_manager.save_state()

        # Replace file (creates new inode)
        log_path.unlink()
        log_path.write_text("")

        # Create crash breadcrumb
        crash_file = temp_log_dir / CRASH_BREADCRUMB_FILENAME
        crash_file.write_text("2025-01-18T10:00:00Z\nfailure_type: audit_failure\n")

        # Create new manager and verify WITHOUT auto_repair_on_crash
        new_manager = IntegrityStateManager(temp_log_dir)
        new_manager.load_state()

        result = new_manager.verify_on_startup([log_path])  # auto_repair_on_crash=False by default

        # Should fail (no auto-repair)
        assert result.success is False
        assert any("replaced or recreated" in e.lower() for e in result.errors)
        # Crash file should still exist
        assert crash_file.exists()

    def test_auto_repair_requires_crash_breadcrumb(
        self, state_manager: IntegrityStateManager, temp_log_dir: Path
    ) -> None:
        """Auto-repair only happens if crash breadcrumb exists."""
        log_path = temp_log_dir / "audit" / "test.jsonl"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text('{"original": 1}\n')

        # Store state with original inode
        state_manager.update_chain_state(
            "audit/test.jsonl",
            entry_hash="hash",
            sequence=1,
            log_path=log_path,
        )

        # Guarantee inode mismatch (Linux tmpfs may recycle inodes on unlink+write)
        state_manager._states["audit/test.jsonl"].last_inode += 1
        state_manager.save_state()

        # Replace file (creates new inode)
        log_path.unlink()
        log_path.write_text("")

        # NO crash breadcrumb (could be tampering, not crash)

        # Create new manager and verify with auto_repair_on_crash=True
        new_manager = IntegrityStateManager(temp_log_dir)
        new_manager.load_state()

        result = new_manager.verify_on_startup([log_path], auto_repair_on_crash=True)

        # Should fail (no crash evidence, might be tampering)
        assert result.success is False
        assert any("replaced or recreated" in e.lower() for e in result.errors)

    def test_auto_repair_blocked_when_other_errors_present(
        self, state_manager: IntegrityStateManager, temp_log_dir: Path
    ) -> None:
        """Auto-repair is blocked when there are non-repairable errors."""
        log_path_1 = temp_log_dir / "audit" / "test1.jsonl"
        log_path_2 = temp_log_dir / "audit" / "test2.jsonl"
        log_path_1.parent.mkdir(parents=True, exist_ok=True)

        # File 1: Will have inode mismatch (repairable)
        log_path_1.write_text('{"original": 1}\n')
        state_manager.update_chain_state(
            "audit/test1.jsonl", entry_hash="hash1", sequence=1, log_path=log_path_1
        )
        log_path_1.unlink()
        log_path_1.write_text("")  # Recreated with new inode

        # File 2: Will have genuine tampering (non-repairable)
        entry = {
            "time": "2025-01-18T10:00:00.000Z",
            "sequence": 5,
            "prev_hash": "some_prev_hash",
            "event": "test",
        }
        entry["entry_hash"] = compute_entry_hash(entry)
        log_path_2.write_text(json.dumps(entry) + "\n")
        stat = log_path_2.stat()
        state_manager._states["audit/test2.jsonl"] = FileIntegrityState(
            last_hash="wrong_hash_indicating_tampering",
            last_sequence=5,
            last_inode=stat.st_ino,
            last_dev=stat.st_dev,
            last_size=stat.st_size,
        )
        state_manager.save_state()

        # Create crash breadcrumb
        crash_file = temp_log_dir / CRASH_BREADCRUMB_FILENAME
        crash_file.write_text("2025-01-18T10:00:00Z\nfailure_type: audit_failure\n")

        # Create new manager and verify
        new_manager = IntegrityStateManager(temp_log_dir)
        new_manager.load_state()

        result = new_manager.verify_on_startup([log_path_1, log_path_2], auto_repair_on_crash=True)

        # Should fail - don't auto-repair when tampering is also present
        assert result.success is False
        # Should have errors for both files
        assert len(result.errors) >= 2
        # Crash file should still exist (we didn't recover)
        assert crash_file.exists()
