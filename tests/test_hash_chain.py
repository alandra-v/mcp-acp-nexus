"""Tests for HashChainFormatter and hash chain utilities."""

from __future__ import annotations

import json
import logging
import tempfile
import threading
from pathlib import Path

import pytest

from mcp_acp.security.integrity.hash_chain import (
    HashChainFormatter,
    compute_entry_hash,
    verify_chain_integrity,
)
from mcp_acp.security.integrity.integrity_state import IntegrityStateManager


class TestComputeEntryHash:
    """Tests for compute_entry_hash function."""

    def test_returns_64_char_hex_string(self) -> None:
        """Hash is 64-character hex string (SHA-256)."""
        entry = {"time": "2025-01-18T10:00:00.000Z", "event": "test"}
        result = compute_entry_hash(entry)

        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)

    def test_deterministic_same_input(self) -> None:
        """Same input produces same hash."""
        entry = {"time": "2025-01-18T10:00:00.000Z", "event": "test", "value": 42}

        hash1 = compute_entry_hash(entry)
        hash2 = compute_entry_hash(entry)

        assert hash1 == hash2

    def test_different_input_different_hash(self) -> None:
        """Different input produces different hash."""
        entry1 = {"time": "2025-01-18T10:00:00.000Z", "event": "test1"}
        entry2 = {"time": "2025-01-18T10:00:00.000Z", "event": "test2"}

        hash1 = compute_entry_hash(entry1)
        hash2 = compute_entry_hash(entry2)

        assert hash1 != hash2

    def test_ignores_key_order(self) -> None:
        """Hash is independent of key order (sorted serialization)."""
        entry1 = {"a": 1, "b": 2, "c": 3}
        entry2 = {"c": 3, "a": 1, "b": 2}

        hash1 = compute_entry_hash(entry1)
        hash2 = compute_entry_hash(entry2)

        assert hash1 == hash2

    def test_excludes_entry_hash_field(self) -> None:
        """entry_hash field is excluded from hash computation."""
        entry_without = {"time": "2025-01-18T10:00:00.000Z", "event": "test"}
        entry_with = {
            "time": "2025-01-18T10:00:00.000Z",
            "event": "test",
            "entry_hash": "should_be_ignored",
        }

        hash1 = compute_entry_hash(entry_without)
        hash2 = compute_entry_hash(entry_with)

        assert hash1 == hash2

    def test_handles_nested_objects(self) -> None:
        """Hash works with nested objects."""
        entry = {
            "time": "2025-01-18T10:00:00.000Z",
            "nested": {"a": 1, "b": [1, 2, 3]},
        }

        # Should not raise
        result = compute_entry_hash(entry)
        assert len(result) == 64


class TestHashChainFormatter:
    """Tests for HashChainFormatter."""

    @pytest.fixture
    def temp_log_dir(self) -> Path:
        """Create a temporary log directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_dir = Path(tmpdir) / "mcp_acp_logs"
            log_dir.mkdir(parents=True)
            yield log_dir

    @pytest.fixture
    def state_manager(self, temp_log_dir: Path) -> IntegrityStateManager:
        """Create a state manager with temp directory."""
        return IntegrityStateManager(temp_log_dir)

    @pytest.fixture
    def log_path(self, temp_log_dir: Path) -> Path:
        """Create a log file path."""
        path = temp_log_dir / "audit" / "test.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch()
        return path

    @pytest.fixture
    def formatter(self, state_manager: IntegrityStateManager, log_path: Path) -> HashChainFormatter:
        """Create a formatter."""
        return HashChainFormatter(
            state_manager=state_manager,
            log_file_key="audit/test.jsonl",
            log_path=log_path,
        )

    def test_first_entry_has_genesis_prev_hash(self, formatter: HashChainFormatter) -> None:
        """First entry should have prev_hash='GENESIS'."""
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg={"event": "test"},
            args=(),
            exc_info=None,
        )

        result = formatter.format(record)
        entry = json.loads(result)

        assert entry["prev_hash"] == "GENESIS"
        assert entry["sequence"] == 1

    def test_subsequent_entry_references_previous_hash(self, formatter: HashChainFormatter) -> None:
        """Second entry should reference first entry's hash."""
        # First entry
        record1 = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg={"event": "first"},
            args=(),
            exc_info=None,
        )
        result1 = formatter.format(record1)
        entry1 = json.loads(result1)

        # Second entry
        record2 = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg={"event": "second"},
            args=(),
            exc_info=None,
        )
        result2 = formatter.format(record2)
        entry2 = json.loads(result2)

        assert entry2["prev_hash"] == entry1["entry_hash"]
        assert entry2["sequence"] == 2

    def test_sequence_increments_monotonically(self, formatter: HashChainFormatter) -> None:
        """Sequence numbers should be 1, 2, 3, ..."""
        sequences = []

        for i in range(5):
            record = logging.LogRecord(
                name="test",
                level=logging.INFO,
                pathname="",
                lineno=0,
                msg={"event": f"entry_{i}"},
                args=(),
                exc_info=None,
            )
            result = formatter.format(record)
            entry = json.loads(result)
            sequences.append(entry["sequence"])

        assert sequences == [1, 2, 3, 4, 5]

    def test_entry_hash_is_valid(self, formatter: HashChainFormatter) -> None:
        """entry_hash should be valid SHA-256 of entry."""
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg={"event": "test"},
            args=(),
            exc_info=None,
        )

        result = formatter.format(record)
        entry = json.loads(result)

        # Verify by recomputing
        computed = compute_entry_hash(entry)
        assert entry["entry_hash"] == computed

    def test_handles_dict_message(self, formatter: HashChainFormatter) -> None:
        """Formatter handles dict messages."""
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg={"event": "test", "data": {"nested": True}},
            args=(),
            exc_info=None,
        )

        result = formatter.format(record)
        entry = json.loads(result)

        assert entry["event"] == "test"
        assert entry["data"] == {"nested": True}

    def test_handles_string_message(self, formatter: HashChainFormatter) -> None:
        """Formatter handles string messages."""
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="plain string message",
            args=(),
            exc_info=None,
        )

        result = formatter.format(record)
        entry = json.loads(result)

        assert entry["message"] == "plain string message"

    def test_handles_json_string_message(self, formatter: HashChainFormatter) -> None:
        """Formatter handles JSON string messages."""
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg='{"event": "from_json_string"}',
            args=(),
            exc_info=None,
        )

        result = formatter.format(record)
        entry = json.loads(result)

        assert entry["event"] == "from_json_string"

    def test_adds_timestamp(self, formatter: HashChainFormatter) -> None:
        """Formatter adds ISO 8601 timestamp."""
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg={"event": "test"},
            args=(),
            exc_info=None,
        )

        result = formatter.format(record)
        entry = json.loads(result)

        assert "time" in entry
        assert entry["time"].endswith("Z")
        assert "T" in entry["time"]

    def test_thread_safety(self, state_manager: IntegrityStateManager, temp_log_dir: Path) -> None:
        """Concurrent formatting maintains chain integrity."""
        log_path = temp_log_dir / "audit" / "concurrent.jsonl"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.touch()

        formatter = HashChainFormatter(
            state_manager=state_manager,
            log_file_key="audit/concurrent.jsonl",
            log_path=log_path,
        )

        results: list[str] = []
        lock = threading.Lock()

        def format_entry(n: int) -> None:
            record = logging.LogRecord(
                name="test",
                level=logging.INFO,
                pathname="",
                lineno=0,
                msg={"event": f"entry_{n}"},
                args=(),
                exc_info=None,
            )
            result = formatter.format(record)
            with lock:
                results.append(result)

        # Run concurrent formatting
        threads = [threading.Thread(target=format_entry, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Verify all entries have unique sequences
        entries = [json.loads(r) for r in results]
        sequences = [e["sequence"] for e in entries]
        assert len(set(sequences)) == 20  # All unique


class TestVerifyChainIntegrity:
    """Tests for verify_chain_integrity function."""

    @pytest.fixture
    def temp_log_file(self) -> Path:
        """Create a temporary log file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "test.jsonl"
            yield path

    def _write_entry(
        self,
        path: Path,
        sequence: int,
        prev_hash: str,
        event: str = "test",
    ) -> str:
        """Write a single entry and return its hash."""
        entry = {
            "time": f"2025-01-18T10:{sequence:02d}:00.000Z",
            "sequence": sequence,
            "prev_hash": prev_hash,
            "event": event,
        }
        entry_hash = compute_entry_hash(entry)
        entry["entry_hash"] = entry_hash

        with path.open("a") as f:
            f.write(json.dumps(entry) + "\n")

        return entry_hash

    def test_verify_valid_chain(self, temp_log_file: Path) -> None:
        """Valid chain passes verification."""
        # Build a valid chain
        hash1 = self._write_entry(temp_log_file, 1, "GENESIS", "first")
        hash2 = self._write_entry(temp_log_file, 2, hash1, "second")
        self._write_entry(temp_log_file, 3, hash2, "third")

        success, errors, warnings = verify_chain_integrity(temp_log_file)

        assert success is True
        assert errors == []

    def test_verify_detects_chain_break(self, temp_log_file: Path) -> None:
        """Chain break is detected (wrong prev_hash)."""
        hash1 = self._write_entry(temp_log_file, 1, "GENESIS", "first")
        # Wrong prev_hash - should reference hash1
        self._write_entry(temp_log_file, 2, "wrong_hash", "second")

        success, errors, warnings = verify_chain_integrity(temp_log_file)

        assert success is False
        assert any("chain break" in e.lower() for e in errors)

    def test_verify_detects_sequence_gap(self, temp_log_file: Path) -> None:
        """Sequence gap is detected."""
        hash1 = self._write_entry(temp_log_file, 1, "GENESIS", "first")
        # Skip sequence 2
        self._write_entry(temp_log_file, 3, hash1, "third")

        success, errors, warnings = verify_chain_integrity(temp_log_file)

        assert success is False
        assert any("sequence gap" in e.lower() for e in errors)

    def test_verify_detects_modified_content(self, temp_log_file: Path) -> None:
        """Modified entry content is detected (hash mismatch)."""
        # Write entry with correct hash
        entry = {
            "time": "2025-01-18T10:01:00.000Z",
            "sequence": 1,
            "prev_hash": "GENESIS",
            "event": "original",
        }
        entry["entry_hash"] = compute_entry_hash(entry)

        # Modify event AFTER computing hash (simulating tampering)
        entry["event"] = "tampered"

        with temp_log_file.open("w") as f:
            f.write(json.dumps(entry) + "\n")

        success, errors, warnings = verify_chain_integrity(temp_log_file)

        assert success is False
        assert any("hash mismatch" in e.lower() for e in errors)

    def test_verify_detects_wrong_first_prev_hash(self, temp_log_file: Path) -> None:
        """First entry must have GENESIS prev_hash."""
        # First entry with wrong prev_hash
        self._write_entry(temp_log_file, 1, "not_genesis", "first")

        success, errors, warnings = verify_chain_integrity(temp_log_file)

        assert success is False
        assert any("genesis" in e.lower() for e in errors)

    def test_verify_warns_on_time_regression(self, temp_log_file: Path) -> None:
        """Time regression produces warning (not error)."""
        # Write entries with timestamps out of order
        entry1 = {
            "time": "2025-01-18T12:00:00.000Z",  # Later
            "sequence": 1,
            "prev_hash": "GENESIS",
            "event": "first",
        }
        entry1["entry_hash"] = compute_entry_hash(entry1)

        entry2 = {
            "time": "2025-01-18T10:00:00.000Z",  # Earlier (regression)
            "sequence": 2,
            "prev_hash": entry1["entry_hash"],
            "event": "second",
        }
        entry2["entry_hash"] = compute_entry_hash(entry2)

        with temp_log_file.open("w") as f:
            f.write(json.dumps(entry1) + "\n")
            f.write(json.dumps(entry2) + "\n")

        success, errors, warnings = verify_chain_integrity(temp_log_file)

        # Should pass (warnings only for time regression)
        assert success is True
        assert any("time regression" in w.lower() for w in warnings)

    def test_verify_skips_pre_upgrade_entries(self, temp_log_file: Path) -> None:
        """Entries without hash chain fields are skipped."""
        # Write entry WITHOUT hash chain fields
        entry = {"time": "2025-01-18T10:00:00.000Z", "event": "old_entry"}

        with temp_log_file.open("w") as f:
            f.write(json.dumps(entry) + "\n")

        success, errors, warnings = verify_chain_integrity(temp_log_file)

        assert success is True
        assert any("pre-upgrade" in w.lower() for w in warnings)

    def test_verify_missing_file(self, temp_log_file: Path) -> None:
        """Missing file returns error."""
        # Don't create the file

        success, errors, warnings = verify_chain_integrity(temp_log_file)

        assert success is False
        assert any("does not exist" in e.lower() for e in errors)

    def test_verify_with_limit(self, temp_log_file: Path) -> None:
        """Limit parameter limits number of entries verified."""
        # Build a chain with many entries
        prev_hash = "GENESIS"
        for i in range(1, 11):
            prev_hash = self._write_entry(temp_log_file, i, prev_hash, f"entry_{i}")

        # Verify only first 5
        success, errors, warnings = verify_chain_integrity(temp_log_file, limit=5)

        assert success is True

    def test_verify_handles_invalid_json(self, temp_log_file: Path) -> None:
        """Invalid JSON lines produce errors."""
        with temp_log_file.open("w") as f:
            f.write("not valid json\n")

        success, errors, warnings = verify_chain_integrity(temp_log_file)

        # Should fail due to invalid JSON, but not crash
        assert any("invalid json" in e.lower() for e in errors)

    def test_verify_handles_empty_file(self, temp_log_file: Path) -> None:
        """Empty file produces warning."""
        temp_log_file.touch()

        success, errors, warnings = verify_chain_integrity(temp_log_file)

        # Empty file with no chain entries produces warning
        assert success is True
        assert any("no hash chain entries" in w.lower() for w in warnings)
