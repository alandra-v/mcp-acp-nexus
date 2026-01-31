"""Tests for proxy disconnect enrichment.

Tests the _read_last_line() and _read_recent_shutdown() helpers that
enrich proxy_disconnected SSE events with crash reasons from shutdowns.jsonl.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from pathlib import Path

import pytest

from mcp_acp.manager.registry import (
    ProxyRegistry,
    _read_last_line,
    _read_recent_shutdown,
)


# ---------------------------------------------------------------------------
# _read_last_line tests
# ---------------------------------------------------------------------------


class TestReadLastLine:
    """Tests for _read_last_line helper."""

    def test_returns_last_line(self, tmp_path: Path) -> None:
        """Returns the last non-empty line from a file."""
        f = tmp_path / "test.jsonl"
        f.write_text("line1\nline2\nline3\n")

        assert _read_last_line(f) == "line3"

    def test_skips_trailing_empty_lines(self, tmp_path: Path) -> None:
        """Skips empty lines at end of file."""
        f = tmp_path / "test.jsonl"
        f.write_text("line1\nline2\n\n\n")

        assert _read_last_line(f) == "line2"

    def test_single_line(self, tmp_path: Path) -> None:
        """Works with a single-line file."""
        f = tmp_path / "test.jsonl"
        f.write_text("only\n")

        assert _read_last_line(f) == "only"

    def test_empty_file(self, tmp_path: Path) -> None:
        """Returns None for empty file."""
        f = tmp_path / "test.jsonl"
        f.write_text("")

        assert _read_last_line(f) is None

    def test_missing_file(self, tmp_path: Path) -> None:
        """Returns None for non-existent file."""
        f = tmp_path / "does_not_exist.jsonl"

        assert _read_last_line(f) is None

    def test_whitespace_only_file(self, tmp_path: Path) -> None:
        """Returns None for file with only whitespace."""
        f = tmp_path / "test.jsonl"
        f.write_text("   \n  \n\n")

        assert _read_last_line(f) is None


# ---------------------------------------------------------------------------
# _read_recent_shutdown tests
# ---------------------------------------------------------------------------


def _write_shutdown_entry(
    shutdowns_path: Path,
    *,
    failure_type: str = "audit_failure",
    reason: str = "Audit log write failed",
    exit_code: int = 10,
    time_offset_seconds: float = 0,
) -> None:
    """Write a shutdown entry to shutdowns.jsonl.

    Args:
        shutdowns_path: Path to shutdowns.jsonl.
        time_offset_seconds: Offset from now (negative = past).
    """
    entry_time = datetime.now(timezone.utc) + timedelta(seconds=time_offset_seconds)
    entry = {
        "time": entry_time.isoformat().replace("+00:00", "Z"),
        "event": "security_shutdown",
        "failure_type": failure_type,
        "reason": reason,
        "exit_code": exit_code,
        "context": {},
    }
    shutdowns_path.parent.mkdir(parents=True, exist_ok=True)
    with shutdowns_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


class TestReadRecentShutdown:
    """Tests for _read_recent_shutdown helper."""

    def test_returns_recent_entry(self, tmp_path: Path) -> None:
        """Returns shutdown info when last entry is recent."""
        shutdowns_path = tmp_path / "shutdowns.jsonl"
        _write_shutdown_entry(shutdowns_path, time_offset_seconds=-2)

        with patch(
            "mcp_acp.manager.config.get_proxy_log_dir",
            return_value=tmp_path,
        ):
            result = _read_recent_shutdown("test-proxy")

        assert result is not None
        assert result["failure_type"] == "audit_failure"
        assert result["reason"] == "Audit log write failed"
        assert result["exit_code"] == 10
        assert result["time"] is not None

    def test_returns_none_for_old_entry(self, tmp_path: Path) -> None:
        """Returns None when last entry is older than max_age_seconds."""
        shutdowns_path = tmp_path / "shutdowns.jsonl"
        _write_shutdown_entry(shutdowns_path, time_offset_seconds=-60)

        with patch(
            "mcp_acp.manager.config.get_proxy_log_dir",
            return_value=tmp_path,
        ):
            result = _read_recent_shutdown("test-proxy", max_age_seconds=30)

        assert result is None

    def test_returns_none_for_missing_file(self, tmp_path: Path) -> None:
        """Returns None when shutdowns.jsonl does not exist."""
        with patch(
            "mcp_acp.manager.config.get_proxy_log_dir",
            return_value=tmp_path,
        ):
            result = _read_recent_shutdown("test-proxy")

        assert result is None

    def test_returns_none_for_empty_file(self, tmp_path: Path) -> None:
        """Returns None when shutdowns.jsonl is empty."""
        shutdowns_path = tmp_path / "shutdowns.jsonl"
        shutdowns_path.write_text("")

        with patch(
            "mcp_acp.manager.config.get_proxy_log_dir",
            return_value=tmp_path,
        ):
            result = _read_recent_shutdown("test-proxy")

        assert result is None

    def test_returns_none_for_malformed_json(self, tmp_path: Path) -> None:
        """Returns None when shutdowns.jsonl has malformed JSON."""
        shutdowns_path = tmp_path / "shutdowns.jsonl"
        shutdowns_path.write_text("not valid json\n")

        with patch(
            "mcp_acp.manager.config.get_proxy_log_dir",
            return_value=tmp_path,
        ):
            result = _read_recent_shutdown("test-proxy")

        assert result is None

    def test_reads_last_entry_from_multiple(self, tmp_path: Path) -> None:
        """Reads the last entry when file has multiple entries."""
        shutdowns_path = tmp_path / "shutdowns.jsonl"
        # Old entry
        _write_shutdown_entry(
            shutdowns_path,
            failure_type="old_failure",
            reason="Old crash",
            time_offset_seconds=-120,
        )
        # Recent entry
        _write_shutdown_entry(
            shutdowns_path,
            failure_type="session_binding_violation",
            reason="Session hijacking detected",
            exit_code=12,
            time_offset_seconds=-1,
        )

        with patch(
            "mcp_acp.manager.config.get_proxy_log_dir",
            return_value=tmp_path,
        ):
            result = _read_recent_shutdown("test-proxy")

        assert result is not None
        assert result["failure_type"] == "session_binding_violation"
        assert result["reason"] == "Session hijacking detected"
        assert result["exit_code"] == 12

    def test_custom_max_age(self, tmp_path: Path) -> None:
        """Respects custom max_age_seconds parameter."""
        shutdowns_path = tmp_path / "shutdowns.jsonl"
        _write_shutdown_entry(shutdowns_path, time_offset_seconds=-10)

        with patch(
            "mcp_acp.manager.config.get_proxy_log_dir",
            return_value=tmp_path,
        ):
            # 5s window: too old
            assert _read_recent_shutdown("test-proxy", max_age_seconds=5) is None
            # 15s window: recent enough
            assert _read_recent_shutdown("test-proxy", max_age_seconds=15) is not None


# ---------------------------------------------------------------------------
# deregister() enrichment tests
# ---------------------------------------------------------------------------


@pytest.fixture
def registry() -> ProxyRegistry:
    """Create a fresh registry for each test."""
    return ProxyRegistry()


@pytest.fixture
def mock_streams() -> tuple[MagicMock, MagicMock]:
    """Create mock stream reader and writer."""
    reader = MagicMock()
    reader.readline = AsyncMock(return_value=b"")

    writer = MagicMock()
    writer.write = MagicMock()
    writer.drain = AsyncMock()
    writer.close = MagicMock()
    writer.wait_closed = AsyncMock()
    return reader, writer


class TestDeregisterEnrichment:
    """Tests for disconnect_reason enrichment in deregister()."""

    async def test_includes_disconnect_reason_on_crash(
        self,
        registry: ProxyRegistry,
        mock_streams: tuple[MagicMock, MagicMock],
    ) -> None:
        """deregister includes disconnect_reason when recent shutdown found."""
        reader, writer = mock_streams
        await registry.register(
            proxy_name="crash-proxy",
            proxy_id="px_crash:crash-proxy",
            instance_id="inst_crash",
            config_summary={},
            socket_path="/tmp/crash.sock",
            reader=reader,
            writer=writer,
        )

        queue = await registry.subscribe_sse()

        crash_reason = {
            "failure_type": "audit_failure",
            "reason": "Audit log write failed",
            "exit_code": 10,
            "time": "2026-01-30T12:00:00Z",
        }

        with patch(
            "mcp_acp.manager.registry._read_recent_shutdown",
            return_value=crash_reason,
        ):
            await registry.deregister("crash-proxy")

        event = queue.get_nowait()
        assert event["type"] == "proxy_disconnected"
        assert event["data"]["proxy_name"] == "crash-proxy"
        assert event["data"]["disconnect_reason"] == crash_reason
        assert event["data"]["disconnect_reason"]["failure_type"] == "audit_failure"

    async def test_disconnect_reason_null_for_normal_disconnect(
        self,
        registry: ProxyRegistry,
        mock_streams: tuple[MagicMock, MagicMock],
    ) -> None:
        """deregister sends disconnect_reason=None for normal disconnect."""
        reader, writer = mock_streams
        await registry.register(
            proxy_name="clean-proxy",
            proxy_id="px_clean:clean-proxy",
            instance_id="inst_clean",
            config_summary={},
            socket_path="/tmp/clean.sock",
            reader=reader,
            writer=writer,
        )

        queue = await registry.subscribe_sse()

        with patch(
            "mcp_acp.manager.registry._read_recent_shutdown",
            return_value=None,
        ):
            await registry.deregister("clean-proxy")

        event = queue.get_nowait()
        assert event["type"] == "proxy_disconnected"
        assert event["data"]["proxy_name"] == "clean-proxy"
        assert event["data"]["disconnect_reason"] is None

    async def test_disconnect_reason_always_present_in_event(
        self,
        registry: ProxyRegistry,
        mock_streams: tuple[MagicMock, MagicMock],
    ) -> None:
        """disconnect_reason key is always present in event data (not omitted)."""
        reader, writer = mock_streams
        await registry.register(
            proxy_name="test-proxy",
            proxy_id="px_test:test-proxy",
            instance_id="inst_test",
            config_summary={},
            socket_path="/tmp/test.sock",
            reader=reader,
            writer=writer,
        )

        queue = await registry.subscribe_sse()

        with patch(
            "mcp_acp.manager.registry._read_recent_shutdown",
            return_value=None,
        ):
            await registry.deregister("test-proxy")

        event = queue.get_nowait()
        assert "disconnect_reason" in event["data"]
