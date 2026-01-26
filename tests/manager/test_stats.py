"""Tests for ProxyState stats tracking.

Tests the request counting and SSE event emission functionality.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

from mcp_acp.manager.state import ProxyState
from mcp_acp.manager.models import ProxyStats
from mcp_acp.manager.events import SSEEventType
from mcp_acp.pdp import Decision


@pytest.fixture
def mock_approval_store() -> MagicMock:
    """Create a mock approval store."""
    store = MagicMock()
    store.ttl_seconds = 300
    store.iter_all.return_value = []
    return store


@pytest.fixture
def mock_session_manager() -> MagicMock:
    """Create a mock session manager."""
    return MagicMock()


@pytest.fixture
def proxy_state(mock_approval_store: MagicMock, mock_session_manager: MagicMock) -> ProxyState:
    """Create a ProxyState instance for testing."""
    return ProxyState(
        backend_id="test-backend",
        api_port=8080,
        approval_store=mock_approval_store,
        session_manager=mock_session_manager,
    )


class TestProxyStats:
    """Tests for ProxyStats model."""

    def test_stats_model_fields(self) -> None:
        """Stats model has expected fields."""
        stats = ProxyStats(
            requests_total=10,
            requests_allowed=6,
            requests_denied=3,
            requests_hitl=1,
        )
        assert stats.requests_total == 10
        assert stats.requests_allowed == 6
        assert stats.requests_denied == 3
        assert stats.requests_hitl == 1

    def test_stats_to_dict(self) -> None:
        """Stats can be converted to dict for SSE/API."""
        stats = ProxyStats(
            requests_total=10,
            requests_allowed=6,
            requests_denied=3,
            requests_hitl=1,
        )
        d = stats.to_dict()
        assert d == {
            "requests_total": 10,
            "requests_allowed": 6,
            "requests_denied": 3,
            "requests_hitl": 1,
        }

    def test_stats_is_frozen(self) -> None:
        """Stats model is immutable."""
        stats = ProxyStats(
            requests_total=10,
            requests_allowed=6,
            requests_denied=3,
            requests_hitl=1,
        )
        with pytest.raises(ValidationError):  # Frozen model raises ValidationError on assignment
            stats.requests_total = 20  # type: ignore[misc]


class TestRecordRequest:
    """Tests for record_request()."""

    def test_increments_total(self, proxy_state: ProxyState) -> None:
        """record_request increments requests_total."""
        assert proxy_state.get_stats().requests_total == 0

        proxy_state.record_request()
        assert proxy_state.get_stats().requests_total == 1

        proxy_state.record_request()
        assert proxy_state.get_stats().requests_total == 2

    def test_does_not_increment_other_counters(self, proxy_state: ProxyState) -> None:
        """record_request only affects requests_total."""
        proxy_state.record_request()
        proxy_state.record_request()

        stats = proxy_state.get_stats()
        assert stats.requests_total == 2
        assert stats.requests_allowed == 0
        assert stats.requests_denied == 0
        assert stats.requests_hitl == 0


class TestRecordDecision:
    """Tests for record_decision()."""

    def test_allow_increments_allowed(self, proxy_state: ProxyState) -> None:
        """record_decision(ALLOW) increments requests_allowed."""
        proxy_state.record_decision(Decision.ALLOW)
        proxy_state.record_decision(Decision.ALLOW)

        stats = proxy_state.get_stats()
        assert stats.requests_allowed == 2
        assert stats.requests_denied == 0
        assert stats.requests_hitl == 0

    def test_deny_increments_denied(self, proxy_state: ProxyState) -> None:
        """record_decision(DENY) increments requests_denied."""
        proxy_state.record_decision(Decision.DENY)

        stats = proxy_state.get_stats()
        assert stats.requests_allowed == 0
        assert stats.requests_denied == 1
        assert stats.requests_hitl == 0

    def test_hitl_increments_hitl(self, proxy_state: ProxyState) -> None:
        """record_decision(HITL) increments requests_hitl."""
        proxy_state.record_decision(Decision.HITL)
        proxy_state.record_decision(Decision.HITL)
        proxy_state.record_decision(Decision.HITL)

        stats = proxy_state.get_stats()
        assert stats.requests_allowed == 0
        assert stats.requests_denied == 0
        assert stats.requests_hitl == 3

    def test_does_not_increment_total(self, proxy_state: ProxyState) -> None:
        """record_decision does not affect requests_total."""
        proxy_state.record_decision(Decision.ALLOW)
        proxy_state.record_decision(Decision.DENY)
        proxy_state.record_decision(Decision.HITL)

        assert proxy_state.get_stats().requests_total == 0


class TestStatsInvariant:
    """Tests for the stats invariant: total == allowed + denied + hitl."""

    def test_invariant_holds_after_mixed_operations(self, proxy_state: ProxyState) -> None:
        """Total equals sum of decision counters after mixed operations."""
        # Simulate typical middleware flow: record_request + record_decision together
        for _ in range(5):
            proxy_state.record_request()
            proxy_state.record_decision(Decision.ALLOW)

        for _ in range(3):
            proxy_state.record_request()
            proxy_state.record_decision(Decision.DENY)

        for _ in range(2):
            proxy_state.record_request()
            proxy_state.record_decision(Decision.HITL)

        stats = proxy_state.get_stats()
        assert stats.requests_total == 10
        assert stats.requests_allowed == 5
        assert stats.requests_denied == 3
        assert stats.requests_hitl == 2
        assert stats.requests_total == stats.requests_allowed + stats.requests_denied + stats.requests_hitl


class TestSSEEvents:
    """Tests for SSE event emission on stats updates."""

    def test_no_event_when_no_subscribers(self, proxy_state: ProxyState) -> None:
        """No SSE event emitted when no UI is connected."""
        # No subscribers, so is_ui_connected is False
        assert not proxy_state.is_ui_connected

        # These should not raise or emit anything
        proxy_state.record_request()
        proxy_state.record_decision(Decision.ALLOW)

    @pytest.mark.asyncio
    async def test_no_event_on_record_request_alone(self, proxy_state: ProxyState) -> None:
        """record_request alone does not emit SSE (record_decision will emit)."""
        queue = proxy_state.subscribe()
        assert proxy_state.is_ui_connected

        proxy_state.record_request()

        # No event emitted - record_decision() handles SSE emission
        assert queue.empty()

        proxy_state.unsubscribe(queue)

    @pytest.mark.asyncio
    async def test_event_emitted_on_record_decision(self, proxy_state: ProxyState) -> None:
        """SSE events emitted when record_decision is called with UI connected."""
        queue = proxy_state.subscribe()

        proxy_state.record_decision(Decision.ALLOW)

        # Should have received stats_updated event
        event = queue.get_nowait()
        assert event["type"] == SSEEventType.STATS_UPDATED.value
        assert event["stats"]["requests_allowed"] == 1

        # Also emits NEW_LOG_ENTRIES event
        event2 = queue.get_nowait()
        assert event2["type"] == SSEEventType.NEW_LOG_ENTRIES.value

        proxy_state.unsubscribe(queue)

    @pytest.mark.asyncio
    async def test_multiple_subscribers_all_receive_events(self, proxy_state: ProxyState) -> None:
        """All SSE subscribers receive stats events."""
        queue1 = proxy_state.subscribe()
        queue2 = proxy_state.subscribe()

        proxy_state.record_decision(Decision.ALLOW)

        # Both queues should have the STATS_UPDATED event
        event1 = queue1.get_nowait()
        event2 = queue2.get_nowait()

        assert event1["type"] == SSEEventType.STATS_UPDATED.value
        assert event2["type"] == SSEEventType.STATS_UPDATED.value

        proxy_state.unsubscribe(queue1)
        proxy_state.unsubscribe(queue2)

    @pytest.mark.asyncio
    async def test_unsubscribed_queue_stops_receiving(self, proxy_state: ProxyState) -> None:
        """Unsubscribed queue no longer receives events."""
        queue = proxy_state.subscribe()
        proxy_state.unsubscribe(queue)

        assert not proxy_state.is_ui_connected

        proxy_state.record_decision(Decision.ALLOW)

        # Queue should be empty (no event sent after unsubscribe)
        assert queue.empty()


class TestGetStats:
    """Tests for get_stats()."""

    def test_returns_proxy_stats_instance(self, proxy_state: ProxyState) -> None:
        """get_stats returns a ProxyStats instance."""
        stats = proxy_state.get_stats()
        assert isinstance(stats, ProxyStats)

    def test_returns_current_values(self, proxy_state: ProxyState) -> None:
        """get_stats returns current counter values."""
        proxy_state.record_request()
        proxy_state.record_decision(Decision.ALLOW)
        proxy_state.record_request()
        proxy_state.record_decision(Decision.DENY)

        stats = proxy_state.get_stats()
        assert stats.requests_total == 2
        assert stats.requests_allowed == 1
        assert stats.requests_denied == 1

    def test_returns_snapshot_not_reference(self, proxy_state: ProxyState) -> None:
        """get_stats returns a snapshot, not a live reference."""
        stats1 = proxy_state.get_stats()

        proxy_state.record_request()
        proxy_state.record_decision(Decision.ALLOW)

        stats2 = proxy_state.get_stats()

        # stats1 should still show old values
        assert stats1.requests_total == 0
        assert stats2.requests_total == 1


class TestInitialState:
    """Tests for initial state of stats counters."""

    def test_all_counters_start_at_zero(self, proxy_state: ProxyState) -> None:
        """All stats counters are zero initially."""
        stats = proxy_state.get_stats()
        assert stats.requests_total == 0
        assert stats.requests_allowed == 0
        assert stats.requests_denied == 0
        assert stats.requests_hitl == 0
