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


class TestRecordDiscovery:
    """Tests for record_discovery()."""

    def test_increments_total(self, proxy_state: ProxyState) -> None:
        """record_discovery increments requests_total."""
        assert proxy_state.get_stats().requests_total == 0

        proxy_state.record_discovery()
        assert proxy_state.get_stats().requests_total == 1

        proxy_state.record_discovery()
        assert proxy_state.get_stats().requests_total == 2

    def test_does_not_increment_decision_counters(self, proxy_state: ProxyState) -> None:
        """record_discovery only affects requests_total, not decision counters."""
        proxy_state.record_discovery()
        proxy_state.record_discovery()

        stats = proxy_state.get_stats()
        assert stats.requests_total == 2
        assert stats.requests_allowed == 0
        assert stats.requests_denied == 0
        assert stats.requests_hitl == 0

    @pytest.mark.asyncio
    async def test_emits_sse_event(self, proxy_state: ProxyState) -> None:
        """record_discovery emits SSE events when UI is connected."""
        queue = proxy_state.subscribe()

        proxy_state.record_discovery()

        # Should have received stats_updated event
        event = queue.get_nowait()
        assert event["type"] == SSEEventType.STATS_UPDATED.value
        assert event["stats"]["requests_total"] == 1

        # Also emits NEW_LOG_ENTRIES event
        event2 = queue.get_nowait()
        assert event2["type"] == SSEEventType.NEW_LOG_ENTRIES.value

        proxy_state.unsubscribe(queue)

    def test_no_event_when_no_subscribers(self, proxy_state: ProxyState) -> None:
        """No SSE event emitted when no UI is connected."""
        assert not proxy_state.is_ui_connected

        # Should not raise or emit anything
        proxy_state.record_discovery()


class TestStatsInvariant:
    """Tests for the stats invariant: total >= allowed + denied + hitl.

    Note: total >= (not ==) because discovery requests are counted in total
    but don't have policy decisions (allowed/denied/hitl).
    """

    def test_invariant_holds_with_policy_only(self, proxy_state: ProxyState) -> None:
        """Total equals sum when only policy-evaluated requests."""
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

    def test_invariant_holds_with_discovery(self, proxy_state: ProxyState) -> None:
        """Total >= sum when discovery requests are included."""
        # Policy-evaluated requests
        for _ in range(5):
            proxy_state.record_request()
            proxy_state.record_decision(Decision.ALLOW)

        # Discovery requests (no decision)
        for _ in range(3):
            proxy_state.record_discovery()

        stats = proxy_state.get_stats()
        assert stats.requests_total == 8  # 5 policy + 3 discovery
        assert stats.requests_allowed == 5
        assert stats.requests_denied == 0
        assert stats.requests_hitl == 0
        # Total > sum because of discovery
        assert stats.requests_total >= stats.requests_allowed + stats.requests_denied + stats.requests_hitl


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


class TestRecordDecisionLatency:
    """Tests for eval_ms and hitl_ms latency recording via record_decision()."""

    def test_eval_ms_recorded(self, proxy_state: ProxyState) -> None:
        """record_decision with eval_ms records to policy_eval tracker."""
        proxy_state.record_decision(Decision.ALLOW, eval_ms=5.0)
        latency = proxy_state.get_latency()
        assert latency["policy_eval"]["median_ms"] == 5.0
        assert latency["policy_eval"]["count"] == 1

    def test_hitl_ms_recorded(self, proxy_state: ProxyState) -> None:
        """record_decision with hitl_ms records to hitl_wait tracker."""
        proxy_state.record_decision(Decision.HITL, hitl_ms=1200.0)
        latency = proxy_state.get_latency()
        assert latency["hitl_wait"]["median_ms"] == 1200.0
        assert latency["hitl_wait"]["count"] == 1

    def test_both_ms_recorded(self, proxy_state: ProxyState) -> None:
        """record_decision with both eval_ms and hitl_ms records to both trackers."""
        proxy_state.record_decision(Decision.HITL, eval_ms=2.0, hitl_ms=500.0)
        latency = proxy_state.get_latency()
        assert latency["policy_eval"]["median_ms"] == 2.0
        assert latency["hitl_wait"]["median_ms"] == 500.0

    def test_none_ms_not_recorded(self, proxy_state: ProxyState) -> None:
        """record_decision with None latencies does not record samples."""
        proxy_state.record_decision(Decision.ALLOW)
        latency = proxy_state.get_latency()
        assert latency["policy_eval"]["count"] == 0
        assert latency["hitl_wait"]["count"] == 0


class TestRecordProxyLatency:
    """Tests for record_proxy_latency()."""

    def test_records_to_proxy_tracker(self, proxy_state: ProxyState) -> None:
        """record_proxy_latency records to the proxy_latency tracker."""
        proxy_state.record_proxy_latency(25.0)
        proxy_state.record_proxy_latency(35.0)
        latency = proxy_state.get_latency()
        assert latency["proxy_latency"]["count"] == 2
        assert latency["proxy_latency"]["median_ms"] == 30.0


class TestGetLatency:
    """Tests for get_latency()."""

    def test_initial_latency_all_empty(self, proxy_state: ProxyState) -> None:
        """get_latency returns empty metrics initially."""
        latency = proxy_state.get_latency()
        assert latency["proxy_latency"]["median_ms"] is None
        assert latency["policy_eval"]["median_ms"] is None
        assert latency["hitl_wait"]["median_ms"] is None

    def test_returns_all_three_keys(self, proxy_state: ProxyState) -> None:
        """get_latency returns all three metric keys."""
        latency = proxy_state.get_latency()
        assert set(latency.keys()) == {"proxy_latency", "policy_eval", "hitl_wait"}

    def test_medians_correct_after_multiple_samples(self, proxy_state: ProxyState) -> None:
        """get_latency returns correct medians after recording samples."""
        for v in [10.0, 20.0, 30.0]:
            proxy_state.record_proxy_latency(v)
        for v in [1.0, 2.0, 3.0]:
            proxy_state.record_decision(Decision.ALLOW, eval_ms=v)
        proxy_state.record_decision(Decision.HITL, hitl_ms=500.0)

        latency = proxy_state.get_latency()
        assert latency["proxy_latency"]["median_ms"] == 20.0
        assert latency["policy_eval"]["median_ms"] == 2.0
        assert latency["hitl_wait"]["median_ms"] == 500.0
