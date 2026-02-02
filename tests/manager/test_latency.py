"""Tests for LatencyTracker circular buffer.

Unit tests for the LatencyTracker dataclass used by ProxyState
to track per-request latency metrics.
"""

from __future__ import annotations

from collections import deque

import pytest

from mcp_acp.constants import LATENCY_BUFFER_SIZE
from mcp_acp.manager.latency import LatencyTracker


class TestEmptyBuffer:
    """Tests for an empty LatencyTracker."""

    def test_median_returns_none(self) -> None:
        tracker = LatencyTracker()
        assert tracker.median() is None

    def test_count_returns_zero(self) -> None:
        tracker = LatencyTracker()
        assert tracker.count() == 0

    def test_to_dict_all_none(self) -> None:
        tracker = LatencyTracker()
        d = tracker.to_dict()
        assert d == {
            "median_ms": None,
            "count": 0,
            "min_ms": None,
            "max_ms": None,
        }


class TestSingleSample:
    """Tests with a single recorded sample."""

    def test_median_equals_sample(self) -> None:
        tracker = LatencyTracker()
        tracker.record(42.0)
        assert tracker.median() == 42.0

    def test_count_is_one(self) -> None:
        tracker = LatencyTracker()
        tracker.record(42.0)
        assert tracker.count() == 1

    def test_to_dict_min_max_equal(self) -> None:
        tracker = LatencyTracker()
        tracker.record(10.5)
        d = tracker.to_dict()
        assert d["median_ms"] == 10.5
        assert d["min_ms"] == 10.5
        assert d["max_ms"] == 10.5
        assert d["count"] == 1


class TestOddSampleCount:
    """Tests with an odd number of samples (exact median)."""

    def test_median_of_three(self) -> None:
        tracker = LatencyTracker()
        for v in [1.0, 3.0, 2.0]:
            tracker.record(v)
        assert tracker.median() == 2.0

    def test_median_of_five(self) -> None:
        tracker = LatencyTracker()
        for v in [5.0, 1.0, 4.0, 2.0, 3.0]:
            tracker.record(v)
        assert tracker.median() == 3.0


class TestEvenSampleCount:
    """Tests with an even number of samples (averaged median)."""

    def test_median_of_two(self) -> None:
        tracker = LatencyTracker()
        tracker.record(2.0)
        tracker.record(4.0)
        assert tracker.median() == 3.0

    def test_median_of_four(self) -> None:
        tracker = LatencyTracker()
        for v in [1.0, 2.0, 3.0, 4.0]:
            tracker.record(v)
        # median of [1, 2, 3, 4] = (2+3)/2 = 2.5
        assert tracker.median() == 2.5


class TestBufferWraparound:
    """Tests that the circular buffer evicts oldest samples."""

    def test_wraps_at_maxlen(self) -> None:
        tracker = LatencyTracker()
        # Fill buffer with 1000 zeros then add one more
        for _ in range(LATENCY_BUFFER_SIZE):
            tracker.record(0.0)
        assert tracker.count() == LATENCY_BUFFER_SIZE

        tracker.record(999.0)
        assert tracker.count() == LATENCY_BUFFER_SIZE  # still capped

    def test_oldest_evicted(self) -> None:
        """After filling and adding more, only recent values remain."""
        tracker = LatencyTracker()
        # Add LATENCY_BUFFER_SIZE values of 100.0
        for _ in range(LATENCY_BUFFER_SIZE):
            tracker.record(100.0)
        # Now replace them all with 200.0
        for _ in range(LATENCY_BUFFER_SIZE):
            tracker.record(200.0)
        # All values should be 200.0 now
        assert tracker.median() == 200.0
        d = tracker.to_dict()
        assert d["min_ms"] == 200.0
        assert d["max_ms"] == 200.0


class TestToDict:
    """Tests for to_dict() output format."""

    def test_values_are_rounded(self) -> None:
        tracker = LatencyTracker()
        tracker.record(1.1111)
        tracker.record(2.2222)
        tracker.record(3.3333)
        d = tracker.to_dict()
        # median of [1.1111, 2.2222, 3.3333] = 2.2222
        assert d["median_ms"] == 2.22
        assert d["min_ms"] == 1.11
        assert d["max_ms"] == 3.33
        assert d["count"] == 3

    def test_keys_present(self) -> None:
        tracker = LatencyTracker()
        tracker.record(5.0)
        d = tracker.to_dict()
        assert set(d.keys()) == {"median_ms", "count", "min_ms", "max_ms"}
