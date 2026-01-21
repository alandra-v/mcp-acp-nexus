"""Unit tests for rate limiting functionality.

Tests use the AAA pattern (Arrange-Act-Assert) for clarity.

Tests cover:
- SessionRateTracker: sliding window algorithm, per-session/per-tool tracking
- RateLimitConfig: configuration dataclass
- create_rate_tracker: factory function
"""

from __future__ import annotations

import time
from unittest.mock import patch

import pytest

from mcp_acp.security.rate_limiter import (
    DEFAULT_RATE_THRESHOLD,
    DEFAULT_RATE_WINDOW_SECONDS,
    RateLimitConfig,
    SessionRateTracker,
    create_rate_tracker,
)


# =============================================================================
# SessionRateTracker Tests
# =============================================================================


class TestSessionRateTrackerBasic:
    """Basic functionality tests for SessionRateTracker."""

    def test_allows_first_request(self) -> None:
        """First request should always be allowed."""
        # Arrange
        tracker = SessionRateTracker()

        # Act
        allowed, count = tracker.check("session1", "read_file")

        # Assert
        assert allowed is True
        assert count == 1

    def test_allows_requests_within_threshold(self) -> None:
        """Requests within threshold should be allowed."""
        # Arrange
        tracker = SessionRateTracker(default_threshold=5)

        # Act - make 5 requests (at threshold)
        for i in range(5):
            allowed, count = tracker.check("session1", "read_file")

        # Assert - all should be allowed
        assert allowed is True
        assert count == 5

    def test_denies_request_at_threshold(self) -> None:
        """Request that would exceed threshold should be denied."""
        # Arrange
        tracker = SessionRateTracker(default_threshold=3)

        # Act - make 3 requests, then try 4th
        for _ in range(3):
            tracker.check("session1", "read_file")
        allowed, count = tracker.check("session1", "read_file")

        # Assert - 4th request denied
        assert allowed is False
        assert count == 3  # Count at denial

    def test_tracks_sessions_independently(self) -> None:
        """Different sessions should be tracked separately."""
        # Arrange
        tracker = SessionRateTracker(default_threshold=2)

        # Act - session1 hits limit
        tracker.check("session1", "read_file")
        tracker.check("session1", "read_file")
        session1_result = tracker.check("session1", "read_file")

        # session2 should still be allowed
        session2_result = tracker.check("session2", "read_file")

        # Assert
        assert session1_result[0] is False  # session1 denied
        assert session2_result[0] is True  # session2 allowed
        assert session2_result[1] == 1

    def test_tracks_tools_independently(self) -> None:
        """Different tools within same session should be tracked separately."""
        # Arrange
        tracker = SessionRateTracker(default_threshold=2)

        # Act - read_file hits limit
        tracker.check("session1", "read_file")
        tracker.check("session1", "read_file")
        read_result = tracker.check("session1", "read_file")

        # write_file should still be allowed
        write_result = tracker.check("session1", "write_file")

        # Assert
        assert read_result[0] is False  # read denied
        assert write_result[0] is True  # write allowed
        assert write_result[1] == 1


class TestSessionRateTrackerSlidingWindow:
    """Sliding window algorithm tests."""

    def test_old_requests_expire(self) -> None:
        """Requests outside window should not count toward threshold."""
        # Arrange
        tracker = SessionRateTracker(window_seconds=1.0, default_threshold=2)

        # Act - make 2 requests
        tracker.check("session1", "read_file")
        tracker.check("session1", "read_file")

        # Wait for window to expire
        time.sleep(1.1)

        # 3rd request should be allowed (old ones expired)
        allowed, count = tracker.check("session1", "read_file")

        # Assert
        assert allowed is True
        assert count == 1  # Only the new request counts

    def test_partial_window_expiry(self) -> None:
        """Only expired requests should be removed from window."""
        # Arrange
        tracker = SessionRateTracker(window_seconds=0.5, default_threshold=3)

        # Act - make 2 requests
        tracker.check("session1", "read_file")
        time.sleep(0.3)
        tracker.check("session1", "read_file")

        # Wait for first request to expire but not second
        time.sleep(0.3)

        # Check count (should be 1 - second request still in window)
        count = tracker.get_count("session1", "read_file")

        # Assert
        assert count == 1


class TestSessionRateTrackerPerToolThresholds:
    """Per-tool threshold configuration tests."""

    def test_uses_per_tool_threshold(self) -> None:
        """Per-tool threshold should override default."""
        # Arrange
        tracker = SessionRateTracker(
            default_threshold=10,
            per_tool_thresholds={"dangerous_tool": 2},
        )

        # Act - dangerous_tool should hit its limit at 2
        tracker.check("session1", "dangerous_tool")
        tracker.check("session1", "dangerous_tool")
        dangerous_result = tracker.check("session1", "dangerous_tool")

        # safe_tool should use default (10)
        safe_result = tracker.check("session1", "safe_tool")

        # Assert
        assert dangerous_result[0] is False  # Hit custom threshold
        assert safe_result[0] is True  # Uses default threshold

    def test_default_threshold_used_for_unconfigured_tools(self) -> None:
        """Tools without per-tool config should use default threshold."""
        # Arrange
        tracker = SessionRateTracker(
            default_threshold=2,
            per_tool_thresholds={"other_tool": 100},
        )

        # Act
        tracker.check("session1", "unconfigured_tool")
        tracker.check("session1", "unconfigured_tool")
        result = tracker.check("session1", "unconfigured_tool")

        # Assert
        assert result[0] is False  # Uses default of 2


class TestSessionRateTrackerCleanup:
    """Session cleanup and memory management tests."""

    def test_cleanup_session_removes_data(self) -> None:
        """cleanup_session should remove all tracking data for session."""
        # Arrange
        tracker = SessionRateTracker()
        tracker.check("session1", "read_file")
        tracker.check("session1", "write_file")

        # Act
        tracker.cleanup_session("session1")

        # Assert - counts should be 0 (data cleared)
        assert tracker.get_count("session1", "read_file") == 0
        assert tracker.get_count("session1", "write_file") == 0

    def test_cleanup_nonexistent_session_is_safe(self) -> None:
        """cleanup_session on nonexistent session should not raise."""
        # Arrange
        tracker = SessionRateTracker()

        # Act & Assert - should not raise
        tracker.cleanup_session("nonexistent")

    def test_clear_removes_all_data(self) -> None:
        """clear should remove all tracking data."""
        # Arrange
        tracker = SessionRateTracker()
        tracker.check("session1", "tool1")
        tracker.check("session2", "tool2")

        # Act
        tracker.clear()

        # Assert
        assert tracker.active_sessions == 0

    def test_active_sessions_property(self) -> None:
        """active_sessions should return number of tracked sessions."""
        # Arrange
        tracker = SessionRateTracker()

        # Act
        tracker.check("session1", "tool")
        tracker.check("session2", "tool")
        tracker.check("session3", "tool")

        # Assert
        assert tracker.active_sessions == 3

    def test_reset_tool_clears_window(self) -> None:
        """reset_tool should clear tracking for specific session/tool."""
        # Arrange
        tracker = SessionRateTracker(default_threshold=3)
        tracker.check("session1", "tool_a")
        tracker.check("session1", "tool_a")
        tracker.check("session1", "tool_b")

        # Act - reset only tool_a
        tracker.reset_tool("session1", "tool_a")

        # Assert - tool_a reset, tool_b unchanged
        assert tracker.get_count("session1", "tool_a") == 0
        assert tracker.get_count("session1", "tool_b") == 1

    def test_reset_tool_allows_continued_usage(self) -> None:
        """After reset, should be able to use tool without hitting limit."""
        # Arrange
        tracker = SessionRateTracker(default_threshold=2)
        tracker.check("session1", "tool")
        tracker.check("session1", "tool")

        # Verify at limit
        allowed, _ = tracker.check("session1", "tool")
        assert allowed is False

        # Act - reset
        tracker.reset_tool("session1", "tool")

        # Assert - can use again
        allowed, count = tracker.check("session1", "tool")
        assert allowed is True
        assert count == 1

    def test_reset_nonexistent_tool_is_safe(self) -> None:
        """reset_tool on nonexistent session/tool should not raise."""
        # Arrange
        tracker = SessionRateTracker()

        # Act & Assert - should not raise
        tracker.reset_tool("nonexistent", "tool")
        tracker.reset_tool("session1", "nonexistent")


class TestSessionRateTrackerGetCount:
    """Tests for get_count method."""

    def test_get_count_returns_current_count(self) -> None:
        """get_count should return count without recording new call."""
        # Arrange
        tracker = SessionRateTracker()
        tracker.check("session1", "tool")
        tracker.check("session1", "tool")

        # Act
        count = tracker.get_count("session1", "tool")

        # Assert
        assert count == 2

    def test_get_count_returns_zero_for_unknown(self) -> None:
        """get_count should return 0 for unknown session/tool."""
        # Arrange
        tracker = SessionRateTracker()

        # Act
        count = tracker.get_count("unknown", "unknown")

        # Assert
        assert count == 0

    def test_get_count_does_not_record_call(self) -> None:
        """get_count should not increment the count."""
        # Arrange
        tracker = SessionRateTracker(default_threshold=2)
        tracker.check("session1", "tool")

        # Act - call get_count multiple times
        for _ in range(10):
            tracker.get_count("session1", "tool")

        # Assert - threshold not reached (get_count didn't increment)
        allowed, _ = tracker.check("session1", "tool")
        assert allowed is True


# =============================================================================
# RateLimitConfig Tests
# =============================================================================


class TestRateLimitConfig:
    """Tests for RateLimitConfig dataclass."""

    def test_default_values(self) -> None:
        """Default values should match module constants."""
        # Arrange & Act
        config = RateLimitConfig()

        # Assert
        assert config.enabled is True
        assert config.window_seconds == DEFAULT_RATE_WINDOW_SECONDS
        assert config.default_threshold == DEFAULT_RATE_THRESHOLD
        assert config.per_tool_thresholds == {}

    def test_custom_values(self) -> None:
        """Should accept custom configuration values."""
        # Arrange & Act
        config = RateLimitConfig(
            enabled=False,
            window_seconds=120.0,
            default_threshold=50,
            per_tool_thresholds={"bash": 10},
        )

        # Assert
        assert config.enabled is False
        assert config.window_seconds == 120.0
        assert config.default_threshold == 50
        assert config.per_tool_thresholds == {"bash": 10}


# =============================================================================
# create_rate_tracker Factory Tests
# =============================================================================


class TestCreateRateTracker:
    """Tests for create_rate_tracker factory function."""

    def test_returns_none_when_config_none(self) -> None:
        """Should return None when config is None."""
        # Act
        tracker = create_rate_tracker(None)

        # Assert
        assert tracker is None

    def test_returns_none_when_disabled(self) -> None:
        """Should return None when rate limiting is disabled."""
        # Arrange
        config = RateLimitConfig(enabled=False)

        # Act
        tracker = create_rate_tracker(config)

        # Assert
        assert tracker is None

    def test_returns_tracker_when_enabled(self) -> None:
        """Should return configured tracker when enabled."""
        # Arrange
        config = RateLimitConfig(
            enabled=True,
            window_seconds=120.0,
            default_threshold=50,
            per_tool_thresholds={"bash": 5},
        )

        # Act
        tracker = create_rate_tracker(config)

        # Assert
        assert tracker is not None
        assert tracker.window_seconds == 120.0
        assert tracker.default_threshold == 50
        assert tracker.per_tool_thresholds == {"bash": 5}


# =============================================================================
# Default Constants Tests
# =============================================================================


class TestDefaultConstants:
    """Tests for default constant values."""

    def test_default_window_is_60_seconds(self) -> None:
        """Default window should be 60 seconds."""
        assert DEFAULT_RATE_WINDOW_SECONDS == 60

    def test_default_threshold_is_30(self) -> None:
        """Default threshold should be 30 calls/minute."""
        assert DEFAULT_RATE_THRESHOLD == 30
