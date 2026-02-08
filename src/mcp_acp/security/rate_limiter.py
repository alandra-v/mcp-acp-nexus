"""Rate limiting for detecting runaway LLM loops and abuse.

This module provides per-session rate tracking to catch:
- Runaway LLM loops (same tool called repeatedly)
- Data exfiltration attempts (rapid file reads)
- Credential abuse (excessive tool usage)

When rate limits are exceeded, HITL is triggered to let the user decide
if the activity is legitimate.

Usage:
    tracker = SessionRateTracker()

    # Check before each tool call
    allowed, count = tracker.check(session_id, tool_name)
    if not allowed:
        # Trigger HITL dialog
        ...

    # Clean up when session ends
    tracker.cleanup_session(session_id)
"""

from __future__ import annotations

__all__ = [
    "DEFAULT_RATE_THRESHOLD",
    "DEFAULT_RATE_WINDOW_SECONDS",
    "RateLimitConfig",
    "SessionRateTracker",
    "create_rate_tracker",
]

from collections import deque
from dataclasses import dataclass, field
from time import monotonic

# ============================================================================
# Rate Limiting Constants (module-level, not in constants.py)
# ============================================================================

# Default sliding window for rate tracking (seconds)
DEFAULT_RATE_WINDOW_SECONDS: int = 60

# Default threshold before HITL trigger (calls per tool per window)
# Why 30? Based on real-world Claude Code usage patterns:
# - Normal usage: 10-20 calls/tool/minute (bursty but spaced)
# - Aggressive batch jobs: 30-40 calls/tool/minute (legitimate but unusual)
# - Runaway LLM loops: 50+ calls/tool/minute (2+ calls/sec sustained)
# At 30/min threshold:
# - Normal usage rarely triggers
# - Aggressive batch jobs may trigger once (user confirms, continues)
# - Runaway loops trigger within 15-30 seconds (before excessive damage)
DEFAULT_RATE_THRESHOLD: int = 30


@dataclass(frozen=True, slots=True)
class RateLimitConfig:
    """Configuration for per-session rate limiting.

    Attributes:
        enabled: Whether rate limiting is active.
        window_seconds: Sliding window duration for counting calls.
        default_threshold: Default max calls per tool before triggering.
        per_tool_thresholds: Custom thresholds for specific tools.

    Note:
        Currently, rate limit breaches always trigger HITL dialog.
        Future: Add on_breach config for hitl/deny/warn modes.
    """

    enabled: bool = True
    window_seconds: float = DEFAULT_RATE_WINDOW_SECONDS
    default_threshold: int = DEFAULT_RATE_THRESHOLD
    per_tool_thresholds: dict[str, int] = field(default_factory=dict)


@dataclass(slots=True)
class SessionRateTracker:
    """Track request rates per session using sliding window.

    Uses a sliding window algorithm to count tool calls per session.
    Each session tracks calls per tool independently.

    Thread-safety: This class is NOT thread-safe. In async contexts,
    calls from the same session are typically sequential, so this is fine.
    For multi-threaded usage, add locking.

    Attributes:
        window_seconds: Duration of the sliding window.
        default_threshold: Max calls before rate limit triggers.
        per_tool_thresholds: Custom thresholds for specific tools.
    """

    window_seconds: float = DEFAULT_RATE_WINDOW_SECONDS
    default_threshold: int = DEFAULT_RATE_THRESHOLD
    per_tool_thresholds: dict[str, int] = field(default_factory=dict)

    # Internal state: {session_id: {tool_name: deque[timestamp]}}
    _windows: dict[str, dict[str, deque[float]]] = field(default_factory=dict)

    def check(self, session_id: str, tool_name: str) -> tuple[bool, int]:
        """Check if request is within rate limit.

        Args:
            session_id: Current session identifier.
            tool_name: Tool being invoked.

        Returns:
            Tuple of (is_allowed, current_count).
            is_allowed is False if the threshold would be exceeded.
            current_count is the number of calls in the current window
            (including this one if allowed).
        """
        now = monotonic()
        cutoff = now - self.window_seconds

        # Get or create session windows
        if session_id not in self._windows:
            self._windows[session_id] = {}
        session_windows = self._windows[session_id]

        # Get or create tool window
        if tool_name not in session_windows:
            session_windows[tool_name] = deque()
        window = session_windows[tool_name]

        # Prune old entries outside the window
        while window and window[0] < cutoff:
            window.popleft()

        # Check threshold
        threshold = self.per_tool_thresholds.get(tool_name, self.default_threshold)
        current_count = len(window)

        if current_count >= threshold:
            # Rate limit exceeded
            return False, current_count

        # Record this request
        window.append(now)
        return True, current_count + 1

    def get_count(self, session_id: str, tool_name: str) -> int:
        """Get current count for a session/tool without recording a new call.

        Args:
            session_id: Session identifier.
            tool_name: Tool name.

        Returns:
            Number of calls in the current window.
        """
        now = monotonic()
        cutoff = now - self.window_seconds

        session_windows = self._windows.get(session_id, {})
        window = session_windows.get(tool_name)

        if not window:
            return 0

        # Count non-expired entries
        return sum(1 for t in window if t >= cutoff)

    def cleanup_session(self, session_id: str) -> None:
        """Remove tracking data for ended session.

        Call this when a session ends to free memory.

        Args:
            session_id: Session identifier to clean up.
        """
        self._windows.pop(session_id, None)

    def reset_tool(self, session_id: str, tool_name: str) -> None:
        """Reset rate tracking for a specific session/tool combination.

        Call this after user approves a rate limit breach to avoid
        immediately triggering another HITL dialog.

        Args:
            session_id: Session identifier.
            tool_name: Tool name to reset.
        """
        session_windows = self._windows.get(session_id)
        if session_windows and tool_name in session_windows:
            session_windows[tool_name].clear()

    def clear(self) -> None:
        """Clear all tracking data.

        Useful for testing or resetting state.
        """
        self._windows.clear()

    @property
    def active_sessions(self) -> int:
        """Number of sessions currently being tracked."""
        return len(self._windows)


def create_rate_tracker(config: RateLimitConfig | None = None) -> SessionRateTracker | None:
    """Create a rate tracker from configuration.

    Args:
        config: Rate limiting configuration. If None or disabled, returns None.

    Returns:
        SessionRateTracker instance if enabled, None otherwise.
    """
    if config is None or not config.enabled:
        return None

    return SessionRateTracker(
        window_seconds=config.window_seconds,
        default_threshold=config.default_threshold,
        per_tool_thresholds=config.per_tool_thresholds,
    )
