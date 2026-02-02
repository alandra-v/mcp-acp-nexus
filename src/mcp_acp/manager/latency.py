"""Per-request latency tracking with circular buffer.

Provides rolling statistics (median, min, max, count) over the most
recent LATENCY_BUFFER_SIZE samples.  Thread-safe for single-writer
(the proxy event loop) but not for concurrent writers.
"""

from __future__ import annotations

__all__ = ["LatencyTracker"]

import statistics
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from mcp_acp.constants import LATENCY_BUFFER_SIZE


@dataclass(slots=True)
class LatencyTracker:
    """Circular-buffer latency tracker for a single metric.

    Keeps the most recent ``maxlen`` samples and exposes rolling
    statistics used by the ``/api/stats`` endpoint.
    """

    _buffer: deque[float] = field(default_factory=lambda: deque(maxlen=LATENCY_BUFFER_SIZE))

    def record(self, ms: float) -> None:
        """Append a latency sample (milliseconds)."""
        self._buffer.append(ms)

    def median(self) -> float | None:
        """Return the median of buffered samples, or ``None`` if empty."""
        if not self._buffer:
            return None
        return statistics.median(self._buffer)

    def count(self) -> int:
        """Return the number of samples currently in the buffer."""
        return len(self._buffer)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-friendly dict.

        Returns:
            Dict with ``median_ms``, ``count``, ``min_ms``, ``max_ms``.
            Values are ``None`` when the buffer is empty.
        """
        med = self.median()
        if med is None:
            return {
                "median_ms": None,
                "count": 0,
                "min_ms": None,
                "max_ms": None,
            }
        return {
            "median_ms": round(med, 2),
            "count": self.count(),
            "min_ms": round(min(self._buffer), 2),
            "max_ms": round(max(self._buffer), 2),
        }
