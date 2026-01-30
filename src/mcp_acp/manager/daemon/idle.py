"""Idle shutdown checker for the manager daemon.

Monitors manager activity and triggers shutdown when idle:
- No proxies registered
- No browser SSE subscribers
- No activity for IDLE_TIMEOUT_SECONDS
"""

from __future__ import annotations

__all__ = [
    "IDLE_CHECK_INTERVAL_SECONDS",
    "IDLE_TIMEOUT_SECONDS",
    "STARTUP_GRACE_PERIOD_SECONDS",
    "idle_shutdown_checker",
]

import asyncio
import logging
import time

from mcp_acp.manager.models import ManagerSystemEvent
from mcp_acp.manager.registry import ProxyRegistry

from .log_config import log_event

# How often to check if manager is idle (seconds)
IDLE_CHECK_INTERVAL_SECONDS = 30.0

# Shutdown manager after this many seconds of inactivity (seconds)
IDLE_TIMEOUT_SECONDS = 300.0

# Don't check for idle shutdown during startup grace period (seconds)
STARTUP_GRACE_PERIOD_SECONDS = 60.0


async def idle_shutdown_checker(
    registry: ProxyRegistry,
    shutdown_event: asyncio.Event,
    startup_time: float,
) -> None:
    """Check if manager is idle and trigger shutdown if so.

    Idle conditions (all must be true):
    - No proxies registered
    - No browser SSE subscribers
    - No activity for IDLE_TIMEOUT_SECONDS

    Args:
        registry: Proxy registry to check for activity.
        shutdown_event: Event to set when shutdown should occur.
        startup_time: Monotonic time when manager started (for grace period).
    """
    while not shutdown_event.is_set():
        await asyncio.sleep(IDLE_CHECK_INTERVAL_SECONDS)

        # Grace period: don't check during first 60s after startup
        if time.monotonic() - startup_time < STARTUP_GRACE_PERIOD_SECONDS:
            continue

        proxy_count = await registry.proxy_count()
        sse_count = registry.sse_subscriber_count
        seconds_idle = registry.seconds_since_last_activity()

        # Idle = no proxies AND no browsers AND no activity for 5 mins
        is_idle = proxy_count == 0 and sse_count == 0 and seconds_idle >= IDLE_TIMEOUT_SECONDS

        if is_idle:
            log_event(
                logging.INFO,
                ManagerSystemEvent(
                    event="idle_shutdown_triggered",
                    message=f"Manager idle for {seconds_idle:.0f}s, shutting down",
                    details={
                        "proxy_count": proxy_count,
                        "sse_count": sse_count,
                        "seconds_idle": seconds_idle,
                    },
                ),
            )
            shutdown_event.set()
            return
