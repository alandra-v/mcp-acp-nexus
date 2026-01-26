"""Tests for manager idle shutdown functionality.

Tests the _idle_shutdown_checker task and related constants.
"""

from __future__ import annotations

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_acp.manager.daemon import (
    IDLE_CHECK_INTERVAL_SECONDS,
    IDLE_TIMEOUT_SECONDS,
    STARTUP_GRACE_PERIOD_SECONDS,
    _idle_shutdown_checker,
)
from mcp_acp.manager.registry import ProxyRegistry


class TestIdleShutdownConstants:
    """Tests for idle shutdown constants."""

    def test_idle_check_interval_is_reasonable(self) -> None:
        """Check interval should be between 10-60 seconds."""
        assert 10 <= IDLE_CHECK_INTERVAL_SECONDS <= 60

    def test_idle_timeout_is_1_minute(self) -> None:
        """Idle timeout should be 1 minute (60 seconds)."""
        assert IDLE_TIMEOUT_SECONDS == 60.0

    def test_startup_grace_period_is_reasonable(self) -> None:
        """Grace period should be between 30-120 seconds."""
        assert 30 <= STARTUP_GRACE_PERIOD_SECONDS <= 120

    def test_grace_period_less_than_idle_timeout(self) -> None:
        """Grace period should be less than idle timeout."""
        assert STARTUP_GRACE_PERIOD_SECONDS < IDLE_TIMEOUT_SECONDS


class TestIdleShutdownChecker:
    """Tests for _idle_shutdown_checker task."""

    @pytest.fixture
    def registry(self) -> ProxyRegistry:
        """Create a fresh registry for each test."""
        return ProxyRegistry()

    @pytest.fixture
    def shutdown_event(self) -> asyncio.Event:
        """Create a shutdown event for each test."""
        return asyncio.Event()

    async def test_does_not_shutdown_during_grace_period(
        self,
        registry: ProxyRegistry,
        shutdown_event: asyncio.Event,
    ) -> None:
        """Checker should not trigger shutdown during grace period."""
        # Use a startup time that's recent (within grace period)
        startup_time = time.monotonic()

        # Mock sleep to return immediately but track calls
        sleep_count = 0

        async def mock_sleep(duration: float) -> None:
            nonlocal sleep_count
            sleep_count += 1
            if sleep_count >= 2:
                # Stop after 2 iterations
                shutdown_event.set()

        with patch("asyncio.sleep", mock_sleep):
            await _idle_shutdown_checker(registry, shutdown_event, startup_time)

        # Shutdown was set by our mock, not by idle detection
        # The checker should have continued past grace period checks
        assert sleep_count >= 2

    async def test_triggers_shutdown_when_idle(
        self,
        registry: ProxyRegistry,
        shutdown_event: asyncio.Event,
    ) -> None:
        """Checker triggers shutdown when manager is idle."""
        # Startup time well in the past (past grace period)
        startup_time = time.monotonic() - STARTUP_GRACE_PERIOD_SECONDS - 10

        # Set activity time well in the past (past idle timeout)
        registry._last_activity_time = time.monotonic() - IDLE_TIMEOUT_SECONDS - 10

        # Mock sleep to return immediately
        async def mock_sleep(duration: float) -> None:
            pass

        with patch("asyncio.sleep", mock_sleep):
            await _idle_shutdown_checker(registry, shutdown_event, startup_time)

        # Should have triggered shutdown
        assert shutdown_event.is_set()

    async def test_does_not_shutdown_with_proxies_connected(
        self,
        registry: ProxyRegistry,
        shutdown_event: asyncio.Event,
    ) -> None:
        """Checker does not shutdown when proxies are connected."""
        # Register a proxy
        reader, writer = AsyncMock(), AsyncMock()
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()

        await registry.register(
            proxy_name="test",
            proxy_id="px_test:test",
            instance_id="inst_1",
            config_summary={},
            socket_path="/tmp/test.sock",
            reader=reader,
            writer=writer,
        )

        # Startup time well in the past
        startup_time = time.monotonic() - STARTUP_GRACE_PERIOD_SECONDS - 10

        # Activity time well in the past
        registry._last_activity_time = time.monotonic() - IDLE_TIMEOUT_SECONDS - 10

        # Mock sleep and limit iterations
        iterations = 0

        async def mock_sleep(duration: float) -> None:
            nonlocal iterations
            iterations += 1
            if iterations >= 3:
                shutdown_event.set()  # Stop the loop externally

        with patch("asyncio.sleep", mock_sleep):
            await _idle_shutdown_checker(registry, shutdown_event, startup_time)

        # Shutdown was set by our mock after 3 iterations,
        # meaning the checker didn't trigger it (proxy was connected)
        assert iterations >= 3

    async def test_does_not_shutdown_with_sse_subscribers(
        self,
        registry: ProxyRegistry,
        shutdown_event: asyncio.Event,
    ) -> None:
        """Checker does not shutdown when SSE subscribers exist."""
        # Subscribe to SSE (simulates browser connection)
        await registry.subscribe_sse()

        # Startup time well in the past
        startup_time = time.monotonic() - STARTUP_GRACE_PERIOD_SECONDS - 10

        # Activity time well in the past
        registry._last_activity_time = time.monotonic() - IDLE_TIMEOUT_SECONDS - 10

        # Mock sleep and limit iterations
        iterations = 0

        async def mock_sleep(duration: float) -> None:
            nonlocal iterations
            iterations += 1
            if iterations >= 3:
                shutdown_event.set()

        with patch("asyncio.sleep", mock_sleep):
            await _idle_shutdown_checker(registry, shutdown_event, startup_time)

        # Checker didn't trigger shutdown (SSE subscriber present)
        assert iterations >= 3

    async def test_does_not_shutdown_with_recent_activity(
        self,
        registry: ProxyRegistry,
        shutdown_event: asyncio.Event,
    ) -> None:
        """Checker does not shutdown when there's recent activity."""
        # Startup time well in the past
        startup_time = time.monotonic() - STARTUP_GRACE_PERIOD_SECONDS - 10

        # Activity time is recent
        registry.record_activity()

        # Mock sleep and limit iterations
        iterations = 0

        async def mock_sleep(duration: float) -> None:
            nonlocal iterations
            iterations += 1
            if iterations >= 3:
                shutdown_event.set()

        with patch("asyncio.sleep", mock_sleep):
            await _idle_shutdown_checker(registry, shutdown_event, startup_time)

        # Checker didn't trigger shutdown (recent activity)
        assert iterations >= 3

    async def test_respects_existing_shutdown_event(
        self,
        registry: ProxyRegistry,
        shutdown_event: asyncio.Event,
    ) -> None:
        """Checker exits immediately if shutdown event is already set."""
        shutdown_event.set()
        startup_time = time.monotonic()

        sleep_called = False

        async def mock_sleep(duration: float) -> None:
            nonlocal sleep_called
            sleep_called = True

        with patch("asyncio.sleep", mock_sleep):
            await _idle_shutdown_checker(registry, shutdown_event, startup_time)

        # Should exit before sleeping
        assert not sleep_called
