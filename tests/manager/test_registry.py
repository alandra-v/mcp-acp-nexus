"""Tests for ProxyRegistry.

Tests proxy registration, deregistration, and SSE event broadcasting.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from mcp_acp.manager.registry import ProxyConnection, ProxyRegistry


@pytest.fixture
def registry() -> ProxyRegistry:
    """Create a fresh registry for each test."""
    return ProxyRegistry()


@pytest.fixture
def mock_streams() -> tuple[MagicMock, MagicMock]:
    """Create mock stream reader and writer.

    Note: writer.write() is synchronous in real asyncio (buffers data),
    while drain() is async. Using MagicMock with specific async overrides.
    """
    reader = MagicMock()
    reader.readline = AsyncMock(return_value=b"")

    writer = MagicMock()
    writer.write = MagicMock()  # Synchronous in real asyncio
    writer.drain = AsyncMock()
    writer.close = MagicMock()
    writer.wait_closed = AsyncMock()
    return reader, writer


class TestProxyConnection:
    """Tests for ProxyConnection dataclass."""

    def test_to_dict_includes_expected_fields(self) -> None:
        """to_dict returns expected fields."""
        reader = MagicMock()
        writer = MagicMock()
        conn = ProxyConnection(
            proxy_name="test-proxy",
            instance_id="inst_abc123",
            config_summary={"backend": "stdio"},
            connected_at=datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
            socket_path="/tmp/proxy.sock",
            writer=writer,
            reader=reader,
        )

        d = conn.to_dict()

        assert d["name"] == "test-proxy"
        assert d["instance_id"] == "inst_abc123"
        assert d["connected"] is True
        assert d["config_summary"] == {"backend": "stdio"}
        assert d["socket_path"] == "/tmp/proxy.sock"
        assert "connected_at" in d

    def test_to_dict_excludes_internal_fields(self) -> None:
        """to_dict does not expose writer/reader."""
        reader = MagicMock()
        writer = MagicMock()
        conn = ProxyConnection(
            proxy_name="test",
            instance_id="inst_123",
            config_summary={},
            connected_at=datetime.now(timezone.utc),
            socket_path="/tmp/test.sock",
            writer=writer,
            reader=reader,
        )

        d = conn.to_dict()

        assert "writer" not in d
        assert "reader" not in d
        assert "_event_task" not in d


class TestProxyRegistration:
    """Tests for proxy registration and deregistration."""

    async def test_register_adds_proxy(
        self,
        registry: ProxyRegistry,
        mock_streams: tuple[AsyncMock, AsyncMock],
    ) -> None:
        """Registering a proxy adds it to the registry."""
        reader, writer = mock_streams

        result = await registry.register(
            proxy_name="test-proxy",
            instance_id="inst_123",
            config_summary={"key": "value"},
            socket_path="/tmp/test.sock",
            reader=reader,
            writer=writer,
        )

        assert result is True
        assert await registry.proxy_count() == 1

        proxy = await registry.get_proxy("test-proxy")
        assert proxy is not None
        assert proxy.proxy_name == "test-proxy"
        assert proxy.instance_id == "inst_123"

    async def test_register_replaces_existing_connection(
        self,
        registry: ProxyRegistry,
        mock_streams: tuple[AsyncMock, AsyncMock],
    ) -> None:
        """Registering same name replaces existing connection."""
        reader1, writer1 = mock_streams
        reader2, writer2 = AsyncMock(), AsyncMock()
        writer2.close = MagicMock()
        writer2.wait_closed = AsyncMock()

        # Register first
        await registry.register(
            proxy_name="proxy-a",
            instance_id="inst_1",
            config_summary={},
            socket_path="/tmp/a1.sock",
            reader=reader1,
            writer=writer1,
        )

        # Register again with same name
        await registry.register(
            proxy_name="proxy-a",
            instance_id="inst_2",
            config_summary={},
            socket_path="/tmp/a2.sock",
            reader=reader2,
            writer=writer2,
        )

        # Should still have only one proxy
        assert await registry.proxy_count() == 1

        # Should have the new instance
        proxy = await registry.get_proxy("proxy-a")
        assert proxy is not None
        assert proxy.instance_id == "inst_2"

        # Old writer should be closed
        writer1.close.assert_called()

    async def test_deregister_removes_proxy(
        self,
        registry: ProxyRegistry,
        mock_streams: tuple[AsyncMock, AsyncMock],
    ) -> None:
        """Deregistering removes proxy from registry."""
        reader, writer = mock_streams

        await registry.register(
            proxy_name="to-remove",
            instance_id="inst_123",
            config_summary={},
            socket_path="/tmp/remove.sock",
            reader=reader,
            writer=writer,
        )

        assert await registry.proxy_count() == 1

        result = await registry.deregister("to-remove")

        assert result is True
        assert await registry.proxy_count() == 0
        assert await registry.get_proxy("to-remove") is None

    async def test_deregister_nonexistent_returns_false(
        self,
        registry: ProxyRegistry,
    ) -> None:
        """Deregistering non-existent proxy returns False."""
        result = await registry.deregister("does-not-exist")
        assert result is False

    async def test_get_proxy_returns_none_for_unknown(
        self,
        registry: ProxyRegistry,
    ) -> None:
        """get_proxy returns None for unknown proxy name."""
        result = await registry.get_proxy("unknown")
        assert result is None

    async def test_list_proxies_returns_all(
        self,
        registry: ProxyRegistry,
    ) -> None:
        """list_proxies returns all registered proxies."""
        for i in range(3):
            reader, writer = AsyncMock(), AsyncMock()
            writer.close = MagicMock()
            writer.wait_closed = AsyncMock()
            await registry.register(
                proxy_name=f"proxy-{i}",
                instance_id=f"inst_{i}",
                config_summary={},
                socket_path=f"/tmp/proxy{i}.sock",
                reader=reader,
                writer=writer,
            )

        proxies = await registry.list_proxies()

        assert len(proxies) == 3
        names = {p["name"] for p in proxies}
        assert names == {"proxy-0", "proxy-1", "proxy-2"}

    async def test_close_all_removes_all_proxies(
        self,
        registry: ProxyRegistry,
    ) -> None:
        """close_all removes all proxies and closes connections."""
        writers = []
        for i in range(3):
            reader, writer = AsyncMock(), AsyncMock()
            writer.close = MagicMock()
            writer.wait_closed = AsyncMock()
            writers.append(writer)
            await registry.register(
                proxy_name=f"proxy-{i}",
                instance_id=f"inst_{i}",
                config_summary={},
                socket_path=f"/tmp/proxy{i}.sock",
                reader=reader,
                writer=writer,
            )

        assert await registry.proxy_count() == 3

        await registry.close_all()

        assert await registry.proxy_count() == 0
        for writer in writers:
            writer.close.assert_called()


class TestSSEBroadcasting:
    """Tests for SSE event broadcasting."""

    async def test_subscribe_returns_queue(
        self,
        registry: ProxyRegistry,
    ) -> None:
        """subscribe_sse returns an asyncio Queue."""
        queue = await registry.subscribe_sse()
        assert isinstance(queue, asyncio.Queue)
        assert registry.sse_subscriber_count == 1

    async def test_unsubscribe_removes_queue(
        self,
        registry: ProxyRegistry,
    ) -> None:
        """unsubscribe_sse removes the queue."""
        queue = await registry.subscribe_sse()
        assert registry.sse_subscriber_count == 1

        await registry.unsubscribe_sse(queue)
        assert registry.sse_subscriber_count == 0

    async def test_unsubscribe_unknown_queue_is_safe(
        self,
        registry: ProxyRegistry,
    ) -> None:
        """Unsubscribing unknown queue doesn't raise."""
        unknown_queue: asyncio.Queue[dict] = asyncio.Queue()
        # Should not raise
        await registry.unsubscribe_sse(unknown_queue)

    async def test_registration_broadcasts_event(
        self,
        registry: ProxyRegistry,
        mock_streams: tuple[AsyncMock, AsyncMock],
    ) -> None:
        """Proxy registration broadcasts proxy_registered event."""
        queue = await registry.subscribe_sse()
        reader, writer = mock_streams

        await registry.register(
            proxy_name="new-proxy",
            instance_id="inst_new",
            config_summary={},
            socket_path="/tmp/new.sock",
            reader=reader,
            writer=writer,
        )

        # Should receive registration event
        event = queue.get_nowait()
        assert event["type"] == "proxy_registered"
        assert event["data"]["proxy_name"] == "new-proxy"
        assert event["data"]["instance_id"] == "inst_new"

    async def test_deregistration_broadcasts_event(
        self,
        registry: ProxyRegistry,
        mock_streams: tuple[AsyncMock, AsyncMock],
    ) -> None:
        """Proxy deregistration broadcasts proxy_disconnected event."""
        reader, writer = mock_streams

        await registry.register(
            proxy_name="leaving-proxy",
            instance_id="inst_leave",
            config_summary={},
            socket_path="/tmp/leave.sock",
            reader=reader,
            writer=writer,
        )

        queue = await registry.subscribe_sse()

        await registry.deregister("leaving-proxy")

        event = queue.get_nowait()
        assert event["type"] == "proxy_disconnected"
        assert event["data"]["proxy_name"] == "leaving-proxy"

    async def test_broadcast_proxy_event_adds_proxy_name(
        self,
        registry: ProxyRegistry,
    ) -> None:
        """broadcast_proxy_event adds proxy_name to event data."""
        queue = await registry.subscribe_sse()

        await registry.broadcast_proxy_event(
            proxy_name="source-proxy",
            event_type="pending_created",
            data={"request_id": "req_123"},
        )

        event = queue.get_nowait()
        assert event["type"] == "pending_created"
        assert event["data"]["proxy_name"] == "source-proxy"
        assert event["data"]["request_id"] == "req_123"

    async def test_multiple_subscribers_receive_events(
        self,
        registry: ProxyRegistry,
    ) -> None:
        """All subscribers receive broadcast events."""
        queue1 = await registry.subscribe_sse()
        queue2 = await registry.subscribe_sse()
        queue3 = await registry.subscribe_sse()

        await registry.broadcast_snapshot("test_event", {"key": "value"})

        # All queues should have the event
        for queue in [queue1, queue2, queue3]:
            event = queue.get_nowait()
            assert event["type"] == "test_event"
            assert event["data"]["key"] == "value"

    async def test_broadcast_includes_timestamp(
        self,
        registry: ProxyRegistry,
    ) -> None:
        """Broadcast events include timestamp."""
        queue = await registry.subscribe_sse()

        await registry.broadcast_snapshot("test_event", {})

        event = queue.get_nowait()
        assert "timestamp" in event
        # Should be ISO format
        assert "T" in event["timestamp"]
