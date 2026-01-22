"""Tests for ManagerClient.

Tests proxy-to-manager communication and graceful degradation.
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from mcp_acp.manager.client import ManagerClient, is_manager_available
from mcp_acp.manager.protocol import encode_ndjson


@pytest.fixture
def temp_socket_path() -> Path:
    """Create a temporary socket path with a short path (Unix socket limit ~104 chars)."""
    # Use /tmp directly for shorter paths (pytest tmp_path is too long for Unix sockets)
    tmpdir = tempfile.mkdtemp(prefix="mcp_", dir="/tmp")
    socket_path = Path(tmpdir) / "mgr.sock"
    yield socket_path
    # Cleanup
    socket_path.unlink(missing_ok=True)
    try:
        os.rmdir(tmpdir)
    except OSError:
        pass


@pytest.fixture
def client(temp_socket_path: Path) -> ManagerClient:
    """Create a ManagerClient for testing."""
    return ManagerClient(
        proxy_name="test-proxy",
        instance_id="inst_test123",
        manager_socket_path=temp_socket_path,
        proxy_api_socket_path="/tmp/proxy.sock",
    )


class TestManagerClientInit:
    """Tests for ManagerClient initialization."""

    def test_initializes_with_expected_state(self, temp_socket_path: Path) -> None:
        """Client initializes with expected state."""
        client = ManagerClient(
            proxy_name="my-proxy",
            instance_id="inst_abc",
            manager_socket_path=temp_socket_path,
            proxy_api_socket_path="/tmp/my.sock",
        )

        assert client.connected is False
        assert client.registered is False

    def test_uses_default_socket_path_when_not_provided(self) -> None:
        """Uses MANAGER_SOCKET_PATH when not provided."""
        from mcp_acp.constants import MANAGER_SOCKET_PATH

        client = ManagerClient(
            proxy_name="test",
            instance_id="inst_1",
        )

        assert client._socket_path == MANAGER_SOCKET_PATH


class TestManagerClientConnect:
    """Tests for ManagerClient.connect()."""

    async def test_connect_returns_false_when_socket_missing(
        self,
        client: ManagerClient,
        temp_socket_path: Path,
    ) -> None:
        """connect() returns False when socket doesn't exist."""
        # Socket path doesn't exist
        assert not temp_socket_path.exists()

        result = await client.connect()

        assert result is False
        assert client.connected is False

    async def test_connect_returns_false_on_connection_refused(
        self,
        client: ManagerClient,
        temp_socket_path: Path,
    ) -> None:
        """connect() returns False when connection is refused."""
        # Create the socket file but no server is listening
        temp_socket_path.touch()

        result = await client.connect()

        assert result is False
        assert client.connected is False

    async def test_connect_succeeds_with_running_server(
        self,
        temp_socket_path: Path,
    ) -> None:
        """connect() succeeds when manager is running."""

        # Start a simple UDS server
        async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            # Just accept connection
            pass

        server = await asyncio.start_unix_server(handle_client, path=str(temp_socket_path))

        client = ManagerClient(
            proxy_name="test",
            instance_id="inst_1",
            manager_socket_path=temp_socket_path,
        )

        try:
            result = await client.connect()
            assert result is True
            assert client.connected is True
        finally:
            server.close()
            await server.wait_closed()
            await client.disconnect()


class TestManagerClientRegister:
    """Tests for ManagerClient.register()."""

    async def test_register_fails_when_not_connected(
        self,
        client: ManagerClient,
    ) -> None:
        """register() returns False when not connected."""
        assert client.connected is False

        result = await client.register({"key": "value"})

        assert result is False
        assert client.registered is False

    async def test_register_succeeds_with_valid_response(
        self,
        temp_socket_path: Path,
    ) -> None:
        """register() succeeds when manager responds with ok=True."""

        # Server that accepts registration
        async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            # Read registration message
            await reader.readline()
            # Send success response
            response = encode_ndjson({"type": "registered", "ok": True})
            writer.write(response)
            await writer.drain()

        server = await asyncio.start_unix_server(handle_client, path=str(temp_socket_path))

        client = ManagerClient(
            proxy_name="test",
            instance_id="inst_1",
            manager_socket_path=temp_socket_path,
            proxy_api_socket_path="/tmp/test.sock",
        )

        try:
            await client.connect()
            result = await client.register({"transport": "stdio"})

            assert result is True
            assert client.registered is True
        finally:
            server.close()
            await server.wait_closed()
            await client.disconnect()

    async def test_register_fails_with_rejection(
        self,
        temp_socket_path: Path,
    ) -> None:
        """register() returns False when manager rejects."""

        async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await reader.readline()
            response = encode_ndjson({"type": "registered", "ok": False, "error": "Invalid protocol"})
            writer.write(response)
            await writer.drain()

        server = await asyncio.start_unix_server(handle_client, path=str(temp_socket_path))

        client = ManagerClient(
            proxy_name="test",
            instance_id="inst_1",
            manager_socket_path=temp_socket_path,
        )

        try:
            await client.connect()
            result = await client.register({})

            assert result is False
            assert client.registered is False
        finally:
            server.close()
            await server.wait_closed()
            await client.disconnect()

    async def test_register_sends_correct_message(
        self,
        temp_socket_path: Path,
    ) -> None:
        """register() sends correct registration message."""
        received_message = None

        async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            nonlocal received_message
            line = await reader.readline()
            received_message = json.loads(line.decode())
            response = encode_ndjson({"type": "registered", "ok": True})
            writer.write(response)
            await writer.drain()

        server = await asyncio.start_unix_server(handle_client, path=str(temp_socket_path))

        client = ManagerClient(
            proxy_name="my-proxy",
            instance_id="inst_abc",
            manager_socket_path=temp_socket_path,
            proxy_api_socket_path="/tmp/my.sock",
        )

        try:
            await client.connect()
            await client.register({"backend": "stdio"})

            assert received_message is not None
            assert received_message["type"] == "register"
            assert received_message["proxy_name"] == "my-proxy"
            assert received_message["instance_id"] == "inst_abc"
            assert received_message["socket_path"] == "/tmp/my.sock"
            assert received_message["config_summary"] == {"backend": "stdio"}
        finally:
            server.close()
            await server.wait_closed()
            await client.disconnect()


class TestManagerClientPushEvent:
    """Tests for ManagerClient.push_event()."""

    async def test_push_event_silent_when_not_registered(
        self,
        client: ManagerClient,
    ) -> None:
        """push_event() silently returns when not registered."""
        # Should not raise
        await client.push_event("test_event", {"key": "value"})

    async def test_push_event_sends_message_when_registered(
        self,
        temp_socket_path: Path,
    ) -> None:
        """push_event() sends event message when registered."""
        received_messages: list[dict] = []
        event_received = asyncio.Event()

        async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            # Handle registration
            await reader.readline()
            writer.write(encode_ndjson({"type": "registered", "ok": True}))
            await writer.drain()

            # Read one event with timeout
            try:
                line = await asyncio.wait_for(reader.readline(), timeout=2.0)
                if line:
                    received_messages.append(json.loads(line.decode()))
                    event_received.set()
            except asyncio.TimeoutError:
                pass

        server = await asyncio.start_unix_server(handle_client, path=str(temp_socket_path))

        client = ManagerClient(
            proxy_name="test",
            instance_id="inst_1",
            manager_socket_path=temp_socket_path,
        )

        try:
            await client.connect()
            await client.register({})

            await client.push_event("pending_created", {"request_id": "req_123"})
            await asyncio.wait_for(event_received.wait(), timeout=2.0)

            assert len(received_messages) >= 1
            event = received_messages[0]
            assert event["type"] == "event"
            assert event["event_type"] == "pending_created"
            assert event["data"]["request_id"] == "req_123"
        finally:
            await client.disconnect()
            server.close()
            await server.wait_closed()


class TestManagerClientDisconnect:
    """Tests for ManagerClient.disconnect()."""

    async def test_disconnect_resets_state(
        self,
        temp_socket_path: Path,
    ) -> None:
        """disconnect() resets connected and registered state."""

        async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await reader.readline()
            writer.write(encode_ndjson({"type": "registered", "ok": True}))
            await writer.drain()

        server = await asyncio.start_unix_server(handle_client, path=str(temp_socket_path))

        client = ManagerClient(
            proxy_name="test",
            instance_id="inst_1",
            manager_socket_path=temp_socket_path,
        )

        try:
            await client.connect()
            await client.register({})

            assert client.connected is True
            assert client.registered is True

            await client.disconnect()

            assert client.connected is False
            assert client.registered is False
        finally:
            server.close()
            await server.wait_closed()

    async def test_disconnect_is_safe_when_not_connected(
        self,
        client: ManagerClient,
    ) -> None:
        """disconnect() is safe to call when not connected."""
        # Should not raise
        await client.disconnect()
        await client.disconnect()  # Multiple calls are safe


class TestGracefulDegradation:
    """Tests for graceful degradation when manager is unavailable."""

    async def test_proxy_operations_work_without_manager(
        self,
        client: ManagerClient,
    ) -> None:
        """Proxy operations don't fail when manager is unavailable."""
        # connect() returns False but doesn't raise
        result = await client.connect()
        assert result is False

        # push_event() is silent when not connected
        await client.push_event("test", {})  # Should not raise

        # disconnect() is safe
        await client.disconnect()  # Should not raise

    async def test_reconnection_after_manager_restart(
        self,
        temp_socket_path: Path,
    ) -> None:
        """Client reconnects when manager becomes available again."""
        client = ManagerClient(
            proxy_name="test",
            instance_id="inst_1",
            manager_socket_path=temp_socket_path,
        )

        # Initially manager not running
        result = await client.connect()
        assert result is False

        # Start manager
        async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            # Just accept connection (don't read/write to avoid blocking)
            pass

        server = await asyncio.start_unix_server(handle_client, path=str(temp_socket_path))

        try:
            # Now connect should succeed
            result = await client.connect()
            assert result is True
            assert client.connected is True
        finally:
            await client.disconnect()
            server.close()
            await server.wait_closed()


class TestIsManagerAvailable:
    """Tests for is_manager_available() helper."""

    def test_returns_false_when_socket_missing(self) -> None:
        """Returns False when socket file doesn't exist."""
        with patch("mcp_acp.manager.client.MANAGER_SOCKET_PATH", Path("/tmp/nonexistent.sock")):
            result = is_manager_available()
            assert result is False

    async def test_returns_true_when_manager_running(self, temp_socket_path: Path) -> None:
        """Returns True when manager is accepting connections."""

        async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_unix_server(handle_client, path=str(temp_socket_path))

        try:
            with patch("mcp_acp.manager.client.MANAGER_SOCKET_PATH", temp_socket_path):
                result = is_manager_available()
                assert result is True
        finally:
            server.close()
            await server.wait_closed()
            # Allow asyncio to clean up transports
            await asyncio.sleep(0)
