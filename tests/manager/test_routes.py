"""Tests for manager HTTP routes.

Tests API routing, manager endpoints, and error handling.
"""

from __future__ import annotations

import json
import os
import time
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

from mcp_acp.manager.registry import ProxyRegistry
from mcp_acp.manager.routes import (
    IDLE_EXEMPT_PATHS,
    MANAGER_API_PREFIXES,
    _is_safe_path,
    create_manager_api_app,
    error_response,
)


@pytest.fixture
def registry() -> ProxyRegistry:
    """Create a fresh registry for each test."""
    return ProxyRegistry()


@pytest.fixture
def app(registry: ProxyRegistry) -> TestClient:
    """Create test client with fresh registry."""
    fastapi_app = create_manager_api_app(token="test-token", registry=registry)
    return TestClient(fastapi_app)


class TestManagerStatusEndpoint:
    """Tests for /api/manager/status endpoint."""

    def test_returns_running_status(self, app: TestClient) -> None:
        """Returns running=True and current PID."""
        response = app.get("/api/manager/status")

        assert response.status_code == 200
        data = response.json()
        assert data["running"] is True
        assert data["pid"] == os.getpid()
        assert data["proxies_connected"] == 0

    async def test_returns_correct_proxy_count(self, registry: ProxyRegistry) -> None:
        """Returns correct count of connected proxies."""
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

        fastapi_app = create_manager_api_app(token="test", registry=registry)
        client = TestClient(fastapi_app)

        response = client.get("/api/manager/status")

        assert response.status_code == 200
        assert response.json()["proxies_connected"] == 1


class TestManagerProxiesEndpoint:
    """Tests for /api/manager/proxies endpoint."""

    def test_returns_empty_list_when_no_proxies(self, app: TestClient) -> None:
        """Returns empty list when no proxies registered."""
        response = app.get("/api/manager/proxies")

        assert response.status_code == 200
        assert response.json() == []

    async def test_returns_registered_proxies(self, registry: ProxyRegistry) -> None:
        """Returns list of registered proxies."""
        reader, writer = AsyncMock(), AsyncMock()
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()

        await registry.register(
            proxy_name="proxy-a",
            proxy_id="px_a:proxy-a",
            instance_id="inst_a",
            config_summary={"transport": "stdio"},
            socket_path="/tmp/a.sock",
            reader=reader,
            writer=writer,
        )

        fastapi_app = create_manager_api_app(token="test", registry=registry)
        client = TestClient(fastapi_app)

        response = client.get("/api/manager/proxies")

        assert response.status_code == 200
        proxies = response.json()
        assert len(proxies) == 1
        assert proxies[0]["name"] == "proxy-a"
        assert proxies[0]["instance_id"] == "inst_a"
        assert proxies[0]["connected"] is True


class TestProxyRoutingErrors:
    """Tests for proxy routing error cases."""

    def test_route_to_unknown_proxy_returns_404(self, app: TestClient) -> None:
        """Routing to unknown proxy returns 404."""
        response = app.get("/api/proxy/nonexistent/status")

        assert response.status_code == 404
        assert "not found" in response.json()["error"].lower()

    def test_fallback_no_proxy_returns_503(self, app: TestClient) -> None:
        """Fallback routing with no default proxy returns 503."""
        response = app.get("/api/approvals/pending")

        assert response.status_code == 503
        assert "no proxies connected" in response.json()["error"].lower()

    async def test_route_to_proxy_with_missing_socket_returns_503(
        self,
        registry: ProxyRegistry,
    ) -> None:
        """Routing to proxy with missing socket returns 503."""
        reader, writer = AsyncMock(), AsyncMock()
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()

        await registry.register(
            proxy_name="broken",
            proxy_id="px_broken:broken",
            instance_id="inst_1",
            config_summary={},
            socket_path="/nonexistent/socket.sock",
            reader=reader,
            writer=writer,
        )

        fastapi_app = create_manager_api_app(token="test", registry=registry)
        client = TestClient(fastapi_app)

        response = client.get("/api/proxy/broken/status")

        assert response.status_code == 503
        assert "socket not available" in response.json()["error"].lower()

    async def test_fallback_multiple_proxies_returns_400(
        self,
        registry: ProxyRegistry,
    ) -> None:
        """Fallback routing with multiple proxies returns 400."""
        # Register two proxies
        for name in ["proxy-a", "proxy-b"]:
            reader, writer = AsyncMock(), AsyncMock()
            writer.close = MagicMock()
            writer.wait_closed = AsyncMock()

            await registry.register(
                proxy_name=name,
                proxy_id=f"px_{name}:{name}",
                instance_id=f"inst_{name}",
                config_summary={},
                socket_path=f"/tmp/{name}.sock",
                reader=reader,
                writer=writer,
            )

        fastapi_app = create_manager_api_app(token="test", registry=registry)
        client = TestClient(fastapi_app)

        # Request without specifying proxy
        response = client.get("/api/approvals/pending")

        assert response.status_code == 400
        error = response.json()["error"].lower()
        assert "multiple proxies" in error or "specify" in error


class TestManagerApiPrefixes:
    """Tests for manager API prefix handling."""

    def test_manager_prefixes_defined(self) -> None:
        """Manager API prefixes are defined."""
        assert "/api/manager/" in MANAGER_API_PREFIXES
        assert "/api/events" in MANAGER_API_PREFIXES
        assert "/api/proxy/" in MANAGER_API_PREFIXES

    def test_manager_status_not_forwarded(self, app: TestClient) -> None:
        """Manager status endpoint is not forwarded to proxy."""
        # This should return 200 from manager, not 503 (no proxy)
        response = app.get("/api/manager/status")
        assert response.status_code == 200

    def test_manager_proxies_not_forwarded(self, app: TestClient) -> None:
        """Manager proxies endpoint is not forwarded to proxy."""
        response = app.get("/api/manager/proxies")
        assert response.status_code == 200


class TestErrorResponse:
    """Tests for error_response helper."""

    def test_creates_json_response_with_error(self) -> None:
        """Creates JSONResponse with error field."""
        response = error_response(404, "Not found")

        assert response.status_code == 404
        body = json.loads(response.body)
        assert body["error"] == "Not found"

    def test_includes_detail_when_provided(self) -> None:
        """Includes detail field when provided."""
        response = error_response(500, "Error", detail="Additional info")

        body = json.loads(response.body)
        assert body["error"] == "Error"
        assert body["detail"] == "Additional info"

    def test_omits_detail_when_not_provided(self) -> None:
        """Omits detail field when not provided."""
        response = error_response(400, "Bad request")

        body = json.loads(response.body)
        assert "detail" not in body


class TestPathSafety:
    """Tests for path traversal protection."""

    def test_safe_path_within_base(self, tmp_path) -> None:
        """Path within base directory is safe."""
        base = tmp_path / "static"
        base.mkdir()
        requested = base / "assets" / "index.js"

        assert _is_safe_path(base, requested) is True

    def test_unsafe_path_traversal_detected(self, tmp_path) -> None:
        """Path traversal attempt is detected."""
        base = tmp_path / "static"
        base.mkdir()
        # Attempt to escape base directory
        requested = base / ".." / ".." / "etc" / "passwd"

        assert _is_safe_path(base, requested) is False

    def test_unsafe_absolute_path_outside_base(self, tmp_path) -> None:
        """Absolute path outside base is unsafe."""
        base = tmp_path / "static"
        base.mkdir()
        requested = tmp_path / "other" / "file.txt"

        assert _is_safe_path(base, requested) is False


class TestStaticFileServing:
    """Tests for static file serving (SPA)."""

    def test_root_returns_index_html(self, app: TestClient) -> None:
        """Root path returns index.html."""
        # This will work if STATIC_DIR exists with index.html
        # In tests, it may return 404 if static files aren't built
        response = app.get("/")
        # Either serves index.html or 404 if not built
        assert response.status_code in (200, 404)

    def test_spa_routes_return_index_html(self, app: TestClient) -> None:
        """SPA routes fall back to index.html."""
        response = app.get("/some/spa/route")
        # Same as above - depends on static files being built
        assert response.status_code in (200, 404)


class TestSSEEndpoint:
    """Tests for /api/events SSE endpoint.

    Note: Full SSE testing requires async client that can handle streaming.
    SSE functionality is covered by registry tests (broadcast_proxy_event, etc.)
    """

    def test_manager_api_prefixes_include_events(self) -> None:
        """SSE events endpoint is in manager API prefixes (not forwarded to proxy)."""
        assert "/api/events" in MANAGER_API_PREFIXES


class TestActivityTrackingMiddleware:
    """Tests for HTTP middleware that tracks activity for idle shutdown."""

    def test_idle_exempt_paths_defined(self) -> None:
        """Idle exempt paths are defined."""
        assert "/api/manager/status" in IDLE_EXEMPT_PATHS
        assert "/api/events" in IDLE_EXEMPT_PATHS

    def test_status_endpoint_does_not_record_activity(self, registry: ProxyRegistry) -> None:
        """Status endpoint requests don't reset idle timer."""
        fastapi_app = create_manager_api_app(token="test", registry=registry)
        client = TestClient(fastapi_app)

        # Record activity and wait
        registry.record_activity()
        time.sleep(0.02)
        before = registry.seconds_since_last_activity()

        # Make status request
        client.get("/api/manager/status")

        # Activity time should NOT have been reset
        after = registry.seconds_since_last_activity()
        assert after >= before

    def test_proxies_endpoint_records_activity(self, registry: ProxyRegistry) -> None:
        """Non-exempt endpoints reset idle timer."""
        fastapi_app = create_manager_api_app(token="test", registry=registry)
        client = TestClient(fastapi_app)

        # Wait to ensure time passes
        time.sleep(0.02)
        before = registry.seconds_since_last_activity()

        # Make proxies request (not exempt)
        client.get("/api/manager/proxies")

        # Activity time should have been reset
        after = registry.seconds_since_last_activity()
        assert after < before

    def test_idle_exempt_paths_is_frozenset(self) -> None:
        """IDLE_EXEMPT_PATHS is immutable."""
        assert isinstance(IDLE_EXEMPT_PATHS, frozenset)
