"""Tests for GET /api/stats endpoint.

Verifies route registration, dependency injection, schema serialization,
and response shape via FastAPI TestClient.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from mcp_acp.api.deps import get_proxy_state
from mcp_acp.api.routes.stats import router
from mcp_acp.manager.models import ProxyStats


# =============================================================================
# Fixtures
# =============================================================================


def _make_mock_state(
    *,
    total: int = 0,
    allowed: int = 0,
    denied: int = 0,
    hitl: int = 0,
    proxy_median: float | None = None,
    eval_median: float | None = None,
    hitl_median: float | None = None,
) -> MagicMock:
    """Build a mock ProxyState with configurable stats and latency."""
    state = MagicMock()
    state.get_stats.return_value = ProxyStats(
        requests_total=total,
        requests_allowed=allowed,
        requests_denied=denied,
        requests_hitl=hitl,
    )
    state.get_latency.return_value = {
        "proxy_latency": {"median_ms": proxy_median, "count": 0, "min_ms": None, "max_ms": None},
        "policy_eval": {"median_ms": eval_median, "count": 0, "min_ms": None, "max_ms": None},
        "hitl_wait": {"median_ms": hitl_median, "count": 0, "min_ms": None, "max_ms": None},
    }
    return state


@pytest.fixture
def mock_state() -> MagicMock:
    """Default mock with some data."""
    return _make_mock_state(
        total=100,
        allowed=80,
        denied=15,
        hitl=5,
        proxy_median=14.2,
        eval_median=3.1,
        hitl_median=1200.0,
    )


@pytest.fixture
def app(mock_state: MagicMock) -> FastAPI:
    """Create a test FastAPI app with stats router."""
    app = FastAPI()
    app.include_router(router, prefix="/api/stats")
    app.dependency_overrides[get_proxy_state] = lambda: mock_state
    return app


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    """Create a test client."""
    return TestClient(app)


# =============================================================================
# Tests
# =============================================================================


class TestGetStats:
    """Tests for GET /api/stats."""

    def test_returns_200(self, client: TestClient) -> None:
        """Endpoint returns 200 OK."""
        response = client.get("/api/stats")
        assert response.status_code == 200

    def test_response_has_counter_fields(self, client: TestClient) -> None:
        """Response includes all four counter fields."""
        data = client.get("/api/stats").json()
        assert data["requests_total"] == 100
        assert data["requests_allowed"] == 80
        assert data["requests_denied"] == 15
        assert data["requests_hitl"] == 5

    def test_response_has_latency_object(self, client: TestClient) -> None:
        """Response includes nested latency object with medians."""
        data = client.get("/api/stats").json()
        latency = data["latency"]
        assert latency["proxy_latency_ms"] == 14.2
        assert latency["policy_eval_ms"] == 3.1
        assert latency["hitl_wait_ms"] == 1200.0

    def test_latency_nulls_when_no_samples(self) -> None:
        """Latency fields are null when no samples recorded."""
        state = _make_mock_state(total=0, allowed=0, denied=0, hitl=0)
        app = FastAPI()
        app.include_router(router, prefix="/api/stats")
        app.dependency_overrides[get_proxy_state] = lambda: state
        client = TestClient(app)

        data = client.get("/api/stats").json()
        latency = data["latency"]
        assert latency["proxy_latency_ms"] is None
        assert latency["policy_eval_ms"] is None
        assert latency["hitl_wait_ms"] is None

    def test_response_shape_matches_schema(self, client: TestClient) -> None:
        """Response has exactly the expected top-level keys."""
        data = client.get("/api/stats").json()
        expected_keys = {
            "requests_total",
            "requests_allowed",
            "requests_denied",
            "requests_hitl",
            "latency",
        }
        assert set(data.keys()) == expected_keys

        expected_latency_keys = {
            "proxy_latency_ms",
            "policy_eval_ms",
            "hitl_wait_ms",
        }
        assert set(data["latency"].keys()) == expected_latency_keys

    def test_503_when_proxy_state_unavailable(self) -> None:
        """Returns 503 when ProxyState not wired (proxy still starting)."""
        app = FastAPI()
        app.include_router(router, prefix="/api/stats")
        # No dependency override — get_proxy_state raises HTTPException 503
        client = TestClient(app)

        response = client.get("/api/stats")
        assert response.status_code == 503
