"""Unit tests for pending approvals API routes.

Tests the pending HITL approval endpoints including SSE streaming.
Uses AAA pattern (Arrange-Act-Assert) for clarity.
"""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from mcp_acp.api.deps import get_identity_provider, get_proxy_state
from mcp_acp.exceptions import AuthenticationError
from mcp_acp.api.errors import APIError
from mcp_acp.api.routes.pending import _resolve_approval, router
from mcp_acp.api.schemas import ApprovalActionResponse, PendingApprovalResponse


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def mock_pending_approval() -> MagicMock:
    """Create a mock pending approval object."""
    approval = MagicMock()
    approval.id = "approval-123"
    approval.proxy_id = "proxy-1"
    approval.tool_name = "read_file"
    approval.path = "/project/file.txt"
    approval.subject_id = "user@example.com"
    approval.created_at = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    approval.timeout_seconds = 30
    approval.request_id = "req-456"
    approval.to_dict.return_value = {
        "id": "approval-123",
        "proxy_id": "proxy-1",
        "tool_name": "read_file",
        "path": "/project/file.txt",
        "subject_id": "user@example.com",
        "created_at": "2024-01-01T12:00:00+00:00",
        "timeout_seconds": 30,
        "request_id": "req-456",
    }
    return approval


@pytest.fixture
def mock_state(mock_pending_approval: MagicMock) -> MagicMock:
    """Create a mock proxy state."""
    state = MagicMock()
    state.get_pending_approvals.return_value = [mock_pending_approval]
    state.get_pending_approval.return_value = mock_pending_approval
    state.resolve_pending.return_value = True
    return state


@pytest.fixture
def mock_identity_provider() -> MagicMock:
    """Create a mock identity provider that returns authenticated user."""
    provider = MagicMock()
    identity = MagicMock()
    identity.subject_id = "user@example.com"
    provider.get_identity = AsyncMock(return_value=identity)
    return provider


@pytest.fixture
def app(mock_state: MagicMock, mock_identity_provider: MagicMock) -> FastAPI:
    """Create a test FastAPI app with pending router and mocked dependencies."""
    app = FastAPI()
    app.include_router(router, prefix="/api/approvals/pending")
    # Override dependencies for testing
    app.dependency_overrides[get_proxy_state] = lambda: mock_state
    app.dependency_overrides[get_identity_provider] = lambda: mock_identity_provider
    return app


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    """Create a test client."""
    return TestClient(app)


# =============================================================================
# Tests: List Pending Approvals
# =============================================================================


class TestListPendingApprovals:
    """Tests for GET /api/approvals/pending/list endpoint."""

    def test_returns_pending_approvals(self, client: TestClient, mock_pending_approval: MagicMock) -> None:
        """Given pending approvals, returns them as list."""
        # Act
        response = client.get("/api/approvals/pending/list")

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["id"] == "approval-123"
        assert data[0]["tool_name"] == "read_file"
        assert data[0]["path"] == "/project/file.txt"

    def test_returns_empty_list_when_none_pending(self) -> None:
        """Given no pending approvals, returns empty list."""
        # Arrange
        mock_state = MagicMock()
        mock_state.get_pending_approvals.return_value = []
        app = FastAPI()
        app.include_router(router, prefix="/api/approvals/pending")
        app.state.proxy_state = mock_state
        client = TestClient(app)

        # Act
        response = client.get("/api/approvals/pending/list")

        # Assert
        assert response.status_code == 200
        assert response.json() == []

    def test_handles_null_path(self) -> None:
        """Given approval with null path, serializes correctly."""
        # Arrange
        approval = MagicMock()
        approval.id = "approval-123"
        approval.proxy_id = "proxy-1"
        approval.tool_name = "list_tools"
        approval.path = None
        approval.subject_id = "user@example.com"
        approval.created_at = datetime.now(timezone.utc)
        approval.timeout_seconds = 30
        approval.request_id = "req-456"

        mock_state = MagicMock()
        mock_state.get_pending_approvals.return_value = [approval]

        app = FastAPI()
        app.include_router(router, prefix="/api/approvals/pending")
        app.state.proxy_state = mock_state
        client = TestClient(app)

        # Act
        response = client.get("/api/approvals/pending/list")

        # Assert
        assert response.status_code == 200
        assert response.json()[0]["path"] is None


# =============================================================================
# Tests: Approve Endpoint
# =============================================================================


class TestApproveEndpoint:
    """Tests for POST /api/approvals/pending/{id}/approve endpoint."""

    def test_approve_success(self, client: TestClient, mock_state: MagicMock) -> None:
        """Given valid approval ID and authenticated user, approves and returns success."""
        # Act
        response = client.post("/api/approvals/pending/approval-123/approve")

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "approved"
        assert data["approval_id"] == "approval-123"
        # Now includes approver_id
        mock_state.resolve_pending.assert_called_once_with("approval-123", "allow", "user@example.com")

    def test_approve_not_found(self, mock_identity_provider: MagicMock) -> None:
        """Given invalid approval ID, returns 404."""
        # Arrange
        mock_state = MagicMock()
        mock_state.resolve_pending.return_value = False
        mock_state.emit_system_event = MagicMock()
        # get_pending_approval returns the approval (so verification passes)
        mock_pending = MagicMock()
        mock_pending.subject_id = "user@example.com"
        mock_state.get_pending_approval.return_value = mock_pending

        app = FastAPI()
        app.include_router(router, prefix="/api/approvals/pending")
        app.dependency_overrides[get_proxy_state] = lambda: mock_state
        app.dependency_overrides[get_identity_provider] = lambda: mock_identity_provider
        client = TestClient(app)

        # Act
        response = client.post("/api/approvals/pending/nonexistent/approve")

        # Assert
        assert response.status_code == 404
        assert "not found" in response.json()["detail"]["message"].lower()

    def test_approve_requires_auth(self) -> None:
        """Given unauthenticated user, returns 401."""
        # Arrange
        mock_state = MagicMock()
        mock_identity_provider = MagicMock()
        mock_identity_provider.get_identity = AsyncMock(side_effect=AuthenticationError("Not logged in"))

        app = FastAPI()
        app.include_router(router, prefix="/api/approvals/pending")
        app.dependency_overrides[get_proxy_state] = lambda: mock_state
        app.dependency_overrides[get_identity_provider] = lambda: mock_identity_provider
        client = TestClient(app)

        # Act
        response = client.post("/api/approvals/pending/approval-123/approve")

        # Assert
        assert response.status_code == 401
        assert "authentication required" in response.json()["detail"]["message"].lower()

    def test_approve_requires_matching_identity(self, mock_identity_provider: MagicMock) -> None:
        """Given approver != requester, returns 403."""
        # Arrange
        mock_pending = MagicMock()
        mock_pending.subject_id = "other-user@example.com"  # Different from approver

        mock_state = MagicMock()
        mock_state.get_pending_approval.return_value = mock_pending

        app = FastAPI()
        app.include_router(router, prefix="/api/approvals/pending")
        app.dependency_overrides[get_proxy_state] = lambda: mock_state
        app.dependency_overrides[get_identity_provider] = lambda: mock_identity_provider
        client = TestClient(app)

        # Act
        response = client.post("/api/approvals/pending/approval-123/approve")

        # Assert
        assert response.status_code == 403
        assert "only approve your own" in response.json()["detail"]["message"].lower()


# =============================================================================
# Tests: Allow Once Endpoint
# =============================================================================


class TestAllowOnceEndpoint:
    """Tests for POST /api/approvals/pending/{id}/allow-once endpoint."""

    def test_allow_once_success(self, client: TestClient, mock_state: MagicMock) -> None:
        """Given valid approval ID and authenticated user, allows once without caching."""
        # Act
        response = client.post("/api/approvals/pending/approval-123/allow-once")

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "allowed_once"
        # Now includes approver_id
        mock_state.resolve_pending.assert_called_once_with("approval-123", "allow_once", "user@example.com")

    def test_allow_once_not_found(self, mock_identity_provider: MagicMock) -> None:
        """Given invalid approval ID, returns 404."""
        # Arrange
        mock_state = MagicMock()
        mock_state.resolve_pending.return_value = False
        mock_state.emit_system_event = MagicMock()
        # get_pending_approval returns the approval (so verification passes)
        mock_pending = MagicMock()
        mock_pending.subject_id = "user@example.com"
        mock_state.get_pending_approval.return_value = mock_pending

        app = FastAPI()
        app.include_router(router, prefix="/api/approvals/pending")
        app.dependency_overrides[get_proxy_state] = lambda: mock_state
        app.dependency_overrides[get_identity_provider] = lambda: mock_identity_provider
        client = TestClient(app)

        # Act
        response = client.post("/api/approvals/pending/nonexistent/allow-once")

        # Assert
        assert response.status_code == 404


# =============================================================================
# Tests: Deny Endpoint
# =============================================================================


class TestDenyEndpoint:
    """Tests for POST /api/approvals/pending/{id}/deny endpoint."""

    def test_deny_success(self, client: TestClient, mock_state: MagicMock) -> None:
        """Given valid approval ID and authenticated user, denies and returns success."""
        # Act
        response = client.post("/api/approvals/pending/approval-123/deny")

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "denied"
        # Now includes approver_id
        mock_state.resolve_pending.assert_called_once_with("approval-123", "deny", "user@example.com")

    def test_deny_not_found(self, mock_identity_provider: MagicMock) -> None:
        """Given invalid approval ID, returns 404."""
        # Arrange
        mock_state = MagicMock()
        mock_state.resolve_pending.return_value = False
        mock_state.emit_system_event = MagicMock()
        # get_pending_approval returns the approval (so verification passes)
        mock_pending = MagicMock()
        mock_pending.subject_id = "user@example.com"
        mock_state.get_pending_approval.return_value = mock_pending

        app = FastAPI()
        app.include_router(router, prefix="/api/approvals/pending")
        app.dependency_overrides[get_proxy_state] = lambda: mock_state
        app.dependency_overrides[get_identity_provider] = lambda: mock_identity_provider
        client = TestClient(app)

        # Act
        response = client.post("/api/approvals/pending/nonexistent/deny")

        # Assert
        assert response.status_code == 404


# =============================================================================
# Tests: Helper Functions
# =============================================================================


class TestResolveApprovalHelper:
    """Tests for _resolve_approval helper function."""

    def test_resolve_success_returns_response(self) -> None:
        """Given successful resolution, returns ApprovalActionResponse."""
        # Arrange
        mock_state = MagicMock()
        mock_state.resolve_pending.return_value = True

        # Act
        result = _resolve_approval("test-id", "allow", "approved", mock_state, "user@example.com")

        # Assert
        assert isinstance(result, ApprovalActionResponse)
        assert result.status == "approved"
        assert result.approval_id == "test-id"
        mock_state.resolve_pending.assert_called_once_with("test-id", "allow", "user@example.com")

    def test_resolve_failure_raises_404(self) -> None:
        """Given failed resolution, raises APIError 404."""
        # Arrange
        mock_state = MagicMock()
        mock_state.resolve_pending.return_value = False
        mock_state.emit_system_event = MagicMock()

        # Act & Assert
        with pytest.raises(APIError) as exc_info:
            _resolve_approval("test-id", "deny", "denied", mock_state, "user@example.com")

        assert exc_info.value.status_code == 404
        assert "test-id" in exc_info.value.detail["message"]

    def test_resolve_emits_event_on_failure(self) -> None:
        """Given failed resolution, emits system event."""
        # Arrange
        mock_state = MagicMock()
        mock_state.resolve_pending.return_value = False
        mock_state.emit_system_event = MagicMock()

        # Act
        with pytest.raises(APIError):
            _resolve_approval("test-id", "deny", "denied", mock_state, "user@example.com")

        # Assert
        mock_state.emit_system_event.assert_called_once()


# =============================================================================
# Tests: Response Models
# =============================================================================


class TestPendingApprovalResponse:
    """Tests for PendingApprovalResponse model."""

    def test_model_serialization(self) -> None:
        """PendingApprovalResponse serializes correctly."""
        # Arrange & Act
        response = PendingApprovalResponse(
            id="approval-123",
            proxy_id="proxy-1",
            tool_name="read_file",
            path="/project/file.txt",
            subject_id="user@example.com",
            created_at=datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
            timeout_seconds=30,
            request_id="req-456",
        )
        data = response.model_dump()

        # Assert
        assert data["id"] == "approval-123"
        assert data["tool_name"] == "read_file"
        assert data["path"] == "/project/file.txt"

    def test_model_with_null_path(self) -> None:
        """PendingApprovalResponse handles null path."""
        # Arrange & Act
        response = PendingApprovalResponse(
            id="approval-123",
            proxy_id="proxy-1",
            tool_name="list_tools",
            path=None,
            subject_id="user@example.com",
            created_at=datetime.now(timezone.utc),
            timeout_seconds=30,
            request_id="req-456",
        )

        # Assert
        assert response.path is None


class TestApprovalActionResponse:
    """Tests for ApprovalActionResponse model."""

    def test_model_serialization(self) -> None:
        """ApprovalActionResponse serializes correctly."""
        # Arrange & Act
        response = ApprovalActionResponse(
            status="approved",
            approval_id="approval-123",
        )
        data = response.model_dump()

        # Assert
        assert data["status"] == "approved"
        assert data["approval_id"] == "approval-123"
