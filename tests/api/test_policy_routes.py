"""Unit tests for policy API routes.

Tests the policy CRUD endpoints.
Uses AAA pattern (Arrange-Act-Assert) for clarity.
"""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from mcp_acp.api.errors import APIError
from mcp_acp.api.routes.policy import _load_policy_or_raise, _rule_to_response, router
from mcp_acp.api.schemas import (
    PolicyResponse,
    PolicyRuleCreate,
    PolicyRuleMutationResponse,
    PolicyRuleResponse,
)
from mcp_acp.pdp.policy import PolicyConfig, PolicyRule, RuleConditions


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def sample_policy() -> PolicyConfig:
    """Create a sample policy for testing."""
    return PolicyConfig(
        version="1",
        default_action="deny",
        rules=[
            PolicyRule(
                id="rule-1",
                effect="allow",
                conditions=RuleConditions(path_pattern="/project/**"),
                description="Allow project access",
            ),
            PolicyRule(
                id="rule-2",
                effect="hitl",
                conditions=RuleConditions(tool_name="bash"),
                description="HITL for bash",
            ),
        ],
    )


@pytest.fixture
def mock_reloader() -> MagicMock:
    """Create a mock policy reloader."""
    reloader = MagicMock()
    reloader.current_version = "v1.0.0"
    reloader.reload = AsyncMock()
    reloader.reload.return_value = MagicMock(status="success", policy_version="v1.0.1")
    return reloader


@pytest.fixture
def app(mock_reloader: MagicMock) -> FastAPI:
    """Create a test FastAPI app with policy router and mocked state."""
    app = FastAPI()
    app.include_router(router, prefix="/api/policy")
    # Set app.state for dependency injection
    app.state.policy_reloader = mock_reloader
    return app


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    """Create a test client."""
    return TestClient(app)


# =============================================================================
# Tests: GET /api/policy
# =============================================================================


class TestGetPolicy:
    """Tests for GET /api/policy endpoint."""

    def test_returns_policy_with_metadata(
        self, client: TestClient, sample_policy: PolicyConfig, mock_reloader: MagicMock
    ) -> None:
        """Given valid policy, returns policy with metadata."""
        # Arrange
        with patch("mcp_acp.api.routes.policy.load_policy", return_value=sample_policy):
            with patch(
                "mcp_acp.api.routes.policy.get_policy_path",
                return_value=Path("/config/policy.json"),
            ):
                # Act
                response = client.get("/api/policy")

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["version"] == "1"
        assert data["default_action"] == "deny"
        assert data["rules_count"] == 2
        assert len(data["rules"]) == 2
        assert data["policy_version"] == "v1.0.0"

    def test_returns_404_when_policy_missing(self, client: TestClient, mock_reloader: MagicMock) -> None:
        """Given missing policy file, returns 404."""
        # Arrange
        with patch(
            "mcp_acp.api.routes.policy.load_policy",
            side_effect=FileNotFoundError,
        ):
            # Act
            response = client.get("/api/policy")

        # Assert
        assert response.status_code == 404
        assert "not found" in response.json()["detail"]["message"].lower()

    def test_returns_500_on_invalid_policy(self, client: TestClient, mock_reloader: MagicMock) -> None:
        """Given invalid policy, returns 500."""
        # Arrange
        with patch(
            "mcp_acp.api.routes.policy.load_policy",
            side_effect=ValueError("Invalid"),
        ):
            # Act
            response = client.get("/api/policy")

        # Assert
        assert response.status_code == 500


# =============================================================================
# Tests: GET /api/policy/rules
# =============================================================================


class TestGetPolicyRules:
    """Tests for GET /api/policy/rules endpoint."""

    def test_returns_rules_list(self, client: TestClient, sample_policy: PolicyConfig) -> None:
        """Given policy, returns simplified rules list."""
        # Arrange
        with patch("mcp_acp.api.routes.policy.load_policy", return_value=sample_policy):
            # Act
            response = client.get("/api/policy/rules")

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 2
        assert data[0]["id"] == "rule-1"
        assert data[0]["effect"] == "allow"
        assert data[1]["id"] == "rule-2"

    def test_returns_empty_list_for_no_rules(self, client: TestClient) -> None:
        """Given policy with no rules, returns empty list."""
        # Arrange
        empty_policy = PolicyConfig(
            version="1",
            default_action="deny",
            rules=[],
        )

        with patch("mcp_acp.api.routes.policy.load_policy", return_value=empty_policy):
            # Act
            response = client.get("/api/policy/rules")

        # Assert
        assert response.status_code == 200
        assert response.json() == []


# =============================================================================
# Tests: POST /api/policy/rules
# =============================================================================


class TestAddPolicyRule:
    """Tests for POST /api/policy/rules endpoint."""

    def test_adds_rule_with_provided_id(
        self, client: TestClient, sample_policy: PolicyConfig, mock_reloader: MagicMock, tmp_path: Path
    ) -> None:
        """Given rule with ID, adds to policy and returns it."""
        # Arrange
        new_rule = {
            "id": "rule-3",
            "effect": "deny",
            "conditions": {"tool_name": "delete_file"},
            "description": "Deny delete",
        }
        policy_file = tmp_path / "policy.json"

        with patch("mcp_acp.api.routes.policy.load_policy", return_value=sample_policy):
            with patch(
                "mcp_acp.api.routes.policy.get_policy_path",
                return_value=policy_file,
            ):
                # Act
                response = client.post("/api/policy/rules", json=new_rule)

        # Assert
        assert response.status_code == 201
        data = response.json()
        assert data["rule"]["id"] == "rule-3"
        assert data["rule"]["effect"] == "deny"
        assert data["rules_count"] == 3

    def test_rejects_duplicate_id(
        self, client: TestClient, sample_policy: PolicyConfig, mock_reloader: MagicMock
    ) -> None:
        """Given rule with existing ID, returns 409 conflict."""
        # Arrange
        duplicate_rule = {
            "id": "rule-1",  # Already exists
            "effect": "deny",
            "conditions": {"tool_name": "test"},
        }

        with patch("mcp_acp.api.routes.policy.load_policy", return_value=sample_policy):
            # Act
            response = client.post("/api/policy/rules", json=duplicate_rule)

        # Assert
        assert response.status_code == 409
        assert "already exists" in response.json()["detail"]["message"]

    def test_validates_conditions(
        self, client: TestClient, sample_policy: PolicyConfig, mock_reloader: MagicMock
    ) -> None:
        """Given invalid conditions, returns 400."""
        # Arrange
        invalid_rule = {
            "effect": "allow",
            "conditions": {"invalid_field": "test"},
        }

        with patch("mcp_acp.api.routes.policy.load_policy", return_value=sample_policy):
            # Act
            response = client.post("/api/policy/rules", json=invalid_rule)

        # Assert
        assert response.status_code == 400

    def test_validates_effect(
        self, client: TestClient, sample_policy: PolicyConfig, mock_reloader: MagicMock
    ) -> None:
        """Given invalid effect, returns 422."""
        # Arrange
        invalid_rule = {
            "effect": "invalid",
            "conditions": {"tool_name": "test"},
        }

        with patch("mcp_acp.api.routes.policy.load_policy", return_value=sample_policy):
            # Act
            response = client.post("/api/policy/rules", json=invalid_rule)

        # Assert
        assert response.status_code == 422


# =============================================================================
# Tests: PUT /api/policy/rules/{id}
# =============================================================================


class TestUpdatePolicyRule:
    """Tests for PUT /api/policy/rules/{id} endpoint."""

    def test_updates_existing_rule(
        self, client: TestClient, sample_policy: PolicyConfig, mock_reloader: MagicMock, tmp_path: Path
    ) -> None:
        """Given valid update, updates rule and returns it."""
        # Arrange
        update_data = {
            "effect": "deny",
            "conditions": {"path_pattern": "/new/**"},
            "description": "Updated rule",
        }
        policy_file = tmp_path / "policy.json"

        with patch("mcp_acp.api.routes.policy.load_policy", return_value=sample_policy):
            with patch(
                "mcp_acp.api.routes.policy.get_policy_path",
                return_value=policy_file,
            ):
                # Act
                response = client.put("/api/policy/rules/rule-1", json=update_data)

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["rule"]["id"] == "rule-1"
        assert data["rule"]["effect"] == "deny"
        assert data["rule"]["description"] == "Updated rule"

    def test_returns_404_for_nonexistent_rule(self, client, sample_policy, mock_reloader):
        """Given nonexistent rule ID, returns 404."""
        # Arrange
        update_data = {
            "effect": "deny",
            "conditions": {"tool_name": "test"},
        }

        with patch("mcp_acp.api.routes.policy.load_policy", return_value=sample_policy):
            # Act
            response = client.put("/api/policy/rules/nonexistent", json=update_data)

        # Assert
        assert response.status_code == 404

    def test_validates_conditions_on_update(
        self, client: TestClient, sample_policy: PolicyConfig, mock_reloader: MagicMock
    ) -> None:
        """Given invalid conditions on update, returns 400."""
        # Arrange
        invalid_update = {
            "effect": "allow",
            "conditions": {"invalid": "field"},
        }

        with patch("mcp_acp.api.routes.policy.load_policy", return_value=sample_policy):
            # Act
            response = client.put("/api/policy/rules/rule-1", json=invalid_update)

        # Assert
        assert response.status_code == 400


# =============================================================================
# Tests: DELETE /api/policy/rules/{id}
# =============================================================================


class TestDeletePolicyRule:
    """Tests for DELETE /api/policy/rules/{id} endpoint."""

    def test_deletes_existing_rule(
        self, client: TestClient, sample_policy: PolicyConfig, mock_reloader: MagicMock, tmp_path: Path
    ) -> None:
        """Given existing rule ID, deletes and returns 204."""
        # Arrange
        policy_file = tmp_path / "policy.json"

        with patch("mcp_acp.api.routes.policy.load_policy", return_value=sample_policy):
            with patch(
                "mcp_acp.api.routes.policy.get_policy_path",
                return_value=policy_file,
            ):
                # Act
                response = client.delete("/api/policy/rules/rule-1")

        # Assert
        assert response.status_code == 204

    def test_returns_404_for_nonexistent_rule_on_delete(
        self, client: TestClient, sample_policy: PolicyConfig, mock_reloader: MagicMock
    ) -> None:
        """Given nonexistent rule ID, returns 404."""
        # Arrange
        with patch("mcp_acp.api.routes.policy.load_policy", return_value=sample_policy):
            # Act
            response = client.delete("/api/policy/rules/nonexistent")

        # Assert
        assert response.status_code == 404


# =============================================================================
# Tests: Helper Functions
# =============================================================================


class TestLoadPolicyOrRaise:
    """Tests for _load_policy_or_raise helper."""

    def test_returns_policy_on_success(self, sample_policy: PolicyConfig) -> None:
        """Given valid policy, returns it."""
        # Arrange
        with patch("mcp_acp.api.routes.policy.load_policy", return_value=sample_policy):
            # Act
            result = _load_policy_or_raise()

        # Assert
        assert result == sample_policy

    def test_raises_404_on_file_not_found(self) -> None:
        """Given missing file, raises 404."""
        # Arrange
        with patch(
            "mcp_acp.api.routes.policy.load_policy",
            side_effect=FileNotFoundError,
        ):
            # Act & Assert
            with pytest.raises(APIError) as exc_info:
                _load_policy_or_raise()

        assert exc_info.value.status_code == 404

    def test_raises_500_on_invalid_policy(self) -> None:
        """Given invalid policy, raises 500."""
        # Arrange
        with patch(
            "mcp_acp.api.routes.policy.load_policy",
            side_effect=ValueError("Invalid"),
        ):
            # Act & Assert
            with pytest.raises(APIError) as exc_info:
                _load_policy_or_raise()

        assert exc_info.value.status_code == 500


class TestRuleToResponse:
    """Tests for _rule_to_response helper."""

    def test_converts_rule_to_response(self) -> None:
        """Given PolicyRule, converts to PolicyRuleResponse."""
        # Arrange
        rule = PolicyRule(
            id="test-rule",
            effect="allow",
            conditions=RuleConditions(tool_name="read_file"),
            description="Test rule",
        )

        # Act
        response = _rule_to_response(rule)

        # Assert
        assert isinstance(response, PolicyRuleResponse)
        assert response.id == "test-rule"
        assert response.effect == "allow"
        assert response.description == "Test rule"

    def test_handles_null_description(self) -> None:
        """Given rule without description, handles gracefully."""
        # Arrange
        rule = PolicyRule(
            id="test-rule",
            effect="deny",
            conditions=RuleConditions(path_pattern="/**"),
        )

        # Act
        response = _rule_to_response(rule)

        # Assert
        assert response.description is None


# =============================================================================
# Tests: Request/Response Models
# =============================================================================


class TestPolicyRuleCreate:
    """Tests for PolicyRuleCreate model validation."""

    def test_valid_rule_with_all_fields(self) -> None:
        """Given all fields, creates model."""
        # Act
        rule = PolicyRuleCreate(
            id="test",
            effect="allow",
            conditions={"tool_name": "test"},
            description="Test",
        )

        # Assert
        assert rule.id == "test"
        assert rule.effect == "allow"

    def test_valid_rule_without_optional_fields(self) -> None:
        """Given only required fields, creates model."""
        # Act
        rule = PolicyRuleCreate(
            effect="deny",
            conditions={"path_pattern": "/**"},
        )

        # Assert
        assert rule.id is None
        assert rule.description is None

    def test_rejects_invalid_effect(self) -> None:
        """Given invalid effect, raises validation error."""
        # Arrange
        from pydantic import ValidationError

        # Act & Assert
        with pytest.raises(ValidationError):
            PolicyRuleCreate(
                effect="invalid",
                conditions={"tool_name": "test"},
            )
