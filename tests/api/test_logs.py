"""Unit tests for logs API routes.

Tests the log viewing endpoints and JSONL file reading.
Uses AAA pattern (Arrange-Act-Assert) for clarity.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from mcp_acp.api.routes.logs import router
from mcp_acp.api.schemas import LogsResponse
from mcp_acp.api.utils.jsonl import read_jsonl_filtered


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def mock_config(tmp_path):
    """Create a mock AppConfig with temp log directory."""
    config = MagicMock()
    config.logging.log_dir = str(tmp_path)
    return config


@pytest.fixture
def app(mock_config):
    """Create a test FastAPI app with logs router and mocked state."""
    app = FastAPI()
    app.include_router(router, prefix="/api/logs")
    # Set app.state.config for dependency injection
    app.state.config = mock_config
    return app


@pytest.fixture
def client(app):
    """Create a test client."""
    return TestClient(app)


# =============================================================================
# Tests: read_jsonl_filtered Helper
# =============================================================================


class TestReadJsonlFiltered:
    """Tests for read_jsonl_filtered helper function."""

    def test_returns_empty_for_missing_file(self, tmp_path):
        """Given a non-existent file, returns empty list."""
        # Arrange
        path = tmp_path / "nonexistent.jsonl"

        # Act
        entries, has_more, scanned = read_jsonl_filtered(path, limit=10)

        # Assert
        assert entries == []
        assert has_more is False
        assert scanned == 0

    def test_returns_empty_for_empty_file(self, tmp_path):
        """Given an empty file, returns empty list."""
        # Arrange
        path = tmp_path / "empty.jsonl"
        path.write_text("")

        # Act
        entries, has_more, scanned = read_jsonl_filtered(path, limit=10)

        # Assert
        assert entries == []
        assert has_more is False
        assert scanned == 0

    def test_reads_single_entry(self, tmp_path):
        """Given a file with one entry, returns that entry."""
        # Arrange
        path = tmp_path / "single.jsonl"
        entry = {"timestamp": "2024-01-01", "message": "test"}
        path.write_text(json.dumps(entry) + "\n")

        # Act
        entries, has_more, scanned = read_jsonl_filtered(path, limit=10)

        # Assert
        assert len(entries) == 1
        assert entries[0] == entry
        assert has_more is False

    def test_returns_newest_first(self, tmp_path):
        """Given multiple entries, returns newest first."""
        # Arrange
        path = tmp_path / "multiple.jsonl"
        entries_data = [
            {"timestamp": "2024-01-01", "id": 1},
            {"timestamp": "2024-01-02", "id": 2},
            {"timestamp": "2024-01-03", "id": 3},
        ]
        path.write_text("\n".join(json.dumps(e) for e in entries_data) + "\n")

        # Act
        entries, has_more, scanned = read_jsonl_filtered(path, limit=10)

        # Assert
        assert len(entries) == 3
        assert entries[0]["id"] == 3  # Newest first
        assert entries[1]["id"] == 2
        assert entries[2]["id"] == 1
        assert has_more is False

    def test_respects_limit(self, tmp_path):
        """Given limit, returns only that many entries."""
        # Arrange
        path = tmp_path / "limit.jsonl"
        entries_data = [{"id": i} for i in range(10)]
        path.write_text("\n".join(json.dumps(e) for e in entries_data) + "\n")

        # Act
        entries, has_more, scanned = read_jsonl_filtered(path, limit=3)

        # Assert
        assert len(entries) == 3
        assert has_more is True

    def test_skips_malformed_lines(self, tmp_path):
        """Given malformed JSON lines, skips them without error."""
        # Arrange
        path = tmp_path / "malformed.jsonl"
        content = '{"valid": 1}\nnot json\n{"valid": 2}\n'
        path.write_text(content)

        # Act
        entries, has_more, scanned = read_jsonl_filtered(path, limit=10)

        # Assert
        assert len(entries) == 2
        assert entries[0]["valid"] == 2
        assert entries[1]["valid"] == 1

    def test_handles_empty_lines(self, tmp_path):
        """Given empty lines in file, filters them out."""
        # Arrange
        path = tmp_path / "empty_lines.jsonl"
        content = '{"id": 1}\n\n{"id": 2}\n\n\n'
        path.write_text(content)

        # Act
        entries, _, _ = read_jsonl_filtered(path, limit=10)

        # Assert
        assert len(entries) == 2

    def test_handles_unicode_content(self, tmp_path):
        """Given unicode content, reads correctly."""
        # Arrange
        path = tmp_path / "unicode.jsonl"
        entry = {"message": "Hello 世界 😀"}
        path.write_text(json.dumps(entry, ensure_ascii=False) + "\n")

        # Act
        entries, _, _ = read_jsonl_filtered(path, limit=10)

        # Assert
        assert entries[0]["message"] == "Hello 世界 😀"


# =============================================================================
# Tests: Log Endpoints
# =============================================================================


class TestLogEndpoints:
    """Tests for log API endpoints."""

    def test_get_decision_logs_success(self, client, tmp_path):
        """GET /api/logs/decisions returns decision logs."""
        # Arrange
        log_dir = tmp_path / "mcp_acp_logs" / "audit"
        log_dir.mkdir(parents=True)
        log_file = log_dir / "decisions.jsonl"
        log_file.write_text('{"type": "decision", "action": "allow"}\n')

        # Act (time_range=all to skip time filtering since test data has no timestamp)
        response = client.get("/api/logs/decisions?time_range=all")

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["total_returned"] == 1
        assert data["entries"][0]["type"] == "decision"

    def test_get_operation_logs_success(self, client, tmp_path):
        """GET /api/logs/operations returns operation logs."""
        # Arrange
        log_dir = tmp_path / "mcp_acp_logs" / "audit"
        log_dir.mkdir(parents=True)
        log_file = log_dir / "operations.jsonl"
        log_file.write_text('{"type": "operation"}\n{"type": "operation"}\n')

        # Act (time_range=all to skip time filtering)
        response = client.get("/api/logs/operations?limit=50&time_range=all")

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["total_returned"] == 2

    def test_get_auth_logs_empty(self, client, tmp_path):
        """GET /api/logs/auth returns empty list when no logs exist."""
        # Arrange - no log file created

        # Act
        response = client.get("/api/logs/auth?time_range=all")

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["entries"] == []
        assert data["total_returned"] == 0

    def test_get_system_logs_success(self, client, tmp_path):
        """GET /api/logs/system returns system logs."""
        # Arrange
        log_dir = tmp_path / "mcp_acp_logs" / "system"
        log_dir.mkdir(parents=True)
        log_file = log_dir / "system.jsonl"
        log_file.write_text('{"level": "INFO", "message": "Started"}\n')

        # Act (time_range=all to skip time filtering)
        response = client.get("/api/logs/system?time_range=all")

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["entries"][0]["level"] == "INFO"

    def test_limit_validation_min(self, client):
        """Given limit < 1, returns 422 validation error."""
        # Act
        response = client.get("/api/logs/decisions?limit=0")

        # Assert
        assert response.status_code == 422

    def test_limit_validation_max(self, client):
        """Given limit > 1000, returns 422 validation error."""
        # Act
        response = client.get("/api/logs/decisions?limit=1001")

        # Assert
        assert response.status_code == 422

    def test_pagination_returns_correct_count(self, client, tmp_path):
        """Given limit, returns correct entries."""
        # Arrange
        log_dir = tmp_path / "mcp_acp_logs" / "audit"
        log_dir.mkdir(parents=True)
        log_file = log_dir / "decisions.jsonl"
        entries = [json.dumps({"id": i}) for i in range(10)]
        log_file.write_text("\n".join(entries) + "\n")

        # Act (time_range=all to skip time filtering)
        response = client.get("/api/logs/decisions?limit=3&time_range=all")

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["total_returned"] == 3
        assert data["has_more"] is True


# =============================================================================
# Tests: Response Models
# =============================================================================


class TestLogsResponse:
    """Tests for LogsResponse model."""

    def test_model_serialization(self):
        """LogsResponse serializes correctly."""
        # Arrange & Act
        response = LogsResponse(
            entries=[{"test": "data"}],
            total_returned=1,
            total_scanned=5,
            log_file="/path/to/logs.jsonl",
            has_more=True,
            filters_applied={"time_range": "5m"},
        )
        data = response.model_dump()

        # Assert
        assert data["entries"] == [{"test": "data"}]
        assert data["total_returned"] == 1
        assert data["total_scanned"] == 5
        assert data["log_file"] == "/path/to/logs.jsonl"
        assert data["has_more"] is True
        assert data["filters_applied"] == {"time_range": "5m"}
