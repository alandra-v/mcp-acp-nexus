"""Tests for proxy deletion module."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_acp.manager.deletion import (
    DeleteResult,
    PurgeResult,
    delete_proxy,
    get_archive_dir,
    get_archived_proxy_dir,
    list_archived_proxies,
    purge_archived_proxy,
)


@pytest.fixture
def temp_config_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Set up temporary config directory."""
    config_dir = tmp_path / "config"
    config_dir.mkdir()

    monkeypatch.setattr(
        "mcp_acp.manager.config.get_app_dir",
        lambda: config_dir,
    )
    monkeypatch.setattr(
        "mcp_acp.utils.file_helpers.get_app_dir",
        lambda: config_dir,
    )
    monkeypatch.setattr(
        "mcp_acp.manager.deletion.get_app_dir",
        lambda: config_dir,
    )

    return config_dir


@pytest.fixture
def temp_log_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Set up temporary log directory."""
    log_dir = tmp_path / "logs"
    log_dir.mkdir()

    monkeypatch.setattr(
        "mcp_acp.manager.deletion.get_proxy_log_dir",
        lambda name: log_dir / name,
    )

    return log_dir


@pytest.fixture
def temp_runtime_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Set up temporary runtime directory for sockets."""
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()

    monkeypatch.setattr(
        "mcp_acp.manager.deletion.get_proxy_socket_path",
        lambda name: runtime_dir / f"proxy_{name}.sock",
    )

    return runtime_dir


@pytest.fixture
def sample_proxy_files(
    temp_config_dir: Path,
    temp_log_dir: Path,
    temp_runtime_dir: Path,
) -> str:
    """Create sample proxy files for testing deletion."""
    name = "testproxy"

    # Config directory
    config_dir = temp_config_dir / "proxies" / name
    config_dir.mkdir(parents=True)
    (config_dir / "config.json").write_text('{"proxy_id": "px_test"}')
    (config_dir / "policy.json").write_text('{"version": "v1"}')
    (config_dir / "bootstrap.jsonl").write_text('{"event": "startup"}\n')

    # Log directory
    log_dir = temp_log_dir / name
    log_dir.mkdir(parents=True)

    # Audit logs
    audit_dir = log_dir / "audit"
    audit_dir.mkdir()
    (audit_dir / "operations.jsonl").write_text('{"op": "read"}\n')
    (audit_dir / "decisions.jsonl").write_text('{"decision": "allow"}\n')

    # System logs
    system_dir = log_dir / "system"
    system_dir.mkdir()
    (system_dir / "system.jsonl").write_text('{"event": "started"}\n')

    # Debug logs
    debug_dir = log_dir / "debug"
    debug_dir.mkdir()
    (debug_dir / "debug.log").write_text("debug output " * 100)

    # Root log files
    (log_dir / ".integrity_state").write_text('{"hash": "abc"}')
    (log_dir / ".last_crash").write_text('{"crash": true}')
    (log_dir / "shutdowns.jsonl").write_text('{"shutdown": true}\n')

    # Socket file
    (temp_runtime_dir / f"proxy_{name}.sock").write_text("")

    return name


@pytest.fixture
def mock_credential_delete(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Mock credential storage to avoid keychain access."""
    deleted_credentials: list[str] = []

    class MockCredentialStorage:
        def __init__(self, proxy_name: str) -> None:
            self._name = proxy_name

        def delete(self) -> None:
            deleted_credentials.append(self._name)

    monkeypatch.setattr(
        "mcp_acp.security.credential_storage.BackendCredentialStorage",
        MockCredentialStorage,
    )

    return deleted_credentials


class TestSoftDelete:
    """Tests for soft delete (archive) behavior."""

    def test_archives_config_directory(
        self,
        temp_config_dir: Path,
        sample_proxy_files: str,
        mock_credential_delete: list[str],
    ) -> None:
        """Config directory is archived to archive/{name}_{ts}/config/."""
        result = delete_proxy(sample_proxy_files)

        assert "Config + policy" in result.archived
        assert result.archive_name is not None

        archive_dir = temp_config_dir / "archive" / result.archive_name
        assert archive_dir.exists()
        assert (archive_dir / "config" / "config.json").exists()
        assert (archive_dir / "config" / "policy.json").exists()
        assert (archive_dir / "config" / "bootstrap.jsonl").exists()

    def test_archives_audit_and_system_logs(
        self,
        temp_config_dir: Path,
        sample_proxy_files: str,
        mock_credential_delete: list[str],
    ) -> None:
        """Audit and system logs are archived."""
        result = delete_proxy(sample_proxy_files)

        archive_dir = temp_config_dir / "archive" / result.archive_name
        assert (archive_dir / "logs" / "audit" / "operations.jsonl").exists()
        assert (archive_dir / "logs" / "audit" / "decisions.jsonl").exists()
        assert (archive_dir / "logs" / "system" / "system.jsonl").exists()
        assert "Audit logs" in result.archived
        assert "System logs" in result.archived

    def test_archives_root_log_files(
        self,
        temp_config_dir: Path,
        sample_proxy_files: str,
        mock_credential_delete: list[str],
    ) -> None:
        """Root log files (.integrity_state, .last_crash, shutdowns.jsonl) are archived."""
        result = delete_proxy(sample_proxy_files)

        archive_dir = temp_config_dir / "archive" / result.archive_name
        assert (archive_dir / "logs" / ".integrity_state").exists()
        assert (archive_dir / "logs" / ".last_crash").exists()
        assert (archive_dir / "logs" / "shutdowns.jsonl").exists()

    def test_deletes_debug_logs(
        self,
        temp_log_dir: Path,
        sample_proxy_files: str,
        mock_credential_delete: list[str],
    ) -> None:
        """Debug logs are permanently deleted (not archived)."""
        result = delete_proxy(sample_proxy_files)

        assert "Debug logs" in result.deleted
        assert not (temp_log_dir / sample_proxy_files / "debug").exists()
        assert result.deleted_size > 0

    def test_deletes_socket_file(
        self,
        temp_runtime_dir: Path,
        sample_proxy_files: str,
        mock_credential_delete: list[str],
    ) -> None:
        """Stale socket file is deleted."""
        result = delete_proxy(sample_proxy_files)

        assert "Socket file" in result.deleted
        assert not (temp_runtime_dir / f"proxy_{sample_proxy_files}.sock").exists()

    def test_writes_metadata_json(
        self,
        temp_config_dir: Path,
        sample_proxy_files: str,
        mock_credential_delete: list[str],
    ) -> None:
        """Machine-readable metadata.json is written to archive."""
        result = delete_proxy(sample_proxy_files)

        metadata_path = temp_config_dir / "archive" / result.archive_name / "metadata.json"
        assert metadata_path.exists()

        metadata = json.loads(metadata_path.read_text())
        assert metadata["version"] == 1
        assert metadata["original_name"] == sample_proxy_files
        assert metadata["deleted_at"] is not None
        assert metadata["archived"]["config"] is True
        assert metadata["archived"]["audit_logs"] is True
        assert metadata["archived"]["system_logs"] is True
        assert metadata["deleted"]["debug_logs"] is True

    def test_writes_readme_txt(
        self,
        temp_config_dir: Path,
        sample_proxy_files: str,
        mock_credential_delete: list[str],
    ) -> None:
        """Human-readable README.txt is written to archive."""
        result = delete_proxy(sample_proxy_files)

        readme_path = temp_config_dir / "archive" / result.archive_name / "README.txt"
        assert readme_path.exists()

        content = readme_path.read_text()
        assert "Proxy deleted:" in content
        assert sample_proxy_files in content

    def test_deletes_credential(
        self,
        sample_proxy_files: str,
        mock_credential_delete: list[str],
    ) -> None:
        """Backend credential is deleted from keychain."""
        delete_proxy(sample_proxy_files)
        assert sample_proxy_files in mock_credential_delete

    def test_removes_original_config_dir(
        self,
        temp_config_dir: Path,
        sample_proxy_files: str,
        mock_credential_delete: list[str],
    ) -> None:
        """Original config directory is removed after archiving."""
        delete_proxy(sample_proxy_files)
        assert not (temp_config_dir / "proxies" / sample_proxy_files).exists()

    def test_cleans_empty_log_dir(
        self,
        temp_log_dir: Path,
        sample_proxy_files: str,
        mock_credential_delete: list[str],
    ) -> None:
        """Empty log directory is cleaned up after archiving."""
        delete_proxy(sample_proxy_files)
        assert not (temp_log_dir / sample_proxy_files).exists()

    def test_archived_size_tracked(
        self,
        sample_proxy_files: str,
        mock_credential_delete: list[str],
    ) -> None:
        """Archived size is tracked correctly."""
        result = delete_proxy(sample_proxy_files)
        assert result.archived_size > 0


class TestPurgeDelete:
    """Tests for purge (hard delete) behavior."""

    def test_purge_deletes_config_dir(
        self,
        temp_config_dir: Path,
        sample_proxy_files: str,
        mock_credential_delete: list[str],
    ) -> None:
        """Purge permanently deletes config directory."""
        result = delete_proxy(sample_proxy_files, purge=True)

        assert "Config directory" in result.deleted
        assert not (temp_config_dir / "proxies" / sample_proxy_files).exists()
        assert result.archive_name is None

    def test_purge_deletes_log_dir(
        self,
        temp_log_dir: Path,
        sample_proxy_files: str,
        mock_credential_delete: list[str],
    ) -> None:
        """Purge permanently deletes log directory."""
        result = delete_proxy(sample_proxy_files, purge=True)

        assert "Log directory" in result.deleted
        assert not (temp_log_dir / sample_proxy_files).exists()

    def test_purge_no_archive_created(
        self,
        temp_config_dir: Path,
        sample_proxy_files: str,
        mock_credential_delete: list[str],
    ) -> None:
        """No archive directory is created during purge."""
        delete_proxy(sample_proxy_files, purge=True)
        assert not (temp_config_dir / "archive").exists()


class TestRunningProxyRefusal:
    """Tests for running proxy safety check.

    Note: The is_running guard was removed from delete_proxy() in Fix 7.
    Both CLI and API callers check running status at their own level before
    calling delete_proxy(). ProxyRunningError is still used by the API route.
    """


class TestPurgeArchived:
    """Tests for purging archived proxies."""

    def test_purge_removes_archive(
        self,
        temp_config_dir: Path,
        sample_proxy_files: str,
        mock_credential_delete: list[str],
    ) -> None:
        """Purge permanently removes an archived proxy."""
        # First soft-delete
        result = delete_proxy(sample_proxy_files)
        archive_name = result.archive_name
        assert archive_name is not None

        archive_dir = temp_config_dir / "archive" / archive_name
        assert archive_dir.exists()

        # Then purge
        purge_result = purge_archived_proxy(archive_name)
        assert purge_result.archive_name == archive_name
        assert purge_result.purged_size > 0
        assert not archive_dir.exists()

    def test_purge_nonexistent_raises(self, temp_config_dir: Path) -> None:
        """Purging nonexistent archive raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError, match="not found"):
            purge_archived_proxy("nonexistent_2024-01-01T00-00-00")


class TestListArchivedProxies:
    """Tests for listing archived proxies."""

    def test_returns_empty_when_no_archives(self, temp_config_dir: Path) -> None:
        """Returns empty list when no archives exist."""
        assert list_archived_proxies() == []

    def test_lists_archived_proxies(
        self,
        temp_config_dir: Path,
        sample_proxy_files: str,
        mock_credential_delete: list[str],
    ) -> None:
        """Lists archived proxy directory names."""
        result = delete_proxy(sample_proxy_files)

        archives = list_archived_proxies()
        assert len(archives) == 1
        assert archives[0] == result.archive_name


class TestEdgeCases:
    """Tests for edge cases."""

    def test_delete_proxy_with_no_logs(
        self,
        temp_config_dir: Path,
        temp_log_dir: Path,
        temp_runtime_dir: Path,
        mock_credential_delete: list[str],
    ) -> None:
        """Delete works when proxy has no log directory."""
        name = "nologs"
        config_dir = temp_config_dir / "proxies" / name
        config_dir.mkdir(parents=True)
        (config_dir / "config.json").write_text("{}")

        result = delete_proxy(name)
        assert "Config + policy" in result.archived
        assert result.archive_name is not None

    def test_delete_proxy_with_no_socket(
        self,
        temp_config_dir: Path,
        temp_log_dir: Path,
        temp_runtime_dir: Path,
        mock_credential_delete: list[str],
    ) -> None:
        """Delete works when socket file doesn't exist."""
        name = "nosocket"
        config_dir = temp_config_dir / "proxies" / name
        config_dir.mkdir(parents=True)
        (config_dir / "config.json").write_text("{}")

        result = delete_proxy(name)
        assert "Socket file" not in result.deleted

    def test_credential_delete_failure_is_handled(
        self,
        temp_config_dir: Path,
        temp_log_dir: Path,
        temp_runtime_dir: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Credential deletion failure doesn't prevent overall deletion."""
        name = "credfail"
        config_dir = temp_config_dir / "proxies" / name
        config_dir.mkdir(parents=True)
        (config_dir / "config.json").write_text("{}")

        class FailingCredentialStorage:
            def __init__(self, proxy_name: str) -> None:
                pass

            def delete(self) -> None:
                raise RuntimeError("Keychain locked")

        monkeypatch.setattr(
            "mcp_acp.security.credential_storage.BackendCredentialStorage",
            FailingCredentialStorage,
        )

        # Should not raise
        result = delete_proxy(name)
        assert result.archive_name is not None
