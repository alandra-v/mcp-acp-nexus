"""Tests for approval store (HITL caching)."""

import time
from unittest.mock import patch

import pytest

from mcp_acp.context.resource import SideEffect
from mcp_acp.pep.approval_store import ApprovalStore, CachedApproval


class TestCachedApproval:
    """Tests for CachedApproval dataclass."""

    def test_cached_approval_is_frozen(self) -> None:
        """CachedApproval is immutable."""
        approval = CachedApproval(
            subject_id="user1",
            tool_name="bash",
            path="/foo/bar.txt",
            stored_at=time.monotonic(),
            request_id="req123",
        )
        with pytest.raises(AttributeError):
            approval.subject_id = "user2"  # type: ignore

    def test_cached_approval_with_none_path(self) -> None:
        """CachedApproval handles None path."""
        approval = CachedApproval(
            subject_id="user1",
            tool_name="list_tools",
            path=None,
            stored_at=time.monotonic(),
            request_id="req123",
        )
        assert approval.path is None


class TestApprovalStore:
    """Tests for ApprovalStore."""

    @pytest.fixture
    def store(self) -> ApprovalStore:
        """Create a store with 60 second TTL."""
        return ApprovalStore(ttl_seconds=60)

    @pytest.fixture
    def short_ttl_store(self) -> ApprovalStore:
        """Create a store with very short TTL for expiry testing."""
        return ApprovalStore(ttl_seconds=1)

    def test_store_creates_approval(self, store: ApprovalStore) -> None:
        """Store creates a CachedApproval with correct fields."""
        approval = store.store(
            subject_id="user1",
            tool_name="bash",
            path="/foo/bar.txt",
            request_id="req123",
        )

        assert isinstance(approval, CachedApproval)
        assert approval.subject_id == "user1"
        assert approval.tool_name == "bash"
        assert approval.request_id == "req123"
        assert approval.stored_at > 0

    def test_store_normalizes_path(self, store: ApprovalStore) -> None:
        """Store normalizes path with realpath."""
        # Use a path that exists so realpath can resolve it
        approval = store.store(
            subject_id="user1",
            tool_name="read_file",
            path=".",  # Current directory
            request_id="req123",
        )

        # Path should be absolute
        assert approval.path is not None
        assert approval.path.startswith("/")

    def test_store_handles_none_path(self, store: ApprovalStore) -> None:
        """Store handles None path correctly."""
        approval = store.store(
            subject_id="user1",
            tool_name="list_tools",
            path=None,
            request_id="req123",
        )

        assert approval.path is None

    def test_lookup_returns_approval_when_valid(self, store: ApprovalStore) -> None:
        """Lookup returns stored approval when valid."""
        store.store(
            subject_id="user1",
            tool_name="bash",
            path="/foo/bar.txt",
            request_id="req123",
        )

        result = store.lookup(
            subject_id="user1",
            tool_name="bash",
            path="/foo/bar.txt",
        )

        assert result is not None
        assert result.subject_id == "user1"
        assert result.tool_name == "bash"

    def test_lookup_returns_none_when_not_found(self, store: ApprovalStore) -> None:
        """Lookup returns None when no matching approval."""
        result = store.lookup(
            subject_id="user1",
            tool_name="bash",
            path="/foo/bar.txt",
        )

        assert result is None

    def test_lookup_returns_none_for_different_user(self, store: ApprovalStore) -> None:
        """Lookup returns None for different user."""
        store.store(
            subject_id="user1",
            tool_name="bash",
            path="/foo/bar.txt",
            request_id="req123",
        )

        result = store.lookup(
            subject_id="user2",  # Different user
            tool_name="bash",
            path="/foo/bar.txt",
        )

        assert result is None

    def test_lookup_returns_none_for_different_tool(self, store: ApprovalStore) -> None:
        """Lookup returns None for different tool."""
        store.store(
            subject_id="user1",
            tool_name="bash",
            path="/foo/bar.txt",
            request_id="req123",
        )

        result = store.lookup(
            subject_id="user1",
            tool_name="python",  # Different tool
            path="/foo/bar.txt",
        )

        assert result is None

    def test_lookup_returns_none_for_different_path(self, store: ApprovalStore) -> None:
        """Lookup returns None for different path."""
        store.store(
            subject_id="user1",
            tool_name="bash",
            path="/foo/bar.txt",
            request_id="req123",
        )

        result = store.lookup(
            subject_id="user1",
            tool_name="bash",
            path="/foo/other.txt",  # Different path
        )

        assert result is None

    def test_lookup_returns_none_when_expired(self, short_ttl_store: ApprovalStore) -> None:
        """Lookup returns None and removes expired approval."""
        short_ttl_store.store(
            subject_id="user1",
            tool_name="bash",
            path="/foo/bar.txt",
            request_id="req123",
        )

        # Wait for TTL to expire
        time.sleep(1.1)

        result = short_ttl_store.lookup(
            subject_id="user1",
            tool_name="bash",
            path="/foo/bar.txt",
        )

        assert result is None
        assert short_ttl_store.count == 0  # Should be cleaned up

    def test_lookup_normalizes_path(self, store: ApprovalStore) -> None:
        """Lookup normalizes path for matching."""
        # Store with current directory
        store.store(
            subject_id="user1",
            tool_name="read_file",
            path=".",
            request_id="req123",
        )

        # Lookup with same path (will be normalized)
        result = store.lookup(
            subject_id="user1",
            tool_name="read_file",
            path=".",
        )

        assert result is not None

    def test_get_age_seconds(self, store: ApprovalStore) -> None:
        """get_age_seconds returns correct age."""
        approval = store.store(
            subject_id="user1",
            tool_name="bash",
            path="/foo",
            request_id="req123",
        )

        # Small sleep to ensure measurable age
        time.sleep(0.1)

        age = store.get_age_seconds(approval)
        assert age >= 0.1
        assert age < 1.0  # Should be quick

    def test_clear_removes_all_approvals(self, store: ApprovalStore) -> None:
        """Clear removes all stored approvals."""
        store.store("user1", "bash", "/foo", "req1")
        store.store("user2", "python", "/bar", "req2")
        store.store("user1", "node", None, "req3")

        assert store.count == 3

        count = store.clear()

        assert count == 3
        assert store.count == 0

    def test_clear_returns_zero_when_empty(self, store: ApprovalStore) -> None:
        """Clear returns 0 when store is empty."""
        count = store.clear()
        assert count == 0

    def test_count_property(self, store: ApprovalStore) -> None:
        """count property returns number of stored approvals."""
        assert store.count == 0

        store.store("user1", "bash", "/foo", "req1")
        assert store.count == 1

        store.store("user2", "python", "/bar", "req2")
        assert store.count == 2

    def test_ttl_seconds_property(self, store: ApprovalStore) -> None:
        """ttl_seconds property returns configured TTL."""
        assert store.ttl_seconds == 60

    def test_overwrite_same_key(self, store: ApprovalStore) -> None:
        """Storing same key overwrites previous approval."""
        store.store("user1", "bash", "/foo", "req1")
        store.store("user1", "bash", "/foo", "req2")  # Same key, new request_id

        assert store.count == 1

        result = store.lookup("user1", "bash", "/foo")
        assert result is not None
        assert result.request_id == "req2"  # Should be the newer one


class TestShouldCache:
    """Tests for should_cache static method."""

    def test_unknown_side_effects_returns_false(self) -> None:
        """Tools with unknown side effects (None) are NOT cached (conservative)."""
        result = ApprovalStore.should_cache(
            tool_side_effects=None,
            allowed_effects=None,
        )
        assert result is False

    def test_empty_side_effects_returns_true(self) -> None:
        """Tools with empty side effects are safe to cache."""
        result = ApprovalStore.should_cache(
            tool_side_effects=frozenset(),
            allowed_effects=None,
        )
        assert result is True

    def test_any_side_effect_default_returns_false(self) -> None:
        """Default: tools with any side effect are not cached."""
        result = ApprovalStore.should_cache(
            tool_side_effects=frozenset({SideEffect.FS_READ}),
            allowed_effects=None,
        )
        assert result is False

    def test_dangerous_side_effect_returns_false(self) -> None:
        """Tools with dangerous side effects are not cached."""
        result = ApprovalStore.should_cache(
            tool_side_effects=frozenset({SideEffect.CODE_EXEC}),
            allowed_effects=None,
        )
        assert result is False

    def test_allowed_effects_subset_returns_true(self) -> None:
        """Tools with subset of allowed effects can be cached."""
        result = ApprovalStore.should_cache(
            tool_side_effects=frozenset({SideEffect.FS_READ}),
            allowed_effects=[SideEffect.FS_READ, SideEffect.FS_WRITE],
        )
        assert result is True

    def test_allowed_effects_not_subset_returns_false(self) -> None:
        """Tools with effects outside allowed list cannot be cached."""
        result = ApprovalStore.should_cache(
            tool_side_effects=frozenset({SideEffect.FS_READ, SideEffect.CODE_EXEC}),
            allowed_effects=[SideEffect.FS_READ, SideEffect.FS_WRITE],
        )
        assert result is False

    def test_multiple_allowed_effects(self) -> None:
        """Multiple side effects all in allowed list returns True."""
        result = ApprovalStore.should_cache(
            tool_side_effects=frozenset({SideEffect.FS_READ, SideEffect.FS_WRITE}),
            allowed_effects=[SideEffect.FS_READ, SideEffect.FS_WRITE, SideEffect.DB_READ],
        )
        assert result is True

    def test_code_exec_never_cached_even_if_allowed(self) -> None:
        """CODE_EXEC tools are NEVER cached, even if in allowed_effects."""
        # This prevents bash/python/etc from being auto-approved for different commands
        result = ApprovalStore.should_cache(
            tool_side_effects=frozenset({SideEffect.CODE_EXEC}),
            allowed_effects=[SideEffect.CODE_EXEC, SideEffect.FS_READ],
        )
        assert result is False

    def test_code_exec_with_other_effects_never_cached(self) -> None:
        """Tools with CODE_EXEC + other effects are never cached."""
        result = ApprovalStore.should_cache(
            tool_side_effects=frozenset({SideEffect.CODE_EXEC, SideEffect.FS_READ}),
            allowed_effects=[SideEffect.CODE_EXEC, SideEffect.FS_READ],
        )
        assert result is False
