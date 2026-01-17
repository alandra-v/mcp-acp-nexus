"""Approval store for caching HITL approvals.

Caches HITL approvals to reduce dialog fatigue. Approved operations
(keyed by subject_id + tool_name + path) bypass HITL for a configurable TTL.

This is transparent caching - internal to HITL handling, not exposed to policies.

Security considerations:
- Approvals are scoped to (subject_id, tool_name, path) - path-specific
- TTL prevents stale approvals from lasting indefinitely
- In-memory store - approvals don't persist across restarts
- Tools with side effects are never cached by default (conservative)
"""

from __future__ import annotations

__all__ = [
    "ApprovalKey",
    "ApprovalStore",
    "CachedApproval",
]

import os
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcp_acp.context.resource import SideEffect


@dataclass(frozen=True)
class CachedApproval:
    """A cached HITL approval with timestamp.

    Attributes:
        subject_id: The user who approved.
        tool_name: The tool that was approved.
        path: The path that was approved (normalized, or None if no path).
        stored_at: Monotonic timestamp when approval was stored.
        request_id: Original request ID for audit trail.
    """

    subject_id: str
    tool_name: str
    path: str | None
    stored_at: float
    request_id: str


# Cache key type for type safety
ApprovalKey = tuple[str, str, str | None]  # (subject_id, tool_name, path)


class ApprovalStore:
    """In-memory cache for HITL approvals.

    Caches approvals by (subject_id, tool_name, path) to reduce HITL dialog
    fatigue. Approvals expire after configurable TTL.

    Concurrency: This store is used within a single-threaded async event loop,
    so no locking is required. Each proxy process has its own store instance.

    Attributes:
        ttl_seconds: How long approvals remain valid.
    """

    def __init__(self, ttl_seconds: int) -> None:
        """Initialize approval store.

        Args:
            ttl_seconds: Approval validity period in seconds.
        """
        self._ttl_seconds = ttl_seconds
        self._store: dict[ApprovalKey, CachedApproval] = {}

    @property
    def ttl_seconds(self) -> int:
        """Get the TTL for cached approvals."""
        return self._ttl_seconds

    @staticmethod
    def _normalize_path(path: str | None) -> str | None:
        """Normalize a path for consistent cache keys.

        Uses os.path.realpath() to resolve symlinks and get canonical path.

        Args:
            path: Raw path from request, or None.

        Returns:
            Normalized absolute path, or None if input was None.
        """
        if path is None:
            return None
        return os.path.realpath(path)

    @staticmethod
    def should_cache(
        tool_side_effects: frozenset["SideEffect"] | None,
        allowed_effects: list["SideEffect"] | None,
    ) -> bool:
        """Determine if a tool's approval should be cached.

        Default (conservative): Only cache tools with KNOWN, EMPTY side effects.
        Unknown tools (side_effects=None) are treated as potentially dangerous.

        This can be overridden via policy to allow specific side effects.

        Args:
            tool_side_effects: Side effects of the tool, or None if unknown.
            allowed_effects: Side effects that are allowed to be cached,
                or None to use default (never cache any side effect).

        Returns:
            True if the approval should be cached, False otherwise.

        Security note:
            Tools with unknown side effects (None) are NOT cached. In the future,
            tools will be tested in a sandboxed environment and only verified
            side effects will be trusted for caching. See docs/roadmap.md
            section 1.4 "Sandbox Verification".

        Security note (CODE_EXEC):
            Tools with CODE_EXEC side effect are NEVER cached, even if cache_side_effects
            includes code_exec. This prevents dangerous scenarios like:
            - User approves `bash cat /etc/passwd`
            - Cache key is (user, bash, /etc/passwd)
            - `bash rm /etc/passwd` matches same cache key and is auto-approved!

            The cache key doesn't include command arguments, so code execution tools
            must always require explicit approval. See docs/roadmap.md section 2.5
            "Tool Arguments in Policy" for future work on argument-aware caching.
        """
        from mcp_acp.context.resource import SideEffect

        # Unknown side effects = don't cache (conservative)
        if tool_side_effects is None:
            return False

        # Known empty side effects = safe to cache
        if len(tool_side_effects) == 0:
            return True

        # NEVER cache code execution tools - cache key doesn't include args
        if SideEffect.CODE_EXEC in tool_side_effects:
            return False

        # If policy specifies allowed effects, check if tool's effects are subset
        if allowed_effects is not None:
            return tool_side_effects.issubset(set(allowed_effects))

        # Default: don't cache tools with any side effect
        return False

    def store(
        self,
        subject_id: str,
        tool_name: str,
        path: str | None,
        request_id: str,
    ) -> CachedApproval:
        """Store an approval after HITL success.

        Args:
            subject_id: The user who approved.
            tool_name: The tool that was approved.
            path: The path that was approved (will be normalized).
            request_id: Request ID for audit trail.

        Returns:
            The stored CachedApproval object.
        """
        normalized_path = self._normalize_path(path)
        key: ApprovalKey = (subject_id, tool_name, normalized_path)

        approval = CachedApproval(
            subject_id=subject_id,
            tool_name=tool_name,
            path=normalized_path,
            stored_at=time.monotonic(),
            request_id=request_id,
        )

        self._store[key] = approval
        return approval

    def lookup(
        self,
        subject_id: str,
        tool_name: str,
        path: str | None,
    ) -> CachedApproval | None:
        """Look up a cached approval.

        Automatically removes expired entries on lookup.

        Args:
            subject_id: The user making the request.
            tool_name: The tool being called.
            path: The path being accessed (will be normalized).

        Returns:
            CachedApproval if valid and not expired, None otherwise.
        """
        normalized_path = self._normalize_path(path)
        key: ApprovalKey = (subject_id, tool_name, normalized_path)

        approval = self._store.get(key)
        if approval is None:
            return None

        # Check TTL using monotonic time
        age = time.monotonic() - approval.stored_at
        if age > self._ttl_seconds:
            # Expired - clean up
            del self._store[key]
            return None

        return approval

    def get_age_seconds(self, approval: CachedApproval) -> float:
        """Get the age of an approval in seconds.

        Args:
            approval: The cached approval.

        Returns:
            Age in seconds since the approval was stored.
        """
        return time.monotonic() - approval.stored_at

    def delete(
        self,
        subject_id: str,
        tool_name: str,
        path: str | None,
    ) -> bool:
        """Delete a specific cached approval.

        Args:
            subject_id: The user who approved.
            tool_name: The tool that was approved.
            path: The path that was approved (will be normalized).

        Returns:
            True if the approval existed and was deleted, False otherwise.
        """
        normalized_path = self._normalize_path(path)
        key: ApprovalKey = (subject_id, tool_name, normalized_path)

        if key in self._store:
            del self._store[key]
            return True
        return False

    def clear(self) -> int:
        """Clear all cached approvals.

        Returns:
            Number of approvals cleared.
        """
        count = len(self._store)
        self._store.clear()
        return count

    def iter_all(self) -> list[tuple[ApprovalKey, CachedApproval]]:
        """Iterate over all cached approvals (for API/debugging).

        Returns a snapshot of current cache contents. May include expired entries.

        Returns:
            List of (key, approval) tuples.
        """
        return list(self._store.items())

    @property
    def count(self) -> int:
        """Number of cached approvals (for testing only).

        Note: May include expired entries. Use lookup() to check validity.
        """
        return len(self._store)
