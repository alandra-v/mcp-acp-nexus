"""Protected path checking for built-in security.

Protects sensitive directories (config, logs) from MCP tool access.
This is a built-in security feature that runs regardless of policy engine,
ensuring config and log directories cannot be accessed even if policy allows.

This is intentionally separate from policy evaluation because:
1. It's a hardcoded security boundary, not configurable policy
2. It must run regardless of which policy engine is used
3. External engines (Casbin, OPA) should not need to implement this

Thread-safe: Protected directories are resolved at initialization.
Symlink-safe: Paths are resolved to real paths before checking.
"""

from __future__ import annotations

__all__ = ["ProtectedPathChecker"]

import os


class ProtectedPathChecker:
    """Check if paths are under protected directories.

    This is a built-in security measure separate from policy evaluation.
    Protected paths cannot be accessed by MCP tools regardless of policy.

    Usage in middleware:
        checker = ProtectedPathChecker(protected_dirs)
        if checker.is_protected(path):
            return Decision.DENY  # Before policy evaluation

    Thread-safe: resolved paths are cached at initialization.
    Symlink-safe: resolves paths to real paths before checking.
    """

    def __init__(self, protected_dirs: tuple[str, ...] = ()) -> None:
        """Initialize with protected directories.

        Args:
            protected_dirs: Directories protected from MCP tool access.
                Typically includes config and log directories.
                These are resolved to real paths to prevent symlink bypass.
        """
        # Resolve all protected dirs to real paths at init time
        self._protected_dirs = tuple(os.path.realpath(d) for d in protected_dirs)

    @property
    def protected_dirs(self) -> tuple[str, ...]:
        """Get the resolved protected directories."""
        return self._protected_dirs

    def is_protected(self, path: str | None) -> bool:
        """Check if path is under a protected directory.

        Args:
            path: File path to check (may be None).

        Returns:
            True if path is under a protected directory, False otherwise.
        """
        if path is None or not self._protected_dirs:
            return False

        try:
            resolved = os.path.realpath(path)
            return any(resolved == d or resolved.startswith(d + os.sep) for d in self._protected_dirs)
        except (OSError, ValueError):
            # Can't resolve path - not a protected path match
            return False
