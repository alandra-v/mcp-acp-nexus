"""Tests for ProtectedPathChecker.

Verifies the built-in security mechanism that protects
config and log directories from MCP tool access.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from mcp_acp.pep.protected_paths import ProtectedPathChecker


class TestProtectedPathChecker:
    """Tests for ProtectedPathChecker class."""

    def test_empty_protected_dirs(self) -> None:
        """No protected dirs means nothing is protected."""
        checker = ProtectedPathChecker(())
        assert not checker.is_protected("/any/path")
        assert not checker.is_protected("/usr/local/bin")

    def test_none_path_not_protected(self) -> None:
        """None path is never protected."""
        checker = ProtectedPathChecker(("/protected",))
        assert not checker.is_protected(None)

    def test_path_under_protected_dir(self, tmp_path: Path) -> None:
        """Path under protected dir is protected."""
        protected = tmp_path / "protected"
        protected.mkdir()
        checker = ProtectedPathChecker((str(protected),))

        # File directly in protected dir
        assert checker.is_protected(str(protected / "file.txt"))
        # File in subdirectory
        assert checker.is_protected(str(protected / "subdir" / "file.txt"))

    def test_path_outside_protected_dir(self, tmp_path: Path) -> None:
        """Path outside protected dir is not protected."""
        protected = tmp_path / "protected"
        protected.mkdir()
        other = tmp_path / "other"
        other.mkdir()

        checker = ProtectedPathChecker((str(protected),))

        assert not checker.is_protected(str(other / "file.txt"))
        assert not checker.is_protected(str(tmp_path / "file.txt"))

    def test_exact_protected_dir_match(self, tmp_path: Path) -> None:
        """The protected directory itself is protected."""
        protected = tmp_path / "protected"
        protected.mkdir()
        checker = ProtectedPathChecker((str(protected),))

        # The directory itself
        assert checker.is_protected(str(protected))

    def test_similar_prefix_not_protected(self, tmp_path: Path) -> None:
        """Path with similar prefix but not under protected dir is not protected."""
        protected = tmp_path / "protected"
        protected.mkdir()
        # Create a directory with similar prefix
        protected_extra = tmp_path / "protected-extra"
        protected_extra.mkdir()

        checker = ProtectedPathChecker((str(protected),))

        # Should NOT be protected - different directory
        assert not checker.is_protected(str(protected_extra / "file.txt"))

    def test_multiple_protected_dirs(self, tmp_path: Path) -> None:
        """Multiple protected directories all work."""
        config = tmp_path / "config"
        logs = tmp_path / "logs"
        data = tmp_path / "data"
        config.mkdir()
        logs.mkdir()
        data.mkdir()

        checker = ProtectedPathChecker((str(config), str(logs)))

        assert checker.is_protected(str(config / "file.txt"))
        assert checker.is_protected(str(logs / "file.txt"))
        assert not checker.is_protected(str(data / "file.txt"))

    def test_symlink_resolved(self, tmp_path: Path) -> None:
        """Symlinks to protected dirs are also protected."""
        protected = tmp_path / "protected"
        protected.mkdir()
        symlink = tmp_path / "symlink"
        symlink.symlink_to(protected)

        checker = ProtectedPathChecker((str(protected),))

        # Access via symlink should still be protected
        assert checker.is_protected(str(symlink / "file.txt"))

    def test_symlink_bypass_prevented(self, tmp_path: Path) -> None:
        """Symlinks from outside protected dir to inside are protected."""
        protected = tmp_path / "protected"
        protected.mkdir()
        (protected / "secret.txt").write_text("secret")

        # Create symlink outside protected dir pointing to file inside
        symlink = tmp_path / "bypass"
        symlink.symlink_to(protected / "secret.txt")

        checker = ProtectedPathChecker((str(protected),))

        # The symlink itself resolves to protected path
        assert checker.is_protected(str(symlink))

    def test_protected_dirs_property(self, tmp_path: Path) -> None:
        """protected_dirs property returns resolved paths."""
        protected = tmp_path / "protected"
        protected.mkdir()

        checker = ProtectedPathChecker((str(protected),))

        # Should return resolved (real) paths
        assert len(checker.protected_dirs) == 1
        assert os.path.isabs(checker.protected_dirs[0])

    def test_nonexistent_path_not_protected(self, tmp_path: Path) -> None:
        """Nonexistent path outside protected dirs is not protected."""
        protected = tmp_path / "protected"
        protected.mkdir()

        checker = ProtectedPathChecker((str(protected),))

        # Path doesn't exist but is outside protected dirs
        nonexistent = tmp_path / "nonexistent" / "file.txt"
        assert not checker.is_protected(str(nonexistent))

    def test_invalid_path_not_protected(self) -> None:
        """Invalid path that can't be resolved is not protected."""
        checker = ProtectedPathChecker(("/protected",))

        # Empty string path
        assert not checker.is_protected("")


class TestProtectedPathCheckerEdgeCases:
    """Edge case tests for ProtectedPathChecker."""

    def test_path_with_dots(self, tmp_path: Path) -> None:
        """Paths with .. that resolve under protected dir are protected."""
        protected = tmp_path / "protected"
        protected.mkdir()
        subdir = protected / "subdir"
        subdir.mkdir()

        checker = ProtectedPathChecker((str(protected),))

        # Path that uses .. but still resolves under protected
        tricky_path = str(subdir / ".." / "file.txt")
        assert checker.is_protected(tricky_path)

    def test_path_with_dots_escape(self, tmp_path: Path) -> None:
        """Paths with .. that escape protected dir are not protected."""
        protected = tmp_path / "protected"
        protected.mkdir()

        checker = ProtectedPathChecker((str(protected),))

        # Path that escapes using ..
        escape_path = str(protected / ".." / "other.txt")
        assert not checker.is_protected(escape_path)
