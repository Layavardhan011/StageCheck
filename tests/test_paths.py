"""Unit Tests for Portable Root & Component-Normalized Path Primitives (P1-T3)."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from stagecheck.core.paths import (
    PathOutsideBoundaryError,
    PathTraversalError,
    StageCheckPathError,
    SymlinkPathEscapeError,
    WorkspaceRootNotFoundError,
    find_workspace_root,
    is_path_contained,
    safe_resolve,
    to_portable_posix,
)


class TestPaths(unittest.TestCase):
    """Test suite verifying portable path resolution and security boundary invariants."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name).resolve()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_find_workspace_root_via_control_descriptor(self) -> None:
        """Verify discovery when controls/STAGECHECK_ROOT.json exists."""
        controls_dir = self.root / "controls"
        controls_dir.mkdir(parents=True)
        (controls_dir / "STAGECHECK_ROOT.json").write_text("{}", encoding="utf-8")

        sub_dir = self.root / "src" / "deep" / "nested"
        sub_dir.mkdir(parents=True)

        discovered = find_workspace_root(sub_dir)
        self.assertEqual(discovered, self.root)

    def test_find_workspace_root_via_bootstrap_lock(self) -> None:
        """Verify discovery when .stagecheck-init.lock exists in root."""
        (self.root / ".stagecheck-init.lock").touch()
        sub_dir = self.root / "pkg"
        sub_dir.mkdir()

        discovered = find_workspace_root(sub_dir)
        self.assertEqual(discovered, self.root)

    def test_find_workspace_root_not_found_raises_error(self) -> None:
        """Verify WorkspaceRootNotFoundError when no marker is present."""
        empty_dir = self.root / "isolated"
        empty_dir.mkdir()

        with self.assertRaises(WorkspaceRootNotFoundError):
            find_workspace_root(empty_dir)

    def test_is_path_contained_prevents_prefix_confusion(self) -> None:
        """Verify prefix confusion defense (e.g. /workspace-other vs /workspace)."""
        base = self.root / "workspace"
        base.mkdir()

        other = self.root / "workspace-other"
        other.mkdir()

        child = base / "child.txt"
        child.touch()

        # Legitimate child is contained
        self.assertTrue(is_path_contained(child, base))
        # Self is contained
        self.assertTrue(is_path_contained(base, base))
        # Sibling with same prefix is NOT contained
        self.assertFalse(is_path_contained(other, base))
        self.assertFalse(is_path_contained(other / "file.txt", base))

    def test_safe_resolve_valid_relative_path(self) -> None:
        """Verify resolving normal relative paths."""
        target_dir = self.root / "repos" / "payment-service"
        target_dir.mkdir(parents=True)
        file_path = target_dir / "pay.py"
        file_path.write_text("code", encoding="utf-8")

        resolved = safe_resolve("repos/payment-service/pay.py", self.root)
        self.assertEqual(resolved, file_path)

    def test_safe_resolve_rejects_path_traversal(self) -> None:
        """Verify rejection of directory traversal attempts escaping boundary."""
        with self.assertRaises(PathTraversalError):
            safe_resolve("../../etc/passwd", self.root)

        with self.assertRaises(PathTraversalError):
            safe_resolve("repos/payment-service/../../..", self.root)

    def test_safe_resolve_rejects_absolute_path_outside_root(self) -> None:
        """Verify rejection of absolute paths pointing outside root."""
        with self.assertRaises(PathOutsideBoundaryError):
            safe_resolve("/etc/shadow", self.root)

    def test_safe_resolve_rejects_symlinks_by_default(self) -> None:
        """Verify symlink rejection when allow_symlinks is False."""
        real_file = self.root / "real.txt"
        real_file.write_text("data", encoding="utf-8")

        symlink_file = self.root / "link.txt"
        symlink_file.symlink_to(real_file)

        with self.assertRaises(SymlinkPathEscapeError):
            safe_resolve("link.txt", self.root, allow_symlinks=False)

    def test_safe_resolve_symlink_escape_detection(self) -> None:
        """Verify that symlinks escaping root are rejected even if allow_symlinks is True."""
        external_file = Path(tempfile.gettempdir()) / "external_target.txt"
        external_file.write_text("external", encoding="utf-8")

        try:
            escaping_link = self.root / "escape_link.txt"
            escaping_link.symlink_to(external_file)

            with self.assertRaises(SymlinkPathEscapeError):
                safe_resolve("escape_link.txt", self.root, allow_symlinks=True)
        finally:
            if external_file.exists():
                external_file.unlink()

    def test_to_portable_posix(self) -> None:
        """Verify POSIX forward-slash conversion."""
        self.assertEqual(to_portable_posix(Path("repos") / "pay" / "code.py"), "repos/pay/code.py")


if __name__ == "__main__":
    unittest.main()

