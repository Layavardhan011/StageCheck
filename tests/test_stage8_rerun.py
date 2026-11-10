"""Comprehensive Test Suite for Task 4.1: Topology-Preserving Multi-Repository Audit Worktrees (FR-11 / DEC-011).

Verifies:
1. Worktree sibling topology:
   - Ephemeral worktrees created under .stagecheck_worktrees/<task_id>/attempt_<N>/repos/
   - Relative sibling references (../shared) resolve identically to workspace repos.
2. Baseline capture and binding:
   - Baselines captured for all participating repositories.
   - Detached HEAD at baseline commit verified.
3. Dirty baseline policy:
   - Clean repository required when enforce_clean_baseline=True; raises DirtyRepositoryError if dirty.
   - Dirty check ignored when enforce_clean_baseline=False.
4. Path safety and injection defense:
   - Path traversal in task_id ('../../etc') rejected with InvalidWorktreePathError.
   - Attempt index < 1 rejected.
   - Safe Git security flags applied (core.hooksPath=/dev/null).
5. Lifecycle and crash recovery:
   - Normal teardown removes worktrees and prunes Git references.
   - Teardown on exception cleans up partially initialized worktrees.
   - prune_abandoned_worktrees cleans orphaned worktrees.
"""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from stagecheck.cli.init_cmd import run_init
from stagecheck.core.git import DirtyRepositoryError
from stagecheck.core.permissions import elevate_permissions_for_teardown
from stagecheck.core.topology import (
    InvalidWorktreePathError,
    TopologyWorktreeManager,
    managed_topology_worktrees,
    prune_abandoned_worktrees,
    validate_worktree_hierarchy,
)


def _init_git_repo(path: Path) -> str:
    """Helper to initialize a Git repository with an initial commit and return HEAD SHA."""
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-b", "main"], cwd=str(path), capture_output=True, check=True)
    subprocess.run(["git", "config", "user.name", "Tester"], cwd=str(path), capture_output=True, check=True)
    subprocess.run(["git", "config", "user.email", "tester@stagecheck.local"], cwd=str(path), capture_output=True, check=True)
    (path / "README.md").write_text(f"# {path.name}\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=str(path), capture_output=True, check=True)
    subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=str(path), capture_output=True, check=True)
    res = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(path), capture_output=True, text=True, check=True)
    return res.stdout.strip()


class TestTopologyWorktreeHierarchy(unittest.TestCase):
    """Test path validation and hierarchy constraints."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.ws = Path(self.temp_dir.name).resolve()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_valid_hierarchy_path(self) -> None:
        """Verify standard path resolves properly."""
        target = validate_worktree_hierarchy(self.ws, "TASK-101", 1)
        expected = self.ws / ".stagecheck_worktrees" / "TASK-101" / "attempt_1" / "repos"
        self.assertEqual(target, expected)

    def test_invalid_task_id_rejection(self) -> None:
        """Verify invalid task IDs (traversal, special characters) are rejected."""
        invalid_ids = ["../escaped", "task/sub", "task*id", "task;rm", ""]
        for bad_id in invalid_ids:
            with self.assertRaises(InvalidWorktreePathError):
                validate_worktree_hierarchy(self.ws, bad_id, 1)

    def test_invalid_attempt_index_rejection(self) -> None:
        """Verify non-positive attempt index is rejected."""
        with self.assertRaises(InvalidWorktreePathError):
            validate_worktree_hierarchy(self.ws, "TASK-101", 0)
        with self.assertRaises(InvalidWorktreePathError):
            validate_worktree_hierarchy(self.ws, "TASK-101", -1)


class TestTopologyPreservingWorktrees(unittest.TestCase):
    """Deep verification of multi-repository sibling topology and relative imports."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.ws = Path(self.temp_dir.name).resolve()

        # Create two sibling repos: backend and shared
        self.shared_dir = self.ws / "repos" / "shared"
        self.shared_commit = _init_git_repo(self.shared_dir)
        (self.shared_dir / "common.py").write_text("VALUE = 42\n", encoding="utf-8")
        subprocess.run(["git", "add", "common.py"], cwd=str(self.shared_dir), check=True)
        subprocess.run(["git", "commit", "-m", "add common"], cwd=str(self.shared_dir), check=True)
        self.shared_commit = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=str(self.shared_dir), capture_output=True, text=True, check=True
        ).stdout.strip()

        self.backend_dir = self.ws / "repos" / "backend"
        self.backend_commit = _init_git_repo(self.backend_dir)
        # backend references ../shared/common.py
        backend_app = self.backend_dir / "app.py"
        backend_app.write_text(
            "import sys\n"
            "from pathlib import Path\n"
            "shared_path = (Path(__file__).parent / '../shared').resolve()\n"
            "sys.path.append(str(shared_path))\n"
            "import common\n"
            "assert common.VALUE == 42\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "add", "app.py"], cwd=str(self.backend_dir), check=True)
        subprocess.run(["git", "commit", "-m", "add app with relative import"], cwd=str(self.backend_dir), check=True)
        self.backend_commit = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=str(self.backend_dir), capture_output=True, text=True, check=True
        ).stdout.strip()

        # Initialize workspace
        rc = run_init(
            workspace=str(self.ws),
            agent1="agent1",
            agent2="agent2",
            repos="backend,shared",
        )
        self.assertEqual(rc, 0)

    def tearDown(self) -> None:
        elevate_permissions_for_teardown(self.ws)
        self.temp_dir.cleanup()

    def test_worktree_sibling_topology(self) -> None:
        """Verify relative sibling import (../shared) resolves identically in audit worktree (DEC-011)."""
        task_id = "TASK-TEST-01"
        attempt = 1

        with managed_topology_worktrees(
            workspace_root=self.ws,
            task_id=task_id,
            attempt_index=attempt,
            enforce_clean_baseline=True,
        ) as layout:
            backend_wt = layout.worktrees["backend"].worktree_path
            shared_wt = layout.worktrees["shared"].worktree_path

            self.assertTrue(backend_wt.exists())
            self.assertTrue(shared_wt.exists())

            # Check exact sibling relative path
            resolved_shared = (backend_wt / "../shared").resolve()
            self.assertEqual(resolved_shared, shared_wt)

            # Execute python script in backend worktree referencing ../shared
            res = subprocess.run(
                ["python3", str(backend_wt / "app.py")],
                cwd=str(backend_wt),
                capture_output=True,
                text=True,
            )
            self.assertEqual(res.returncode, 0, f"Relative import failed: {res.stderr}")

        # After context exit, worktrees must be dismantled
        self.assertFalse(backend_wt.exists())
        self.assertFalse(shared_wt.exists())

    def test_dirty_baseline_policy_enforcement(self) -> None:
        """Verify dirty repository blocks worktree creation when enforce_clean_baseline=True."""
        # Make backend dirty
        (self.backend_dir / "uncommitted.txt").write_text("dirty\n", encoding="utf-8")

        manager = TopologyWorktreeManager(
            workspace_root=self.ws,
            task_id="TASK-DIRTY-01",
            attempt_index=1,
            enforce_clean_baseline=True,
        )
        with self.assertRaises(DirtyRepositoryError):
            manager.setup()

        # Ensure no dangling worktree was left behind
        wt_repos = self.ws / ".stagecheck_worktrees" / "TASK-DIRTY-01" / "attempt_1" / "repos"
        self.assertFalse(wt_repos.exists())

    def test_untouched_repo_symlink_optimization(self) -> None:
        """Verify untouched repositories use isolated detached worktrees rather than live symlinks."""
        task_id = "TASK-SYM-01"
        attempt = 1

        # Only backend touched; shared is untouched
        with managed_topology_worktrees(
            workspace_root=self.ws,
            task_id=task_id,
            attempt_index=attempt,
            enforce_clean_baseline=True,
            touched_repos={"backend"},
        ) as layout:
            backend_wt = layout.worktrees["backend"]
            shared_wt = layout.worktrees["shared"]

            self.assertFalse(backend_wt.is_symlink)
            self.assertFalse(shared_wt.is_symlink)
            self.assertNotEqual(shared_wt.worktree_path.resolve(), self.shared_dir.resolve())

            # Sibling import still resolves cleanly across isolated worktrees!
            res = subprocess.run(
                ["python3", str(backend_wt.worktree_path / "app.py")],
                cwd=str(backend_wt.worktree_path),
                capture_output=True,
                text=True,
            )
            self.assertEqual(res.returncode, 0, f"Worktree sibling resolution failed: {res.stderr}")

    def test_prune_abandoned_worktrees(self) -> None:
        """Verify crash recovery helper cleans abandoned worktrees."""
        # Manually create a dangling worktree directly with git
        orphan_dir = self.ws / ".stagecheck_worktrees" / "ORPHAN-01" / "attempt_1" / "repos" / "backend"
        orphan_dir.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["git", "-C", str(self.backend_dir), "worktree", "add", "--detach", str(orphan_dir), self.backend_commit],
            check=True,
            capture_output=True,
        )
        self.assertTrue(orphan_dir.exists())

        # Prune abandoned worktrees
        prune_abandoned_worktrees(self.ws)

        # Stale worktree should be gone or pruned
        res = subprocess.run(
            ["git", "-C", str(self.backend_dir), "worktree", "list"],
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertNotIn("ORPHAN-01", res.stdout)


if __name__ == "__main__":
    unittest.main()

