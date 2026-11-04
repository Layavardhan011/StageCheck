"""Unit Tests for Multi-Repository Discovery & Git Baseline Capture (P2-T1)."""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from stagecheck.core.git import (
    DirtyRepositoryError,
    NotAGitRepositoryError,
    RepoBaseline,
    RepositoryNotFoundError,
    UnbornRepositoryError,
    discover_multi_repositories,
    discover_repository,
)


class TestGitDiscovery(unittest.TestCase):
    """Test suite verifying repository discovery, worktrees, unborn HEADs, and baseline capture."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp_dir.name).resolve()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _init_git_repo(self, path: Path, initial_commit: bool = True) -> Path:
        """Helper to create a fresh Git repository."""
        path.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "init", "-b", "main"], cwd=str(path), check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Test Committer"], cwd=str(path), check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "test@stagecheck.local"], cwd=str(path), check=True, capture_output=True)

        if initial_commit:
            readme = path / "README.md"
            readme.write_text("# Test Repo\n", encoding="utf-8")
            subprocess.run(["git", "add", "README.md"], cwd=str(path), check=True, capture_output=True)
            subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=str(path), check=True, capture_output=True)
        return path

    def test_discover_standard_clean_repository(self) -> None:
        """Verify discovering a standard clean git repository."""
        repo_path = self.workspace / "repos" / "payment-service"
        self._init_git_repo(repo_path, initial_commit=True)

        baseline = discover_repository(repo_path, workspace_root=self.workspace)
        self.assertEqual(baseline.name, "payment-service")
        self.assertEqual(baseline.rel_path, "repos/payment-service")
        self.assertIsNotNone(baseline.head_commit)
        self.assertEqual(len(baseline.head_commit or ""), 40)
        self.assertEqual(baseline.branch, "main")
        self.assertFalse(baseline.is_dirty)
        self.assertFalse(baseline.is_unborn)
        self.assertFalse(baseline.is_worktree)

    def test_discover_unborn_repository(self) -> None:
        """Verify detection of unborn branch with zero commits."""
        repo_path = self.workspace / "repos" / "unborn-repo"
        self._init_git_repo(repo_path, initial_commit=False)

        # By default, unborn repos raise UnbornRepositoryError
        with self.assertRaises(UnbornRepositoryError):
            discover_repository(repo_path)

        # When allow_unborn=True, captures baseline with None commit
        baseline = discover_repository(repo_path, allow_unborn=True)
        self.assertTrue(baseline.is_unborn)
        self.assertIsNone(baseline.head_commit)

    def test_discover_dirty_repository(self) -> None:
        """Verify detection of dirty working tree status."""
        repo_path = self.workspace / "repos" / "dirty-repo"
        self._init_git_repo(repo_path, initial_commit=True)

        # Create uncommitted file
        (repo_path / "dirty.txt").write_text("uncommitted", encoding="utf-8")

        baseline = discover_repository(repo_path, require_clean=False)
        self.assertTrue(baseline.is_dirty)

        # When require_clean=True, raises DirtyRepositoryError
        with self.assertRaises(DirtyRepositoryError):
            discover_repository(repo_path, require_clean=True)

    def test_discover_worktree_repository(self) -> None:
        """Verify discovering a git worktree pointer (where .git is a file)."""
        main_repo = self.workspace / "main-repo"
        self._init_git_repo(main_repo, initial_commit=True)

        worktree_path = self.workspace / "repos" / "worktree-repo"
        subprocess.run(
            ["git", "worktree", "add", "-b", "feature/worktree", str(worktree_path)],
            cwd=str(main_repo),
            check=True,
            capture_output=True,
        )

        baseline = discover_repository(worktree_path, workspace_root=self.workspace)
        self.assertTrue(baseline.is_worktree)
        self.assertEqual(baseline.branch, "feature/worktree")
        self.assertIsNotNone(baseline.head_commit)

    def test_missing_repository_raises_error(self) -> None:
        """Verify RepositoryNotFoundError when directory does not exist."""
        nonexistent = self.workspace / "repos" / "missing"
        with self.assertRaises(RepositoryNotFoundError):
            discover_repository(nonexistent)

    def test_not_a_git_repository_raises_error(self) -> None:
        """Verify NotAGitRepositoryError on plain directory."""
        plain_dir = self.workspace / "plain-folder"
        plain_dir.mkdir(parents=True)
        with self.assertRaises(NotAGitRepositoryError):
            discover_repository(plain_dir)

    def test_multi_repository_discovery(self) -> None:
        """Verify multi-repository discovery across repos/."""
        repo1 = self._init_git_repo(self.workspace / "repos" / "payment-service")
        repo2 = self._init_git_repo(self.workspace / "repos" / "ledger-api")

        baselines = discover_multi_repositories(
            workspace_root=self.workspace,
            declared_repos=["payment-service", "ledger-api"],
        )

        self.assertIn("payment-service", baselines)
        self.assertIn("ledger-api", baselines)
        self.assertEqual(baselines["payment-service"].rel_path, "repos/payment-service")
        self.assertEqual(baselines["ledger-api"].rel_path, "repos/ledger-api")

    def test_no_silent_mutation(self) -> None:
        """Verify that discovery does not alter commit HEAD, config, or working files."""
        repo_path = self.workspace / "repos" / "immutable-test"
        self._init_git_repo(repo_path, initial_commit=True)

        initial_head = (
            subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(repo_path), capture_output=True, text=True)
            .stdout.strip()
        )

        # Run discovery multiple times
        for _ in range(5):
            baseline = discover_repository(repo_path)
            self.assertEqual(baseline.head_commit, initial_head)

        after_head = (
            subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(repo_path), capture_output=True, text=True)
            .stdout.strip()
        )
        self.assertEqual(initial_head, after_head)


if __name__ == "__main__":
    unittest.main()
