"""Unit Tests for Multi-Repository Discovery & Git Baseline Capture (P2-T1)."""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from stagecheck.core.git import (
    DirtyRepositoryError,
    GitError,
    NotAGitRepositoryError,
    RepoBaseline,
    RepositoryNotFoundError,
    SAFE_GIT_SECURITY_FLAGS,
    UnbornRepositoryError,
    _run_git_cmd,
    discover_multi_repositories,
    discover_repository,
    run_safe_git,
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

    def test_git_security_flags_applied(self) -> None:
        """Verify SAFE_GIT_SECURITY_FLAGS and safe diff flags prevent config injection (DEC-015 / SR-02)."""
        repo_path = self.workspace / "repos" / "security-repo"
        self._init_git_repo(repo_path, initial_commit=True)

        # 1. Verify SAFE_GIT_SECURITY_FLAGS definition
        self.assertIn("-c", SAFE_GIT_SECURITY_FLAGS)
        self.assertIn("core.fsmonitor=false", SAFE_GIT_SECURITY_FLAGS)
        self.assertIn("core.pager=cat", SAFE_GIT_SECURITY_FLAGS)
        self.assertIn("core.hooksPath=/dev/null", SAFE_GIT_SECURITY_FLAGS)
        self.assertIn("core.editor=cat", SAFE_GIT_SECURITY_FLAGS)

        # 2. Verify _run_git_cmd uses the flags
        from unittest.mock import patch
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="test\n", stderr="")
            _run_git_cmd(repo_path, ["status", "--porcelain"])
            self.assertTrue(mock_run.called)
            called_cmd = mock_run.call_args[0][0]
            self.assertEqual(called_cmd[0], "git")
            for flag in SAFE_GIT_SECURITY_FLAGS:
                self.assertIn(flag, called_cmd)

        # 3. Verify get_repo_diff uses safe git flags and --no-ext-diff --no-textconv
        from stagecheck.core.branch_governance import get_repo_diff
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="diff output", stderr="")
            get_repo_diff(repo_path, "HEAD~1")
            self.assertTrue(mock_run.called)
            called_cmd = mock_run.call_args[0][0]
            for flag in SAFE_GIT_SECURITY_FLAGS:
                self.assertIn(flag, called_cmd)
            self.assertIn("--binary", called_cmd)
            self.assertIn("--no-ext-diff", called_cmd)
            self.assertIn("--no-textconv", called_cmd)

    def test_run_safe_git_blocks_fsmonitor_and_ext_diff(self) -> None:
        """Verify run_safe_git prevents local core.fsmonitor and diff.external execution (SC-SEC-07)."""
        repo_path = self.workspace / "repos" / "fsmonitor-repo"
        self._init_git_repo(repo_path, initial_commit=True)

        marker = self.workspace / "fsmonitor_marker"
        diff_marker = self.workspace / "extdiff_marker"
        subprocess.run(
            ["git", "config", "core.fsmonitor", f"touch {marker} && false"],
            cwd=str(repo_path), check=True, capture_output=True,
        )
        subprocess.run(
            ["git", "config", "diff.external", f"touch {diff_marker} && false"],
            cwd=str(repo_path), check=True, capture_output=True,
        )

        # Modify tracked file so git diff and git status exercise diff/status paths
        (repo_path / "README.md").write_text("# Modified\n", encoding="utf-8")

        res_status = run_safe_git(repo_path, ["status", "--porcelain"])
        self.assertEqual(res_status.returncode, 0)
        self.assertIn("README.md", res_status.stdout)
        self.assertFalse(marker.exists(), "run_safe_git must neutralize core.fsmonitor")

        res_diff = run_safe_git(repo_path, ["diff"])
        self.assertEqual(res_diff.returncode, 0)
        self.assertFalse(diff_marker.exists(), "run_safe_git must neutralize diff.external")

    def test_assert_safe_repo_git_config_detects_malicious_keys(self) -> None:
        """Verify assert_safe_repo_git_config fails closed on dangerous git config sections (SC-SEC-07)."""
        from stagecheck.core.git import assert_safe_repo_git_config

        dangerous_configs = [
            ("filter \"evil\"", "clean", "evil-clean %f"),
            ("filter \"evil\"", "smudge", "evil-smudge %f"),
            ("diff \"evil\"", "command", "/bin/sh -c evil"),
            ("merge \"evil\"", "driver", "/bin/sh -c evil"),
            ("core", "sshCommand", "evil-ssh"),
            ("credential", "helper", "evil-credential-helper"),
            ("alias", "status", "!evil-cmd"),
            ("remote \"origin\"", "uploadpack", "evil-uploadpack"),
        ]

        for section, key, val in dangerous_configs:
            with self.subTest(section=section, key=key):
                test_repo = self.workspace / "repos" / f"danger-{key}"
                self._init_git_repo(test_repo, initial_commit=True)
                cfg_path = test_repo / ".git" / "config"
                with cfg_path.open("a", encoding="utf-8") as f:
                    f.write(f"\n[{section}]\n    {key} = {val}\n")

                with self.assertRaises(GitError) as ctx:
                    assert_safe_repo_git_config(test_repo)
                self.assertIn("UNSAFE_GIT_CONFIG", str(ctx.exception))

                # run_safe_git must also fail closed
                with self.assertRaises(GitError):
                    run_safe_git(test_repo, ["status", "--porcelain"])


if __name__ == "__main__":
    unittest.main()

