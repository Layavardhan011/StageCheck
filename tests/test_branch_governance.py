"""Unit and Integration Tests for Branch Governance & Multi-Repo Baseline Binding (P3-T3)."""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from stagecheck.core.branch_governance import (
    BaseCommitMismatchError,
    DirtyWorkingTreeError,
    NonCompliantBranchError,
    ProtectedBranchPolicyError,
    UntouchedRepoViolationError,
    capture_multi_repo_task_baseline,
    compute_diff_hash,
    validate_branch_compliance,
    verify_multi_repo_governance,
)


class TestBranchGovernance(unittest.TestCase):
    """Test suite covering branch policy, multi-repo baselines, diff hashing, and untouched repos."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp_dir.name).resolve()

        # Set up repos/backend and repos/frontend
        self.repos_dir = self.workspace / "repos"
        self.backend_dir = self.repos_dir / "backend"
        self.frontend_dir = self.repos_dir / "frontend"
        self.backend_dir.mkdir(parents=True, exist_ok=True)
        self.frontend_dir.mkdir(parents=True, exist_ok=True)

        self._init_git_repo(self.backend_dir, "order-service/task-101")
        self._init_git_repo(self.frontend_dir, "main")

        self.task_id = "task-101"
        self.attempt = 1

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _init_git_repo(self, repo_path: Path, branch_name: str) -> None:
        subprocess.run(["git", "init", "-b", branch_name], cwd=str(repo_path), check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Test User"], cwd=str(repo_path), check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "test@stagecheck.local"], cwd=str(repo_path), check=True, capture_output=True)
        readme = repo_path / "README.md"
        readme.write_text(f"# {repo_path.name}\n", encoding="utf-8")
        subprocess.run(["git", "add", "README.md"], cwd=str(repo_path), check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=str(repo_path), check=True, capture_output=True)

    def test_branch_policy_rejects_main_and_master(self) -> None:
        """Verify protected default branches main and master are rejected."""
        with self.assertRaises(ProtectedBranchPolicyError):
            validate_branch_compliance("main")

        with self.assertRaises(ProtectedBranchPolicyError):
            validate_branch_compliance("master")

    def test_branch_policy_permits_development_and_compliant_patterns(self) -> None:
        """Verify Development and task sprint branches pass validation."""
        # Development
        validate_branch_compliance("Development")

        # Compliant task / sprint patterns
        validate_branch_compliance("order-service/task-101")
        validate_branch_compliance("web-client/sprint-12")
        validate_branch_compliance("task-404")
        validate_branch_compliance("feature/resilient-orders")

    def test_branch_policy_rejects_non_compliant_branches(self) -> None:
        """Verify non-compliant arbitrary branch names are rejected."""
        with self.assertRaises(NonCompliantBranchError):
            validate_branch_compliance("random_branch_foo")

        with self.assertRaises(NonCompliantBranchError):
            validate_branch_compliance("fix-now")

    def test_capture_and_verify_multi_repo_baseline_clear(self) -> None:
        """Verify multi-repo baseline capture and clean verification."""
        all_repos = ["backend", "frontend"]
        baselines = capture_multi_repo_task_baseline(
            workspace_root=self.workspace,
            task_id=self.task_id,
            attempt=self.attempt,
            repo_names=all_repos,
        )
        self.assertIn("backend", baselines)
        self.assertIn("frontend", baselines)
        self.assertEqual(len(baselines["backend"]["head_commit"]), 40)
        self.assertEqual(len(baselines["backend"]["tree_sha"]), 40)

        # In backend, make a valid new commit on compliant branch
        src_file = self.backend_dir / "order.py"
        src_file.write_text("print('order')\n", encoding="utf-8")
        subprocess.run(["git", "add", "order.py"], cwd=str(self.backend_dir), check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "Add order endpoint"], cwd=str(self.backend_dir), check=True, capture_output=True)

        # Audit backend as touched, frontend as untouched
        result = verify_multi_repo_governance(
            workspace_root=self.workspace,
            task_id=self.task_id,
            attempt=self.attempt,
            touched_repos=["backend"],
            all_registered_repos=all_repos,
            base_commits={"backend": baselines["backend"]["head_commit"]},
        )
        self.assertEqual(result["status"], "CLEAR")
        self.assertTrue(result["checked_heads"]["backend"]["modified"])
        self.assertFalse(result["checked_heads"]["frontend"]["modified"])
        self.assertIn("backend", result["approved_diff_hashes"])

    def test_verify_rejects_dirty_working_tree_in_touched_repo(self) -> None:
        """Verify audit fails when a touched repository has uncommitted changes."""
        all_repos = ["backend", "frontend"]
        capture_multi_repo_task_baseline(self.workspace, self.task_id, self.attempt, all_repos)

        # Leave uncommitted file in backend
        dirty_file = self.backend_dir / "dirty.txt"
        dirty_file.write_text("uncommitted\n", encoding="utf-8")

        with self.assertRaises(DirtyWorkingTreeError):
            verify_multi_repo_governance(
                self.workspace,
                self.task_id,
                self.attempt,
                touched_repos=["backend"],
                all_registered_repos=all_repos,
            )

    def test_verify_rejects_protected_branch_in_touched_repo(self) -> None:
        """Verify audit fails when touched repository is on main or master."""
        all_repos = ["backend", "frontend"]
        capture_multi_repo_task_baseline(self.workspace, self.task_id, self.attempt, all_repos)

        # Attempt to audit frontend (which is on 'main') as touched
        with self.assertRaises(ProtectedBranchPolicyError):
            verify_multi_repo_governance(
                self.workspace,
                self.task_id,
                self.attempt,
                touched_repos=["frontend"],
                all_registered_repos=all_repos,
            )

    def test_verify_rejects_base_commit_mismatch(self) -> None:
        """Verify audit fails when declared base commit does not match ancestor."""
        all_repos = ["backend", "frontend"]
        capture_multi_repo_task_baseline(self.workspace, self.task_id, self.attempt, all_repos)

        with self.assertRaises(BaseCommitMismatchError):
            verify_multi_repo_governance(
                self.workspace,
                self.task_id,
                self.attempt,
                touched_repos=["backend"],
                all_registered_repos=all_repos,
                base_commits={"backend": "0" * 40},  # Non-existent/unrelated SHA
            )

    def test_verify_rejects_unexpected_mutation_in_untouched_repo(self) -> None:
        """Verify audit fails when an untouched repository has been modified."""
        all_repos = ["backend", "frontend"]
        capture_multi_repo_task_baseline(self.workspace, self.task_id, self.attempt, all_repos)

        # Touch frontend (which is declared untouched)
        unauth_file = self.frontend_dir / "unauthorized.txt"
        unauth_file.write_text("leak\n", encoding="utf-8")

        with self.assertRaises(UntouchedRepoViolationError):
            verify_multi_repo_governance(
                self.workspace,
                self.task_id,
                self.attempt,
                touched_repos=["backend"],
                all_registered_repos=all_repos,
            )


if __name__ == "__main__":
    unittest.main()

