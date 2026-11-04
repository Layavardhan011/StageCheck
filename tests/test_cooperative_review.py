"""Unit and Integration Tests for Phase 2A Pre-Commit Cooperative Review (P3-T5)."""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from stagecheck.cli.main import main
from stagecheck.core.cooperative_review import (
    CommitDivergenceError,
    CommitUnauthorizedError,
    ReviewGateError,
    assert_commit_authorization,
    compute_uncommitted_diff_hashes,
    record_pre_commit_review,
    submit_pre_commit_status,
    verify_committed_diff_fidelity,
)


class TestCooperativeReview(unittest.TestCase):
    """Test suite covering Phase 2A review cycles, diff hashing, approval gates, and issue history."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp_dir.name).resolve()

        # Set up a mock git repository in repos/backend
        self.repos_dir = self.workspace / "repos"
        self.backend_dir = self.repos_dir / "backend"
        self.backend_dir.mkdir(parents=True, exist_ok=True)

        subprocess.run(["git", "init", "-b", "order-service/task-101"], cwd=str(self.backend_dir), check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Test User"], cwd=str(self.backend_dir), check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "test@stagecheck.local"], cwd=str(self.backend_dir), check=True, capture_output=True)
        readme = self.backend_dir / "README.md"
        readme.write_text("# Backend\n", encoding="utf-8")
        subprocess.run(["git", "add", "README.md"], cwd=str(self.backend_dir), check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=str(self.backend_dir), check=True, capture_output=True)

        res = subprocess.run(["git", "-C", str(self.backend_dir), "rev-parse", "HEAD"], stdout=subprocess.PIPE, text=True, check=True)
        self.base_commit = res.stdout.strip()

        self.task_id = "task-101"
        self.attempt = 1

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_submit_pre_commit_status_success(self) -> None:
        """Verify Agent 2 submits valid pre_commit_status.json."""
        status_file = submit_pre_commit_status(
            workspace_root=self.workspace,
            task_id=self.task_id,
            attempt=self.attempt,
            cycle=1,
            touched_repositories=["backend"],
            base_commits={"backend": self.base_commit},
            summary="Initial uncommitted implementation ready",
        )
        self.assertTrue(status_file.is_file())
        data = json.loads(status_file.read_text(encoding="utf-8"))
        self.assertEqual(data["task_id"], self.task_id)
        self.assertEqual(data["cycle"], 1)
        self.assertEqual(data["status"], "AWAITING_REVIEW")

    def test_revision_required_flow_appends_to_issue_history(self) -> None:
        """Verify REVISION_REQUIRED records findings, writes response.json, and appends to issue history."""
        # Uncommitted change in backend
        order_file = self.backend_dir / "order.py"
        order_file.write_text("def order(): pass\n", encoding="utf-8")

        new_issues = [
            {"defect_id": "ARCH-01", "description": "Missing timeout handling in order endpoint"}
        ]
        pre_existing = [
            {"diagnostic": "Legacy warning in README"}
        ]

        review_file = record_pre_commit_review(
            workspace_root=self.workspace,
            task_id=self.task_id,
            attempt=self.attempt,
            cycle=1,
            status="REVISION_REQUIRED",
            summary="Defects detected in order.py",
            base_commits={"backend": self.base_commit},
            pre_existing_issues=pre_existing,
            new_issues=new_issues,
        )
        self.assertTrue(review_file.is_file())
        data = json.loads(review_file.read_text(encoding="utf-8"))
        self.assertEqual(data["status"], "REVISION_REQUIRED")

        # Verify response.json written
        phase2a_dir = self.workspace / "evidence" / "tasks" / self.task_id / f"attempt_{self.attempt}" / "Phase-2A"
        response_file = phase2a_dir / "response.json"
        self.assertTrue(response_file.is_file())

        # Verify cumulative issue history updated
        history_file = self.workspace / "evidence" / "tasks" / self.task_id / f"{self.task_id.upper()}_ISSUE_HISTORY.md"
        self.assertTrue(history_file.is_file())
        history_text = history_file.read_text(encoding="utf-8")
        self.assertIn("ARCH-01", history_text)

        # Committing must be blocked
        with self.assertRaises(CommitUnauthorizedError):
            assert_commit_authorization(self.workspace, self.task_id, self.attempt)

    def test_approval_flow_authorizes_commit_and_binds_diff_hash(self) -> None:
        """Verify APPROVED status calculates approved_diff_hashes and authorizes commit."""
        # Implement valid change in backend
        order_file = self.backend_dir / "order.py"
        order_file.write_text("def order(): return {'status': 'ok'}\n", encoding="utf-8")

        review_file = record_pre_commit_review(
            workspace_root=self.workspace,
            task_id=self.task_id,
            attempt=self.attempt,
            cycle=2,  # Iterated to cycle 2 without consuming attempt
            status="APPROVED",
            summary="All architectural contracts satisfied",
            base_commits={"backend": self.base_commit},
            architectural_intents=[{"intent": "Added order return dictionary"}],
        )
        self.assertTrue(review_file.is_file())
        data = json.loads(review_file.read_text(encoding="utf-8"))
        self.assertEqual(data["status"], "APPROVED")
        self.assertIn("backend", data["approved_diff_hashes"])
        self.assertEqual(len(data["approved_snapshot_sha256"]), 64)

        # assert_commit_authorization must succeed
        approved_record = assert_commit_authorization(self.workspace, self.task_id, self.attempt)
        self.assertEqual(approved_record["status"], "APPROVED")

    def test_verify_committed_diff_fidelity_detects_divergence(self) -> None:
        """Verify committed diff differing from approved uncommitted diff raises CommitDivergenceError."""
        # Approved working tree state
        order_file = self.backend_dir / "order.py"
        order_file.write_text("def order(): return 1\n", encoding="utf-8")

        record_pre_commit_review(
            workspace_root=self.workspace,
            task_id=self.task_id,
            attempt=self.attempt,
            cycle=1,
            status="APPROVED",
            summary="Approved",
            base_commits={"backend": self.base_commit},
        )
        approved_data = assert_commit_authorization(self.workspace, self.task_id, self.attempt)

        # Now Agent 2 sneakily modifies order.py before committing
        order_file.write_text("def order(): return 999  # SNEAKY CHANGE\n", encoding="utf-8")
        subprocess.run(["git", "add", "order.py"], cwd=str(self.backend_dir), check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "Commit with unreviewed change"], cwd=str(self.backend_dir), check=True, capture_output=True)

        res = subprocess.run(["git", "-C", str(self.backend_dir), "rev-parse", "HEAD"], stdout=subprocess.PIPE, text=True, check=True)
        target_commit = res.stdout.strip()

        # Fidelity check must fail with CommitDivergenceError
        with self.assertRaises(CommitDivergenceError):
            verify_committed_diff_fidelity(
                workspace_root=self.workspace,
                touched_repos=["backend"],
                base_commits={"backend": self.base_commit},
                approved_diff_hashes=approved_data["approved_diff_hashes"],
                target_commits={"backend": target_commit},
            )

    def test_cli_review_precommit_and_approve_subcommands(self) -> None:
        """Verify CLI 'review-precommit' and 'approve-review' subcommands."""
        # Step 1: Submit pre-commit status
        submit_pre_commit_status(
            workspace_root=self.workspace,
            task_id=self.task_id,
            attempt=self.attempt,
            cycle=1,
            touched_repositories=["backend"],
            base_commits={"backend": self.base_commit},
        )

        # Step 2: Run review-precommit CLI
        ret_rev = main([
            "review-precommit",
            "--task", self.task_id,
            "--attempt", str(self.attempt),
            "--workspace", str(self.workspace),
        ])
        self.assertEqual(ret_rev, 0)

        # Step 3: Run approve-review CLI
        ret_appr = main([
            "approve-review",
            "--task", self.task_id,
            "--attempt", str(self.attempt),
            "--workspace", str(self.workspace),
        ])
        self.assertEqual(ret_appr, 0)

        # Assert authorization now passes
        approved = assert_commit_authorization(self.workspace, self.task_id, self.attempt)
        self.assertEqual(approved["status"], "APPROVED")


if __name__ == "__main__":
    unittest.main()

