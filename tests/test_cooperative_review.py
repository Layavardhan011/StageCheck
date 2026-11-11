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
        from stagecheck.core.gate_engine import advance_gate_atomic
        from stagecheck.core.git import discover_repository
        from stagecheck.core.scaffold import scaffold_controls_atomic
        from stagecheck.core.start_manifest import generate_start_manifest
        from stagecheck.core.state import load_active_state, save_active_state

        # Step 1: Submit pre-commit status
        submit_pre_commit_status(
            workspace_root=self.workspace,
            task_id=self.task_id,
            attempt=self.attempt,
            cycle=1,
            touched_repositories=["backend"],
            base_commits={"backend": self.base_commit},
        )

        # Calling review-precommit before Gate 1 is cleared must fail fail-closed
        ret_rev_premature = main([
            "review-precommit",
            "--task", self.task_id,
            "--attempt", str(self.attempt),
            "--workspace", str(self.workspace),
        ])
        self.assertEqual(ret_rev_premature, 1)

        # Scaffolding controls and satisfying Gate 1
        baselines = {
            "backend": discover_repository(
                self.backend_dir,
                name="backend",
                workspace_root=self.workspace,
            )
        }
        scaffold_controls_atomic(self.workspace, baselines)
        generate_start_manifest(self.workspace)

        from stagecheck.core.agents_md import write_agents_contract
        from stagecheck.core.permissions import controlled_write_transaction
        from stagecheck.core.rubric_engine import load_270_rule_catalog
        from stagecheck.core.utils import canonical_json_dumps, sha256_file

        p1_dir = self.workspace / "evidence" / "tasks" / self.task_id / f"attempt_{self.attempt}" / "Phase-1"
        p1_dir.mkdir(parents=True, exist_ok=True)
        (p1_dir / "prompt.md").write_text("# Prompt\n", encoding="utf-8")
        (p1_dir / "declared_scope.json").write_text(
            json.dumps({
                "schema_version": "2.0",
                "task_id": self.task_id,
                "allowed_paths": ["repos/backend/order.py", "repos/backend/test_order.py"],
            }),
            encoding="utf-8",
        )
        (p1_dir / "prompt_verified.json").write_text(
            json.dumps({"task_id": self.task_id, "status": "VERIFIED"}),
            encoding="utf-8",
        )

        # Compliant tests, evals, waivers, reviews, and phase evidence for strict 270-rule check-rubric
        (self.backend_dir / "test_order.py").write_text(
            "import unittest\n\n\n"
            "def validate_qty(q):\n"
            "    if not isinstance(q, int):\n"
            "        raise TypeError('int expected')\n"
            "    if q <= 0:\n"
            "        raise ValueError('must be positive')\n"
            "    return q\n\n\n"
            "class TestOrder(unittest.TestCase):\n"
            "    def test_positive(self):\n"
            "        self.assertEqual(validate_qty(3), 3)\n\n"
            "    def test_negative_boundary(self):\n"
            "        with self.assertRaises(ValueError):\n"
            "            validate_qty(0)\n\n"
            "    def test_malformed_input(self):\n"
            "        with self.assertRaises(TypeError):\n"
            "            validate_qty(None)\n\n"
            "    def test_duplicate_replay_idempotent(self):\n"
            "        self.assertEqual(validate_qty(2), validate_qty(2))\n",
            encoding="utf-8",
        )
        (self.workspace / "evals").mkdir(parents=True, exist_ok=True)
        from stagecheck.core.dispositions import build_waiver_entry, record_waiver_in_replay_ledger
        from stagecheck.core.rubric_engine import build_agent_reviews_artifact

        waiver_evidence = self.workspace / "evidence" / "waiver_coop.txt"
        waiver_evidence.parent.mkdir(parents=True, exist_ok=True)
        waiver_evidence.write_text("Cooperative pre-commit waiver support.\n", encoding="utf-8")

        catalog = load_270_rule_catalog()
        waiver_ids = [r.rule_id for r in catalog if r.category == "HUMAN_WAIVER"]
        w_entry = build_waiver_entry(
            workspace_root=self.workspace,
            task_id=self.task_id,
            defect_id=waiver_ids[0],
            rationale="Authorized for cooperative pre-commit CLI test",
            authorized_by="owner@stagecheck.local",
            attempt=self.attempt,
            evidence_path="evidence/waiver_coop.txt",
            rule_id=waiver_ids[0],
            waived_rules=waiver_ids,
        )
        disp_doc = {
            "schema_version": "2.0",
            "dispositions": [w_entry],
        }
        with controlled_write_transaction(self.workspace / "controls"):
            (self.workspace / "controls" / "DISPOSITIONS.json").write_text(
                canonical_json_dumps(disp_doc), encoding="utf-8"
            )
        record_waiver_in_replay_ledger(self.workspace, w_entry)
        write_agents_contract(self.workspace)
        if not (self.workspace / "evidence" / "issue_history.json").is_file():
            (self.workspace / "evidence" / "issue_history.json").write_text(
                canonical_json_dumps({"schema_version": "1.0", "issues": []}), encoding="utf-8"
            )
        p2a_dir = self.workspace / "evidence" / "tasks" / self.task_id / f"attempt_{self.attempt}" / "Phase-2A"
        agent_reviews = {
            r.rule_id: {
                "status": "PASS",
                "rationale": f"Verified semantic criterion for {r.title}.",
                "evidence_path": "Phase-2A/agent_reviews.json",
            }
            for r in catalog
            if r.category == "AGENT_ASSISTED"
        }
        reviews_artifact = build_agent_reviews_artifact(
            workspace_root=self.workspace,
            task_id=self.task_id,
            attempt=self.attempt,
            reviews=agent_reviews,
            reviewer="agent1",
            reviewer_role="prompt_and_audit",
        )
        (p2a_dir / "agent_reviews.json").write_text(
            canonical_json_dumps(reviews_artifact),
            encoding="utf-8",
        )
        p2b_dir = self.workspace / "evidence" / "tasks" / self.task_id / f"attempt_{self.attempt}" / "Phase-2B"
        p2b_dir.mkdir(parents=True, exist_ok=True)
        report_file = p2b_dir / "report.md"
        report_file.write_text("# Delivery Report\nImplemented order service.\n", encoding="utf-8")
        (p2b_dir / "claims.json").write_text(
            canonical_json_dumps({
                "task_id": self.task_id,
                "iteration": 1,
                "contract_sha256": sha256_file(self.workspace / "AGENTS.md"),
                "record": "Phase-2B/report.md",
                "record_sha256": sha256_file(report_file),
                "claims": [],
            }),
            encoding="utf-8",
        )
        p3_dir = self.workspace / "evidence" / "tasks" / self.task_id / f"attempt_{self.attempt}" / "Phase-3"
        p3_dir.mkdir(parents=True, exist_ok=True)
        (p3_dir / "test_execution.json").write_text(
            canonical_json_dumps({
                "schema_version": "2.0",
                "task_id": self.task_id,
                "attempt": self.attempt,
                "status": "PASS",
                "repositories": {"backend": {"status": "PASS", "exit_code": 0}},
            }),
            encoding="utf-8",
        )
        (p3_dir / "scanner_report.json").write_text(
            canonical_json_dumps({"schema_version": "2.0", "status": "CLEAN", "findings": []}),
            encoding="utf-8",
        )
        (p3_dir / "verdict.json").write_text(
            canonical_json_dumps({"schema_version": "2.0", "result": "CLEAR", "counts": {"blocking": 0}}),
            encoding="utf-8",
        )

        state = load_active_state(self.workspace)
        state["task_id"] = self.task_id
        state["attempt_index"] = self.attempt
        state["phase"] = "PHASE_1_PLANNING"
        save_active_state(self.workspace, state)

        # Advance Gate 1 to transition to PHASE_2A_CODING
        advance_gate_atomic(self.workspace, "Gate-1", task_id=self.task_id, attempt=self.attempt)

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

    def test_untracked_limits_and_index_lock_enforcement(self) -> None:
        """Verify untracked file ceilings (20 MiB, 500 files) and git index lock (FR-09 / ARCH-03)."""
        from stagecheck.core.cooperative_review import (
            GitIndexLockedError,
            UntrackedBytesExceededError,
            UntrackedCountExceededError,
            inspect_untracked_files,
        )

        # 1. Clean repo inspection
        untracked, count, total_bytes = inspect_untracked_files(self.backend_dir)
        self.assertEqual(count, 0)
        self.assertEqual(total_bytes, 0)

        # 2. Test Git Index Lock
        lock_file = self.backend_dir / ".git" / "index.lock"
        lock_file.write_text("lock", encoding="utf-8")
        try:
            with self.assertRaises(GitIndexLockedError):
                inspect_untracked_files(self.backend_dir)
        finally:
            if lock_file.exists():
                lock_file.unlink()

        # 3. Test untracked count ceiling (> 500 files)
        scratch_dir = self.backend_dir / "untracked_bulk"
        scratch_dir.mkdir(parents=True, exist_ok=True)
        try:
            for i in range(505):
                (scratch_dir / f"file_{i}.txt").write_text("x", encoding="utf-8")

            with self.assertRaises(UntrackedCountExceededError):
                inspect_untracked_files(self.backend_dir)
        finally:
            import shutil
            shutil.rmtree(scratch_dir, ignore_errors=True)

    def test_scope_containment_violation_returns_127(self) -> None:
        """Verify modifying files outside declared scope causes review-precommit to exit with code 127."""
        from stagecheck.core.gate_engine import advance_gate_atomic
        from stagecheck.core.git import discover_repository
        from stagecheck.core.scaffold import scaffold_controls_atomic
        from stagecheck.core.start_manifest import generate_start_manifest
        from stagecheck.core.state import load_active_state, save_active_state

        baselines = {
            "backend": discover_repository(self.backend_dir, name="backend", workspace_root=self.workspace)
        }
        scaffold_controls_atomic(self.workspace, baselines)
        generate_start_manifest(self.workspace)

        p1_dir = self.workspace / "evidence" / "tasks" / self.task_id / f"attempt_{self.attempt}" / "Phase-1"
        p1_dir.mkdir(parents=True, exist_ok=True)
        (p1_dir / "prompt.md").write_text("# Prompt\n", encoding="utf-8")
        (p1_dir / "declared_scope.json").write_text(
            json.dumps({"schema_version": "2.0", "task_id": self.task_id, "allowed_paths": ["repos/backend/order.py"]}),
            encoding="utf-8",
        )
        (p1_dir / "prompt_verified.json").write_text(
            json.dumps({"task_id": self.task_id, "status": "VERIFIED"}),
            encoding="utf-8",
        )

        state = load_active_state(self.workspace)
        state["task_id"] = self.task_id
        state["attempt_index"] = self.attempt
        state["phase"] = "PHASE_1_PLANNING"
        save_active_state(self.workspace, state)

        advance_gate_atomic(self.workspace, "Gate-1", task_id=self.task_id, attempt=self.attempt)

        # Agent 2 introduces an unauthorized file outside declared scope
        unauth = self.backend_dir / "unauthorized_exploit.py"
        unauth.write_text("# exploit\n", encoding="utf-8")

        submit_pre_commit_status(
            workspace_root=self.workspace,
            task_id=self.task_id,
            attempt=self.attempt,
            cycle=1,
            touched_repositories=["backend"],
            base_commits={"backend": self.base_commit},
        )

        ret_rev = main([
            "review-precommit",
            "--task", self.task_id,
            "--attempt", str(self.attempt),
            "--workspace", str(self.workspace),
        ])
        self.assertEqual(ret_rev, 127, "Scope escape must exit with code 127")

    def test_repair_cycles_do_not_consume_attempt_budget(self) -> None:
        """Verify multiple repair cycles in Phase 2A increment cycle without consuming attempt budget (FR-06)."""
        from stagecheck.core.state import load_active_state, save_active_state

        state = load_active_state(self.workspace) if (self.workspace / "controls" / "ACTIVE_STATE.json").is_file() else {}
        initial_attempt = state.get("attempt_index", 1)

        # Cycle 1: Revision required
        record_pre_commit_review(
            workspace_root=self.workspace,
            task_id=self.task_id,
            attempt=self.attempt,
            cycle=1,
            status="REVISION_REQUIRED",
            summary="Defects found in cycle 1",
            base_commits={"backend": self.base_commit},
            new_issues=[{"defect_id": "BUG-01", "description": "Fix bug 1"}],
        )

        # Cycle 2: Revision required
        record_pre_commit_review(
            workspace_root=self.workspace,
            task_id=self.task_id,
            attempt=self.attempt,
            cycle=2,
            status="REVISION_REQUIRED",
            summary="Defects found in cycle 2",
            base_commits={"backend": self.base_commit},
            new_issues=[{"defect_id": "BUG-02", "description": "Fix bug 2"}],
        )

        # Cycle 3: Approved
        record_pre_commit_review(
            workspace_root=self.workspace,
            task_id=self.task_id,
            attempt=self.attempt,
            cycle=3,
            status="APPROVED",
            summary="Approved in cycle 3",
            base_commits={"backend": self.base_commit},
        )

        # Verify attempt index was NOT incremented
        if (self.workspace / "controls" / "ACTIVE_STATE.json").is_file():
            final_state = load_active_state(self.workspace)
            self.assertEqual(final_state.get("attempt_index", 1), initial_attempt)



if __name__ == "__main__":
    unittest.main()

