"""Comprehensive Unit and Integration Tests for Task 3.4: Commit Authorization and Gate 2B.

Verifies:
1. Gate 2B criteria evaluation:
   - Prior pre-commit review must be APPROVED and bound as a receipt deliverable.
   - Phase 2B delivery report must exist and be bound as a receipt deliverable.
   - Working tree must be clean across all touched/declared repositories.
   - Commits must not be directly on protected branch (main/master).
   - Committed diff must strictly match approved pre-commit diff (verify_committed_diff_fidelity).
   - Remote push URLs must comply with authorized remote whitelist (approved_remote).
   - Agent 2 zero remote push policy is enforced.
2. Atomic Gate 2B advance transitions state from PHASE_2B_COMMITTING to PHASE_3_AUDIT,
   sets turn to STAGECHECK_AUDITING, records live receipt SHA-256, and freezes Phase-2B/ to 0555/0444.
3. Commit divergence or unauthorized remote fails closed without consuming attempt budget.
"""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from stagecheck.cli.gate_cmd import run_gate_advance, run_gate_check
from stagecheck.cli.init_cmd import run_init
from stagecheck.cli.review_cmd import run_approve_review
from stagecheck.core.prompt_gate import freeze_prompt_and_scope
from stagecheck.core.gate_engine import (
    GateCriteriaFailedError,
    GateId,
    advance_gate_atomic,
    check_gate_preconditions,
    evaluate_gate_2b_criteria,
)
from stagecheck.core.git import approved_remote, get_approved_remote_urls, get_repo_remote_push_urls
from stagecheck.core.permissions import controlled_write_transaction, elevate_permissions_for_teardown
from stagecheck.core.state import load_active_state, save_active_state
from stagecheck.core.utils import sha256_file


def _git_run(args, cwd):
    return subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        check=True,
    )


class TestGate2BAuthorization(unittest.TestCase):
    """Test suite validating Gate 2B commit authorization, diff fidelity, and remote whitelist."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.ws = Path(self.temp_dir.name).resolve()

        # Create git repo first
        self.repo_dir = self.ws / "repos" / "payment-service"
        self.repo_dir.mkdir(parents=True, exist_ok=True)
        _git_run(["init", "-b", "main"], cwd=self.repo_dir)
        _git_run(["config", "user.name", "Test Committer"], cwd=self.repo_dir)
        _git_run(["config", "user.email", "test@stagecheck.local"], cwd=self.repo_dir)
        readme = self.repo_dir / "README.md"
        readme.write_text("# Payment Service\n", encoding="utf-8")
        _git_run(["add", "README.md"], cwd=self.repo_dir)
        _git_run(["commit", "-m", "Initial commit"], cwd=self.repo_dir)

        # Initialize workspace with repo "payment-service"
        rc = run_init(
            workspace=str(self.ws),
            repos=["payment-service"],
            agent1="agent1",
            agent2="agent2",
        )
        self.assertEqual(rc, 0)

        # Switch to task branch
        _git_run(["checkout", "-b", "feature/task-101"], cwd=self.repo_dir)

        # Baseline commit
        self.base_commit = _git_run(["rev-parse", "HEAD"], cwd=self.repo_dir).stdout.strip()

        # Set up active state in PHASE_1_PLANNING
        self.task_id = "task-101"
        self.attempt = 1
        state = load_active_state(self.ws)
        state["task_id"] = self.task_id
        state["attempt_index"] = self.attempt
        state["phase"] = "PHASE_1_PLANNING"
        state["turn"] = "AGENT1_PLANNING"
        save_active_state(self.ws, state)

        # Set up directories
        self.attempt_dir = self.ws / "evidence" / "tasks" / self.task_id / f"attempt_{self.attempt}"
        self.p1_dir = self.attempt_dir / "Phase-1"
        self.p2a_dir = self.attempt_dir / "Phase-2A"
        self.p2b_dir = self.attempt_dir / "Phase-2B"
        self.p1_dir.mkdir(parents=True, exist_ok=True)
        self.p2a_dir.mkdir(parents=True, exist_ok=True)
        self.p2b_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        elevate_permissions_for_teardown(self.ws)
        self.temp_dir.cleanup()

    def _setup_approved_review(self, diff_content: str = "def process(): pass\n") -> None:
        """Set up Phase 1 -> Gate 1 -> Phase 2A -> approve review -> Gate 2A -> Phase 2B."""
        # 1. Setup Phase 1 prompt and scope
        (self.p1_dir / "prompt.md").write_text(
            "# Task Execution Blueprint\n"
            "## 1. Task Framing & Objectives\nTask objective.\n"
            "## 2. Architecture & Design Principles\nDesign principles.\n"
            "## 3. Scope Definition & Boundary Guardrails\nScope definition.\n"
            "## 4. Work Breakdown Structure & Phasing\nPhasing.\n"
            "## 5. Implementation Strategy\nStrategy.\n"
            "## 6. Verification & Quality Engineering\nVerification.\n"
            "## 7. Security Hardening & Isolation Constraints\nSecurity.\n"
            "## 8. Defect Severity Matrix & Resolution SLA\nSLA.\n"
            "## 9. Rollback & Emergency Teardown Protocol\nRollback.\n"
            "## 10. Operational Handover & Claims Synthesis\nHandover.\n"
            "## 11. Multi-Agent Turn Protocols\nProtocols.\n"
            "## 12. Traceability Matrix & Manifest Attestation\nAttestation.\n",
            encoding="utf-8",
        )
        (self.p1_dir / "declared_scope.json").write_text(
            json.dumps({
                "schema_version": "2.0",
                "task_id": self.task_id,
                "allowed_paths": ["repos/payment-service/**"],
            }),
            encoding="utf-8",
        )
        # Freeze prompt and verify
        freeze_prompt_and_scope(self.ws, self.task_id, self.attempt)

        # Advance Gate 1
        rc = run_gate_advance("Gate-1", task=self.task_id, attempt=self.attempt, workspace=str(self.ws))
        self.assertEqual(rc, 0)

        # 2. In Phase 2A: write uncommitted file and pre_commit_status.json
        service_file = self.repo_dir / "service.py"
        service_file.write_text(diff_content, encoding="utf-8")
        _git_run(["add", "."], cwd=self.repo_dir)

        status_data = {
            "schema_version": "2.0",
            "task_id": self.task_id,
            "attempt": self.attempt,
            "cycle": 1,
            "status": "AWAITING_REVIEW",
            "touched_repositories": ["payment-service"],
            "base_commits": {"payment-service": self.base_commit},
            "summary": "Implementation ready for review",
        }
        (self.p2a_dir / "pre_commit_status.json").write_text(json.dumps(status_data, indent=2) + "\n", encoding="utf-8")

        # Run approve-review
        rc = run_approve_review(self.task_id, attempt=self.attempt, workspace=str(self.ws))
        self.assertEqual(rc, 0)
        self.assertTrue((self.p2a_dir / "pre_commit_review.json").is_file())

        # Advance Gate 2A
        rc = run_gate_advance("Gate-2A", task=self.task_id, attempt=self.attempt, workspace=str(self.ws))
        self.assertEqual(rc, 0)
        st = load_active_state(self.ws)
        self.assertEqual(st["phase"], "PHASE_2B_COMMITTING")

    def test_gate2b_advance_success_with_matching_commit(self) -> None:
        """Verify Gate 2B advances to PHASE_3_AUDIT when commit matches approved review diff."""
        self._setup_approved_review("def process_payment(): return True\n")

        # Agent 2 commits the exact approved changes
        _git_run(["add", "service.py"], cwd=self.repo_dir)
        _git_run(["commit", "-m", "feat: implement payment service"], cwd=self.repo_dir)

        # Write Phase 2B delivery report
        (self.p2b_dir / "report.md").write_text("# Delivery Report\nAll features committed.\n", encoding="utf-8")

        # Evaluate criteria
        criteria, deliverables = evaluate_gate_2b_criteria(self.ws, self.task_id, self.attempt)
        crit_map = {c.criterion_id: c.status for c in criteria}

        self.assertEqual(crit_map.get("gate2b.prior_review_approved"), "MET")
        self.assertEqual(crit_map.get("gate2b.delivery_report_exists"), "MET")
        self.assertEqual(crit_map.get("gate2b.working_tree_clean.payment-service"), "MET")
        self.assertEqual(crit_map.get("gate2b.branch_governance.payment-service"), "MET")
        self.assertEqual(crit_map.get("gate2b.commit_fidelity.payment-service"), "MET")
        self.assertEqual(crit_map.get("gate2b.remote_authority.payment-service"), "MET")
        self.assertEqual(crit_map.get("gate2b.remote_push_prohibition"), "MET")

        # Advance Gate 2B via CLI
        rc = run_gate_advance("Gate-2B", task=self.task_id, attempt=self.attempt, workspace=str(self.ws))
        self.assertEqual(rc, 0)

        # Verify state transition
        new_state = load_active_state(self.ws)
        self.assertEqual(new_state["phase"], "PHASE_3_AUDIT")
        self.assertEqual(new_state["turn"], "STAGECHECK_AUDITING")
        self.assertIn("GATE_2B", new_state.get("cleared_gates", {}))

        # Verify receipt contents and deliverables binding
        receipt_path = self.p2b_dir / "gate2b_receipt.json"
        self.assertTrue(receipt_path.is_file())
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        self.assertEqual(receipt["gate_id"], "GATE_2B")
        self.assertEqual(receipt["status"], "PASSED")
        self.assertEqual(receipt["from_phase"], "PHASE_2B_COMMITTING")
        self.assertEqual(receipt["to_phase"], "PHASE_3_AUDIT")

        deliv_paths = [d["path"] for d in receipt["deliverables"]]
        self.assertIn(f"evidence/tasks/{self.task_id}/attempt_{self.attempt}/Phase-2A/pre_commit_review.json", deliv_paths)
        self.assertIn(f"evidence/tasks/{self.task_id}/attempt_{self.attempt}/Phase-2B/report.md", deliv_paths)

        # Verify Phase-2B directory is frozen to 0555
        self.assertEqual(oct(self.p2b_dir.stat().st_mode)[-3:], "555")

    def test_gate2b_fails_on_commit_divergence(self) -> None:
        """Verify Gate 2B rejects commits that diverge from the approved Phase 2A diff."""
        self._setup_approved_review("def process_payment(): return True\n")

        # Agent 2 commits a DIFFERENT content than approved
        service_file = self.repo_dir / "service.py"
        service_file.write_text("def process_payment(): return False  # altered after approval\n", encoding="utf-8")
        _git_run(["add", "service.py"], cwd=self.repo_dir)
        _git_run(["commit", "-m", "feat: implement payment service with stealth changes"], cwd=self.repo_dir)

        (self.p2b_dir / "report.md").write_text("# Delivery Report\n", encoding="utf-8")

        # Evaluate criteria
        criteria, _ = evaluate_gate_2b_criteria(self.ws, self.task_id, self.attempt)
        crit_map = {c.criterion_id: c.status for c in criteria}
        self.assertEqual(crit_map.get("gate2b.commit_fidelity.payment-service"), "FAILED")

        # Advance should fail
        with self.assertRaises(GateCriteriaFailedError):
            advance_gate_atomic(self.ws, GateId.GATE_2B, self.task_id, self.attempt)

        # Ensure state remained PHASE_2B_COMMITTING and attempt was not consumed
        st = load_active_state(self.ws)
        self.assertEqual(st["phase"], "PHASE_2B_COMMITTING")
        self.assertEqual(st["attempt_index"], self.attempt)

    def test_gate2b_fails_on_dirty_working_tree(self) -> None:
        """Verify Gate 2B rejects when working tree has uncommitted modifications."""
        self._setup_approved_review("def process_payment(): return True\n")
        _git_run(["add", "service.py"], cwd=self.repo_dir)
        _git_run(["commit", "-m", "feat: implement payment service"], cwd=self.repo_dir)
        (self.p2b_dir / "report.md").write_text("# Delivery Report\n", encoding="utf-8")

        # Leave an uncommitted file
        dirty_file = self.repo_dir / "leftover.py"
        dirty_file.write_text("uncommitted = True\n", encoding="utf-8")

        criteria, _ = evaluate_gate_2b_criteria(self.ws, self.task_id, self.attempt)
        crit_map = {c.criterion_id: c.status for c in criteria}
        self.assertEqual(crit_map.get("gate2b.working_tree_clean.payment-service"), "FAILED")

    def test_gate2b_fails_on_protected_branch(self) -> None:
        """Verify Gate 2B rejects when on protected branch main."""
        self._setup_approved_review("def process_payment(): return True\n")
        # Switch to main
        _git_run(["checkout", "main"], cwd=self.repo_dir)
        _git_run(["add", "service.py"], cwd=self.repo_dir)
        _git_run(["commit", "-m", "feat: commit directly to main"], cwd=self.repo_dir)
        (self.p2b_dir / "report.md").write_text("# Delivery Report\n", encoding="utf-8")

        criteria, _ = evaluate_gate_2b_criteria(self.ws, self.task_id, self.attempt)
        crit_map = {c.criterion_id: c.status for c in criteria}
        self.assertEqual(crit_map.get("gate2b.branch_governance.payment-service"), "FAILED")

    def test_gate2b_fails_on_unauthorized_remote_url(self) -> None:
        """Verify Gate 2B rejects when remote push URL is not in the approved whitelist."""
        self._setup_approved_review("def process_payment(): return True\n")
        _git_run(["add", "service.py"], cwd=self.repo_dir)
        _git_run(["commit", "-m", "feat: implement payment service"], cwd=self.repo_dir)
        (self.p2b_dir / "report.md").write_text("# Delivery Report\n", encoding="utf-8")

        # Configure an unauthorized remote
        _git_run(["remote", "add", "origin", "git@github.com:attacker/malicious.git"], cwd=self.repo_dir)

        criteria, _ = evaluate_gate_2b_criteria(self.ws, self.task_id, self.attempt)
        crit_map = {c.criterion_id: c.status for c in criteria}
        self.assertEqual(crit_map.get("gate2b.remote_authority.payment-service"), "FAILED")

    def test_gate2b_fails_on_blacklisted_remote_url(self) -> None:
        """Verify Gate 2B rejects when remote push URL points to blacklisted domain."""
        self._setup_approved_review("def process_payment(): return True\n")
        _git_run(["add", "service.py"], cwd=self.repo_dir)
        _git_run(["commit", "-m", "feat: implement payment service"], cwd=self.repo_dir)
        (self.p2b_dir / "report.md").write_text("# Delivery Report\n", encoding="utf-8")

        # Configure blacklisted remote
        _git_run(["remote", "add", "origin", "https://multiversx.com/repo.git"], cwd=self.repo_dir)

        criteria, _ = evaluate_gate_2b_criteria(self.ws, self.task_id, self.attempt)
        crit_map = {c.criterion_id: c.status for c in criteria}
        self.assertEqual(crit_map.get("gate2b.remote_authority.payment-service"), "FAILED")

    def test_gate2b_passes_with_authorized_remote_url(self) -> None:
        """Verify Gate 2B passes when remote push URL is explicitly authorized in controls/remotes.json."""
        self._setup_approved_review("def process_payment(): return True\n")
        _git_run(["add", "service.py"], cwd=self.repo_dir)
        _git_run(["commit", "-m", "feat: implement payment service"], cwd=self.repo_dir)
        (self.p2b_dir / "report.md").write_text("# Delivery Report\n", encoding="utf-8")

        auth_url = "git@github.com:acme-corp/payment-service.git"
        _git_run(["remote", "add", "origin", auth_url], cwd=self.repo_dir)

        # Authorize URL in controls/remotes.json
        with controlled_write_transaction(self.ws / "controls"):
            (self.ws / "controls" / "remotes.json").write_text(
                json.dumps({"approved_push_urls": [auth_url]}, indent=2),
                encoding="utf-8",
            )

        criteria, _ = evaluate_gate_2b_criteria(self.ws, self.task_id, self.attempt)
        crit_map = {c.criterion_id: c.status for c in criteria}
        self.assertEqual(crit_map.get("gate2b.remote_authority.payment-service"), "MET")

    def test_gate2b_fails_missing_prior_review_or_delivery_report(self) -> None:
        """Verify Gate 2B fails closed if pre_commit_review.json or report.md is absent."""
        # 1. Missing review
        criteria, _ = evaluate_gate_2b_criteria(self.ws, self.task_id, self.attempt)
        crit_map = {c.criterion_id: c.status for c in criteria}
        self.assertEqual(crit_map.get("gate2b.prior_review_approved"), "FAILED")
        self.assertEqual(crit_map.get("gate2b.delivery_report_exists"), "FAILED")

        # 2. Add unapproved review (REVISION_REQUIRED)
        rev_data = {
            "schema_version": "2.0",
            "task_id": self.task_id,
            "attempt": self.attempt,
            "cycle": 1,
            "status": "REVISION_REQUIRED",
            "summary": "Fix defects",
        }
        (self.p2a_dir / "pre_commit_review.json").write_text(json.dumps(rev_data))
        criteria, _ = evaluate_gate_2b_criteria(self.ws, self.task_id, self.attempt)
        crit_map = {c.criterion_id: c.status for c in criteria}
        self.assertEqual(crit_map.get("gate2b.prior_review_approved"), "FAILED")


if __name__ == "__main__":
    unittest.main()
