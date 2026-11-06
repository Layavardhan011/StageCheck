"""Comprehensive Test Suite for Task 4.2: Independent Test, Scanner, and Rubric Audit Pipeline (FR-01 / DEC-024).

Verifies:
1. Operational separation between 'stagecheck audit' and 'stagecheck gate advance Gate-3':
   - 'stagecheck audit' runs verification, emits test_execution.json, scanner_report.json,
     rubric_evaluation.json, and verdict.json, but does NOT create seal.json or gate3_receipt.json,
     and leaves workspace in PHASE_3_AUDIT.
   - 'stagecheck gate advance Gate-3' verifies verdict.json is PASSED (0 blocking defects),
     generates gate3_receipt.json, freezes Phase-3/, and advances phase to GATE_4_SEALING.
2. Multi-repository aggregate requirements:
   - All declared repositories in controls/PRODUCT_REPOSITORIES.json must participate.
   - Any failing check in any required repository fails the aggregate verdict (zero partial pass).
3. Gate 3 pass criteria:
   - Requires zero blocking defects.
   - Incomplete, missing, or failing rubric evaluations fail closed.
"""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from stagecheck.cli.audit_cmd import run_audit_cmd
from stagecheck.cli.gate_cmd import run_gate_advance, run_gate_check
from stagecheck.cli.init_cmd import run_init
from stagecheck.cli.main import main
from stagecheck.cli.review_cmd import run_approve_review
from stagecheck.core.gate_engine import GateId, advance_gate_atomic, check_gate_preconditions
from stagecheck.core.orchestrator import run_audit
from stagecheck.core.permissions import elevate_permissions_for_teardown
from stagecheck.core.prompt_gate import freeze_prompt_and_scope
from stagecheck.core.state import load_active_state, save_active_state
from stagecheck.core.utils import canonical_json_dumps, sha256_file


def _setup_git_repo(repo_dir: Path, file_name: str = "app.py", task_id: str = "task-audit-01") -> str:
    """Helper to initialize a Git repository with an initial commit and task branch."""
    repo_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-b", "main"], cwd=str(repo_dir), capture_output=True, check=True)
    subprocess.run(["git", "config", "user.name", "Tester"], cwd=str(repo_dir), capture_output=True, check=True)
    subprocess.run(["git", "config", "user.email", "tester@stagecheck.local"], cwd=str(repo_dir), capture_output=True, check=True)
    (repo_dir / file_name).write_text("# Initial code\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=str(repo_dir), capture_output=True, check=True)
    subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=str(repo_dir), capture_output=True, check=True)
    subprocess.run(["git", "switch", "-c", f"task/{task_id}"], cwd=str(repo_dir), capture_output=True, check=True)
    res = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(repo_dir), capture_output=True, text=True, check=True)
    return res.stdout.strip()


class TestAuditPipeline(unittest.TestCase):
    """Test suite for Phase 3 independent audit execution, multi-repo aggregation, and Gate 3 advance."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.ws = Path(self.temp_dir.name).resolve()
        self.task_id = "task-audit-01"
        self.attempt = 1

        # Set up repositories under repos/
        self.repo_api = self.ws / "repos" / "api-service"
        self.commit_api = _setup_git_repo(self.repo_api, "api.py")

        self.repo_db = self.ws / "repos" / "db-service"
        self.commit_db = _setup_git_repo(self.repo_db, "db.py")

        # Initialize workspace
        rc = run_init(
            workspace=str(self.ws),
            agent1="agent1",
            agent2="agent2",
            repos="api-service,db-service",
        )
        self.assertEqual(rc, 0)

        # Qualification directory
        (self.ws / "evals").mkdir(parents=True, exist_ok=True)

        # Create valid Phase-1 evidence & advance Gate 1
        p1_dir = self.ws / "evidence" / "tasks" / self.task_id / f"attempt_{self.attempt}" / "Phase-1"
        p1_dir.mkdir(parents=True, exist_ok=True)
        (p1_dir / "prompt.md").write_text(
            "# Task Execution Blueprint\n"
            "## 1. Task Framing & Objectives\nObj\n"
            "## 2. Architecture & Design Principles\nArch\n"
            "## 3. Scope Definition & Boundary Guardrails\nScope\n"
            "## 4. Work Breakdown Structure & Phasing\nPhases\n"
            "## 5. Implementation Strategy\nStrat\n"
            "## 6. Verification & Quality Engineering\nQA\n"
            "## 7. Security Hardening & Isolation Constraints\nSec\n"
            "## 8. Defect Severity Matrix & Resolution SLA\nSLA\n"
            "## 9. Rollback & Emergency Teardown Protocol\nRollback\n"
            "## 10. Operational Handover & Claims Synthesis\nHandover\n"
            "## 11. Multi-Agent Turn Protocols\nTurn\n"
            "## 12. Traceability Matrix & Manifest Attestation\nTrace\n"
        )
        scope = {
            "schema_version": "2.0",
            "task_id": self.task_id,
            "allowed_paths": ["repos/api-service/api.py", "repos/db-service/db.py"],
            "read_only_paths": [],
            "forbidden_paths": [".git/**"],
        }
        (p1_dir / "declared_scope.json").write_text(json.dumps(scope), encoding="utf-8")
        freeze_prompt_and_scope(self.ws, self.task_id, self.attempt)

        state = load_active_state(self.ws)
        state["task_id"] = self.task_id
        state["attempt_index"] = self.attempt
        state["phase"] = "PHASE_1_PLANNING"
        save_active_state(self.ws, state)
        advance_gate_atomic(self.ws, GateId.GATE_1, self.task_id, self.attempt)

        # Setup Phase 2A approved review & advance Gate 2A
        p2a_dir = self.ws / "evidence" / "tasks" / self.task_id / f"attempt_{self.attempt}" / "Phase-2A"
        p2a_dir.mkdir(parents=True, exist_ok=True)
        (p2a_dir / "pre_commit_status.json").write_text(
            json.dumps({
                "schema_version": "2.0",
                "task_id": self.task_id,
                "attempt": self.attempt,
                "cycle": 1,
                "base_commits": {"api-service": self.commit_api, "db-service": self.commit_db},
                "summary": "Implementation ready for review",
            }),
            encoding="utf-8",
        )
        review_data = {
            "schema_version": "2.0",
            "task_id": self.task_id,
            "attempt": self.attempt,
            "cycle": 1,
            "status": "APPROVED",
            "summary": "Multi-repo review approved",
            "base_commits": {"api-service": self.commit_api, "db-service": self.commit_db},
            "approved_diff_hashes": {
                "api-service": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "db-service": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            },
            "approved_snapshot_sha256": "0" * 64,
            "approved_diff_sha256": "0" * 64,
            "pre_existing_issues_ignored": [],
            "architectural_intents_approved": [],
            "new_issues_found": [],
            "code_quality_observations": [],
        }
        (p2a_dir / "pre_commit_review.json").write_text(json.dumps(review_data), encoding="utf-8")
        advance_gate_atomic(self.ws, GateId.GATE_2A, self.task_id, self.attempt)

        # Setup Phase 2B delivery report & advance Gate 2B
        p2b_dir = self.ws / "evidence" / "tasks" / self.task_id / f"attempt_{self.attempt}" / "Phase-2B"
        p2b_dir.mkdir(parents=True, exist_ok=True)
        (p2b_dir / "report.md").write_text("# Delivery Report\n\n## Summary\nAll clean.\n\n## Changes\nNone.\n\n## Verification\nVerified.\n", encoding="utf-8")
        report_data = {
            "schema_version": "2.0",
            "task_id": self.task_id,
            "attempt": self.attempt,
            "status": "DELIVERED",
            "repositories": {
                "api-service": {"commit": self.commit_api, "clean": True},
                "db-service": {"commit": self.commit_db, "clean": True},
            },
        }
        (p2b_dir / "delivery_report.json").write_text(json.dumps(report_data), encoding="utf-8")
        advance_gate_atomic(self.ws, GateId.GATE_2B, self.task_id, self.attempt)

        # Ensure state is in PHASE_3_AUDIT
        state = load_active_state(self.ws)
        self.assertEqual(state["phase"], "PHASE_3_AUDIT")

    def tearDown(self) -> None:
        elevate_permissions_for_teardown(self.ws)
        self.temp_dir.cleanup()

    def test_gate3_audit_advance_separation(self) -> None:
        """Verify DEC-024: 'stagecheck audit' does NOT advance Gate 3, emit gate receipt, or seal attempt."""
        p3_dir = self.ws / "evidence" / "tasks" / self.task_id / f"attempt_{self.attempt}" / "Phase-3"
        attempt_dir = self.ws / "evidence" / "tasks" / self.task_id / f"attempt_{self.attempt}"

        # 1. Execute 'stagecheck audit'
        rc = run_audit_cmd(task=self.task_id, attempt=self.attempt, workspace=str(self.ws))
        self.assertEqual(rc, 0)

        # 2. Verify audit artifacts are emitted
        self.assertTrue((p3_dir / "verdict.json").is_file())
        self.assertTrue((p3_dir / "test_execution.json").is_file())
        self.assertTrue((p3_dir / "scanner_report.json").is_file())
        self.assertTrue((p3_dir / "rubric_evaluation.json").is_file())

        verdict = json.loads((p3_dir / "verdict.json").read_text(encoding="utf-8"))
        self.assertIn(verdict.get("result"), ("CLEAR", "PASSED"))

        # 3. Assert NO premature sealing or gate advancement
        self.assertFalse((attempt_dir / "seal.json").exists())
        self.assertFalse((p3_dir / "gate3_receipt.json").exists())

        state_after_audit = load_active_state(self.ws)
        self.assertEqual(state_after_audit["phase"], "PHASE_3_AUDIT")
        self.assertNotIn("GATE_3", state_after_audit.get("cleared_gates", {}))

        # 4. Now execute 'stagecheck gate advance Gate-3'
        rc_advance = run_gate_advance("Gate-3", workspace=str(self.ws), task=self.task_id, attempt=self.attempt)
        self.assertEqual(rc_advance, 0)

        # 5. Verify gate receipt is now created and phase advanced to GATE_4_SEALING
        self.assertTrue((p3_dir / "gate3_receipt.json").is_file())
        state_after_gate3 = load_active_state(self.ws)
        self.assertEqual(state_after_gate3["phase"], "GATE_4_SEALING")
        self.assertIn("GATE_3", state_after_gate3.get("cleared_gates", {}))

        # 6. Verify seal.json is STILL not created (belongs exclusively to Gate 4)
        self.assertFalse((attempt_dir / "seal.json").exists())

    def test_multi_repo_participates_and_zero_partial_pass(self) -> None:
        """Verify all declared repositories participate and any failure blocks the aggregate."""
        p3_dir = self.ws / "evidence" / "tasks" / self.task_id / f"attempt_{self.attempt}" / "Phase-3"

        # Inject an unauthorized override config into db-service (.gitleaks.toml)
        (self.repo_db / ".gitleaks.toml").write_text("# unauthorized\n", encoding="utf-8")

        # Run audit
        passed, verdict = run_audit(self.ws, self.task_id, self.attempt)
        self.assertFalse(passed)
        self.assertEqual(verdict["result"], "BLOCKED")
        self.assertGreater(verdict["counts"]["blocking"], 0)

        # Verify Gate 3 advance fails closed
        report = check_gate_preconditions(self.ws, GateId.GATE_3, self.task_id, self.attempt)
        self.assertFalse(report.passed)

    def test_rubric_failure_blocks_gate_3(self) -> None:
        """Verify Gate 3 fails closed when rubric evaluation contains blocking defects."""
        # Corrupt prompt.md in Phase 1 to trigger rubric defect
        p1_prompt = self.ws / "evidence" / "tasks" / self.task_id / f"attempt_{self.attempt}" / "Phase-1" / "prompt.md"
        elevate_permissions_for_teardown(self.ws)
        p1_prompt.chmod(0o644)
        p1_prompt.write_text("# Incomplete Prompt\nNo sections.\n", encoding="utf-8")

        passed, verdict = run_audit(self.ws, self.task_id, self.attempt)
        self.assertFalse(passed)
        self.assertEqual(verdict["result"], "BLOCKED")


if __name__ == "__main__":
    unittest.main()
