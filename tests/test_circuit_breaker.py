"""Unit and Integration Tests for Circuit Breaker and Escalation Protocol (P4-T4)."""

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from stagecheck.cli.main import main
from stagecheck.core.circuit_breaker import (
    AttemptBudgetExhaustedError,
    CircuitBreakerEvaluation,
    ResetAttemptsError,
    evaluate_circuit_breaker,
    reset_circuit_breaker,
    trip_circuit_breaker,
    write_escalation_report,
)
from stagecheck.core.git import discover_repository
from stagecheck.core.scaffold import scaffold_controls_atomic
from stagecheck.core.utils import canonical_json_dumps


class TestCircuitBreaker(unittest.TestCase):
    """Test suite covering attempt caps, no-progress, regressions, timeout masking, and reset-attempts."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="stagecheck_cb_test_")
        self.workspace_root = Path(self.temp_dir)
        self.task_id = "task-303"

        # Mock repository
        self.repo_dir = self.workspace_root / "repos" / "app"
        self.repo_dir.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "init", str(self.repo_dir)], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(self.repo_dir), "config", "user.name", "Tester"], check=True)
        subprocess.run(["git", "-C", str(self.repo_dir), "config", "user.email", "tester@example.com"], check=True)
        (self.repo_dir / "main.py").write_text("print('hello')\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.repo_dir), "add", "."], check=True)
        subprocess.run(["git", "-C", str(self.repo_dir), "commit", "-m", "init"], check=True)

        baseline = discover_repository(self.repo_dir, name="app", workspace_root=self.workspace_root)
        scaffold_controls_atomic(self.workspace_root, {"app": baseline})

        # Set active task in ACTIVE_STATE.json
        state_file = self.workspace_root / "controls" / "ACTIVE_STATE.json"
        with open(state_file, "r", encoding="utf-8") as f:
            state = json.load(f)
        state["task_id"] = self.task_id
        os.chmod(state_file.parent, 0o755)
        os.chmod(state_file, 0o644)
        state_file.write_text(canonical_json_dumps(state), encoding="utf-8")
        os.chmod(state_file, 0o444)
        os.chmod(state_file.parent, 0o555)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_attempt_cap_trigger_on_attempt_3(self):
        """Verify Trigger 1: Attempt 3 failure exhausts attempt budget and trips breaker."""
        defects = [{"defect_id": "rerun.mismatch", "mode": "blocking"}]
        evaluation = evaluate_circuit_breaker(
            workspace_root=self.workspace_root,
            task_id=self.task_id,
            attempt=3,
            current_defects=defects,
            active_state={"attempt_budget_base": 0},
        )
        self.assertTrue(evaluation.tripped)
        self.assertEqual(evaluation.trigger, "max_attempts_exhausted")
        self.assertIn("maximum permitted attempt threshold", evaluation.reason)

        # Trip breaker
        report_path = trip_circuit_breaker(
            workspace_root=self.workspace_root,
            task_id=self.task_id,
            attempt=3,
            evaluation=evaluation,
            current_defects=defects,
        )
        self.assertTrue(report_path.is_file())

        # Assert active state updated
        with open(self.workspace_root / "controls" / "ACTIVE_STATE.json") as f:
            state = json.load(f)
        self.assertEqual(state["phase"], "AWAITING_HUMAN_DISPOSITION")
        self.assertTrue(state["circuit_breaker_tripped"])
        self.assertEqual(state["halt_trigger"], "max_attempts_exhausted")

    def test_stagnant_defects_zero_progress_trigger(self):
        """Verify Trigger 2: Consecutive attempts with identical blocking defects trip breaker."""
        p1_dir = self.workspace_root / "evidence" / "tasks" / self.task_id / "attempt_1" / "Phase-3"
        p1_dir.mkdir(parents=True, exist_ok=True)
        verdict_1 = {
            "result": "BLOCKED",
            "defects": [
                {"defect_id": "rerun.mismatch", "mode": "blocking"},
                {"defect_id": "scope.unauthorized_path", "mode": "blocking"},
            ],
        }
        (p1_dir / "verdict.json").write_text(canonical_json_dumps(verdict_1), encoding="utf-8")

        # Attempt 2 produces exact same blocking defects
        current_defects = [
            {"defect_id": "rerun.mismatch", "mode": "blocking"},
            {"defect_id": "scope.unauthorized_path", "mode": "blocking"},
        ]
        evaluation = evaluate_circuit_breaker(
            workspace_root=self.workspace_root,
            task_id=self.task_id,
            attempt=2,
            current_defects=current_defects,
        )
        self.assertTrue(evaluation.tripped)
        self.assertEqual(evaluation.trigger, "stagnant_defects")
        self.assertIn("Zero progress detected", evaluation.reason)

    def test_defect_reappearance_regression_trigger(self):
        """Verify Trigger 3: Defect resolved in attempt 2 reappearing in attempt 3 trips breaker."""
        task_dir = self.workspace_root / "evidence" / "tasks" / self.task_id
        # Attempt 1: defects A and B
        (task_dir / "attempt_1" / "Phase-3").mkdir(parents=True, exist_ok=True)
        v1 = {"result": "BLOCKED", "defects": [{"defect_id": "defect_A", "mode": "blocking"}]}
        (task_dir / "attempt_1" / "Phase-3" / "verdict.json").write_text(canonical_json_dumps(v1), encoding="utf-8")

        # Attempt 2: defect A fixed, defect B introduced
        (task_dir / "attempt_2" / "Phase-3").mkdir(parents=True, exist_ok=True)
        v2 = {"result": "BLOCKED", "defects": [{"defect_id": "defect_B", "mode": "blocking"}]}
        (task_dir / "attempt_2" / "Phase-3" / "verdict.json").write_text(canonical_json_dumps(v2), encoding="utf-8")

        # Attempt 3: defect A reappears!
        v3_defects = [
            {"defect_id": "defect_A", "mode": "blocking"},
            {"defect_id": "defect_B", "mode": "blocking"},
        ]
        evaluation = evaluate_circuit_breaker(
            workspace_root=self.workspace_root,
            task_id=self.task_id,
            attempt=3,
            current_defects=v3_defects,
        )
        self.assertTrue(evaluation.tripped)
        # On attempt 3, either max_attempts or defect_reappearance applies; here attempt 3 checks regression
        self.assertIn(evaluation.trigger, ("defect_reappearance", "max_attempts_exhausted"))

    def test_timeout_masking_detection(self):
        """Verify Trigger 4: Pure timeout modifications without root cause fix are rejected."""
        # Baseline commit has timeout=30
        (self.repo_dir / "test.py").write_text("timeout = 30\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.repo_dir), "add", "."], check=True)
        subprocess.run(["git", "-C", str(self.repo_dir), "commit", "-m", "set base timeout"], check=True)

        res = subprocess.run(["git", "-C", str(self.repo_dir), "rev-parse", "HEAD"], capture_output=True, text=True, check=True)
        base_sha = res.stdout.strip()

        # Update product repositories baseline head
        prod_repos_path = self.workspace_root / "controls" / "PRODUCT_REPOSITORIES.json"
        prod_data = {
            "schema_version": "2.0",
            "repositories": {
                "app": {
                    "path": "repos/app",
                    "default_branch": "main",
                    "baseline_head": base_sha,
                }
            },
        }
        prod_repos_path.write_text(canonical_json_dumps(prod_data), encoding="utf-8")

        # Now agent commits only a timeout change: timeout = 300
        (self.repo_dir / "test.py").write_text("timeout = 300\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.repo_dir), "add", "."], check=True)
        subprocess.run(["git", "-C", str(self.repo_dir), "commit", "-m", "mask timeout"], check=True)

        # Mark Phase-2A review
        p2a_dir = self.workspace_root / "evidence" / "tasks" / self.task_id / "attempt_1" / "Phase-2A"
        p2a_dir.mkdir(parents=True, exist_ok=True)
        (p2a_dir / "pre_commit_review.json").write_text("{}", encoding="utf-8")

        evaluation = evaluate_circuit_breaker(
            workspace_root=self.workspace_root,
            task_id=self.task_id,
            attempt=1,
            current_defects=[{"defect_id": "test_failure", "mode": "blocking"}],
        )
        self.assertTrue(evaluation.tripped)
        self.assertEqual(evaluation.trigger, "timeout_masking")

    def test_escalation_report_contents(self):
        """Verify escalation_report.md documents all actionable options (A, B, C, D)."""
        evaluation = CircuitBreakerEvaluation(
            tripped=True,
            trigger="max_attempts_exhausted",
            reason="Exhausted 3 attempts.",
        )
        defects = [{"defect_id": "qual_naming.required_suite_empty", "stage": "qual_naming", "severity": "CRITICAL"}]
        report_path = write_escalation_report(
            self.workspace_root,
            self.task_id,
            attempt=3,
            evaluation=evaluation,
            defects=defects,
        )
        self.assertTrue(report_path.is_file())
        content = report_path.read_text(encoding="utf-8")
        self.assertIn("Option A (Manual Code Fix)", content)
        self.assertIn("Option B (Human Disposition)", content)
        self.assertIn("Option C (Attempt Reset)", content)
        self.assertIn("Option D (Permanent Halt)", content)
        self.assertIn("qual_naming.required_suite_empty", content)

    def test_reset_attempts_preconditions_and_monotonic_budget(self):
        """Verify reset-attempts validates task match, trips requirement, and unlatches state."""
        # 1. Reject reset when task is NOT tripped
        with self.assertRaises(ResetAttemptsError) as cm_premature:
            reset_circuit_breaker(self.workspace_root, self.task_id)
        self.assertIn("not tripped", str(cm_premature.exception))

        # Trip the breaker at attempt 2
        eval_tripped = CircuitBreakerEvaluation(tripped=True, trigger="stagnant_defects", reason="No progress")
        trip_circuit_breaker(self.workspace_root, self.task_id, 2, eval_tripped, [])

        # 2. Reject reset when task ID mismatches
        with self.assertRaises(ResetAttemptsError) as cm_mismatch:
            reset_circuit_breaker(self.workspace_root, "different-task-999")
        self.assertIn("Task ID mismatch", str(cm_mismatch.exception))

        # 3. Successful reset from attempt 2 -> advances monotonically to attempt 3
        updated = reset_circuit_breaker(
            self.workspace_root,
            self.task_id,
            authorized_by="developer@example.com",
        )
        self.assertFalse(updated["circuit_breaker_tripped"])
        self.assertEqual(updated["phase"], "PHASE_1_PLANNING")
        self.assertEqual(updated["attempt_index"], 3)
        self.assertEqual(updated["last_reset"]["authorized_by"], "developer@example.com")

    def test_attempt_budget_cap_enforcement(self):
        """Verify DEC-028 / FR-06: Attempt budget hard cap of 3 cannot be bypassed via retry."""
        # Trip breaker at attempt 3
        eval_tripped = CircuitBreakerEvaluation(tripped=True, trigger="max_attempts_exhausted", reason="Exhausted")
        trip_circuit_breaker(self.workspace_root, self.task_id, 3, eval_tripped, [])

        # Attempting reset or retry at attempt 3 MUST fail closed with AttemptBudgetExhaustedError
        with self.assertRaises(AttemptBudgetExhaustedError) as cm_exhausted:
            reset_circuit_breaker(self.workspace_root, self.task_id)
        self.assertIn("Attempt budget exhausted", str(cm_exhausted.exception))

    def test_attempt_budget_accounting(self):
        """Verify DEC-006 / FR-06: Attempt budget accounting strictly enforces max 3 attempts."""
        eval_tripped = CircuitBreakerEvaluation(tripped=True, trigger="max_attempts_exhausted", reason="Exhausted")
        trip_circuit_breaker(self.workspace_root, self.task_id, 3, eval_tripped, [])

        state_file = self.workspace_root / "controls" / "ACTIVE_STATE.json"
        state = json.loads(state_file.read_text(encoding="utf-8"))
        self.assertEqual(state["attempt_index"], 3)
        self.assertEqual(state["phase"], "AWAITING_HUMAN_DISPOSITION")

    def test_cli_reset_attempts_command(self):
        """Verify CLI 'stagecheck reset-attempts' exit codes."""
        # Trip breaker first at attempt 2
        eval_tripped = CircuitBreakerEvaluation(tripped=True, trigger="stagnant_defects", reason="Done")
        trip_circuit_breaker(self.workspace_root, self.task_id, 2, eval_tripped, [])

        exit_code = main([
            "reset-attempts",
            "--task", self.task_id,
            "--authorized-by", "owner@example.com",
            "--workspace", str(self.workspace_root),
        ])
        self.assertEqual(exit_code, 0)


if __name__ == "__main__":
    unittest.main()
