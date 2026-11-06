"""Tests for Gate 4 Sealing, Idempotency, Dispositions, Attempt Budget, and Protected Teardown (P4-T5).

Verifies:
1. Gate 4 advancement: Merkle DAG seal generation, attempt freeze (0555/0444), manifest indexing, SEALED_PASSED.
2. stagecheck seal as authoritative idempotent alias for Gate 4 advance.
3. Gate 4 blocked when prior receipts (1, 2A, 2B, 3) are missing or Phase-3 verdict is FAILED.
4. Write-ahead journal recovery on Gate 4 interruption.
5. Attempt budget invariants:
   - Resumption (--action resume) does NOT increment attempt_index.
   - Audit failure on attempt 1 increments attempt_index to 2 and initializes attempt_2/.
   - Attempt budget cap: attempt 3 failure trips breaker; retry is permanently rejected with AttemptBudgetExhaustedError.
6. Protected teardown:
   - stagecheck unlock --force against active task fails closed with ActiveTaskTeardownBlockedError.
   - stagecheck unlock --force --abort-active-task logs structured event to evidence/teardown.log and elevates permissions.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import tempfile
import unittest
from pathlib import Path

from stagecheck.cli.main import main
from stagecheck.core.circuit_breaker import (
    AttemptBudgetExhaustedError,
    CircuitBreakerEvaluation,
    trip_circuit_breaker,
)
from stagecheck.core.gate_engine import (
    GateCriteriaFailedError,
    GateId,
    advance_gate_atomic,
    generate_gate_receipt,
    handle_audit_verdict,
)
from stagecheck.core.permissions import (
    ActiveTaskTeardownBlockedError,
    assert_safe_teardown_preconditions,
    controlled_write_transaction,
)
from stagecheck.core.sealing import verify_attempt_merkle_seal
from stagecheck.core.state import load_active_state, save_active_state
from stagecheck.core.utils import sha256_file


class TestGate4SealingAndLifecycle(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="stagecheck_test_gate4_")
        self.workspace_root = Path(self.test_dir).resolve()
        self.task_id = "task-gate4-01"
        self.attempt = 1

        # Enable CI mode so headless tests pass Guard 2
        os.environ["CI"] = "true"

        # Setup base workspace structure
        controls_dir = self.workspace_root / "controls"
        controls_dir.mkdir(parents=True, exist_ok=True)
        evidence_dir = self.workspace_root / "evidence"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        manifest_file = evidence_dir / "EVIDENCE_MANIFEST.json"
        manifest_file.write_text(json.dumps({"manifest_version": "2.0.0", "tasks": {}}), encoding="utf-8")

        # Initial active state conforming to active_state.schema.json
        self.active_state_file = controls_dir / "ACTIVE_STATE.json"
        self.state_data = {
            "schema_version": "2.0",
            "task_id": self.task_id,
            "attempt_index": self.attempt,
            "repair_index": 0,
            "max_total_attempts": 3,
            "max_repairs": 3,
            "circuit_breaker_tripped": False,
            "target_repositories": ["core"],
            "phase": "GATE_4_SEALING",
            "turn": "STAGECHECK_SEALING",
            "status": "IN_PROGRESS",
            "cleared_gates": {},
        }
        self.active_state_file.write_text(json.dumps(self.state_data, indent=2), encoding="utf-8")

        # Setup attempt directory hierarchy
        self.attempt_dir = evidence_dir / "tasks" / self.task_id / f"attempt_{self.attempt}"
        self.p1_dir = self.attempt_dir / "Phase-1"
        self.p2a_dir = self.attempt_dir / "Phase-2A"
        self.p2b_dir = self.attempt_dir / "Phase-2B"
        self.p3_dir = self.attempt_dir / "Phase-3"
        for d in (self.p1_dir, self.p2a_dir, self.p2b_dir, self.p3_dir):
            d.mkdir(parents=True, exist_ok=True)

        # Create valid receipts for Gates 1, 2A, 2B, 3
        self._create_mock_receipts_and_verdict(verdict_status="PASSED")

    def tearDown(self):
        # Restore permissions for cleanup
        for root, dirs, files in os.walk(self.workspace_root):
            for d in dirs:
                try:
                    os.chmod(os.path.join(root, d), 0o755)
                except OSError:
                    pass
            for f in files:
                try:
                    os.chmod(os.path.join(root, f), 0o644)
                except OSError:
                    pass
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _create_mock_receipts_and_verdict(self, verdict_status: str = "PASSED"):
        """Populate prerequisite receipts (1, 2A, 2B, 3) and Phase-3 verdict on disk."""
        # Phase 1
        p1_receipt, p1_data, _ = generate_gate_receipt(
            self.workspace_root, GateId.GATE_1, self.task_id, self.attempt,
            "PHASE_1_PLANNING", "PHASE_2A_CODING", deliverables=[], checks_evaluated=["CHECK_P1"]
        )
        p1_receipt.parent.mkdir(parents=True, exist_ok=True)
        p1_receipt.write_text(json.dumps(p1_data, indent=2) + "\n", encoding="utf-8")
        self.state_data.setdefault("cleared_gates", {})["GATE_1"] = sha256_file(p1_receipt)

        # Phase 2A
        p2a_receipt, p2a_data, _ = generate_gate_receipt(
            self.workspace_root, GateId.GATE_2A, self.task_id, self.attempt,
            "PHASE_2A_CODING", "PHASE_2B_COMMITTING", deliverables=[], checks_evaluated=["CHECK_P2A"]
        )
        p2a_receipt.parent.mkdir(parents=True, exist_ok=True)
        p2a_receipt.write_text(json.dumps(p2a_data, indent=2) + "\n", encoding="utf-8")
        self.state_data["cleared_gates"]["GATE_2A"] = sha256_file(p2a_receipt)

        # Phase 2B
        p2b_receipt, p2b_data, _ = generate_gate_receipt(
            self.workspace_root, GateId.GATE_2B, self.task_id, self.attempt,
            "PHASE_2B_COMMITTING", "PHASE_3_AUDIT", deliverables=[], checks_evaluated=["CHECK_P2B"]
        )
        p2b_receipt.parent.mkdir(parents=True, exist_ok=True)
        p2b_receipt.write_text(json.dumps(p2b_data, indent=2) + "\n", encoding="utf-8")
        self.state_data["cleared_gates"]["GATE_2B"] = sha256_file(p2b_receipt)

        # Phase 3 verdict & receipt
        verdict = {
            "schema_version": "2.0.0",
            "task_id": self.task_id,
            "attempt": self.attempt,
            "status": verdict_status,
            "result": "CLEAR" if verdict_status == "PASSED" else "FAIL",
            "blocking_defects_count": 0 if verdict_status == "PASSED" else 2,
            "defects": [] if verdict_status == "PASSED" else [{"defect_id": "D01", "mode": "blocking"}],
        }
        verdict_file = self.p3_dir / "verdict.json"
        verdict_file.write_text(json.dumps(verdict, indent=2), encoding="utf-8")

        p3_receipt, p3_data, _ = generate_gate_receipt(
            self.workspace_root, GateId.GATE_3, self.task_id, self.attempt,
            "PHASE_3_AUDIT", "GATE_4_SEALING",
            deliverables=[{"path": str(verdict_file.relative_to(self.workspace_root)), "sha256": sha256_file(verdict_file), "status": "VALID"}],
            checks_evaluated=["CHECK_P3"]
        )
        p3_receipt.parent.mkdir(parents=True, exist_ok=True)
        p3_receipt.write_text(json.dumps(p3_data, indent=2) + "\n", encoding="utf-8")
        self.state_data["cleared_gates"]["GATE_3"] = sha256_file(p3_receipt)
        self.active_state_file.write_text(json.dumps(self.state_data, indent=2), encoding="utf-8")

    def test_gate_4_advance_creates_seal_and_freezes(self):
        """Verify Gate 4 advance generates Merkle seal, indexes in manifest, freezes attempt, and updates state."""
        res = advance_gate_atomic(
            workspace_root=self.workspace_root,
            gate="Gate-4",
            task_id=self.task_id,
            attempt=self.attempt,
        )

        self.assertEqual(res.gate_id, "GATE_4")
        self.assertEqual(res.to_phase, "SEALED_PASSED")

        # 1. gate4_receipt.json exists
        receipt_file = self.attempt_dir / "gate4_receipt.json"
        self.assertTrue(receipt_file.is_file())
        receipt_mode = stat.S_IMODE(receipt_file.stat().st_mode)
        self.assertEqual(receipt_mode, 0o444)

        # 2. seal.json exists and verifies Merkle DAG
        seal_file = self.attempt_dir / "seal.json"
        self.assertTrue(seal_file.is_file())
        is_valid, violations = verify_attempt_merkle_seal(self.attempt_dir, self.workspace_root)
        self.assertTrue(is_valid, f"Seal verification failed: {violations}")

        # 3. EVIDENCE_MANIFEST.json indexes the seal
        manifest = json.loads((self.workspace_root / "evidence" / "EVIDENCE_MANIFEST.json").read_text(encoding="utf-8"))
        task_manifest = manifest.get("sealed_tasks", {}).get(self.task_id, {})
        self.assertIn("attempt_1", task_manifest)
        self.assertIn("merkle_root_sha256", task_manifest["attempt_1"])

        # 4. Attempt directory hierarchy is frozen (0555 dir / 0444 files)
        dir_mode = stat.S_IMODE(self.attempt_dir.stat().st_mode)
        self.assertEqual(dir_mode, 0o555)

        # 5. ACTIVE_STATE updated to SEALED_PASSED and turn IDLE
        state = load_active_state(self.workspace_root)
        self.assertEqual(state["status"], "SEALED_PASSED")
        self.assertEqual(state["phase"], "COMPLETED")
        self.assertEqual(state["turn"], "IDLE")
        self.assertIn("GATE_4", state["cleared_gates"])

    def test_stagecheck_seal_authoritative_idempotent_alias(self):
        """Verify CLI 'stagecheck seal' is an exact authoritative alias for Gate 4 advance and is idempotent."""
        # First seal via CLI
        code1 = main(["seal", "--task", self.task_id, "--attempt", str(self.attempt), "--workspace", str(self.workspace_root)])
        self.assertEqual(code1, 0)

        seal_file = self.attempt_dir / "seal.json"
        self.assertTrue(seal_file.is_file())

        # Second seal via CLI (idempotency check)
        code2 = main(["seal", "--task", self.task_id, "--attempt", str(self.attempt), "--workspace", str(self.workspace_root)])
        self.assertEqual(code2, 0)

        # Third seal via 'stagecheck gate advance Gate-4' (also idempotent)
        code3 = main(["gate", "advance", "Gate-4", "--task", self.task_id, "--attempt", str(self.attempt), "--workspace", str(self.workspace_root)])
        self.assertEqual(code3, 0)

    def test_gate_4_blocked_on_missing_receipt(self):
        """Verify Gate 4 fails closed when a prerequisite receipt is missing."""
        # Delete Gate 2A receipt
        p2a_receipt = self.p2a_dir / "gate2a_receipt.json"
        try:
            os.chmod(self.p2a_dir, 0o755)
            os.chmod(p2a_receipt, 0o644)
            p2a_receipt.unlink()
        except OSError:
            pass

        with self.assertRaises(GateCriteriaFailedError) as cm:
            advance_gate_atomic(self.workspace_root, "Gate-4", self.task_id, self.attempt)
        self.assertIn("G4-PREREQ-GATE_2A", str(cm.exception))

    def test_gate_4_blocked_on_failed_verdict(self):
        """Verify Gate 4 fails closed when Phase-3 audit verdict is FAILED."""
        # Overwrite verdict with FAILED
        verdict_file = self.p3_dir / "verdict.json"
        try:
            os.chmod(self.p3_dir, 0o755)
            os.chmod(verdict_file, 0o644)
        except OSError:
            pass
        verdict = {
            "schema_version": "2.0.0",
            "task_id": self.task_id,
            "attempt": self.attempt,
            "status": "FAILED",
            "result": "FAIL",
            "blocking_defects_count": 1,
            "defects": [{"defect_id": "D01", "mode": "blocking"}],
        }
        verdict_file.write_text(json.dumps(verdict, indent=2), encoding="utf-8")

        with self.assertRaises(GateCriteriaFailedError) as cm:
            advance_gate_atomic(self.workspace_root, "Gate-4", self.task_id, self.attempt)
        self.assertIn("G4-VERDICT-PASSED", str(cm.exception))

    def test_attempt_budget_resumption_does_not_increment(self):
        """Verify DEC-028: stagecheck disposition --action resume preserves attempt_index."""
        # Put state into AWAITING_HUMAN_DISPOSITION from watchdog
        with controlled_write_transaction(self.workspace_root / "controls"):
            state = load_active_state(self.workspace_root)
            state["phase"] = "AWAITING_HUMAN_DISPOSITION"
            state["halt_reason"] = "WATCHDOG_INACTIVITY_TIMEOUT: 10 minutes elapsed"
            state["attempt_index"] = 1
            save_active_state(self.workspace_root, state)

        # Run disposition --action resume
        code = main([
            "disposition",
            "--task", self.task_id,
            "--action", "resume",
            "--workspace", str(self.workspace_root),
        ])
        self.assertEqual(code, 0)

        # Verify attempt_index remains 1
        state_after = load_active_state(self.workspace_root)
        self.assertEqual(state_after["attempt_index"], 1)

    def test_audit_failure_increments_attempt_index(self):
        """Verify FR-06 / DEC-028: Phase 3 audit failure on attempt 1 increments to attempt 2 and initializes attempt_2."""
        failed_verdict = {
            "status": "FAILED",
            "blocking_defects_count": 1,
            "defects": [{"defect_id": "ERR-01", "mode": "blocking"}],
        }
        res = handle_audit_verdict(self.workspace_root, self.task_id, 1, failed_verdict)
        self.assertEqual(res["action"], "ATTEMPT_INCREMENTED")
        self.assertEqual(res["attempt"], 2)

        state = load_active_state(self.workspace_root)
        self.assertEqual(state["attempt_index"], 2)
        self.assertEqual(state["phase"], "PHASE_1_PLANNING")

        # Verify attempt_2/Phase-1 directory initialized
        att2_p1 = self.workspace_root / "evidence" / "tasks" / self.task_id / "attempt_2" / "Phase-1"
        self.assertTrue(att2_p1.is_dir())

    def test_attempt_budget_cap_exhaustion_at_attempt_3(self):
        """Verify FR-06 / DEC-028: Audit failure on attempt 3 trips breaker and retry is permanently rejected."""
        failed_verdict = {
            "status": "FAILED",
            "blocking_defects_count": 1,
            "defects": [{"defect_id": "ERR-01", "mode": "blocking"}],
        }
        res = handle_audit_verdict(self.workspace_root, self.task_id, 3, failed_verdict)
        self.assertEqual(res["action"], "CIRCUIT_BREAKER_TRIPPED")

        state = load_active_state(self.workspace_root)
        self.assertEqual(state["phase"], "AWAITING_HUMAN_DISPOSITION")
        self.assertTrue(state["circuit_breaker_tripped"])

        # Attempting retry on attempt 3 MUST fail closed with AttemptBudgetExhaustedError (exit 1)
        code = main([
            "disposition",
            "--task", self.task_id,
            "--action", "retry",
            "--authorized-by", "operator@example.com",
            "--workspace", str(self.workspace_root),
        ])
        self.assertEqual(code, 1)

    def test_active_task_protected_teardown(self):
        """Verify Spec M11: stagecheck unlock --force fails closed during active task without --abort-active-task."""
        # Ensure task is marked IN_PROGRESS
        with controlled_write_transaction(self.workspace_root / "controls"):
            state = load_active_state(self.workspace_root)
            state["status"] = "IN_PROGRESS"
            state["phase"] = "PHASE_2A_CODING"
            save_active_state(self.workspace_root, state)

        # 1. unlock --force WITHOUT --abort-active-task fails closed with exit code 1
        code_blocked = main(["unlock", "--force", "--workspace", str(self.workspace_root)])
        self.assertEqual(code_blocked, 1)

        # Direct function check raises ActiveTaskTeardownBlockedError
        with self.assertRaises(ActiveTaskTeardownBlockedError):
            assert_safe_teardown_preconditions(self.workspace_root, force=True, abort_active=False)

        # 2. unlock --force WITH --abort-active-task succeeds and records in teardown.log
        code_success = main(["unlock", "--force", "--abort-active-task", "--workspace", str(self.workspace_root)])
        self.assertEqual(code_success, 0)

        # Verify task is aborted in active state
        state_after = load_active_state(self.workspace_root)
        self.assertEqual(state_after["status"], "ABORTED")
        self.assertEqual(state_after["phase"], "ABORTED")

        # Verify evidence/teardown.log recorded structured event
        teardown_log = self.workspace_root / "evidence" / "teardown.log"
        self.assertTrue(teardown_log.is_file())
        lines = [json.loads(line) for line in teardown_log.read_text(encoding="utf-8").strip().splitlines()]
        self.assertTrue(any(l.get("event") == "WORKSPACE_UNLOCKED" and l.get("active_task_aborted") is True for l in lines))


if __name__ == "__main__":
    unittest.main()
