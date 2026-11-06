"""Unit and Integration Tests for Immutable Gate Receipts and Atomic Transitions (FR-01 / Spec 01 / Task 2.4).

Verifies receipt schema compliance, atomic state updates under lock, rollback on failure,
tamper detection for modified/missing/unregistered receipts, and sequential clearance.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from stagecheck.core.gate_engine import (
    GateAdvanceResult,
    GateCriteriaFailedError,
    GateId,
    ReceiptTamperDetectedError,
    advance_gate_atomic,
    generate_gate_receipt,
    get_gate_receipt_path,
    verify_gate_receipts,
)
from stagecheck.core.git import RepoBaseline
from stagecheck.core.scaffold import scaffold_controls_atomic
from stagecheck.core.state import load_active_state, save_active_state
from stagecheck.core.utils import sha256_file
from stagecheck.schemas.validator import validate_gate_receipt


class TestGateReceipts(unittest.TestCase):
    """Test suite for Gate Receipt generation, atomic advancement, rollback, and anti-forgery."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp_dir.name).resolve()
        self.task_id = "task-receipt-test"
        self.attempt = 1

        # Baseline repo mock
        self.repo_dir = self.workspace / "repos" / "service"
        self.repo_dir.mkdir(parents=True, exist_ok=True)

        self.baselines = {
            "service": RepoBaseline(
                name="service",
                rel_path="repos/service",
                abs_path=self.repo_dir,
                git_dir=self.repo_dir / ".git",
                head_commit="d" * 40,
                branch="task/task-receipt-test",
                is_dirty=False,
                is_unborn=False,
                is_worktree=False,
            )
        }

        scaffold_controls_atomic(
            workspace_root=self.workspace,
            baselines=self.baselines,
            manifest_sha256="0" * 64,
        )

        # Set initial active state to PHASE_1_PLANNING
        state = load_active_state(self.workspace)
        state["task_id"] = self.task_id
        state["phase"] = "PHASE_1_PLANNING"
        state["attempt_index"] = self.attempt
        save_active_state(self.workspace, state)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _setup_valid_gate1_deliverables(self) -> Path:
        """Create valid deliverables for Gate 1."""
        p1_dir = self.workspace / "evidence" / "tasks" / self.task_id / f"attempt_{self.attempt}" / "Phase-1"
        p1_dir.mkdir(parents=True, exist_ok=True)

        prompt_file = p1_dir / "prompt.md"
        prompt_file.write_text("# Feature prompt\nExecute task.\n", encoding="utf-8")

        scope_file = p1_dir / "declared_scope.json"
        scope_file.write_text(json.dumps({
            "schema_version": "2.0",
            "task_id": self.task_id,
            "allowed_paths": ["repos/service/main.py"],
        }), encoding="utf-8")

        pv_file = p1_dir / "prompt_verified.json"
        pv_file.write_text(json.dumps({
            "schema_version": "2.0",
            "task_id": self.task_id,
            "attempt": self.attempt,
            "status": "VERIFIED",
            "prompt_sha256": sha256_file(prompt_file),
            "scope_sha256": sha256_file(scope_file),
        }), encoding="utf-8")

        return p1_dir

    def test_generate_gate_receipt_schema_compliance(self) -> None:
        """Verify generate_gate_receipt constructs schema-compliant receipt with 64-hex digest."""
        receipt_path, data, digest = generate_gate_receipt(
            workspace_root=self.workspace,
            gate_id=GateId.GATE_1,
            task_id=self.task_id,
            attempt=self.attempt,
            from_phase="PHASE_1_PLANNING",
            to_phase="PHASE_2A_CODING",
            deliverables=[{"path": "p.md", "sha256": "0" * 64, "status": "VALID"}],
            checks_evaluated=["gate1.prompt_valid"],
        )

        self.assertEqual(data["gate_id"], "GATE_1")
        self.assertEqual(data["task_id"], self.task_id)
        self.assertEqual(data["attempt"], self.attempt)
        self.assertEqual(data["receipt_sha256"], digest)
        self.assertEqual(len(digest), 64)

        # Must pass JSON schema validation without exception
        validate_gate_receipt(data)

    def test_advance_gate_atomic_success_and_state_update(self) -> None:
        """Verify atomic gate advance updates phase, turn, cleared_gates, and writes receipt."""
        self._setup_valid_gate1_deliverables()

        res = advance_gate_atomic(self.workspace, "Gate-1")
        self.assertIsInstance(res, GateAdvanceResult)
        self.assertEqual(res.gate_id, "GATE_1")
        self.assertEqual(res.to_phase, "PHASE_2A_CODING")
        self.assertEqual(res.turn, "AGENT2_CODING")
        self.assertTrue(res.receipt_path.is_file())

        # Verify receipt content format: 2-space indent and trailing newline
        content = res.receipt_path.read_text(encoding="utf-8")
        self.assertTrue(content.endswith("\n"))
        self.assertIn('  "gate_id": "GATE_1"', content)

        # Verify state updated
        state = load_active_state(self.workspace)
        self.assertEqual(state["phase"], "PHASE_2A_CODING")
        self.assertEqual(state["turn"], "AGENT2_CODING")
        self.assertIn("GATE_1", state.get("cleared_gates", {}))
        self.assertEqual(state["cleared_gates"]["GATE_1"], res.receipt_sha256)

        # Verify anti-forgery check passes
        verification = verify_gate_receipts(self.workspace)
        self.assertTrue(verification["valid"])
        self.assertIn("GATE_1", verification["verified_gates"])

    def test_advance_gate_fails_closed_when_criteria_unmet(self) -> None:
        """Verify advancing gate without meeting criteria raises GateCriteriaFailedError and preserves state."""
        state_before = load_active_state(self.workspace)

        # Criteria not met (no deliverables created)
        with self.assertRaises(GateCriteriaFailedError):
            advance_gate_atomic(self.workspace, "Gate-1")

        state_after = load_active_state(self.workspace)
        self.assertEqual(state_before, state_after)

    def test_verify_gate_receipts_detects_tampered_receipt(self) -> None:
        """Verify tamper detection when receipt bytes on disk are modified."""
        self._setup_valid_gate1_deliverables()
        res = advance_gate_atomic(self.workspace, "Gate-1")

        # Tamper with receipt file
        receipt_file = res.receipt_path
        os.chmod(receipt_file, 0o644)
        receipt_file.write_text('{"tampered": true}\n', encoding="utf-8")

        with self.assertRaises(ReceiptTamperDetectedError) as ctx:
            verify_gate_receipts(self.workspace)
        self.assertIn("has been altered", str(ctx.exception))

    def test_verify_gate_receipts_detects_missing_receipt(self) -> None:
        """Verify detection when a registered receipt file is deleted from disk."""
        self._setup_valid_gate1_deliverables()
        res = advance_gate_atomic(self.workspace, "Gate-1")

        # Delete receipt file (simulate attacker tampering)
        try:
            os.chmod(res.receipt_path.parent, 0o755)
        except OSError:
            pass
        os.chmod(res.receipt_path, 0o644)
        res.receipt_path.unlink()

        with self.assertRaises(ReceiptTamperDetectedError) as ctx:
            verify_gate_receipts(self.workspace)
        self.assertIn("is missing on disk", str(ctx.exception))

    def test_verify_gate_receipts_detects_unregistered_receipt(self) -> None:
        """Verify detection when an unrecorded gate receipt is placed on disk."""
        self._setup_valid_gate1_deliverables()
        # Create an unregistered gate receipt file
        p1_receipt = get_gate_receipt_path(self.workspace, GateId.GATE_1, self.task_id, self.attempt)
        p1_receipt.parent.mkdir(parents=True, exist_ok=True)
        p1_receipt.write_text('{"schema_version": "2.0.0"}\n', encoding="utf-8")

        # ACTIVE_STATE.json has NOT cleared GATE_1
        with self.assertRaises(ReceiptTamperDetectedError) as ctx:
            verify_gate_receipts(self.workspace)
        self.assertIn("Unregistered gate receipt detected", str(ctx.exception))


    def test_advance_gate_atomic_rollback_on_failure(self) -> None:
        """Verify atomic rollback if state update fails midway through advance."""
        self._setup_valid_gate1_deliverables()
        state_before = load_active_state(self.workspace)
        receipt_path = get_gate_receipt_path(self.workspace, GateId.GATE_1, self.task_id, self.attempt)

        # Mock update_evidence_manifest to fail during commit
        from unittest.mock import patch
        with patch("stagecheck.core.gate_engine.update_evidence_manifest", side_effect=RuntimeError("Manifest update failed")):
            from stagecheck.core.gate_engine import GateError
            with self.assertRaises(GateError):
                advance_gate_atomic(self.workspace, "Gate-1")

        # Verify receipt was deleted during rollback
        self.assertFalse(receipt_path.exists())

        # Verify state is restored to state_before
        state_after = load_active_state(self.workspace)
        self.assertEqual(state_before["phase"], state_after["phase"])
        self.assertNotIn("GATE_1", state_after.get("cleared_gates", {}))

    def test_advance_gate_atomic_lock_contention_handled_safely(self) -> None:
        """Verify lock contention safely blocks concurrent gate advance without corrupting state."""
        from stagecheck.core.locking import LockCollisionError, acquire_runtime_lock
        self._setup_valid_gate1_deliverables()
        state_before = load_active_state(self.workspace)

        # Hold exclusive runtime lock
        with acquire_runtime_lock(self.workspace):
            with self.assertRaises(LockCollisionError):
                advance_gate_atomic(self.workspace, "Gate-1")

        # State remains clean and unchanged
        state_after = load_active_state(self.workspace)
        self.assertEqual(state_before, state_after)


if __name__ == "__main__":
    unittest.main()
