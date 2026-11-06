"""Unit and Integration Tests for Gate CLI Commands and Universal Prerequisite Enforcement (Task 2.5).

Verifies:
1. 'stagecheck gate check' non-mutating criteria inspection (exit 0 when met, 1 when blocked).
2. 'stagecheck gate advance' atomic state transitions and cryptographic receipt generation.
3. Fail-closed rejection of premature 'review-precommit' when Gate 1 is unadvanced or missing.
4. Fail-closed rejection of premature 'audit' when Gate 2B is unadvanced or missing.
5. Anti-forgery detection: tampered receipts halt downstream CLI entrypoints.
6. Gate identifier normalization across various naming conventions.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from stagecheck.cli.main import main
from stagecheck.core.gate_engine import (
    GateId,
    get_gate_receipt_path,
)
from stagecheck.core.git import RepoBaseline
from stagecheck.core.scaffold import scaffold_controls_atomic
from stagecheck.core.start_manifest import generate_start_manifest
from stagecheck.core.state import load_active_state, save_active_state
from stagecheck.core.utils import sha256_file


class TestGateCLIAndPrerequisites(unittest.TestCase):
    """Test suite covering 'stagecheck gate check/advance' and universal prerequisite guards."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp_dir.name).resolve()
        self.task_id = "task-gate-cli"
        self.attempt = 1

        # Mock repository
        self.repo_dir = self.workspace / "repos" / "core-service"
        self.repo_dir.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "init", str(self.repo_dir)], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(self.repo_dir), "config", "user.name", "Tester"], check=True)
        subprocess.run(["git", "-C", str(self.repo_dir), "config", "user.email", "tester@test.local"], check=True)
        (self.repo_dir / "service.py").write_text("# service\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.repo_dir), "add", "."], check=True)
        subprocess.run(["git", "-C", str(self.repo_dir), "commit", "-m", "init"], check=True)

        res = subprocess.run(["git", "-C", str(self.repo_dir), "rev-parse", "HEAD"], capture_output=True, text=True, check=True)
        self.base_commit = res.stdout.strip()

        # Switch to task branch
        subprocess.run(["git", "-C", str(self.repo_dir), "switch", "-c", "task/task-gate-cli"], check=True, capture_output=True)

        from stagecheck.core.git import discover_repository

        # Baseline and controls
        baselines = {
            "core-service": discover_repository(
                self.repo_dir,
                name="core-service",
                workspace_root=self.workspace,
            )
        }
        scaffold_controls_atomic(self.workspace, baselines)
        generate_start_manifest(self.workspace)

        # Set active state to Phase 1
        state = load_active_state(self.workspace)
        state["task_id"] = self.task_id
        state["attempt_index"] = self.attempt
        state["phase"] = "PHASE_1_PLANNING"
        save_active_state(self.workspace, state)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _setup_gate1_artifacts(self) -> Path:
        p1_dir = self.workspace / "evidence" / "tasks" / self.task_id / f"attempt_{self.attempt}" / "Phase-1"
        p1_dir.mkdir(parents=True, exist_ok=True)
        (p1_dir / "prompt.md").write_text("# Prompt\nImplement service\n", encoding="utf-8")
        scope = {
            "schema_version": "2.0",
            "task_id": self.task_id,
            "allowed_paths": ["repos/core-service/service.py"],
        }
        (p1_dir / "declared_scope.json").write_text(json.dumps(scope, indent=2) + "\n", encoding="utf-8")
        (p1_dir / "prompt_verified.json").write_text(
            json.dumps({"task_id": self.task_id, "status": "VERIFIED"}, indent=2) + "\n", encoding="utf-8"
        )
        return p1_dir

    def test_gate_check_reports_status_without_mutations(self) -> None:
        """Verify 'stagecheck gate check' inspects criteria and makes no disk changes."""
        # Unmet criteria initially
        rc = main([
            "gate", "check", "Gate-1",
            "--task", self.task_id,
            "--attempt", str(self.attempt),
            "--workspace", str(self.workspace),
        ])
        self.assertEqual(rc, 1, "Unmet gate criteria should yield exit code 1")

        # Ensure no gate receipt was created
        receipt_path = get_gate_receipt_path(self.workspace, GateId.GATE_1, self.task_id, self.attempt)
        self.assertFalse(receipt_path.exists())

        # Now satisfy criteria
        self._setup_gate1_artifacts()

        rc = main([
            "gate", "check", "Gate-1",
            "--task", self.task_id,
            "--attempt", str(self.attempt),
            "--workspace", str(self.workspace),
        ])
        self.assertEqual(rc, 0, "Satisfied gate criteria should yield exit code 0")

        # Verify phase is STILL PHASE_1_PLANNING (no mutation occurred)
        state = load_active_state(self.workspace)
        self.assertEqual(state["phase"], "PHASE_1_PLANNING")
        self.assertFalse(receipt_path.exists())

    def test_gate_advance_generates_receipt_and_advances_phase(self) -> None:
        """Verify 'stagecheck gate advance Gate-1' transitions phase to PHASE_2A_CODING and records receipt."""
        self._setup_gate1_artifacts()

        rc = main([
            "gate", "advance", "gate-1",
            "--task", self.task_id,
            "--attempt", str(self.attempt),
            "--workspace", str(self.workspace),
        ])
        self.assertEqual(rc, 0, "gate advance Gate-1 should succeed")

        state = load_active_state(self.workspace)
        self.assertEqual(state["phase"], "PHASE_2A_CODING")
        self.assertIn("GATE_1", state.get("cleared_gates", {}))

        receipt_path = get_gate_receipt_path(self.workspace, GateId.GATE_1, self.task_id, self.attempt)
        self.assertTrue(receipt_path.is_file())
        receipt_data = json.loads(receipt_path.read_text(encoding="utf-8"))
        self.assertEqual(receipt_data["gate_id"], "GATE_1")
        self.assertEqual(receipt_data["status"], "PASSED")
        self.assertEqual(receipt_data["to_phase"], "PHASE_2A_CODING")

    def test_premature_review_precommit_rejected_when_gate1_not_cleared(self) -> None:
        """Verify review-precommit fails immediately if Gate 1 is not cleared."""
        # Setup pre_commit_status.json in Phase-2A
        p2a_dir = self.workspace / "evidence" / "tasks" / self.task_id / f"attempt_{self.attempt}" / "Phase-2A"
        p2a_dir.mkdir(parents=True, exist_ok=True)
        (p2a_dir / "pre_commit_status.json").write_text(
            json.dumps({
                "schema_version": "1.0.0",
                "task_id": self.task_id,
                "attempt": self.attempt,
                "cycle": 1,
                "status": "AWAITING_REVIEW",
                "touched_repositories": ["core-service"],
                "base_commits": {"core-service": self.base_commit},
            }),
            encoding="utf-8",
        )

        # Workspace is in PHASE_1_PLANNING, Gate 1 not cleared
        rc = main([
            "review-precommit",
            "--task", self.task_id,
            "--attempt", str(self.attempt),
            "--workspace", str(self.workspace),
        ])
        self.assertEqual(rc, 1, "review-precommit must fail when Gate 1 not cleared")

    def test_premature_audit_rejected_when_gate2b_not_cleared(self) -> None:
        """Verify stagecheck audit fails immediately if Gate 2B is not cleared."""
        rc = main([
            "audit",
            "--task", self.task_id,
            "--attempt", str(self.attempt),
            "--workspace", str(self.workspace),
        ])
        self.assertEqual(rc, 1, "stagecheck audit must fail when Gate 2B not cleared")

    def test_tampered_receipt_blocks_execution_fail_closed(self) -> None:
        """Verify altered receipt on disk halts downstream operations fail-closed."""
        self._setup_gate1_artifacts()

        # Advance Gate 1
        rc = main([
            "gate", "advance", "Gate-1",
            "--task", self.task_id,
            "--attempt", str(self.attempt),
            "--workspace", str(self.workspace),
        ])
        self.assertEqual(rc, 0)

        # Pre-commit review status
        p2a_dir = self.workspace / "evidence" / "tasks" / self.task_id / f"attempt_{self.attempt}" / "Phase-2A"
        p2a_dir.mkdir(parents=True, exist_ok=True)
        (p2a_dir / "pre_commit_status.json").write_text(
            json.dumps({
                "schema_version": "1.0.0",
                "task_id": self.task_id,
                "attempt": self.attempt,
                "cycle": 1,
                "status": "AWAITING_REVIEW",
                "touched_repositories": ["core-service"],
                "base_commits": {"core-service": self.base_commit},
            }),
            encoding="utf-8",
        )

        # Pristine review-precommit works
        rc = main([
            "review-precommit",
            "--task", self.task_id,
            "--attempt", str(self.attempt),
            "--workspace", str(self.workspace),
        ])
        self.assertEqual(rc, 0)

        # Now adversary tampers with Gate 1 receipt
        receipt_path = get_gate_receipt_path(self.workspace, GateId.GATE_1, self.task_id, self.attempt)
        receipt_path.chmod(0o666)
        receipt_path.write_text('{"tampered": true}\n', encoding="utf-8")

        # review-precommit MUST fail with exit code 1
        rc_tampered = main([
            "review-precommit",
            "--task", self.task_id,
            "--attempt", str(self.attempt),
            "--workspace", str(self.workspace),
        ])
        self.assertEqual(rc_tampered, 1, "Tampered gate receipt must block execution fail-closed")


if __name__ == "__main__":
    unittest.main()
