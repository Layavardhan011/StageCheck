"""Unit and Integration Tests for Human Disposition Ledger & Telemetry Flow (P4-T5)."""

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from stagecheck.cli.main import main
from stagecheck.core.dispositions import (
    NonInteractiveDispositionBlockedError,
    add_disposition,
    load_dispositions,
    resume_after_disposition,
)
from stagecheck.core.git import discover_repository
from stagecheck.core.orchestrator import AuditOrchestrator
from stagecheck.core.scaffold import scaffold_controls_atomic
from stagecheck.core.agents_md import write_agents_contract
from stagecheck.core.utils import canonical_json_dumps, sha256_file


class TestDispositions(unittest.TestCase):
    """Test suite for human disposition ledger, non-TTY fail-closed gates, and resume protocol."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="stagecheck_disp_test_")
        self.workspace_root = Path(self.temp_dir)
        self.task_id = "task-404"

        # Mock repository
        self.repo_dir = self.workspace_root / "repos" / "app"
        self.repo_dir.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "init", str(self.repo_dir)], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(self.repo_dir), "config", "user.name", "Tester"], check=True)
        subprocess.run(["git", "-C", str(self.repo_dir), "config", "user.email", "tester@example.com"], check=True)
        (self.repo_dir / "main.py").write_text("print('test')\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.repo_dir), "add", "."], check=True)
        subprocess.run(["git", "-C", str(self.repo_dir), "commit", "-m", "init"], check=True)

        baseline = discover_repository(self.repo_dir, name="app", workspace_root=self.workspace_root)
        scaffold_controls_atomic(self.workspace_root, {"app": baseline})
        write_agents_contract(self.workspace_root)

        # Set task in ACTIVE_STATE.json
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

    def test_non_tty_without_confirmation_fails_closed(self):
        """Verify SEC-03: Scripted / non-TTY disposition attempts without confirmation fail closed."""
        with patch("sys.stdin.isatty", return_value=False):
            with self.assertRaises(NonInteractiveDispositionBlockedError):
                add_disposition(
                    workspace_root=self.workspace_root,
                    task_id=self.task_id,
                    defect_id="scope_paths.out_of_scope_modification",
                    rationale="Upgraded dependency",
                    require_tty=True,
                    confirmed=False,
                )

    def test_interactive_or_confirmed_disposition_succeeds(self):
        """Verify confirmed human disposition updates DISPOSITIONS.json, AGENTS.md, and manifest."""
        entry = add_disposition(
            workspace_root=self.workspace_root,
            task_id=self.task_id,
            defect_id="scope_paths.out_of_scope_modification",
            rationale="Intentional design upgrade for RFC-12",
            action="ACCEPT_AS_INTENTIONAL",
            authorized_by="developer@company.com",
            require_tty=False,
            confirmed=True,
        )

        self.assertEqual(entry["task_id"], self.task_id)
        self.assertEqual(entry["action"], "ACCEPT_AS_INTENTIONAL")

        # 1. Assert DISPOSITIONS.json contains entry
        doc = load_dispositions(self.workspace_root)
        self.assertEqual(len(doc["dispositions"]), 1)
        self.assertEqual(doc["dispositions"][0]["defect_id"], "scope_paths.out_of_scope_modification")

        # 2. Assert AGENTS.md hash table matches live hash
        agents_md = (self.workspace_root / "AGENTS.md").read_text(encoding="utf-8")
        disp_hash = sha256_file(self.workspace_root / "controls" / "DISPOSITIONS.json")
        self.assertIn(disp_hash, agents_md)

        # 3. Assert TASK_<ID>_ISSUE_HISTORY.md contains DISPOSITION_ADDED audit event
        history_path = self.workspace_root / "evidence" / "tasks" / self.task_id / f"TASK_{self.task_id}_ISSUE_HISTORY.md"
        self.assertTrue(history_path.is_file())
        history_text = history_path.read_text(encoding="utf-8")
        self.assertIn("Event: DISPOSITION_ADDED", history_text)
        self.assertIn("scope_paths.out_of_scope_modification", history_text)

    def test_notification_failures_do_not_corrupt_state(self):
        """Verify subprocess notify-send failures do not fail or corrupt disposition recording."""
        with patch("subprocess.run", side_effect=OSError("D-Bus connection refused")):
            entry = add_disposition(
                workspace_root=self.workspace_root,
                task_id=self.task_id,
                defect_id="rerun.timeout",
                rationale="Expected long run",
                require_tty=False,
                confirmed=True,
            )
            self.assertEqual(entry["defect_id"], "rerun.timeout")

        doc = load_dispositions(self.workspace_root)
        self.assertTrue(any(d["defect_id"] == "rerun.timeout" for d in doc["dispositions"]))

    def test_deterministic_resume_protocol_transitions(self):
        """Verify GAP-B1 resume protocol transitions to verification or repair."""
        # Setup mock verdict with 2 blocking defects
        attempt_dir = self.workspace_root / "evidence" / "tasks" / self.task_id / "attempt_1" / "Phase-3"
        attempt_dir.mkdir(parents=True, exist_ok=True)
        verdict_data = {
            "result": "BLOCKED",
            "defects": [
                {"defect_id": "defect_1", "mode": "blocking"},
                {"defect_id": "defect_2", "mode": "blocking"},
            ],
        }
        (attempt_dir / "verdict.json").write_text(canonical_json_dumps(verdict_data), encoding="utf-8")

        # 1. Waive only defect_1 -> 1 defect still unresolved -> transitions to PHASE_1_REPAIR
        add_disposition(
            workspace_root=self.workspace_root,
            task_id=self.task_id,
            defect_id="defect_1",
            rationale="Waived defect 1",
            require_tty=False,
            confirmed=True,
        )
        res_repair = resume_after_disposition(self.workspace_root, self.task_id)
        self.assertEqual(res_repair["resumed_phase"], "PHASE_1_REPAIR")
        self.assertIn("1 blocking defect(s) remain", res_repair["reason"])

        # 2. Waive defect_2 -> all blocking defects waived -> transitions to PHASE_3_VERIFICATION
        add_disposition(
            workspace_root=self.workspace_root,
            task_id=self.task_id,
            defect_id="defect_2",
            rationale="Waived defect 2",
            require_tty=False,
            confirmed=True,
        )
        res_verify = resume_after_disposition(self.workspace_root, self.task_id)
        self.assertEqual(res_verify["resumed_phase"], "PHASE_3_VERIFICATION")
        self.assertIn("All blocking defects waived", res_verify["reason"])

    def test_resume_preserves_circuit_breaker_tripped(self):
        """Verify resume preserves CIRCUIT_BREAKER_TRIPPED when breaker was tripped."""
        state_file = self.workspace_root / "controls" / "ACTIVE_STATE.json"
        with open(state_file, "r", encoding="utf-8") as f:
            state = json.load(f)
        state["circuit_breaker_tripped"] = True
        os.chmod(state_file.parent, 0o755)
        os.chmod(state_file, 0o644)
        state_file.write_text(canonical_json_dumps(state), encoding="utf-8")
        os.chmod(state_file, 0o444)
        os.chmod(state_file.parent, 0o555)

        res = resume_after_disposition(self.workspace_root, self.task_id)
        self.assertEqual(res["resumed_phase"], "CIRCUIT_BREAKER_TRIPPED")

    def test_cli_disposition_and_resume(self):
        """Verify CLI 'stagecheck disposition add' and 'stagecheck resume' execution."""
        # 1. CLI disposition add with --yes
        exit_disp = main([
            "disposition", "add",
            "--task", self.task_id,
            "--defect", "secrets.leak_detected",
            "--rationale", "Test key for mock test suite only",
            "--yes",
            "--workspace", str(self.workspace_root),
        ])
        self.assertEqual(exit_disp, 0)

        # 2. CLI resume
        exit_resume = main([
            "resume",
            "--task", self.task_id,
            "--workspace", str(self.workspace_root),
        ])
        self.assertEqual(exit_resume, 0)


if __name__ == "__main__":
    unittest.main()
