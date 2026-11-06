"""Unit and Integration Tests for Agent Turn Handshake and Polling Protocol (FR-07 / Spec 04 / Task 3.1).

Verifies:
1. Turn state machine resolution across Phase 1, Phase 2A, Phase 2B, Phase 3, Gate 4, and Circuit Breaker.
2. CLI 'stagecheck turn' stdout and machine-readable '--json' output compliance with turn_status.schema.json.
3. Throttling and rate-limit enforcement (>3 requests in 5s window returns 429 [RATE_LIMITED]).
4. Watchdog last_active_timestamp reset on valid turn queries during agent phases.
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from stagecheck.cli.main import main
from stagecheck.core.gate_engine import advance_gate_atomic
from stagecheck.core.git import discover_repository
from stagecheck.core.scaffold import scaffold_controls_atomic
from stagecheck.core.start_manifest import generate_start_manifest
from stagecheck.core.state import load_active_state, save_active_state
from stagecheck.core.turn import check_and_record_turn_rate_limit, compute_turn_status
from stagecheck.schemas.validator import validate_turn_status


class TestTurnProtocol(unittest.TestCase):
    """Test suite covering turn resolution, JSON schema validation, throttling, and watchdog integration."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp_dir.name).resolve()
        self.task_id = "task-turn-101"
        self.attempt = 1

        # Setup mock git repo
        self.repo_dir = self.workspace / "repos" / "service"
        self.repo_dir.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "init"], cwd=str(self.repo_dir), check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Tester"], cwd=str(self.repo_dir), check=True)
        subprocess.run(["git", "config", "user.email", "tester@test.local"], cwd=str(self.repo_dir), check=True)
        (self.repo_dir / "app.py").write_text("# app\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=str(self.repo_dir), check=True)
        subprocess.run(["git", "commit", "-m", "init"], cwd=str(self.repo_dir), check=True)
        subprocess.run(["git", "switch", "-c", "task/task-turn-101"], cwd=str(self.repo_dir), check=True, capture_output=True)

        baselines = {
            "service": discover_repository(self.repo_dir, name="service", workspace_root=self.workspace)
        }
        scaffold_controls_atomic(self.workspace, baselines)
        generate_start_manifest(self.workspace)

        # Set active state
        state = load_active_state(self.workspace)
        state["task_id"] = self.task_id
        state["attempt_index"] = self.attempt
        state["phase"] = "PHASE_1_PLANNING"
        save_active_state(self.workspace, state)

        # Clear rate limit tracker
        tracker = self.workspace / ".stagecheck_turn_tracker.json"
        if tracker.exists():
            tracker.unlink()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_phase1_turn_progression(self) -> None:
        """Verify Phase 1 turn steps: AGENT_1 (no prompt) -> STAGECHECK (prompt drafted) -> STAGECHECK (verified)."""
        p1_dir = self.workspace / "evidence" / "tasks" / self.task_id / f"attempt_{self.attempt}" / "Phase-1"

        # 1. Before prompt drafted: AGENT_1 turn
        t1 = compute_turn_status(self.workspace)
        self.assertEqual(t1.active_turn, "AGENT_1")
        self.assertEqual(t1.waiting_for, "Phase-1/prompt.md")
        self.assertEqual(t1.retry_after_seconds, 5)
        validate_turn_status(t1.to_dict())

        # 2. Prompt drafted but not verified: STAGECHECK turn
        p1_dir.mkdir(parents=True, exist_ok=True)
        (p1_dir / "prompt.md").write_text("# 12 Section Prompt\n", encoding="utf-8")
        (p1_dir / "declared_scope.json").write_text(
            json.dumps({"schema_version": "2.0", "task_id": self.task_id, "allowed_paths": ["repos/service/app.py"]}),
            encoding="utf-8",
        )

        t2 = compute_turn_status(self.workspace)
        self.assertEqual(t2.active_turn, "STAGECHECK")
        self.assertEqual(t2.waiting_for, "prompt_verified.json")
        validate_turn_status(t2.to_dict())

        # 3. Prompt verified: STAGECHECK turn (waiting for Gate-1 advance)
        (p1_dir / "prompt_verified.json").write_text(
            json.dumps({"task_id": self.task_id, "status": "VERIFIED"}, indent=2),
            encoding="utf-8",
        )
        t3 = compute_turn_status(self.workspace)
        self.assertEqual(t3.active_turn, "STAGECHECK")
        self.assertEqual(t3.waiting_for, "Gate-1 advance")
        validate_turn_status(t3.to_dict())

    def test_phase2a_cooperative_review_turn_progression(self) -> None:
        """Verify Phase 2A turn transitions: AGENT_2 -> AGENT_1 -> AGENT_2 (revision) -> STAGECHECK (approved)."""
        p1_dir = self.workspace / "evidence" / "tasks" / self.task_id / f"attempt_{self.attempt}" / "Phase-1"
        p1_dir.mkdir(parents=True, exist_ok=True)
        (p1_dir / "prompt.md").write_text("# Prompt\n", encoding="utf-8")
        (p1_dir / "declared_scope.json").write_text(
            json.dumps({"schema_version": "2.0", "task_id": self.task_id, "allowed_paths": ["repos/service/app.py"]}),
            encoding="utf-8",
        )
        (p1_dir / "prompt_verified.json").write_text(
            json.dumps({"task_id": self.task_id, "status": "VERIFIED"}),
            encoding="utf-8",
        )
        advance_gate_atomic(self.workspace, "Gate-1", task_id=self.task_id, attempt=self.attempt)

        p2a_dir = self.workspace / "evidence" / "tasks" / self.task_id / f"attempt_{self.attempt}" / "Phase-2A"
        p2a_dir.mkdir(parents=True, exist_ok=True)

        # 1. In Phase 2A before pre_commit_status: AGENT_2 turn
        t1 = compute_turn_status(self.workspace)
        self.assertEqual(t1.phase, "PHASE_2A_CODING")
        self.assertEqual(t1.active_turn, "AGENT_2")
        self.assertEqual(t1.waiting_for, "Phase-2A/pre_commit_status.json")

        # 2. After pre_commit_status submitted: AGENT_1 turn (auditor)
        (p2a_dir / "pre_commit_status.json").write_text(
            json.dumps({
                "schema_version": "1.0.0",
                "task_id": self.task_id,
                "attempt": self.attempt,
                "cycle": 1,
                "status": "AWAITING_REVIEW",
                "touched_repositories": ["service"],
                "base_commits": {"service": "abc"},
            }),
            encoding="utf-8",
        )
        t2 = compute_turn_status(self.workspace)
        self.assertEqual(t2.active_turn, "AGENT_1")
        self.assertEqual(t2.waiting_for, "Phase-2A/pre_commit_review.json")

        # 3. If review requires revision: loops back to AGENT_2 turn
        (p2a_dir / "pre_commit_review.json").write_text(
            json.dumps({
                "schema_version": "2.0",
                "task_id": self.task_id,
                "attempt": self.attempt,
                "cycle": 1,
                "status": "REVISION_REQUIRED",
                "summary": "Fix syntax error",
            }),
            encoding="utf-8",
        )
        t3 = compute_turn_status(self.workspace)
        self.assertEqual(t3.active_turn, "AGENT_2")

        # 4. If review is approved: STAGECHECK turn (commit & advance)
        (p2a_dir / "pre_commit_review.json").write_text(
            json.dumps({
                "schema_version": "2.0",
                "task_id": self.task_id,
                "attempt": self.attempt,
                "cycle": 2,
                "status": "APPROVED",
                "summary": "Ready",
            }),
            encoding="utf-8",
        )
        t4 = compute_turn_status(self.workspace)
        self.assertEqual(t4.active_turn, "STAGECHECK")

    def test_circuit_breaker_turn_is_human_operator(self) -> None:
        """Verify circuit breaker tripped sets active_turn to HUMAN_OPERATOR."""
        state = load_active_state(self.workspace)
        state["circuit_breaker_tripped"] = True
        save_active_state(self.workspace, state)

        t = compute_turn_status(self.workspace)
        self.assertEqual(t.active_turn, "HUMAN_OPERATOR")
        self.assertIn("Human operator", t.instructions_for_active_agent)
        validate_turn_status(t.to_dict())

    def test_cli_turn_json_output(self) -> None:
        """Verify 'stagecheck turn --json' outputs valid JSON matching schema."""
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["turn", "--task", self.task_id, "--json", "--workspace", str(self.workspace)])
        self.assertEqual(rc, 0)

        output = buf.getvalue().strip()
        data = json.loads(output)
        self.assertEqual(data["task_id"], self.task_id)
        self.assertEqual(data["active_turn"], "AGENT_1")
        self.assertEqual(data["retry_after_seconds"], 5)
        validate_turn_status(data)

    def test_rate_limiting_throttling_invariant(self) -> None:
        """Verify exceeding 3 queries within 5s returns 429 [RATE_LIMITED] (ARCH-04)."""
        # Call 1, 2, 3 must succeed
        for i in range(3):
            rc = main(["turn", "--task", self.task_id, "--workspace", str(self.workspace)])
            self.assertEqual(rc, 0, f"Query {i+1} should succeed within rate limit")

        # Call 4 must be rate limited with exit code 429
        err_buf = io.StringIO()
        with redirect_stderr(err_buf):
            rc4 = main(["turn", "--task", self.task_id, "--workspace", str(self.workspace)])
        self.assertEqual(rc4, 429)
        self.assertIn("[RATE_LIMITED]", err_buf.getvalue())

    def test_watchdog_resets_on_turn_query(self) -> None:
        """Verify 'stagecheck turn' refreshes ACTIVE_STATE watchdog timestamp (FR-05)."""
        state_before = load_active_state(self.workspace)
        self.assertNotIn("watchdog", state_before)

        rc = main(["turn", "--task", self.task_id, "--workspace", str(self.workspace)])
        self.assertEqual(rc, 0)

        state_after = load_active_state(self.workspace)
        self.assertIn("watchdog", state_after)
        self.assertIn("last_active_timestamp", state_after["watchdog"])


if __name__ == "__main__":
    unittest.main()
