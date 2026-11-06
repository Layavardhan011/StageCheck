"""Comprehensive Test Suite for Task 3.5: Interactive Supervisor, Debounce, and Watchdog Lifecycle.

Verifies:
1. Prompt Debounce (ARCH-01):
   - Sliding 30-second silence window -> freeze_reason: "INOTIFY_SILENCE_30S".
   - Hard 300-second ceiling under continuous editing -> freeze_reason: "HARD_CEILING_300S".
   - Both exit reasons properly logged in prompt_verified.json.
2. Dual-Condition Watchdog Lifecycle (FR-05):
   - Active strictly in agent phases (PHASE_1_PLANNING, PHASE_2A_CODING, PHASE_2B_COMMITTING).
   - Suspended during PHASE_3_AUDIT and GATE_4_SEALING.
   - Relevant filesystem events (repos/, Phase-*) reset fs timer; irrelevant paths ignored.
   - Agent turn heartbeats reset turn timer.
   - Dual-condition trip when both delta_fs >= 600s and delta_turn >= 600s.
   - Halts to AWAITING_HUMAN_DISPOSITION, preserves attempt count without consumption.
   - Restart restores monotonic timing behavior from ACTIVE_STATE.json.
3. Supervisor Engine and CLI commands:
   - stagecheck supervisor check-task
   - stagecheck supervisor check-stability
   - stagecheck supervisor check-watchdog
   - Step-by-step gate orchestration
"""

import datetime
import json
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from stagecheck.cli.init_cmd import run_init
from stagecheck.cli.main import main
from stagecheck.cli.supervisor_cmd import run_supervisor_cmd
from stagecheck.core.permissions import elevate_permissions_for_teardown
from stagecheck.core.prompt_gate import freeze_prompt_and_scope
from stagecheck.core.state import load_active_state, save_active_state
from stagecheck.core.supervisor import (
    PromptDebouncer,
    SupervisorEngine,
    evaluate_watchdog,
    get_last_relevant_filesystem_timestamp,
    get_last_turn_heartbeat_timestamp,
    is_relevant_sentinel_path,
)


def _setup_mock_repo(ws: Path, repo_name: str = "core-service") -> Path:
    repo_dir = ws / "repos" / repo_name
    repo_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-b", "main"], cwd=str(repo_dir), capture_output=True, check=True)
    subprocess.run(["git", "config", "user.name", "Test Committer"], cwd=str(repo_dir), capture_output=True, check=True)
    subprocess.run(["git", "config", "user.email", "test@stagecheck.local"], cwd=str(repo_dir), capture_output=True, check=True)
    (repo_dir / "README.md").write_text("# Test Repo\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=str(repo_dir), capture_output=True, check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=str(repo_dir), capture_output=True, check=True)
    return repo_dir


class TestPromptDebounce(unittest.TestCase):
    """Test 30-second sliding debounce with 300-second hard ceiling (ARCH-01)."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.temp_dir.name).resolve()
        self.prompt_file = self.tmp / "prompt.md"

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_sliding_window_silence_debounce(self) -> None:
        """Verify 30s silence debounce triggers INOTIFY_SILENCE_30S."""
        debouncer = PromptDebouncer(quiet_seconds=30.0, max_ceiling_seconds=300.0)

        # File does not exist yet
        stable, reason = debouncer.check_stability(self.prompt_file)
        self.assertFalse(stable)
        self.assertIsNone(reason)

        # File created at t=100
        self.prompt_file.write_text("# Blueprint Draft 1\n", encoding="utf-8")
        stable, reason = debouncer.check_stability(self.prompt_file, now=100.0)
        self.assertFalse(stable)

        # File untouched after 10s (t=110) -> not stable yet
        stable, reason = debouncer.check_stability(self.prompt_file, now=110.0)
        self.assertFalse(stable)

        # File untouched after 29s (t=129) -> not stable yet
        stable, reason = debouncer.check_stability(self.prompt_file, now=129.0)
        self.assertFalse(stable)

        # File untouched after 30s (t=130) -> STABLE via sliding window silence
        stable, reason = debouncer.check_stability(self.prompt_file, now=130.0)
        self.assertTrue(stable)
        self.assertEqual(reason, "INOTIFY_SILENCE_30S")

    def test_hard_ceiling_prevents_starvation_under_continuous_editing(self) -> None:
        """Verify continuous edits past 300s trigger HARD_CEILING_300S."""
        debouncer = PromptDebouncer(quiet_seconds=30.0, max_ceiling_seconds=300.0)

        # File created at t=0
        self.prompt_file.write_text("# Version 0\n", encoding="utf-8")
        debouncer.check_stability(self.prompt_file, now=0.0)

        # Simulate agent editing every 15s (never silent for 30s)
        current_time = 0.0
        version = 0
        while current_time < 275.0:
            current_time += 15.0
            version += 1
            self.prompt_file.write_text(f"# Version {version}\n", encoding="utf-8")
            stable, reason = debouncer.check_stability(self.prompt_file, now=current_time)
            self.assertFalse(stable, f"Prematurely stable at t={current_time}")

        # At t=305s (still editing every 15s), hard ceiling of 300s is exceeded
        current_time = 305.0
        self.prompt_file.write_text("# Version Final Edit\n", encoding="utf-8")
        stable, reason = debouncer.check_stability(self.prompt_file, now=current_time)
        self.assertTrue(stable)
        self.assertEqual(reason, "HARD_CEILING_300S")

    def test_prompt_verified_records_both_freeze_reasons(self) -> None:
        """Verify prompt_verified.json correctly records freeze_reason metadata."""
        # 1. Setup workspace
        ws = self.tmp / "ws"
        ws.mkdir(parents=True, exist_ok=True)
        _setup_mock_repo(ws, "core-service")
        rc = run_init(workspace=str(ws), agent1="agent1", agent2="agent2", repos="core-service")
        self.assertEqual(rc, 0)

        p1_dir = ws / "evidence/tasks/task-101/attempt_1/Phase-1"
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
        (p1_dir / "declared_scope.json").write_text(
            json.dumps({"schema_version": "2.0", "task_id": "task-101", "allowed_paths": ["repos/**"]})
        )

        # Freeze with INOTIFY_SILENCE_30S
        rec_path = freeze_prompt_and_scope(ws, "task-101", 1, freeze_reason="INOTIFY_SILENCE_30S")
        data1 = json.loads(rec_path.read_text())
        self.assertEqual(data1["freeze_reason"], "INOTIFY_SILENCE_30S")

        # Freeze with HARD_CEILING_300S
        rec_path.chmod(0o644)
        rec_path2 = freeze_prompt_and_scope(ws, "task-101", 1, freeze_reason="HARD_CEILING_300S")
        data2 = json.loads(rec_path2.read_text())
        self.assertEqual(data2["freeze_reason"], "HARD_CEILING_300S")

        elevate_permissions_for_teardown(ws)


class TestWatchdogLifecycle(unittest.TestCase):
    """Test Dual-Condition Watchdog Lifecycle, Relevance, and Monotonic Recovery (FR-05)."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.ws = Path(self.temp_dir.name).resolve()
        _setup_mock_repo(self.ws, "core-service")
        rc = run_init(workspace=str(self.ws), agent1="agent1", agent2="agent2", repos="core-service")
        self.assertEqual(rc, 0)

        self.sentinel_log = self.ws / "evidence" / "sentinel.log"
        self.sentinel_log.parent.mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        elevate_permissions_for_teardown(self.ws)
        self.temp_dir.cleanup()

    def test_relevant_sentinel_paths(self) -> None:
        """Verify is_relevant_sentinel_path only matches repos/ and active phase evidence."""
        self.assertTrue(is_relevant_sentinel_path("repos/payment-service/src/main.py"))
        self.assertTrue(is_relevant_sentinel_path("evidence/tasks/task-01/attempt_1/Phase-1/prompt.md"))
        self.assertTrue(is_relevant_sentinel_path("evidence/tasks/task-01/attempt_1/Phase-2A/status.json"))
        self.assertTrue(is_relevant_sentinel_path("evidence/tasks/task-01/attempt_1/Phase-2B/report.md"))

        # Irrelevant paths must not count as agent work
        self.assertFalse(is_relevant_sentinel_path(".git/index"))
        self.assertFalse(is_relevant_sentinel_path("tmp/scratch.txt"))
        self.assertFalse(is_relevant_sentinel_path(".tox/py312/lib/something.py"))
        self.assertFalse(is_relevant_sentinel_path("controls/ACTIVE_STATE.json"))

    def test_watchdog_suspended_in_non_agent_phases(self) -> None:
        """Verify watchdog is strictly suspended in PHASE_3_AUDIT and GATE_4_SEALING."""
        state = load_active_state(self.ws)
        for suspended_phase in ("PHASE_3_AUDIT", "GATE_4_SEALING", "SEALED_PASSED", "IDLE"):
            state["phase"] = suspended_phase
            save_active_state(self.ws, state)

            tripped, msg, meta = evaluate_watchdog(self.ws, timeout_seconds=600.0)
            self.assertFalse(tripped)
            self.assertFalse(meta["active"])
            self.assertIn("suspended", msg)

    def test_watchdog_healthy_when_fs_or_turn_active(self) -> None:
        """Verify watchdog does NOT trip if either filesystem or turn heartbeat is recent."""
        state = load_active_state(self.ws)
        state["phase"] = "PHASE_2A_CODING"

        now_utc = datetime.datetime(2026, 11, 6, 12, 0, 0, tzinfo=datetime.timezone.utc)

        # 1. Heartbeat is recent (5 minutes ago = 300s), but fs is old (12 minutes ago = 720s)
        t_recent = (now_utc - datetime.timedelta(seconds=300)).isoformat()
        t_old = (now_utc - datetime.timedelta(seconds=720)).isoformat()

        state.setdefault("watchdog", {})["last_active_timestamp"] = t_recent
        save_active_state(self.ws, state)

        self.sentinel_log.write_text(f"[{t_old}] [Tier 1] [MODIFIED] repos/core/app.py\n", encoding="utf-8")

        tripped, msg, meta = evaluate_watchdog(self.ws, timeout_seconds=600.0, now_utc=now_utc)
        self.assertFalse(tripped, "Watchdog tripped despite recent turn heartbeat")

        # 2. Filesystem is recent (3 minutes ago = 180s), but heartbeat is old (15 minutes ago = 900s)
        t_recent_fs = (now_utc - datetime.timedelta(seconds=180)).isoformat()
        state.setdefault("watchdog", {})["last_active_timestamp"] = t_old
        save_active_state(self.ws, state)

        self.sentinel_log.write_text(f"[{t_recent_fs}] [Tier 1] [MODIFIED] repos/core/app.py\n", encoding="utf-8")

        tripped, msg, meta = evaluate_watchdog(self.ws, timeout_seconds=600.0, now_utc=now_utc)
        self.assertFalse(tripped, "Watchdog tripped despite recent filesystem activity")

    def test_watchdog_trips_when_both_fs_and_turn_inactive(self) -> None:
        """Verify watchdog trips to AWAITING_HUMAN_DISPOSITION when BOTH conditions exceed 600s."""
        state = load_active_state(self.ws)
        state["phase"] = "PHASE_2A_CODING"
        state["attempt_index"] = 1

        now_utc = datetime.datetime(2026, 11, 6, 12, 0, 0, tzinfo=datetime.timezone.utc)
        t_stale = (now_utc - datetime.timedelta(seconds=650)).isoformat()

        state.setdefault("watchdog", {})["last_active_timestamp"] = t_stale
        save_active_state(self.ws, state)

        self.sentinel_log.write_text(f"[{t_stale}] [Tier 1] [MODIFIED] repos/core/app.py\n", encoding="utf-8")

        tripped, msg, meta = evaluate_watchdog(self.ws, timeout_seconds=600.0, now_utc=now_utc)
        self.assertTrue(tripped)
        self.assertIn("WATCHDOG_INACTIVITY_TIMEOUT", msg)

        # Verify state transition
        new_state = load_active_state(self.ws)
        self.assertEqual(new_state["phase"], "AWAITING_HUMAN_DISPOSITION")
        self.assertEqual(new_state["attempt_index"], 1)  # Budget preserved!
        self.assertIn("WATCHDOG_INACTIVITY_TIMEOUT", new_state.get("halt_reason", ""))

    def test_watchdog_restores_from_state_on_restart(self) -> None:
        """Verify process restart reads last_active_timestamp and restores timing accurately."""
        state = load_active_state(self.ws)
        state["phase"] = "PHASE_1_PLANNING"

        now_utc = datetime.datetime.now(datetime.timezone.utc)
        # Record activity 200s ago
        past_iso = (now_utc - datetime.timedelta(seconds=200)).isoformat()
        state.setdefault("watchdog", {})["last_active_timestamp"] = past_iso
        save_active_state(self.ws, state)

        # Fresh supervisor engine (simulating daemon restart)
        engine = SupervisorEngine(self.ws, watchdog_timeout_seconds=600.0)
        report = engine.check_task()

        self.assertFalse(report["watchdog_tripped"])
        self.assertTrue(report["watchdog"]["active"])
        # Delta should reflect ~200s elapsed
        self.assertGreaterEqual(report["watchdog"]["delta_turn_seconds"], 190.0)
        self.assertLessEqual(report["watchdog"]["delta_turn_seconds"], 220.0)


class TestSupervisorCLI(unittest.TestCase):
    """Test CLI command integration for stagecheck supervisor."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.ws = Path(self.temp_dir.name).resolve()
        _setup_mock_repo(self.ws, "core-service")
        rc = run_init(workspace=str(self.ws), agent1="agent1", agent2="agent2", repos="core-service")
        self.assertEqual(rc, 0)

    def tearDown(self) -> None:
        elevate_permissions_for_teardown(self.ws)
        self.temp_dir.cleanup()

    def test_supervisor_check_task_cli(self) -> None:
        """Verify 'stagecheck supervisor check-task --json'."""
        rc = main(["supervisor", "check-task", "--workspace", str(self.ws), "--json"])
        self.assertEqual(rc, 0)

    def test_supervisor_check_stability_cli(self) -> None:
        """Verify 'stagecheck supervisor check-stability'."""
        test_file = self.ws / "test_file.txt"
        test_file.write_text("Hello\n", encoding="utf-8")

        # Right after creation with 30s threshold -> unstable (rc=1)
        rc = main(["supervisor", "check-stability", "--file", str(test_file), "--seconds", "30", "--workspace", str(self.ws)])
        self.assertEqual(rc, 1)

    def test_supervisor_check_watchdog_cli(self) -> None:
        """Verify 'stagecheck supervisor check-watchdog'."""
        rc = main(["supervisor", "check-watchdog", "--workspace", str(self.ws), "--json"])
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
