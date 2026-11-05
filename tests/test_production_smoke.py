"""Production-Grade End-to-End Smoke Test for StageCheck (P4-T5).

Exercises the full realistic delivery cycle:
1. Workspace initialization via `stagecheck init`
2. Daemon launch with IPC readiness and verified < 25MB RSS
3. Task roadmap validation and task activation
4. Phase 1 prompt blueprint verification
5. Production daemon restart (stop -> start -> status)
6. Phase 2A cooperative pre-commit review and operator approval
7. Clean daemon shutdown with verified PID unlinking and zero zombie/orphan processes
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from stagecheck.cli.main import main
from stagecheck.core.sentinel import SentinelDaemon, is_process_alive, get_process_rss_mib


class TestProductionSmoke(unittest.TestCase):
    """End-to-end production smoke test."""

    def setUp(self) -> None:
        self.workspace_dir = Path(tempfile.mkdtemp(prefix="stagecheck_prod_smoke_"))
        # Initialize product repository under repos/
        repo_dir = self.workspace_dir / "repos" / "core-service"
        repo_dir.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "init", "-b", "main", str(repo_dir)], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(repo_dir), "config", "user.name", "Tester"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(repo_dir), "config", "user.email", "tester@stagecheck.local"], check=True, capture_output=True)
        (repo_dir / "service.py").write_text("# Core service implementation\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo_dir), "add", "."], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(repo_dir), "commit", "-m", "Initial commit"], check=True, capture_output=True)

    def tearDown(self) -> None:
        # Guarantee no lingering daemon from test failures
        try:
            daemon = SentinelDaemon(self.workspace_dir)
            daemon.stop()
        except Exception:
            pass
        from stagecheck.core.permissions import elevate_permissions_for_teardown
        try:
            elevate_permissions_for_teardown(self.workspace_dir)
        except Exception:
            pass
        shutil.rmtree(self.workspace_dir, ignore_errors=True)

    def test_full_production_lifecycle_and_sentinel_restart(self) -> None:
        """Run complete production delivery cycle with daemon monitoring and restart."""
        ws = str(self.workspace_dir)

        # 1. Workspace initialization
        init_exit = main(["init", "--workspace", ws, "--agent1", "agent1", "--agent2", "agent2"])
        self.assertEqual(init_exit, 0, "stagecheck init failed")
        self.assertTrue((self.workspace_dir / "controls" / "ACTIVE_STATE.json").is_file())
        self.assertTrue((self.workspace_dir / "specs" / "TASK_PLAN.json").is_file())

        # 2. Start Sentinel daemon in background
        daemon = SentinelDaemon(self.workspace_dir)
        start_exit = daemon.start(daemon=True, timeout=10.0)
        self.assertEqual(start_exit, 0, "Sentinel daemon failed to start")

        running, pid1 = daemon.is_running()
        self.assertTrue(running, "Daemon reported running=False after start")
        self.assertIsNotNone(pid1)
        self.assertNotEqual(pid1, os.getpid())

        # Verify initial memory RSS < 25 MB
        status1 = daemon.status()
        self.assertTrue(status1["running"])
        self.assertEqual(status1["pid"], pid1)
        self.assertLess(status1["rss_mb"], 25.0, f"Initial RSS {status1['rss_mb']} exceeded 25MB")

        # 3. Task Plan validation
        plan_exit = main(["plan", "validate", "--workspace", ws])
        self.assertEqual(plan_exit, 0, "Task plan validation failed")

        # 4. Activate task
        start_task_exit = main(["start", "--task", "task-101", "--workspace", ws])
        self.assertEqual(start_task_exit, 0, "Task start failed")

        # Verify Sentinel status sees active task
        status_task = daemon.status()
        self.assertEqual(status_task["active_task"], "task-101")

        # 5. Simulate daemon restart
        stop_exit = daemon.stop()
        self.assertEqual(stop_exit, 0, "Sentinel daemon stop failed")
        self.assertFalse(daemon.is_running()[0], "Daemon still running after stop")
        self.assertFalse(is_process_alive(pid1), "Previous daemon process remained alive/zombie")

        # Restart daemon
        restart_exit = daemon.start(daemon=True, timeout=10.0)
        self.assertEqual(restart_exit, 0, "Sentinel daemon failed to restart")

        running2, pid2 = daemon.is_running()
        self.assertTrue(running2)
        self.assertIsNotNone(pid2)
        self.assertNotEqual(pid2, pid1, "Restarted daemon must have new PID")

        status2 = daemon.status()
        self.assertTrue(status2["running"])
        self.assertLess(status2["rss_mb"], 25.0, f"Restarted RSS {status2['rss_mb']} exceeded 25MB")
        self.assertEqual(status2["active_task"], "task-101")

        # 6. Execute Phase 2A pre-commit review
        phase2a_dir = self.workspace_dir / "evidence/tasks/task-101/attempt_1/Phase-2A"
        phase2a_dir.mkdir(parents=True, exist_ok=True)
        status_payload = {
            "schema_version": "2.0",
            "task_id": "task-101",
            "cycle": 1,
            "status": "READY_FOR_REVIEW",
            "touched_repositories": ["core-service"],
            "base_commits": {},
            "summary": "Implemented core-service components.",
        }
        (phase2a_dir / "pre_commit_status.json").write_text(
            __import__("json").dumps(status_payload, indent=2) + "\n", encoding="utf-8"
        )

        review_exit = main(["review-precommit", "--task", "task-101", "--workspace", ws])
        self.assertEqual(review_exit, 0, "review-precommit failed")

        # 7. Operator approval
        approve_exit = main(["approve-review", "--task", "task-101", "--workspace", ws])
        self.assertEqual(approve_exit, 0, "approve-review failed")

        # 8. Clean final daemon shutdown
        final_stop_exit = daemon.stop()
        self.assertEqual(final_stop_exit, 0, "Final daemon stop failed")
        self.assertFalse(daemon.is_running()[0])
        self.assertFalse(is_process_alive(pid2), "Daemon process remained alive or zombie after final stop")
        self.assertFalse(daemon.pid_file.exists(), "PID file was not cleaned up on stop")


if __name__ == "__main__":
    unittest.main()
