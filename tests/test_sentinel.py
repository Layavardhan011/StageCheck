"""Unit and CLI Tests for Continuous Sentinel Daemon & 4-Tier Watcher (P4-T1)."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from stagecheck.cli.main import main
from stagecheck.core.sentinel import (
    SentinelDaemon,
    SentinelError,
    classify_event_path,
    send_desktop_notification,
)


class TestSentinel(unittest.TestCase):
    """Test suite covering 4-tier event routing, PID lifecycle, notifications, and CLI."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp_dir.name).resolve()
        (self.workspace / "controls").mkdir(parents=True, exist_ok=True)
        (self.workspace / "evidence" / "tasks").mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_tier_1_governance_guard_classification(self) -> None:
        """Verify Tier 1 intercepts governance and critical Git control mutations."""
        tier1_cases = [
            "controls/ACTIVE_STATE.json",
            "specs/TASK_PLAN.md",
            "AGENTS.md",
            "stagecheck/core/sentinel.py",
            "evidence/EVIDENCE_MANIFEST.json",
            "repos/backend/.git/config",
            "repos/backend/.git/hooks/pre-commit",
            "repos/backend/.git/info/exclude",
        ]
        for path_str in tier1_cases:
            with self.subTest(path=path_str):
                # When no transaction active
                tier, label = classify_event_path(self.workspace, path_str, active_transaction=False)
                self.assertEqual(tier, 1)
                self.assertEqual(label, "GOVERNANCE_BREACH")

                # When transaction is active
                tier_tx, label_tx = classify_event_path(self.workspace, path_str, active_transaction=True)
                self.assertEqual(tier_tx, 1)
                self.assertEqual(label_tx, "AUTHORIZED_TRANSACTION")

    def test_tier_2_build_cache_noise_silent_drop(self) -> None:
        """Verify Tier 2 silently drops compiler artifacts, caches, and swap files."""
        tier2_cases = [
            "repos/backend/.git/objects/4b/825dc642cb6eb9a060e54bf8d69288fbee4904",
            "repos/backend/.git/index",
            "repos/backend/.git/logs/HEAD",
            ".stagecheck_worktrees/backend_base_task-101/main.py",
            "repos/backend/__pycache__/order.cpython-312.pyc",
            "repos/backend/.pytest_cache/v/cache/nodeids",
            "repos/backend/src/.main.py.swp",
            "repos/backend/tmp.12345.tmp.",
        ]
        for path_str in tier2_cases:
            with self.subTest(path=path_str):
                tier, label = classify_event_path(self.workspace, path_str)
                self.assertEqual(tier, 2)
                self.assertEqual(label, "SILENT_DROP")

    def test_tier_3_evidence_lifecycle_routing(self) -> None:
        """Verify Tier 3 routes milestone submissions to verifier lifecycle handlers."""
        t3_prompt = "evidence/tasks/task-101/attempt_1/Phase-1/prompt.md"
        tier, label = classify_event_path(self.workspace, t3_prompt)
        self.assertEqual(tier, 3)
        self.assertEqual(label, "PROMPT_SUBMISSION")

        t3_review = "evidence/tasks/task-101/attempt_1/Phase-2A/pre_commit_status.json"
        tier, label = classify_event_path(self.workspace, t3_review)
        self.assertEqual(tier, 3)
        self.assertEqual(label, "REVIEW_REQUEST")

        t3_claims = "evidence/tasks/task-101/attempt_1/Phase-2B/claims.json"
        tier, label = classify_event_path(self.workspace, t3_claims)
        self.assertEqual(tier, 3)
        self.assertEqual(label, "DELIVERY_COMPLETE")

    def test_tier_4_repository_scope_enforcement(self) -> None:
        """Verify Tier 4 evaluates working-tree repository changes against declared scope."""
        scope = {
            "allowed_paths": ["repos/backend/src/order.py"],
            "forbidden_paths": ["repos/backend/secret.key"],
        }
        # In scope
        tier, label = classify_event_path(self.workspace, "repos/backend/src/order.py", declared_scope=scope)
        self.assertEqual(tier, 4)
        self.assertEqual(label, "ALLOWED_SCOPE")

        # Out of scope / forbidden
        tier, label = classify_event_path(self.workspace, "repos/backend/secret.key", declared_scope=scope)
        self.assertEqual(tier, 4)
        self.assertEqual(label, "SCOPE_BREACH")

        tier, label = classify_event_path(self.workspace, "repos/backend/other.py", declared_scope=scope)
        self.assertEqual(tier, 4)
        self.assertEqual(label, "SCOPE_BREACH")

    def test_desktop_notification_html_escaping(self) -> None:
        """Verify notification helper neutralizes Pango markup injection without errors."""
        malicious_title = "<script>alert('pwned')</script> & <b>test</b>"
        malicious_msg = "Injection <span foreground='red'>test</span>"
        # Must execute without raising exception
        send_desktop_notification(title=malicious_title, message=malicious_msg)

    def test_pid_lifecycle_and_stale_recovery(self) -> None:
        """Verify PID writing, reading, and automatic recovery of dead/stale PIDs."""
        sentinel = SentinelDaemon(self.workspace)
        self.assertFalse(sentinel.is_running()[0])

        # Write a dead PID
        pid_file = self.workspace / ".stagecheck_sentinel.pid"
        pid_file.write_text("999999\n", encoding="utf-8")

        # Liveness check must recognize dead PID, auto-unlink file, and return not running
        running, pid = sentinel.is_running()
        self.assertFalse(running)
        self.assertFalse(pid_file.exists())

        # Write current live PID
        sentinel.write_pid()
        self.assertTrue(pid_file.exists())
        running, live_pid = sentinel.is_running()
        self.assertTrue(running)
        self.assertEqual(live_pid, os.getpid())

        # Stop clears PID file
        sentinel.pid_file.unlink(missing_ok=True)

    def test_pid_symlink_attack_rejected(self) -> None:
        """Verify symlink substitution in .stagecheck_sentinel.pid is rejected (SEC-AA1)."""
        sentinel = SentinelDaemon(self.workspace)
        pid_file = self.workspace / ".stagecheck_sentinel.pid"
        target_file = self.workspace / "real_file.txt"
        target_file.write_text("dummy\n", encoding="utf-8")

        os.symlink(str(target_file), str(pid_file))
        with self.assertRaises(SentinelError):
            sentinel.write_pid()

    def test_cli_sentinel_status_and_logs(self) -> None:
        """Verify CLI 'stagecheck sentinel status' and 'stagecheck sentinel logs'."""
        ret_status = main(["sentinel", "status", "--workspace", str(self.workspace)])
        self.assertEqual(ret_status, 0)

        ret_logs = main(["sentinel", "logs", "--workspace", str(self.workspace)])
        self.assertEqual(ret_logs, 0)

    def test_daemon_start_and_stop_lifecycle(self) -> None:
        """Verify real Sentinel daemon background startup, PID acquisition, and graceful stop."""
        import time
        sentinel = SentinelDaemon(self.workspace)
        exit_code = sentinel.start(daemon=True)
        self.assertEqual(exit_code, 0)

        # Confirm daemon registers PID
        pid = None
        for _ in range(50):
            time.sleep(0.05)
            running, active_pid = sentinel.is_running()
            if running and active_pid:
                pid = active_pid
                break

        self.assertIsNotNone(pid, "Sentinel daemon failed to register PID in time")
        self.assertGreater(pid, 1)

        # Confirm status sees it running
        status = sentinel.status()
        self.assertTrue(status["running"])
        self.assertEqual(status["pid"], pid)

        # Stop daemon
        stop_code = sentinel.stop()
        self.assertEqual(stop_code, 0)
        self.assertFalse(sentinel.is_running()[0])
        self.assertFalse(sentinel.pid_file.exists())


if __name__ == "__main__":
    unittest.main()

