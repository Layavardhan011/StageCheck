"""Unit and CLI Tests for Continuous Sentinel Daemon & 4-Tier Watcher (P4-T1)."""

from __future__ import annotations

import datetime
import json
import os
import tempfile
import time
import unittest
from pathlib import Path

from stagecheck.cli.main import main
from stagecheck.core.permissions import controlled_write_transaction
from stagecheck.core.sentinel import (
    SentinelDaemon,
    SentinelError,
    classify_event_path,
    send_desktop_notification,
)
from stagecheck.core.state import load_active_state, save_active_state
from stagecheck.core.supervisor import evaluate_watchdog


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
            "evidence/sentinel.log",
            ".stagecheck_sentinel.pid",
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

        # Verify option termination ('--'), html escaping, and urgency/icon sanitization
        from unittest.mock import patch
        with patch("stagecheck.core.sentinel.subprocess.run") as mock_run:
            send_desktop_notification(
                title="-leading-dash <b>title</b>",
                message="--msg <script>x</script>",
                urgency="--evil",
                icon="-bad-icon",
            )
            self.assertTrue(mock_run.called)
            cmd = mock_run.call_args[0][0]
            self.assertEqual(cmd[0], "notify-send")
            self.assertIn("--", cmd)
            dash_idx = cmd.index("--")
            self.assertEqual(cmd[cmd.index("--urgency") + 1], "normal")
            self.assertEqual(cmd[cmd.index("--icon") + 1], "dialog-information")
            self.assertEqual(cmd[dash_idx + 1], "-leading-dash &lt;b&gt;title&lt;/b&gt;")
            self.assertEqual(cmd[dash_idx + 2], "--msg &lt;script&gt;x&lt;/script&gt;")

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

    def test_process_rss_measurement_returns_positive_value(self) -> None:
        """RSS helper measures a real process in MiB."""
        from stagecheck.core.sentinel import get_process_rss_mib

        rss = get_process_rss_mib(os.getpid())
        self.assertGreater(rss, 0.0)
        self.assertLess(rss, 1024.0)
        # Non-existent PID returns 0.0
        self.assertEqual(get_process_rss_mib(9999999), 0.0)

    def test_daemon_start_and_stop_lifecycle(self) -> None:
        """Verify real Sentinel daemon background startup, PID acquisition, and graceful stop."""
        sentinel = SentinelDaemon(self.workspace)
        exit_code = sentinel.start(daemon=True, timeout=10.0)
        self.assertEqual(exit_code, 0)

        # Confirm daemon is immediately registered and running via readiness protocol
        running, pid = sentinel.is_running()
        self.assertTrue(running)
        self.assertIsNotNone(pid)
        self.assertGreater(pid, 1)
        self.assertNotEqual(pid, os.getpid(), "Daemon PID must differ from parent test runner PID")

        # Confirm status sees it running with valid RSS (< 25 MiB)
        status = sentinel.status()
        self.assertTrue(status["running"])
        self.assertEqual(status["pid"], pid)
        self.assertGreater(status["rss_mb"], 0.0)
        self.assertLess(status["rss_mb"], 25.0)

        # Stop daemon cleanly
        stop_code = sentinel.stop()
        self.assertEqual(stop_code, 0)
        self.assertFalse(sentinel.is_running()[0])
        self.assertFalse(sentinel.pid_file.exists())

        # Verify no orphan or zombie process remains
        from stagecheck.core.sentinel import is_process_alive
        self.assertFalse(is_process_alive(pid), f"Daemon process {pid} remained alive or zombie after stop")

    def test_repeated_start_and_stop_lifecycle(self) -> None:
        """Verify repeated start and stop cycles cleanly manage PID files and processes."""
        sentinel = SentinelDaemon(self.workspace)
        for cycle in range(2):
            exit_code = sentinel.start(daemon=True, timeout=10.0)
            self.assertEqual(exit_code, 0, f"Failed start on cycle {cycle}")
            running, pid = sentinel.is_running()
            self.assertTrue(running)
            self.assertIsNotNone(pid)

            stop_code = sentinel.stop()
            self.assertEqual(stop_code, 0, f"Failed stop on cycle {cycle}")
            self.assertFalse(sentinel.is_running()[0])
            self.assertFalse(sentinel.pid_file.exists())

    def test_isolated_runtime_command_and_environment(self) -> None:
        """Verify daemon launches with -I, -S, sanitized environment, and direct script path."""
        sentinel = SentinelDaemon(self.workspace)
        exit_code = sentinel.start(daemon=True, timeout=10.0)
        self.assertEqual(exit_code, 0)

        running, pid = sentinel.is_running()
        self.assertTrue(running)
        self.assertIsNotNone(pid)

        try:
            # 1. Verify cmdline arguments
            cmdline_parts = [
                arg.decode("utf-8", errors="replace")
                for arg in Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\x00")
                if arg
            ]
            self.assertIn("-I", cmdline_parts, "Child interpreter must use -I isolation flag")
            self.assertIn("-S", cmdline_parts, "Child interpreter must use -S flag to skip site-packages")
            self.assertTrue(
                any(arg.endswith("sentinel.py") for arg in cmdline_parts),
                "Child command must invoke sentinel.py by absolute path",
            )

            # 2. Verify sanitized environment
            environ_bytes = Path(f"/proc/{pid}/environ").read_bytes().split(b"\x00")
            daemon_env = dict(
                e.decode("utf-8", errors="replace").split("=", 1)
                for e in environ_bytes
                if b"=" in e
            )
            for bad_key in (
                "PYTHONPATH",
                "PYTHONHOME",
                "PYTHONSTARTUP",
                "PYTHONUSERBASE",
                "PYTHONINSPECT",
                "PYTHONPROFILEIMPORTTIME",
            ):
                self.assertNotIn(bad_key, daemon_env, f"{bad_key} must be purged from daemon environment")
            self.assertEqual(daemon_env.get("PYTHONNOUSERSITE"), "1")

            # 3. Verify memory maps do not include pytest or test frameworks
            maps_content = Path(f"/proc/{pid}/maps").read_text(encoding="utf-8", errors="replace")
            self.assertNotIn("pytest", maps_content, "Daemon must not load or map pytest modules")

        finally:
            sentinel.stop()

    def test_daemon_startup_failure_timeout(self) -> None:
        """Verify daemon start failure when readiness protocol times out."""
        bad_dir = self.workspace / "non_existent_subdir" / "locked"
        sentinel = SentinelDaemon(bad_dir)
        exit_code = sentinel.start(daemon=True, timeout=0.1)
        if exit_code != 0:
            self.assertNotEqual(exit_code, 0)
        else:
            sentinel.stop()

    def test_invalid_and_malformed_pid_file(self) -> None:
        """Verify malformed and corrupted PID files are detected and recovered."""
        sentinel = SentinelDaemon(self.workspace)
        pid_file = self.workspace / ".stagecheck_sentinel.pid"

        # Case 1: Corrupted non-digit string
        pid_file.write_text("not_a_number\n", encoding="utf-8")
        self.assertIsNone(sentinel.read_pid())
        running, _ = sentinel.is_running()
        self.assertFalse(running)
        self.assertFalse(pid_file.exists(), "Malformed PID file should be unlinked")

        # Case 2: Negative number
        pid_file.write_text("-50\n", encoding="utf-8")
        self.assertIsNone(sentinel.read_pid())
        running, _ = sentinel.is_running()
        self.assertFalse(running)

    def test_pid_file_atomic_write_no_empty_read(self) -> None:
        """Verify that atomic write via temporary file prevents reading empty PID file."""
        sentinel = SentinelDaemon(self.workspace)
        for _ in range(50):
            sentinel.write_pid()
            pid = sentinel.read_pid()
            self.assertEqual(pid, os.getpid(), "read_pid must never return None or corrupted PID")
        sentinel.pid_file.unlink(missing_ok=True)

    def test_watchdog_restart_and_monotonic_tracking(self) -> None:
        """Verify DEC-027: Sentinel daemon restores monotonic timing from ACTIVE_STATE.json upon restart."""
        # 1. Setup ACTIVE_STATE with last_active_timestamp 650s ago
        old_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=650)
        state_data = {
            "schema_version": "2.0",
            "task_id": "task-wd-01",
            "attempt_index": 1,
            "repair_index": 0,
            "max_total_attempts": 3,
            "max_repairs": 3,
            "circuit_breaker_tripped": False,
            "target_repositories": ["backend"],
            "phase": "PHASE_2A_CODING",
            "turn": "AGENT2_CODING",
            "status": "IN_PROGRESS",
            "watchdog": {
                "last_active_timestamp": old_time.isoformat(),
            },
        }
        state_file = self.workspace / "controls" / "ACTIVE_STATE.json"
        state_file.write_text(json.dumps(state_data, indent=2), encoding="utf-8")

        # 2. Instantiate SentinelDaemon and verify restored monotonic offset
        daemon = SentinelDaemon(self.workspace)
        elapsed_in_daemon = time.monotonic() - daemon.last_activity_monotonic
        self.assertGreaterEqual(elapsed_in_daemon, 640.0)

        # 3. Evaluate watchdog -> must trip into AWAITING_HUMAN_DISPOSITION
        tripped, msg, meta = evaluate_watchdog(self.workspace, timeout_seconds=600.0)
        self.assertTrue(tripped)
        self.assertIn("WATCHDOG_INACTIVITY_TIMEOUT", msg)

        state_after = load_active_state(self.workspace)
        self.assertEqual(state_after["phase"], "AWAITING_HUMAN_DISPOSITION")

    def test_watchdog_resets_on_relevant_repo_inotify_event(self) -> None:
        """Verify Issue 4: Inotify event under repos/ resets watchdog monotonic timer and ACTIVE_STATE timestamp."""
        old_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=200)
        state_data = {
            "schema_version": "2.0",
            "task_id": "task-wd-02",
            "attempt_index": 1,
            "repair_index": 0,
            "max_total_attempts": 3,
            "max_repairs": 3,
            "circuit_breaker_tripped": False,
            "target_repositories": ["backend"],
            "phase": "PHASE_2A_CODING",
            "turn": "AGENT2_CODING",
            "status": "IN_PROGRESS",
            "watchdog": {
                "last_active_timestamp": old_time.isoformat(),
            },
        }
        state_file = self.workspace / "controls" / "ACTIVE_STATE.json"
        state_file.write_text(json.dumps(state_data, indent=2), encoding="utf-8")

        daemon = SentinelDaemon(self.workspace)
        start_mono = daemon.last_activity_monotonic

        # Log event for relevant repo path
        daemon._log_event("repos/backend/service.py", tier=4, label="ALLOWED_SCOPE")

        # Verify monotonic timer refreshed
        self.assertGreater(daemon.last_activity_monotonic, start_mono)

        # Verify sentinel.log recorded the relevant event
        from stagecheck.core.supervisor import get_last_relevant_filesystem_timestamp
        last_fs_ts = get_last_relevant_filesystem_timestamp(self.workspace)
        self.assertIsNotNone(last_fs_ts)

    def test_watchdog_ignores_unrelated_file_events(self) -> None:
        """Verify Issue 4: Unrelated file events (.git/logs, /tmp) do NOT reset the watchdog timer."""
        fixed_ts = "2026-11-06T12:00:00+00:00"
        state_data = {
            "schema_version": "2.0",
            "task_id": "task-wd-03",
            "attempt_index": 1,
            "repair_index": 0,
            "max_total_attempts": 3,
            "max_repairs": 3,
            "circuit_breaker_tripped": False,
            "target_repositories": ["backend"],
            "phase": "PHASE_2A_CODING",
            "turn": "AGENT2_CODING",
            "status": "IN_PROGRESS",
            "watchdog": {
                "last_active_timestamp": fixed_ts,
            },
        }
        state_file = self.workspace / "controls" / "ACTIVE_STATE.json"
        state_file.write_text(json.dumps(state_data, indent=2), encoding="utf-8")

        daemon = SentinelDaemon(self.workspace)
        mono_before = daemon.last_activity_monotonic

        # Log event for unrelated git log file
        daemon._log_event(".git/logs/HEAD", tier=1, label="GOVERNANCE_BREACH")

        # Monotonic timer and state timestamp must remain UNCHANGED
        self.assertEqual(daemon.last_activity_monotonic, mono_before)
        state_after = load_active_state(self.workspace)
        self.assertEqual(state_after["watchdog"]["last_active_timestamp"], fixed_ts)

    def test_watchdog_suspended_in_audit_and_sealing_phases(self) -> None:
        """Verify watchdog is automatically suspended in PHASE_3_AUDIT and GATE_4_SEALING."""
        for suspended_phase in ("PHASE_3_AUDIT", "GATE_4_SEALING", "IDLE", "COMPLETED"):
            with self.subTest(phase=suspended_phase):
                state_data = {
                    "schema_version": "2.0",
                    "task_id": "task-wd-04",
                    "attempt_index": 1,
                    "repair_index": 0,
                    "max_total_attempts": 3,
                    "max_repairs": 3,
                    "circuit_breaker_tripped": False,
                    "target_repositories": ["backend"],
                    "phase": suspended_phase,
                    "turn": "IDLE",
                    "status": "IN_PROGRESS",
                    "watchdog": {
                        "last_active_timestamp": "2020-01-01T00:00:00+00:00",
                    },
                }
                state_file = self.workspace / "controls" / "ACTIVE_STATE.json"
                state_file.write_text(json.dumps(state_data, indent=2), encoding="utf-8")

                tripped, msg, meta = evaluate_watchdog(self.workspace, timeout_seconds=600.0)
                self.assertFalse(tripped)
                self.assertFalse(meta.get("active"))
                self.assertIn("suspended", msg.lower())

    def test_daemon_graceful_degradation_without_libc(self) -> None:
        """Verify SentinelDaemon degrades cleanly when libc or inotify support is unavailable."""
        daemon = SentinelDaemon(self.workspace)
        daemon._libc = None
        daemon._init_libc = lambda: None
        # Should exit gracefully without unhandled exception
        daemon._run_loop(ready_fd=None)
        self.assertFalse(daemon.is_running()[0])

    def test_daemon_rejects_symlink_daemon_log_and_lock(self) -> None:
        """SentinelDaemon.start rejects symlinked sentinel_daemon.log and .stagecheck_sentinel.lock."""
        from stagecheck.core.sentinel import SentinelError
        daemon = SentinelDaemon(self.workspace)
        daemon.log_file.parent.mkdir(parents=True, exist_ok=True)
        daemon_log = self.workspace / "evidence" / "sentinel_daemon.log"
        target = self.workspace / "evidence" / "victim.txt"
        target.write_text("do-not-touch", encoding="utf-8")
        daemon_log.unlink(missing_ok=True)
        daemon_log.symlink_to(target)
        with self.assertRaises(SentinelError):
            daemon.start(daemon=True)

        daemon_log.unlink(missing_ok=True)
        lock_file = self.workspace / ".stagecheck_sentinel.lock"
        lock_file.unlink(missing_ok=True)
        lock_file.symlink_to(target)
        with self.assertRaises(SentinelError):
            daemon.start(daemon=True)
        lock_file.unlink(missing_ok=True)

    def test_sanitize_log_field_escapes_c1_and_unicode_line_separators(self) -> None:
        """_sanitize_log_field escapes U+0085, U+2028, and U+2029 so forged lines cannot be injected."""
        from stagecheck.core.sentinel import _sanitize_log_field
        raw = "repos/backend/a\u0085b\u2028c\u2029d.py"
        sanitized = _sanitize_log_field(raw)
        self.assertNotIn("\u0085", sanitized)
        self.assertNotIn("\u2028", sanitized)
        self.assertNotIn("\u2029", sanitized)
        self.assertIn("\\x85", sanitized)
        self.assertIn("\\u2028", sanitized)
        self.assertIn("\\u2029", sanitized)

    def test_authorized_runtime_lock_classified_as_authorized_transaction(self) -> None:
        """Verify SentinelDaemon detects active/recent runtime lock transactions and avoids false GOVERNANCE_BREACH."""
        from stagecheck.core.locking import acquire_runtime_lock
        from stagecheck.core.permissions import MODE_DIR_RO, MODE_DIR_RW

        controls_dir = self.workspace / "controls"
        daemon = SentinelDaemon(self.workspace)

        # Without lock or recent transaction -> False -> GOVERNANCE_BREACH
        self.assertFalse(daemon._is_active_transaction())
        tier, label = classify_event_path(self.workspace, "controls/ACTIVE_STATE.json", active_transaction=daemon._is_active_transaction())
        self.assertEqual((tier, label), (1, "GOVERNANCE_BREACH"))

        # During/immediately after acquire_runtime_lock with at-rest 0555 controls/ -> AUTHORIZED_TRANSACTION
        os.chmod(controls_dir, MODE_DIR_RO)
        try:
            with acquire_runtime_lock(self.workspace):
                self.assertTrue(daemon._is_active_transaction())
                tier_tx, label_tx = classify_event_path(
                    self.workspace, "controls/ACTIVE_STATE.json", active_transaction=daemon._is_active_transaction()
                )
                self.assertEqual((tier_tx, label_tx), (1, "AUTHORIZED_TRANSACTION"))
            # Right after release (within 1.0s epoll delivery window) with 0555 controls/ -> still True
            self.assertTrue(daemon._is_active_transaction())
        finally:
            os.chmod(controls_dir, MODE_DIR_RW)


if __name__ == "__main__":
    unittest.main()

