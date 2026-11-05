"""Unit and CLI Tests for Safe Workspace Initialization & Permissions (P2-T5)."""

from __future__ import annotations

import fcntl
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from stagecheck.cli.init_cmd import run_init
from stagecheck.core.locking import acquire_bootstrap_lock
from stagecheck.core.permissions import (
    controlled_write_transaction,
    elevate_permissions_for_teardown,
)


class TestInitCommand(unittest.TestCase):
    """Test suite verifying stagecheck init, reinit confirmation, locks, and permissions."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp_dir.name).resolve()

        # Create a mock product repository in repos/
        self.repo_dir = self.workspace / "repos" / "payment-service"
        self.repo_dir.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "init", "-b", "main"], cwd=str(self.repo_dir), check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Test Committer"], cwd=str(self.repo_dir), check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "test@stagecheck.local"], cwd=str(self.repo_dir), check=True, capture_output=True)
        readme = self.repo_dir / "README.md"
        readme.write_text("# Payment Service\n", encoding="utf-8")
        subprocess.run(["git", "add", "README.md"], cwd=str(self.repo_dir), check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=str(self.repo_dir), check=True, capture_output=True)

    def tearDown(self) -> None:
        # Elevate permissions first so teardown can remove read-only directories
        elevate_permissions_for_teardown(self.workspace)
        self.temp_dir.cleanup()

    def test_init_fresh_workspace_success(self) -> None:
        """Verify successful fresh workspace initialization and mode enforcement."""
        ret = run_init(
            workspace=str(self.workspace),
            repos="payment-service",
            force=False,
            agent1="agent1",
            agent2="agent2",
        )
        self.assertEqual(ret, 0)

        controls_dir = self.workspace / "controls"
        self.assertTrue(controls_dir.is_dir())
        self.assertTrue((self.workspace / "AGENTS.md").is_file())
        self.assertTrue((self.workspace / "evidence" / "tasks").is_dir())

        # Verify permissions at rest
        controls_stat = controls_dir.stat()
        self.assertEqual(oct(controls_stat.st_mode)[-3:], "555")

        state_file = controls_dir / "ACTIVE_STATE.json"
        self.assertEqual(oct(state_file.stat().st_mode)[-3:], "444")

        # Verify bootstrap lock unlinked
        self.assertFalse((self.workspace / ".stagecheck-init.lock").exists())

    def test_init_rejects_already_initialized_without_force(self) -> None:
        """Verify reinit halt when workspace is already initialized."""
        # Initial run
        run_init(workspace=str(self.workspace), repos="payment-service", force=False, agent1="agent1", agent2="agent2")

        # Second run without force
        ret = run_init(workspace=str(self.workspace), repos="payment-service", force=False, agent1="agent1", agent2="agent2")
        self.assertEqual(ret, 1)

    def test_init_with_force_preserves_dispositions(self) -> None:
        """Verify reinit with --force succeeds and preserves prior dispositions."""
        run_init(workspace=str(self.workspace), repos="payment-service", force=False, agent1="agent1", agent2="agent2")

        # Add a custom disposition waiver
        disp_file = self.workspace / "controls" / "DISPOSITIONS.json"
        elevate_permissions_for_teardown(self.workspace)
        disp_file.write_text('{"schema_version": "2.0", "dispositions": [{"defect_id": "PRESERVED"}]}', encoding="utf-8")

        # Reinit with force
        ret = run_init(workspace=str(self.workspace), repos="payment-service", force=True, agent1="agent1", agent2="agent2")
        self.assertEqual(ret, 0)

        # Check disposition preserved
        elevate_permissions_for_teardown(self.workspace)
        content = disp_file.read_text(encoding="utf-8")
        self.assertIn("PRESERVED", content)

    def test_init_halts_on_missing_repo(self) -> None:
        """Verify halt when declared target repo does not exist."""
        ret = run_init(
            workspace=str(self.workspace),
            repos="nonexistent-repo",
            force=False,
            agent1="agent1",
            agent2="agent2",
        )
        self.assertEqual(ret, 1)

    def test_init_bootstrap_lock_collision(self) -> None:
        """Verify lock collision handling when bootstrap lock is held by another process."""
        lock_path = self.workspace / ".stagecheck-init.lock"
        fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

        try:
            ret = run_init(workspace=str(self.workspace), repos="payment-service", agent1="agent1", agent2="agent2")
            self.assertEqual(ret, 1)
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
            lock_path.unlink(missing_ok=True)

    def test_controlled_write_transaction_protocol(self) -> None:
        """Verify controlled_write_transaction elevates and restores modes."""
        test_dir = self.workspace / "test_ctrl"
        test_dir.mkdir()
        test_file = test_dir / "target.json"
        test_file.write_text('{"a": 1}', encoding="utf-8")
        os.chmod(str(test_file), 0o444)
        os.chmod(str(test_dir), 0o555)

        with controlled_write_transaction(test_dir):
            # Directory should now be writable (0755)
            self.assertEqual(oct(test_dir.stat().st_mode)[-3:], "755")
            # Overwrite file
            test_file.write_text('{"a": 2}', encoding="utf-8")

        # After context manager, directory must be 0555 and file 0444
        self.assertEqual(oct(test_dir.stat().st_mode)[-3:], "555")
        self.assertEqual(oct(test_file.stat().st_mode)[-3:], "444")

    def test_init_cli_reinit_flag(self) -> None:
        """Verify CLI parser accepts --reinit as alias for --force."""
        from stagecheck.cli.main import main
        ret1 = main(["init", "--workspace", str(self.workspace), "--repos", "payment-service", "--agent1", "agent1", "--agent2", "agent2"])
        self.assertEqual(ret1, 0)
        # Calling again with --reinit must succeed
        ret2 = main(["init", "--workspace", str(self.workspace), "--repos", "payment-service", "--reinit", "--agent1", "agent1", "--agent2", "agent2"])
        self.assertEqual(ret2, 0)


if __name__ == "__main__":
    unittest.main()
