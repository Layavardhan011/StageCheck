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

    def test_init_idempotent_reconciliation_without_force(self) -> None:
        """Verify repeated init succeeds and performs idempotent reconciliation with zero content mutation (FR-08)."""
        from stagecheck.core.utils import sha256_file

        # 1. Initial run
        ret1 = run_init(
            workspace=str(self.workspace),
            repos="payment-service",
            force=False,
            agent1="agent1",
            agent2="agent2",
        )
        self.assertEqual(ret1, 0)

        # Record hashes of all generated files
        specs_dir = self.workspace / "specs"
        self.assertTrue((specs_dir / "TASK_PLAN.json").is_file())
        self.assertTrue((specs_dir / "ARCHITECTURE.md").is_file())
        self.assertTrue((specs_dir / "START_MANIFEST.md").is_file())

        controls_dir = self.workspace / "controls"
        ctrl_hashes_before = {f.name: sha256_file(f) for f in controls_dir.iterdir() if f.is_file()}
        specs_hashes_before = {f.name: sha256_file(f) for f in specs_dir.iterdir() if f.is_file()}

        # 2. Second run without force must succeed (idempotent self-healing)
        ret2 = run_init(
            workspace=str(self.workspace),
            repos="payment-service",
            force=False,
            agent1="agent1",
            agent2="agent2",
        )
        self.assertEqual(ret2, 0)

        # Assert zero content mutation on repeated run
        ctrl_hashes_after = {f.name: sha256_file(f) for f in controls_dir.iterdir() if f.is_file()}
        specs_hashes_after = {f.name: sha256_file(f) for f in specs_dir.iterdir() if f.is_file()}

        self.assertEqual(ctrl_hashes_before, ctrl_hashes_after)
        self.assertEqual(specs_hashes_before, specs_hashes_after)

    def test_init_partial_reconciliation_preserves_customizations(self) -> None:
        """Verify partial workspaces reconcile missing files while preserving user edits (Spec 05)."""
        # Run init initially
        run_init(workspace=str(self.workspace), repos="payment-service", force=False, agent1="agent1", agent2="agent2")

        # User customizes specs/TASK_PLAN.json and deletes ARCHITECTURE.md and START_MANIFEST.md
        specs_dir = self.workspace / "specs"
        custom_content = '{"custom": "user_plan_v2"}'
        (specs_dir / "TASK_PLAN.json").write_text(custom_content, encoding="utf-8")
        (specs_dir / "ARCHITECTURE.md").unlink()
        (specs_dir / "START_MANIFEST.md").unlink()

        # Re-run init without force
        ret = run_init(workspace=str(self.workspace), repos="payment-service", force=False, agent1="agent1", agent2="agent2")
        self.assertEqual(ret, 0)

        # Missing files were recreated
        self.assertTrue((specs_dir / "ARCHITECTURE.md").is_file())
        self.assertTrue((specs_dir / "START_MANIFEST.md").is_file())

        # User customization was preserved verbatim
        self.assertEqual((specs_dir / "TASK_PLAN.json").read_text(encoding="utf-8"), custom_content)

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
