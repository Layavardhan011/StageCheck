"""Unit Tests for Atomic Runtime and Bootstrap Locking (SEC-05 / SR-06 / DEC-019)."""

from __future__ import annotations

import os
import stat
import tempfile
import unittest
from pathlib import Path

from stagecheck.core.locking import (
    LockCollisionError,
    acquire_bootstrap_lock,
    acquire_runtime_lock,
)


class TestLockingPrimitives(unittest.TestCase):
    """Test suite verifying atomic runtime lock acquisition, root placement, and collision handling."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp_dir.name).resolve()
        self.controls_dir = self.workspace / "controls"
        self.controls_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_atomic_root_lock_acquisition(self) -> None:
        """Verify atomic runtime lock acquisition at workspace root with mode 0600 (DEC-019 / SR-06)."""
        lock_path = self.workspace / ".stagecheck.lock"

        # 1. Acquire runtime lock passing controls_dir
        with acquire_runtime_lock(self.controls_dir) as fd:
            self.assertGreater(fd, 0)
            # Must be created at workspace root, not inside controls/
            self.assertTrue(lock_path.is_file())
            self.assertFalse((self.controls_dir / ".stagecheck.lock").exists())

            # Verify mode 0600
            file_mode = stat.S_IMODE(lock_path.stat().st_mode)
            self.assertEqual(file_mode, 0o600)

            # 2. Concurrency collision: another acquisition attempts to lock while held
            with self.assertRaises(LockCollisionError):
                with acquire_runtime_lock(self.workspace):
                    pass

        # 3. After release, lock can be acquired again (passing workspace root)
        with acquire_runtime_lock(self.workspace) as fd2:
            self.assertGreater(fd2, 0)

    def test_bootstrap_lock_lifecycle(self) -> None:
        """Verify bootstrap lock lifecycle and collision prevention during initialization."""
        init_lock = self.workspace / ".stagecheck-init.lock"

        with acquire_bootstrap_lock(self.workspace) as fd:
            self.assertGreater(fd, 0)
            self.assertTrue(init_lock.is_file())

            # Concurrent bootstrap attempt fails with LockCollisionError
            with self.assertRaises(LockCollisionError):
                with acquire_bootstrap_lock(self.workspace):
                    pass

        # After clean release, bootstrap lock file is unlinked
        self.assertFalse(init_lock.exists())


if __name__ == "__main__":
    unittest.main()

