"""Unit Tests for Atomic Generation of the 8 Workspace Controls (P2-T3)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from stagecheck.core.git import RepoBaseline
from stagecheck.core.scaffold import (
    ScaffoldingRollbackError,
    scaffold_controls_atomic,
)
from stagecheck.core.utils import load_json_file
from stagecheck.schemas.validator import validate_control_descriptor


class TestAtomicScaffolding(unittest.TestCase):
    """Test suite verifying atomic generation, schema compliance, and rollback safety."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp_dir.name).resolve()

        # Mock repository baseline
        self.baselines = {
            "payment-service": RepoBaseline(
                name="payment-service",
                rel_path="repos/payment-service",
                abs_path=self.workspace / "repos" / "payment-service",
                git_dir=self.workspace / "repos" / "payment-service" / ".git",
                head_commit="1" * 40,
                branch="main",
                is_dirty=False,
                is_unborn=False,
                is_worktree=False,
            ),
            "ledger-api": RepoBaseline(
                name="ledger-api",
                rel_path="repos/ledger-api",
                abs_path=self.workspace / "repos" / "ledger-api",
                git_dir=self.workspace / "repos" / "ledger-api" / ".git",
                head_commit="2" * 40,
                branch="release/v2",
                is_dirty=False,
                is_unborn=False,
                is_worktree=False,
            ),
        }

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_scaffold_all_eight_controls_success(self) -> None:
        """Verify atomic generation of all 8 mandatory control files."""
        expected_controls = [
            "STAGECHECK_ROOT.json",
            "EVIDENCE_ROOT.json",
            "PRODUCT_REPOSITORIES.json",
            "QUALIFICATION_ROOT.json",
            "ACTIVE_STATE.json",
            "OWNER_GRANTS.md",
            "FAILURE_PREVENTION.md",
            "DISPOSITIONS.json",
        ]

        paths = scaffold_controls_atomic(
            workspace_root=self.workspace,
            baselines=self.baselines,
            manifest_sha256="f" * 64,
        )

        # 1. Assert all 8 returned paths exist on disk
        self.assertEqual(len(paths), 8)
        controls_dir = self.workspace / "controls"
        self.assertTrue(controls_dir.is_dir())

        for name in expected_controls:
            self.assertIn(name, paths)
            file_path = controls_dir / name
            self.assertTrue(file_path.is_file(), f"Missing control file: {name}")

            # 2. Assert all JSON descriptors validate against their schemas
            if name.endswith(".json"):
                data = load_json_file(file_path)
                validate_control_descriptor(name, data)

    def test_scaffold_rollback_on_injected_fault(self) -> None:
        """Verify transactional rollback when a failure occurs during generation."""
        def inject_fault(filename: str) -> None:
            if filename == "ACTIVE_STATE.json":
                raise RuntimeError("Simulated crash during ACTIVE_STATE generation")

        with self.assertRaises(ScaffoldingRollbackError):
            scaffold_controls_atomic(
                workspace_root=self.workspace,
                baselines=self.baselines,
                fault_injector=inject_fault,
            )

        # Verify rollback: controls directory should either not exist or be empty
        controls_dir = self.workspace / "controls"
        if controls_dir.exists():
            remaining_files = list(controls_dir.iterdir())
            self.assertEqual(
                len(remaining_files),
                0,
                f"Rollback failed: partial files remaining in controls/: {remaining_files}",
            )


if __name__ == "__main__":
    unittest.main()

