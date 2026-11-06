"""Unit and Integration Tests for Controls Registry & Descriptor Schemas (FR-08 / Spec 05).

Verifies the 8 mandatory workspace controls, schema validation for each JSON control,
non-empty check for Markdown controls, and symlink rejection.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from stagecheck.core.controls import (
    MANDATORY_CONTROLS,
    ControlsRegistryError,
    ControlsSecurityError,
    MissingControlError,
    get_mandatory_controls,
    validate_controls_registry,
)
from stagecheck.core.git import RepoBaseline
from stagecheck.core.scaffold import scaffold_controls_atomic
from stagecheck.schemas.validator import validate_control_descriptor


class TestControlsRegistry(unittest.TestCase):
    """Test suite for the 8 mandatory controls and schema enforcement."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp_dir.name).resolve()

        # Mock repository baseline
        self.baselines = {
            "app": RepoBaseline(
                name="app",
                rel_path="repos/app",
                abs_path=self.workspace / "repos" / "app",
                git_dir=self.workspace / "repos" / "app" / ".git",
                head_commit="b" * 40,
                branch="main",
                is_dirty=False,
                is_unborn=False,
                is_worktree=False,
            )
        }

        # Scaffold initial 8 controls
        scaffold_controls_atomic(
            workspace_root=self.workspace,
            baselines=self.baselines,
            manifest_sha256="0" * 64,
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_get_mandatory_controls_returns_all_eight(self) -> None:
        """Verify get_mandatory_controls returns exactly the 8 mandatory control filenames."""
        controls = get_mandatory_controls()
        self.assertEqual(len(controls), 8)
        self.assertIn("STAGECHECK_ROOT.json", controls)
        self.assertIn("EVIDENCE_ROOT.json", controls)
        self.assertIn("PRODUCT_REPOSITORIES.json", controls)
        self.assertIn("QUALIFICATION_ROOT.json", controls)
        self.assertIn("ACTIVE_STATE.json", controls)
        self.assertIn("OWNER_GRANTS.md", controls)
        self.assertIn("FAILURE_PREVENTION.md", controls)
        self.assertIn("DISPOSITIONS.json", controls)

    def test_validate_controls_registry_passes_on_valid_workspace(self) -> None:
        """Verify validate_controls_registry passes when all 8 controls are valid."""
        res = validate_controls_registry(self.workspace, strict=True)
        self.assertTrue(res["valid"])
        self.assertEqual(len(res["validated"]), 8)
        self.assertEqual(len(res["missing"]), 0)

    def test_missing_control_file_fails_closed(self) -> None:
        """Verify missing control descriptor raises MissingControlError."""
        controls_dir = self.workspace / "controls"
        os.chmod(controls_dir, 0o755)
        (controls_dir / "DISPOSITIONS.json").unlink()
        os.chmod(controls_dir, 0o555)

        with self.assertRaises(MissingControlError):
            validate_controls_registry(self.workspace, strict=True)

        res = validate_controls_registry(self.workspace, strict=False)
        self.assertFalse(res["valid"])
        self.assertIn("DISPOSITIONS.json", res["missing"])

    def test_corrupted_json_control_fails_closed(self) -> None:
        """Verify malformed JSON in a control file raises ControlsRegistryError."""
        controls_dir = self.workspace / "controls"
        os.chmod(controls_dir, 0o755)
        state_file = controls_dir / "ACTIVE_STATE.json"
        os.chmod(state_file, 0o644)
        state_file.write_text("NOT_VALID_JSON{", encoding="utf-8")
        os.chmod(state_file, 0o444)
        os.chmod(controls_dir, 0o555)

        with self.assertRaises(ControlsRegistryError):
            validate_controls_registry(self.workspace, strict=True)

    def test_schema_invalid_control_fails_closed(self) -> None:
        """Verify schema violation in a control file raises ControlsRegistryError."""
        controls_dir = self.workspace / "controls"
        os.chmod(controls_dir, 0o755)
        state_file = controls_dir / "ACTIVE_STATE.json"
        os.chmod(state_file, 0o644)
        # Violate schema: attempt_index must be >= 1, not 0
        state_file.write_text(json.dumps({
            "schema_version": "2.0",
            "task_id": "task-test",
            "phase": "NOT_STARTED",
            "attempt_index": 0,
            "repair_index": 0,
            "max_total_attempts": 3,
            "max_repairs": 2,
            "circuit_breaker_tripped": False,
            "single_agent_mode": False,
            "target_repositories": ["app"],
            "registered_agents": []
        }), encoding="utf-8")
        os.chmod(state_file, 0o444)
        os.chmod(controls_dir, 0o555)

        with self.assertRaises(ControlsRegistryError):
            validate_controls_registry(self.workspace, strict=True)

    def test_dispositions_schema_validation_with_entries(self) -> None:
        """Verify DISPOSITIONS.json with multiple valid entries passes schema validation."""
        controls_dir = self.workspace / "controls"
        os.chmod(controls_dir, 0o755)
        disp_file = controls_dir / "DISPOSITIONS.json"
        os.chmod(disp_file, 0o644)
        disp_content = {
            "schema_version": "2.0",
            "dispositions": [
                {
                    "disposition_id": "DSP-001",
                    "task_id": "task-101",
                    "defect_id": "scope.extra_file",
                    "action": "ACCEPT_AS_INTENTIONAL",
                    "rationale": "Required for RFC-10",
                    "authorized_by": "lead@company.com",
                    "authorized_at": "2026-11-06T12:00:00Z"
                }
            ]
        }
        disp_file.write_text(json.dumps(disp_content), encoding="utf-8")
        os.chmod(disp_file, 0o444)
        os.chmod(controls_dir, 0o555)

        res = validate_controls_registry(self.workspace, strict=True)
        self.assertTrue(res["valid"])

    def test_symlink_in_controls_fails_closed(self) -> None:
        """Verify symbolic links in controls directory fail closed."""
        controls_dir = self.workspace / "controls"
        os.chmod(controls_dir, 0o755)
        target_file = self.workspace / "outside_control.md"
        target_file.write_text("# Outside\n", encoding="utf-8")
        (controls_dir / "OWNER_GRANTS.md").unlink()
        (controls_dir / "OWNER_GRANTS.md").symlink_to(target_file)
        os.chmod(controls_dir, 0o555)

        with self.assertRaises(ControlsSecurityError):
            validate_controls_registry(self.workspace, strict=True)


if __name__ == "__main__":
    unittest.main()

