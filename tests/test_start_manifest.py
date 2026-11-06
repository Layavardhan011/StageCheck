"""Unit and Integration Tests for Specification Manifest Protocol (DEC-008 / FR-08 / Spec 05).

Verifies specs/START_MANIFEST.md generation, verification, authorized updates,
tamper detection, unregistered addition detection, and symlink protection.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path

from stagecheck.cli.main import main
from stagecheck.core.start_manifest import (
    START_MANIFEST_FILENAME,
    SpecManifestNotFoundError,
    SpecManifestSecurityError,
    SpecManifestVerificationError,
    generate_start_manifest,
    parse_start_manifest,
    update_spec_manifest,
    verify_spec_manifest,
)
from stagecheck.core.utils import sha256_file


class TestStartManifest(unittest.TestCase):
    """Test suite for specs/START_MANIFEST.md cryptographic governance."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp_dir.name).resolve()
        self.specs_dir = self.workspace / "specs"
        self.specs_dir.mkdir(parents=True, exist_ok=True)

        # Create standard specification files
        (self.specs_dir / "TASK_PLAN.json").write_text('{"schema_version": 1, "tasks": []}\n', encoding="utf-8")
        (self.specs_dir / "ARCHITECTURE.md").write_text("# System Architecture\nInterface definitions.\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_generate_start_manifest_creates_table_without_self_cycle(self) -> None:
        """Verify START_MANIFEST.md generation hashes all spec files but excludes itself."""
        manifest_path = generate_start_manifest(self.workspace)
        self.assertTrue(manifest_path.is_file())

        content = manifest_path.read_text(encoding="utf-8")
        self.assertIn("START_MANIFEST.md", content)
        self.assertIn("TASK_PLAN.json", content)
        self.assertIn("ARCHITECTURE.md", content)

        # Parse manifest and check hashes
        entries = parse_start_manifest(self.workspace)
        expected_task_hash = sha256_file(self.specs_dir / "TASK_PLAN.json")
        expected_arch_hash = sha256_file(self.specs_dir / "ARCHITECTURE.md")

        self.assertEqual(entries["TASK_PLAN.json"], expected_task_hash)
        self.assertEqual(entries["ARCHITECTURE.md"], expected_arch_hash)

        # Invariant: No self-hash cycle
        self.assertNotIn("START_MANIFEST.md", entries)

    def test_spec_integrity_verification(self) -> None:
        """DEC-008: Verify specification baseline integrity matches when untampered."""
        generate_start_manifest(self.workspace)
        result = verify_spec_manifest(self.workspace, strict=True)
        self.assertTrue(result["valid"])
        self.assertIn("TASK_PLAN.json", result["verified"])
        self.assertIn("ARCHITECTURE.md", result["verified"])
        self.assertEqual(len(result["missing"]), 0)
        self.assertEqual(len(result["tampered"]), 0)
        self.assertEqual(len(result["unregistered"]), 0)

    def test_verify_manifest_detects_tampered_file(self) -> None:
        """Verify tamper detection when a specification file is altered."""
        generate_start_manifest(self.workspace)

        # Tamper with ARCHITECTURE.md
        (self.specs_dir / "ARCHITECTURE.md").write_text("# Weakened Requirements\nBypassed.\n", encoding="utf-8")

        result = verify_spec_manifest(self.workspace, strict=False)
        self.assertFalse(result["valid"])
        self.assertEqual(len(result["tampered"]), 1)
        self.assertEqual(result["tampered"][0]["file"], "ARCHITECTURE.md")

        with self.assertRaises(SpecManifestVerificationError) as ctx:
            verify_spec_manifest(self.workspace, strict=True)
        self.assertIn("Tampered spec files", str(ctx.exception))

    def test_verify_manifest_detects_missing_file(self) -> None:
        """Verify detection when a registered specification file is deleted."""
        generate_start_manifest(self.workspace)

        # Delete TASK_PLAN.json
        (self.specs_dir / "TASK_PLAN.json").unlink()

        result = verify_spec_manifest(self.workspace, strict=False)
        self.assertFalse(result["valid"])
        self.assertIn("TASK_PLAN.json", result["missing"])

        with self.assertRaises(SpecManifestVerificationError):
            verify_spec_manifest(self.workspace, strict=True)

    def test_verify_manifest_detects_unregistered_addition(self) -> None:
        """Verify addition detection when an untracked specification file is added."""
        generate_start_manifest(self.workspace)

        # Add an unregistered spec file
        (self.specs_dir / "EXTRA_SPEC.md").write_text("# Secret Spec\n", encoding="utf-8")

        result = verify_spec_manifest(self.workspace, strict=False)
        self.assertFalse(result["valid"])
        self.assertIn("EXTRA_SPEC.md", result["unregistered"])

        with self.assertRaises(SpecManifestVerificationError) as ctx:
            verify_spec_manifest(self.workspace, strict=True)
        self.assertIn("Unregistered spec additions", str(ctx.exception))

    def test_update_spec_manifest_reconciles_changes(self) -> None:
        """Verify update-manifest recomputes digests and restores validity."""
        generate_start_manifest(self.workspace)

        # Modify spec and add another
        (self.specs_dir / "ARCHITECTURE.md").write_text("# Updated Architecture\nNew design.\n", encoding="utf-8")
        (self.specs_dir / "API_SPEC.json").write_text('{"version": "1.0"}\n', encoding="utf-8")

        # Before update: fails
        self.assertFalse(verify_spec_manifest(self.workspace)["valid"])

        # Execute update
        update_spec_manifest(self.workspace)

        # After update: passes
        result = verify_spec_manifest(self.workspace, strict=True)
        self.assertTrue(result["valid"])
        self.assertIn("API_SPEC.json", result["verified"])

    def test_symlink_in_specs_rejected_pre_resolution(self) -> None:
        """Verify symbolic links in specs directory fail closed."""
        target_file = self.workspace / "outside.txt"
        target_file.write_text("outside\n", encoding="utf-8")
        symlink_path = self.specs_dir / "symlinked_spec.md"
        symlink_path.symlink_to(target_file)

        with self.assertRaises(SpecManifestSecurityError):
            generate_start_manifest(self.workspace)

        with self.assertRaises(SpecManifestSecurityError):
            verify_spec_manifest(self.workspace)

    def test_cli_verify_and_update_manifest(self) -> None:
        """Verify CLI subcommands 'stagecheck verify-manifest' and 'stagecheck update-manifest'."""
        generate_start_manifest(self.workspace)

        # 1. verify-manifest returns 0
        ret_val = main(["verify-manifest", "--workspace", str(self.workspace)])
        self.assertEqual(ret_val, 0)

        # 2. Tamper file -> verify-manifest returns 1
        (self.specs_dir / "TASK_PLAN.json").write_text('{"tampered": true}\n', encoding="utf-8")
        ret_val_tampered = main(["verify-manifest", "--workspace", str(self.workspace)])
        self.assertEqual(ret_val_tampered, 1)

        # 3. update-manifest returns 0
        ret_val_update = main(["update-manifest", "--workspace", str(self.workspace)])
        self.assertEqual(ret_val_update, 0)

        # 4. verify-manifest returns 0 again
        ret_val_verified = main(["verify-manifest", "--workspace", str(self.workspace)])
        self.assertEqual(ret_val_verified, 0)


if __name__ == "__main__":
    unittest.main()

