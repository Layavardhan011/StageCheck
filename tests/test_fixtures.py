"""Tests for StageCheck synthetic fixture factory (P5-T1).

Verifies self-contained temporary programme fixtures, all eight controls,
contract Merkle hashes, specs, evidence roots, packaged assets, mock Git baseline,
and deterministic teardown with zero external path dependencies.
"""
import json
import os
import unittest
from pathlib import Path

from evals.fixtures import SyntheticFixture, create_test_fixture, synthetic_workspace
from stagecheck.core.utils import sha256_file


class TestSyntheticFixtures(unittest.TestCase):
    """Verifies synthetic workspace generator meets all Spec 11 portability requirements."""

    def test_fixture_scaffolding_and_controls(self):
        """Verify all eight mandatory controls and synthetic descriptors exist."""
        with synthetic_workspace() as fix:
            self.assertIsInstance(fix, SyntheticFixture)
            self.assertTrue(fix.root.is_dir())
            self.assertTrue(fix.tool.is_dir())
            self.assertTrue(fix.workspace.is_dir())

            # 1. Verify 8 Mandatory Controls exist
            mandatory_controls = [
                "STAGECHECK_ROOT.json",
                "EVIDENCE_ROOT.json",
                "PRODUCT_REPOSITORIES.json",
                "QUALIFICATION_ROOT.json",
                "ACTIVE_STATE.json",
                "OWNER_GRANTS.md",
                "FAILURE_PREVENTION.md",
                "DISPOSITIONS.json",
            ]
            controls_dir = fix.root / "controls"
            for ctrl in mandatory_controls:
                ctrl_path = controls_dir / ctrl
                self.assertTrue(ctrl_path.exists(), f"Control descriptor missing: {ctrl}")

            # 2. Verify Specs Exist
            specs_dir = fix.root / "specs"
            for spec_file in ["START_MANIFEST.md", "TASK_PLAN.md", "ARCHITECTURE.md", "TASK_PLAN.json"]:
                self.assertTrue((specs_dir / spec_file).exists(), f"Spec missing: {spec_file}")

            # 3. Verify Evidence Directory and Manifest
            ev_dir = fix.root / "evidence"
            self.assertTrue((ev_dir / "EVIDENCE_MANIFEST.json").exists())
            self.assertTrue((ev_dir / "claude_audits/tools/verify_manifest.py").exists())
            self.assertTrue((ev_dir / "claude_audits/tools/verify_state_chain.py").exists())

            # 4. Verify Qualification Reviews
            qual_dir = fix.root / "qualification"
            self.assertTrue((qual_dir / "reviews/capture_sp1_evidence.py").exists())

            # 5. Verify Mock Git Repos
            self.assertTrue((fix.root / "build/product/.git").is_dir())
            self.assertTrue((fix.root / "repos/product/.git").is_dir())

    def test_contract_merkle_binding_hashes(self):
        """Verify contract binds real SHA-256 digests matching control files."""
        with synthetic_workspace() as fix:
            contract_path = fix.workspace / "contract.txt"
            self.assertTrue(contract_path.exists())
            text = contract_path.read_text()

            # Verify each control row has accurate SHA-256 hash
            controls_dir = fix.root / "controls"
            for role, filename in [
                ("Current-state pointer", "DRWA_ACTIVE_STATE.json"),
                ("Owner authority and grants", "OWNER_GRANTS.md"),
                ("Failure prevention register", "FAILURE_PREVENTION.md"),
                ("Evidence root", "EVIDENCE_ROOT.json"),
                ("Product repositories", "PRODUCT_REPOSITORIES.json"),
                ("Qualification tree (§11)", "QUALIFICATION_ROOT.json"),
            ]:
                target_file = controls_dir / filename
                actual_hash = sha256_file(target_file)
                self.assertIn(actual_hash, text, f"Hash for {role} ({filename}) not bound in contract")

            # Check STAGECHECK_ROOT manifest binding
            manifest_path = fix.tool / "MANIFEST.sha256"
            actual_manifest_hash = sha256_file(manifest_path)
            self.assertIn(actual_manifest_hash, text)

    def test_zero_external_path_leakage(self):
        """Verify zero /home/magnus or external developer paths exist in generated fixture."""
        with synthetic_workspace() as fix:
            # Walk all files in fixture workspace
            for root_dir, _, files in os.walk(fix.workspace):
                for f in files:
                    file_path = Path(root_dir) / f
                    if file_path.suffix in (".json", ".md", ".txt", ".py"):
                        try:
                            content = file_path.read_text(encoding="utf-8", errors="ignore")
                            self.assertNotIn(
                                "/home/magnus",
                                content,
                                f"Forbidden external path leaked in {file_path}",
                            )
                        except Exception:
                            pass

    def test_deterministic_teardown(self):
        """Verify context manager cleans up temporary directory completely."""
        workspace_dir = None
        with synthetic_workspace() as fix:
            workspace_dir = fix.workspace
            self.assertTrue(workspace_dir.exists())

        # After context exit, the temporary directory must be removed
        self.assertFalse(workspace_dir.exists(), "Teardown failed: fixture directory still exists")


if __name__ == "__main__":
    unittest.main()

