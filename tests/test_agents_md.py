"""Unit Tests for AGENTS.md Binding Contract Renderer (P2-T4)."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from stagecheck.core.agents_md import (
    AgentsContractNotFoundError,
    AgentsContractSecurityError,
    AgentsContractVerificationError,
    parse_agents_contract_table,
    render_agents_contract,
    verify_agents_contract,
    write_agents_contract,
)
from stagecheck.core.git import RepoBaseline
from stagecheck.core.scaffold import scaffold_controls_atomic
from stagecheck.core.utils import sha256_file


class TestAgentsContract(unittest.TestCase):
    """Test suite verifying AGENTS.md rendering, hash accuracy, and role constraints."""

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
                head_commit="a" * 40,
                branch="main",
                is_dirty=False,
                is_unborn=False,
                is_worktree=False,
            )
        }

        # Scaffold controls
        scaffold_controls_atomic(
            workspace_root=self.workspace,
            baselines=self.baselines,
            manifest_sha256="e" * 64,
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_render_agents_contract_hashes_match_descriptors(self) -> None:
        """Verify that hashes embedded in AGENTS.md match real descriptor hashes on disk."""
        controls_dir = self.workspace / "controls"
        contract_text = render_agents_contract(controls_dir)

        # Verify each of the 8 control hashes is present in the rendered text
        for filename in [
            "STAGECHECK_ROOT.json",
            "EVIDENCE_ROOT.json",
            "PRODUCT_REPOSITORIES.json",
            "QUALIFICATION_ROOT.json",
            "ACTIVE_STATE.json",
            "OWNER_GRANTS.md",
            "FAILURE_PREVENTION.md",
            "DISPOSITIONS.json",
        ]:
            expected_hash = sha256_file(controls_dir / filename)
            self.assertIn(expected_hash, contract_text, f"Hash for {filename} missing in AGENTS.md")

    def test_deterministic_rendering(self) -> None:
        """Verify that rendering twice produces identical string output."""
        controls_dir = self.workspace / "controls"
        render1 = render_agents_contract(controls_dir)
        render2 = render_agents_contract(controls_dir)
        self.assertEqual(render1, render2)

    def test_write_agents_contract_creates_file(self) -> None:
        """Verify write_agents_contract writes AGENTS.md at workspace root."""
        written_path = write_agents_contract(self.workspace)
        self.assertEqual(written_path, self.workspace / "AGENTS.md")
        self.assertTrue(written_path.is_file())

        content = written_path.read_text(encoding="utf-8")
        # Assert roles and constraints
        self.assertIn("prompt_and_audit", content)
        self.assertIn("code_implementation", content)
        self.assertIn("Zero Remote Pushes", content)
        self.assertIn("Direct commits to `main` or `master` branches are strictly prohibited", content)
        self.assertIn("Advisory Workspace Locking", content)
        self.assertIn("Attempt Budget & Circuit Breaker", content)

    def test_render_missing_control_raises_error(self) -> None:
        """Verify FileNotFoundError if a mandatory control file is missing."""
        controls_dir = self.workspace / "controls"
        # Delete one control file
        (controls_dir / "DISPOSITIONS.json").unlink()

        with self.assertRaises(FileNotFoundError):
            render_agents_contract(controls_dir)


    def test_verify_agents_contract_valid_workspace(self) -> None:
        """Verify that verify_agents_contract succeeds when all 8 controls match."""
        write_agents_contract(self.workspace)
        result = verify_agents_contract(self.workspace, strict=True, include_active_state=True)
        self.assertTrue(result["valid"])
        self.assertEqual(len(result["verified"]), 8)
        self.assertEqual(len(result["missing"]), 0)
        self.assertEqual(len(result["mismatches"]), 0)

    def test_verify_agents_contract_detects_tampered_control(self) -> None:
        """Verify tamper detection when a control descriptor is modified out-of-band."""
        write_agents_contract(self.workspace)

        # Tamper with OWNER_GRANTS.md
        grants_file = self.workspace / "controls" / "OWNER_GRANTS.md"
        # Temporarily make writable
        os.chmod(self.workspace / "controls", 0o755)
        os.chmod(grants_file, 0o644)
        grants_file.write_text("# Malicious Grants\ngit push allowed\n", encoding="utf-8")
        os.chmod(grants_file, 0o444)
        os.chmod(self.workspace / "controls", 0o555)

        result = verify_agents_contract(self.workspace, strict=False)
        self.assertFalse(result["valid"])
        self.assertEqual(len(result["mismatches"]), 1)
        self.assertEqual(result["mismatches"][0]["control"], "OWNER_GRANTS.md")

        with self.assertRaises(AgentsContractVerificationError):
            verify_agents_contract(self.workspace, strict=True)

    def test_verify_agents_contract_detects_missing_control(self) -> None:
        """Verify detection when a control file is deleted after AGENTS.md was written."""
        write_agents_contract(self.workspace)

        # Delete DISPOSITIONS.json
        disp_file = self.workspace / "controls" / "DISPOSITIONS.json"
        os.chmod(self.workspace / "controls", 0o755)
        disp_file.unlink()
        os.chmod(self.workspace / "controls", 0o555)

        result = verify_agents_contract(self.workspace, strict=False)
        self.assertFalse(result["valid"])
        self.assertIn("DISPOSITIONS.json", result["missing"])

    def test_verify_agents_contract_rejects_symlink(self) -> None:
        """Verify symbolic link AGENTS.md fails closed."""
        real_file = self.workspace / "real_contract.md"
        real_file.write_text("# Real\n", encoding="utf-8")
        symlink_contract = self.workspace / "AGENTS.md"
        symlink_contract.symlink_to(real_file)

        with self.assertRaises(AgentsContractSecurityError):
            verify_agents_contract(self.workspace)


if __name__ == "__main__":
    unittest.main()

