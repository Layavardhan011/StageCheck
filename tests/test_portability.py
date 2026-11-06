"""Tests for StageCheck portability and hardcoded path decoupling (P5-T2).

Verifies automated scanning blocks prohibited paths (/home/magnus, /Users/*, C:\\*)
and dual-mode asset resolution works correctly across installed and vendored roots.
"""
import tempfile
import unittest
from pathlib import Path

from stagecheck.core.portability import (
    audit_portability,
    resolve_asset_path,
    validate_environment_portability,
)


class TestPortability(unittest.TestCase):
    """Verifies Spec 11 portability invariants and automated audit scanning."""

    def test_codebase_portability_cleanliness(self):
        """Verify the current repository has ZERO prohibited path leaks in code/configs."""
        repo_root = Path(__file__).resolve().parents[1]
        findings = audit_portability(repo_root=repo_root, include_docs=False)
        self.assertEqual(
            findings,
            [],
            f"Prohibited machine-specific paths detected in codebase: {findings}",
        )

    def test_audit_portability_detection(self):
        """Verify audit scanner accurately detects and blocks prohibited paths."""
        with tempfile.TemporaryDirectory() as td:
            temp_path = Path(td)
            bad_file = temp_path / "bad_script.py"
            bad_file.write_text(
                "# Header\n"
                "p1 = '/home/magnus/Desktop/repo'\n"
                "p2 = 'C:\\\\Users\\\\developer\\\\workspace'\n"
                "p3 = '/Users/alice/projects'\n"
                "clean = 'relative/path/ok'\n"
            )

            findings = audit_portability(search_root=temp_path)
            self.assertEqual(len(findings), 3)

            lines = {f["line"] for f in findings}
            self.assertEqual(lines, {2, 3, 4})

    def test_dual_mode_asset_resolution(self):
        """Verify asset resolver successfully locates schemas, configs, instructions, and scanner assets."""
        # 1. Resolve all 14 schema assets
        schema_names = [
            "active_state.schema.json",
            "claims.schema.json",
            "control_descriptors.schema.json",
            "declared_scope.schema.json",
            "gate_receipt.schema.json",
            "pre_commit_review.schema.json",
            "pre_commit_status.schema.json",
            "product_repositories.schema.json",
            "prompt_verified.schema.json",
            "quality_record.schema.json",
            "rubric_evaluation.schema.json",
            "task_plan.schema.json",
            "turn_status.schema.json",
            "verdict.schema.json",
        ]
        for s_name in schema_names:
            with self.subTest(schema=s_name):
                p = resolve_asset_path(f"schemas/assets/{s_name}")
                self.assertTrue(p.is_file(), f"Schema asset '{s_name}' not resolved.")

        # 2. Resolve all default configuration assets
        config_names = [
            "agents.json",
            "commands.json",
            "controlled_vocabulary.json",
            "depth.json",
            "modes.json",
            "paths.json",
            "quality_targets.json",
            "remotes.json",
            "required_outcomes.json",
            "response_hook.json",
        ]
        for c_name in config_names:
            with self.subTest(config=c_name):
                p = resolve_asset_path(f"config/defaults/{c_name}")
                self.assertTrue(p.is_file(), f"Config default asset '{c_name}' not resolved.")

        # 3. Resolve gitleaks security configuration
        gitleaks_path = resolve_asset_path("config/.gitleaks.toml")
        self.assertTrue(gitleaks_path.is_file())

        # 4. Resolve agent instructions
        instruction_names = [
            "00_common.md",
            "blast_radius.md",
            "claim_support.md",
            "eval_curator.md",
            "failure_class.md",
            "independent_rerun.md",
            "orchestrator.md",
            "test_adequacy.md",
            "upstream_reuse.md",
        ]
        for inst_name in instruction_names:
            with self.subTest(instruction=inst_name):
                p = resolve_asset_path(f"agent_instructions/{inst_name}")
                self.assertTrue(p.is_file(), f"Instruction asset '{inst_name}' not resolved.")

        # 5. Non-existent asset raises FileNotFoundError
        with self.assertRaises(FileNotFoundError):
            resolve_asset_path("nonexistent/missing_file.xyz")

    def test_packaged_wheel_integrity(self):
        """Verify built wheel package contains all required assets, entry points, and schemas."""
        import zipfile
        repo_root = Path(__file__).resolve().parents[1]
        wheel_files = sorted((repo_root / "dist").glob("stagecheck-2.*.whl"), key=lambda p: p.stat().st_mtime)
        if not wheel_files:
            self.skipTest("No v2 wheel found in dist/ directory to inspect.")

        wheel_path = wheel_files[-1]
        with zipfile.ZipFile(wheel_path, "r") as zf:
            namelist = set(zf.namelist())

            # Check CLI entry point definition
            self.assertTrue(
                any("entry_points.txt" in n for n in namelist),
                "Wheel missing entry_points.txt",
            )

            # Check metadata
            self.assertTrue(
                any("METADATA" in n for n in namelist),
                "Wheel missing METADATA",
            )

            # Check core package modules
            self.assertIn("stagecheck/cli/main.py", namelist)
            self.assertIn("stagecheck/core/gate_engine.py", namelist)
            self.assertIn("stagecheck/core/sealing.py", namelist)
            self.assertIn("stagecheck/core/sentinel.py", namelist)

            # Check packaged schemas and configurations
            self.assertIn("stagecheck/schemas/assets/active_state.schema.json", namelist)
            self.assertIn("stagecheck/config/.gitleaks.toml", namelist)
            self.assertIn("stagecheck/config/defaults/agents.json", namelist)
            self.assertIn("stagecheck/agent_instructions/00_common.md", namelist)

    def test_environment_portability(self):
        """Verify environment portability validation reports Linux capabilities."""
        env = validate_environment_portability()
        self.assertIn("platform", env)
        self.assertIn("is_linux", env)
        self.assertIn("has_flock", env)


if __name__ == "__main__":
    unittest.main()

