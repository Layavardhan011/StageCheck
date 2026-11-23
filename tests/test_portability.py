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

    def test_executable_permissions_and_zip_mode_preservation(self):
        """Verify 100755 executable bits on wrapper scripts/gitleaks, restoration, and ZIP external_attr preservation (GAP-02)."""
        import os
        import stat
        import subprocess
        import tempfile
        import zipfile
        from stagecheck.core.portability import (
            EXECUTABLE_REPO_PATHS,
            create_source_zip_preserving_modes,
            extract_zip_preserving_modes,
            restore_executable_permissions,
            verify_executable_permissions,
        )

        repo_root = Path(__file__).resolve().parent.parent

        # 1. Verify disk permissions (0o755)
        res = verify_executable_permissions(repo_root)
        self.assertTrue(res["ok"], f"Expected executable permissions 0o755 on repo scripts: {res}")
        for rel in EXECUTABLE_REPO_PATHS:
            mode = stat.S_IMODE((repo_root / rel).stat().st_mode)
            self.assertEqual(mode, 0o755, f"Expected 0o755 on {rel}, got {oct(mode)}")

        # 2. Verify Git index records 100755 for all required executables
        ls_out = subprocess.run(
            ["git", "ls-files", "-s", *EXECUTABLE_REPO_PATHS],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            check=True,
        ).stdout.splitlines()
        self.assertEqual(len(ls_out), len(EXECUTABLE_REPO_PATHS))
        for line in ls_out:
            self.assertTrue(line.startswith("100755 "), f"Git index entry missing 100755 mode: {line}")

        # 3. Verify ZIP archive creation and extraction preserve 0o755 modes and recovery restores stripped bits
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            pkg_zip = tmp_path / "dist_scripts.zip"
            create_source_zip_preserving_modes(repo_root, pkg_zip, rel_files=list(EXECUTABLE_REPO_PATHS))
            out_dir = tmp_path / "extracted"
            extract_zip_preserving_modes(pkg_zip, out_dir)
            extracted_check = verify_executable_permissions(out_dir)
            self.assertTrue(extracted_check["ok"], f"ZIP extraction dropped executable bits: {extracted_check}")
            for rel in EXECUTABLE_REPO_PATHS:
                mode = stat.S_IMODE((out_dir / rel).stat().st_mode)
                self.assertEqual(mode, 0o755)

            # Strip execute bit on temp copy and verify fail-closed detection + restore_executable_permissions
            stripped = out_dir / "bin" / "stagecheck.sh"
            os.chmod(stripped, 0o644)
            bad_check = verify_executable_permissions(out_dir)
            self.assertFalse(bad_check["ok"])
            self.assertIn("bin/stagecheck.sh", bad_check["non_executable"])

            repaired = restore_executable_permissions(out_dir)
            self.assertTrue(repaired["ok"])
            self.assertEqual(stat.S_IMODE(stripped.stat().st_mode), 0o755)

            # Fail closed when ZIP lacks POSIX executable external_attr
            broken_zip = tmp_path / "broken.zip"
            with zipfile.ZipFile(broken_zip, "w") as zf:
                zf.writestr("bin/stagecheck.sh", "#!/bin/sh\necho hi\n")
            with self.assertRaises(PermissionError):
                extract_zip_preserving_modes(broken_zip, tmp_path / "broken_out")


if __name__ == "__main__":
    unittest.main()

