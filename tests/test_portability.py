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
        """Verify asset resolver successfully locates schemas and configuration defaults."""
        # 1. Resolve schema asset
        schema_path = resolve_asset_path("schemas/assets/declared_scope.schema.json")
        self.assertTrue(schema_path.is_file(), f"Schema asset not found: {schema_path}")
        self.assertTrue(schema_path.name.endswith(".schema.json"))

        # 2. Resolve default configuration asset
        config_path = resolve_asset_path("config/defaults/commands.json")
        self.assertTrue(config_path.is_file(), f"Config default asset not found: {config_path}")

        # 3. Non-existent asset raises FileNotFoundError
        with self.assertRaises(FileNotFoundError):
            resolve_asset_path("nonexistent/missing_file.xyz")

    def test_environment_portability(self):
        """Verify environment portability validation reports Linux capabilities."""
        env = validate_environment_portability()
        self.assertIn("platform", env)
        self.assertIn("is_linux", env)
        self.assertIn("has_flock", env)


if __name__ == "__main__":
    unittest.main()
