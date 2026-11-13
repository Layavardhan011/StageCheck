"""Unit Tests for Atomic Generation of the 8 Workspace Controls (P2-T3)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from stagecheck.core.git import RepoBaseline
from stagecheck.core.scaffold import (
    ScaffoldingRollbackError,
    reconcile_controls,
    reconcile_specs_directory,
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

    def test_reconcile_specs_directory(self) -> None:
        """Verify reconcile_specs_directory creates missing files and preserves existing ones (Spec 05)."""
        specs_dir = self.workspace / "specs"
        specs_dir.mkdir(parents=True, exist_ok=True)

        # 1. Pre-create TASK_PLAN.json with custom content
        custom_plan = '{"custom_plan": true}'
        (specs_dir / "TASK_PLAN.json").write_text(custom_plan, encoding="utf-8")

        # 2. Reconcile specs
        paths = reconcile_specs_directory(self.workspace, target_repos=["payment-service"])
        self.assertIn("TASK_PLAN.json", paths)
        self.assertIn("ARCHITECTURE.md", paths)
        self.assertIn("START_MANIFEST.md", paths)

        # Custom plan preserved
        self.assertEqual((specs_dir / "TASK_PLAN.json").read_text(encoding="utf-8"), custom_plan)
        # Architecture template created
        self.assertTrue((specs_dir / "ARCHITECTURE.md").is_file())
        # START_MANIFEST.md created and hashes TASK_PLAN.json and ARCHITECTURE.md
        manifest_text = (specs_dir / "START_MANIFEST.md").read_text(encoding="utf-8")
        self.assertIn("TASK_PLAN.json", manifest_text)
        self.assertIn("ARCHITECTURE.md", manifest_text)

    def test_reconcile_controls_preserves_customizations(self) -> None:
        """Verify reconcile_controls creates missing controls without overwriting existing files."""
        controls_dir = self.workspace / "controls"
        controls_dir.mkdir(parents=True, exist_ok=True)

        # Pre-create custom OWNER_GRANTS.md
        custom_grants = "# Custom Grants by Human Owner"
        (controls_dir / "OWNER_GRANTS.md").write_text(custom_grants, encoding="utf-8")

        paths = reconcile_controls(self.workspace, baselines=self.baselines)
        self.assertEqual(len(paths), 8)

        # Custom grants preserved verbatim
        self.assertEqual((controls_dir / "OWNER_GRANTS.md").read_text(encoding="utf-8"), custom_grants)
        # Missing controls created
        self.assertTrue((controls_dir / "ACTIVE_STATE.json").is_file())
        self.assertTrue((controls_dir / "DISPOSITIONS.json").is_file())

    def test_reconcile_controls_repeated_idempotency_and_missing_creation(self) -> None:
        """Verify repeated reconciliation creates missing controls deterministically without modifying existing ones (Spec 05)."""
        controls_dir = self.workspace / "controls"
        controls_dir.mkdir(parents=True, exist_ok=True)

        # 1. First run creates all 8 controls
        paths1 = reconcile_controls(self.workspace, baselines=self.baselines)
        self.assertEqual(len(paths1), 8)

        # Record modification times and hashes
        from stagecheck.core.utils import sha256_file
        hashes_first = {name: sha256_file(path) for name, path in paths1.items()}

        # 2. Delete one file (simulating missing control file)
        (controls_dir / "QUALIFICATION_ROOT.json").unlink()
        self.assertFalse((controls_dir / "QUALIFICATION_ROOT.json").exists())

        # 3. Modify an existing file with user customization
        (controls_dir / "FAILURE_PREVENTION.md").write_text("# Custom Developer Invariants", encoding="utf-8")

        # 4. Re-reconcile
        paths2 = reconcile_controls(self.workspace, baselines=self.baselines)
        self.assertEqual(len(paths2), 8)

        # Missing control recreated
        self.assertTrue((controls_dir / "QUALIFICATION_ROOT.json").is_file())
        # Custom user invariant preserved
        self.assertEqual(
            (controls_dir / "FAILURE_PREVENTION.md").read_text(encoding="utf-8"),
            "# Custom Developer Invariants",
        )
        # Other unmodified controls remain untouched
        self.assertEqual(sha256_file(controls_dir / "ACTIVE_STATE.json"), hashes_first["ACTIVE_STATE.json"])

    def test_init_scaffolds_remotes_json_and_approve_remote_cli(self) -> None:
        """init scaffolds controls/remotes.json and --approve-remote / approve_remote_url register URLs under 0555/0444."""
        import stat
        import subprocess
        from stagecheck.cli.main import main
        from stagecheck.core.git import get_approved_remote_urls
        from stagecheck.core.scaffold import approve_remote_url

        ws = self.workspace / "remotes_ws"
        repo = ws / "repos" / "app"
        repo.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "-C", str(repo), "init"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.name", "Tester"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.email", "tester@example.com"], check=True, capture_output=True)
        (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "add", "app.py"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(repo), "commit", "-m", "init"], check=True, capture_output=True)

        url1 = "https://github.com/org/repo-one.git"
        url2 = "git@github.com:org/repo-two.git"

        rc_init = main(["init", "--workspace", str(ws), "--agent1", "agent1", "--agent2", "agent2", "--approve-remote", url1])
        self.assertEqual(rc_init, 0)

        remotes_file = ws / "controls" / "remotes.json"
        self.assertTrue(remotes_file.is_file())
        self.assertEqual(stat.S_IMODE(remotes_file.stat().st_mode), 0o444)
        self.assertEqual(stat.S_IMODE((ws / "controls").stat().st_mode), 0o555)
        self.assertEqual(get_approved_remote_urls(ws), {url1})

        # Approve a second remote on a locked workspace via helper & init reconcile
        approve_remote_url(ws, url2)
        self.assertEqual(stat.S_IMODE(remotes_file.stat().st_mode), 0o444)
        self.assertEqual(stat.S_IMODE((ws / "controls").stat().st_mode), 0o555)
        self.assertEqual(get_approved_remote_urls(ws), {url1, url2})

        # Reconcile preserves existing approved_push_urls
        rc_rec = main(["init", "--workspace", str(ws), "--agent1", "agent1", "--agent2", "agent2"])
        self.assertEqual(rc_rec, 0)
        self.assertEqual(get_approved_remote_urls(ws), {url1, url2})

    def test_scaffold_instructions_contain_role_exclusions_and_citation_standards(self) -> None:
        """Verify generated agent instructions enforce role exclusions, controls warning, and citation standards."""
        from stagecheck.core.scaffold import scaffold_agent_instructions

        inst_paths = scaffold_agent_instructions(
            workspace_root=self.workspace,
            agent1_name="opencode",
            agent2_name="antigravity",
            refresh=True,
        )

        a1_text = inst_paths["opencode_prompt_and_audit.md"].read_text(encoding="utf-8")
        a2_text = inst_paths["antigravity_code_implementation.md"].read_text(encoding="utf-8")

        # Agent 1 instruction checks
        self.assertIn("MUST NOT author Agent 2 deliverables", a1_text)
        self.assertIn("pre_commit_status.json", a1_text)
        self.assertIn("Phase-2B/claims.json", a1_text)
        self.assertIn("Phase-2B/report.md", a1_text)
        self.assertIn("MUST NOT include `controls/`", a1_text)

        # Agent 2 instruction checks
        self.assertIn("Phase-2B/claims.json", a2_text)
        self.assertIn("Phase-2B Deliverable Contracts & Citation Standards", a2_text)
        self.assertIn("verbatim_quote", a2_text)
        self.assertIn("line_range", a2_text)
        self.assertIn("NEVER use `#L1-L1`", a2_text)


if __name__ == "__main__":
    unittest.main()

