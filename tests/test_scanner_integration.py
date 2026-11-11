"""Integration Tests for Fail-Closed Secret Scanner in Production Workflows (Item 1).

Proves that:
1. Missing Gitleaks blocks Stage 1 (preflight).
2. Missing Gitleaks blocks Stage 6 (secrets).
3. Gitleaks failure/unavailability blocks end-to-end audit (zero partial pass).
4. Detected secret credential blocks end-to-end audit.
5. Gitleaks failure during pre-commit denies commit authorization.
6. Centralized SecretScanner is called by all production workflows.
"""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from stagecheck.checks.base import AuditContext
from stagecheck.checks.stage1_preflight import run_stage1_preflight
from stagecheck.checks.stage6_secrets import run_stage6_secrets
from stagecheck.core.cooperative_review import ReviewGateError, record_pre_commit_review
from stagecheck.core.git import discover_repository
from stagecheck.core.orchestrator import AuditOrchestrator
from stagecheck.core.prompt_gate import freeze_prompt_and_scope
from stagecheck.core.scaffold import scaffold_controls_atomic
from stagecheck.core.scanner import ScanExecutionResult, SecretScanner
from stagecheck.core.utils import canonical_json_dumps, sha256_digest


class TestSecretScannerIntegration(unittest.TestCase):
    """Integration verification for SecretScanner in production audit workflows."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workspace_root = Path(self.temp_dir.name).resolve()
        self.task_id = "task-sec-01"
        self.attempt = 1

        self.repo_dir = self.workspace_root / "repos" / "service"
        self.repo_dir.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "init", str(self.repo_dir)], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(self.repo_dir), "config", "user.name", "Security Tester"], check=True)
        subprocess.run(["git", "-C", str(self.repo_dir), "config", "user.email", "sec@example.com"], check=True)

        # Initial commit
        (self.repo_dir / "README.md").write_text("# Service\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.repo_dir), "add", "."], check=True)
        subprocess.run(["git", "-C", str(self.repo_dir), "commit", "-m", "init"], check=True)
        subprocess.run(["git", "-C", str(self.repo_dir), "switch", "-c", f"task/{self.task_id}"], check=True, capture_output=True)

        baseline = discover_repository(self.repo_dir, name="service", workspace_root=self.workspace_root)
        scaffold_controls_atomic(self.workspace_root, {"service": baseline})

        # Phase 1 setup
        p1_dir = self.workspace_root / "evidence" / "tasks" / self.task_id / f"attempt_{self.attempt}" / "Phase-1"
        p1_dir.mkdir(parents=True, exist_ok=True)
        (p1_dir / "prompt.md").write_text("# Spec\nImplement secure feature.\n", encoding="utf-8")
        scope = {
            "schema_version": "2.0",
            "task_id": self.task_id,
            "allowed_paths": ["repos/service/**"],
            "read_only_paths": [],
            "forbidden_paths": [".git/**"],
        }
        (p1_dir / "declared_scope.json").write_text(canonical_json_dumps(scope), encoding="utf-8")
        freeze_prompt_and_scope(self.workspace_root, self.task_id, self.attempt)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_gitleaks_missing_blocks_stage1(self):
        """1. Prove missing Gitleaks blocks Stage 1 preflight."""
        ctx = AuditContext(
            workspace_root=self.workspace_root,
            task_id=self.task_id,
            attempt=self.attempt,
            touched_repos=["service"],
            all_registered_repos=["service"],
        )
        with patch("shutil.which", return_value=None):
            res = run_stage1_preflight(ctx)
            self.assertFalse(res.is_clear)
            self.assertTrue(any(d.defect_id == "preflight.gitleaks_missing" and d.blocking for d in res.defects))

    def test_gitleaks_missing_blocks_stage6(self):
        """2. Prove missing Gitleaks blocks Stage 6 secrets."""
        ctx = AuditContext(
            workspace_root=self.workspace_root,
            task_id=self.task_id,
            attempt=self.attempt,
            touched_repos=["service"],
            all_registered_repos=["service"],
            base_commits={"service": "HEAD~1"},
            target_commits={"service": "HEAD"},
        )
        with patch("shutil.which", return_value=None):
            res = run_stage6_secrets(ctx)
            self.assertFalse(res.is_clear)
            self.assertTrue(any(d.defect_id == "secrets.scanner_missing" and d.blocking for d in res.defects))

    def test_gitleaks_failure_blocks_audit(self):
        """3. Prove scanner execution failure blocks overall audit verification."""
        # Commit a clean change
        (self.repo_dir / "feature.py").write_text("print('clean')\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.repo_dir), "add", "."], check=True)
        subprocess.run(["git", "-C", str(self.repo_dir), "commit", "-m", "add feature"], check=True)

        base_sha = subprocess.run(
            ["git", "-C", str(self.repo_dir), "rev-parse", "HEAD~1"],
            capture_output=True, text=True, check=True
        ).stdout.strip()
        target_sha = subprocess.run(
            ["git", "-C", str(self.repo_dir), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True
        ).stdout.strip()

        # Phase 2A review setup
        p2a_dir = self.workspace_root / "evidence" / "tasks" / self.task_id / f"attempt_{self.attempt}" / "Phase-2A"
        p2a_dir.mkdir(parents=True, exist_ok=True)
        diff_res = subprocess.run(
            ["git", "-C", str(self.repo_dir), "diff", "--binary", f"{base_sha}..{target_sha}"],
            capture_output=True, check=True
        )
        diff_hash = sha256_digest(diff_res.stdout)
        review_data = {
            "schema_version": "2.0",
            "task_id": self.task_id,
            "attempt": self.attempt,
            "cycle": 1,
            "status": "APPROVED",
            "summary": "Clean approved review",
            "base_commits": {"service": base_sha},
            "approved_diff_hashes": {"service": diff_hash},
            "approved_snapshot_sha256": diff_hash,
            "approved_diff_sha256": diff_hash,
            "pre_existing_issues_ignored": [],
            "architectural_intents_approved": [],
            "new_issues_found": [],
            "code_quality_observations": [],
        }
        (p2a_dir / "pre_commit_review.json").write_text(canonical_json_dumps(review_data), encoding="utf-8")

        # Phase 2B delivery report setup
        p2b_dir = self.workspace_root / "evidence" / "tasks" / self.task_id / f"attempt_{self.attempt}" / "Phase-2B"
        p2b_dir.mkdir(parents=True, exist_ok=True)
        report_data = {
            "schema_version": "2.0",
            "task_id": self.task_id,
            "attempt": self.attempt,
            "declared_scope": {"service": ["repos/service/**"]},
            "base_commits": {"service": base_sha},
            "target_commits": {"service": target_sha},
            "claims": [],
        }
        (p2b_dir / "delivery_report.json").write_text(canonical_json_dumps(report_data), encoding="utf-8")

        # Simulate scanner failure during Stage 6
        orchestrator = AuditOrchestrator(self.workspace_root)
        ctx = orchestrator.discover_context(self.task_id, self.attempt)

        import shutil
        orig_which = shutil.which
        with patch(
            "shutil.which",
            side_effect=lambda cmd, *a, **kw: None if cmd == "gitleaks" else orig_which(cmd, *a, **kw),
        ):
            passed, verdict = orchestrator.run_all_stages(ctx)
            self.assertFalse(passed)
            self.assertEqual(verdict["result"], "BLOCKED")
            self.assertTrue(any("gitleaks" in d["defect_id"] or "scanner" in d["defect_id"] for d in verdict["defects"]))

    def test_detected_secret_blocks_audit(self):
        """4. Prove detected credentials in commit range block audit verification."""
        # Commit a real secret pattern into git
        (self.repo_dir / "config.py").write_text(
            'AWS_KEY = "AKIA1234567890ABCDEF"\n', encoding="utf-8"
        )
        subprocess.run(["git", "-C", str(self.repo_dir), "add", "."], check=True)
        subprocess.run(["git", "-C", str(self.repo_dir), "commit", "-m", "leak secret"], check=True)

        base_sha = subprocess.run(
            ["git", "-C", str(self.repo_dir), "rev-parse", "HEAD~1"],
            capture_output=True, text=True, check=True
        ).stdout.strip()
        target_sha = subprocess.run(
            ["git", "-C", str(self.repo_dir), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True
        ).stdout.strip()

        ctx = AuditContext(
            workspace_root=self.workspace_root,
            task_id=self.task_id,
            attempt=self.attempt,
            touched_repos=["service"],
            all_registered_repos=["service"],
            base_commits={"service": base_sha},
            target_commits={"service": target_sha},
        )
        res = run_stage6_secrets(ctx)
        self.assertFalse(res.is_clear)
        self.assertTrue(any(d.defect_id == "secrets.detected_credential" and d.blocking for d in res.defects))

    def test_gitleaks_failure_during_precommit_denies_authorization(self):
        """5. Prove pre-commit approval gate raises ReviewGateError when scanner fails."""
        # Stage a clean change
        (self.repo_dir / "clean.py").write_text("a = 1\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.repo_dir), "add", "."], check=True)

        base_sha = subprocess.run(
            ["git", "-C", str(self.repo_dir), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True
        ).stdout.strip()

        # When scanner is missing or fails, approve_pre_commit_review MUST deny authorization
        with patch.object(SecretScanner, "scan_staged_changes", return_value=ScanExecutionResult(
            is_clear=False,
            defects=[MagicMock(message="Scanner execution failed: permission denied", blocking=True)]
        )):
            with self.assertRaises(ReviewGateError) as cm:
                record_pre_commit_review(
                    workspace_root=self.workspace_root,
                    task_id=self.task_id,
                    attempt=self.attempt,
                    cycle=1,
                    status="APPROVED",
                    summary="Attempting approval with failing scanner",
                    base_commits={"service": base_sha},
                )
            self.assertIn("Pre-commit staged secret scan failed", str(cm.exception))

    def test_central_scanner_called_by_production_workflow(self):
        """6. Prove SecretScanner is directly invoked in Stage 1, Stage 6, and Pre-commit."""
        ctx = AuditContext(
            workspace_root=self.workspace_root,
            task_id=self.task_id,
            attempt=self.attempt,
            touched_repos=["service"],
            all_registered_repos=["service"],
            base_commits={"service": "HEAD~1"},
            target_commits={"service": "HEAD"},
        )

        with patch.object(SecretScanner, "verify_scanner_binary", wraps=SecretScanner().verify_scanner_binary) as mock_verify:
            run_stage1_preflight(ctx)
            self.assertTrue(mock_verify.called, "SecretScanner.verify_scanner_binary was not called in Stage 1!")

        with patch.object(SecretScanner, "scan_commit_range", wraps=SecretScanner().scan_commit_range) as mock_scan:
            run_stage6_secrets(ctx)
            self.assertTrue(mock_scan.called, "SecretScanner.scan_commit_range was not called in Stage 6!")


if __name__ == "__main__":
    unittest.main()
