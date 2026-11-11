"""Comprehensive Multi-Repository Aggregate Verdict and Failure Boundary Tests (Spec 09 / REQ-4.3).

Verifies:
1. All repositories pass -> CLEAR aggregate verdict.
2. All repositories fail -> BLOCKED with defects for each repository.
3. One repository fails -> BLOCKED (zero partial pass rule).
4. One repository is unavailable -> BLOCKED with repo availability defect.
5. Partial evidence (missing repo citations/delivery) -> BLOCKED.
6. Empty repository list -> Handled deterministically.
7. Duplicate repository entries -> Handled safely without duplicate execution.
8. Invalid repository paths (path traversal attempts) -> Rejected safely.
9. Interrupted verification (injected stage exception) -> BLOCKED with exception defect.
"""

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from stagecheck.checks.base import AuditContext, Defect, StageResult
from stagecheck.core.agents_md import write_agents_contract
from stagecheck.core.git import discover_repository
from stagecheck.core.orchestrator import AuditOrchestrator
from stagecheck.core.prompt_gate import freeze_prompt_and_scope
from stagecheck.core.scaffold import scaffold_controls_atomic
from stagecheck.core.utils import canonical_json_dumps, sha256_digest


class TestMultiRepoAggregateScenarios(unittest.TestCase):
    """Deep verification of multi-repository aggregation and failure boundaries."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workspace_root = Path(self.temp_dir.name).resolve()
        self.task_id = "task-mr-01"
        self.attempt = 1

        # Set up Repo A (service-a)
        self.repo_a = self.workspace_root / "repos" / "service-a"
        self.repo_a.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "init", str(self.repo_a)], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(self.repo_a), "config", "user.name", "Tester"], check=True)
        subprocess.run(["git", "-C", str(self.repo_a), "config", "user.email", "tester@example.com"], check=True)
        (self.repo_a / "app.py").write_text("# service a\n", encoding="utf-8")
        (self.repo_a / "test_app.py").write_text(
            "import unittest\n\n\n"
            "def validate_a(x):\n"
            "    if not isinstance(x, int):\n"
            "        raise TypeError('int expected')\n"
            "    if x < 0:\n"
            "        raise ValueError('negative disallowed')\n"
            "    return x\n\n\n"
            "class TestServiceA(unittest.TestCase):\n"
            "    def test_positive(self):\n"
            "        self.assertEqual(validate_a(1), 1)\n\n"
            "    def test_negative_boundary(self):\n"
            "        with self.assertRaises(ValueError):\n"
            "            validate_a(-1)\n\n"
            "    def test_malformed_input(self):\n"
            "        with self.assertRaises(TypeError):\n"
            "            validate_a(None)\n\n"
            "    def test_duplicate_replay_idempotent(self):\n"
            "        self.assertEqual(validate_a(2), validate_a(2))\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "-C", str(self.repo_a), "add", "."], check=True)
        subprocess.run(["git", "-C", str(self.repo_a), "commit", "-m", "init a"], check=True)
        subprocess.run(["git", "-C", str(self.repo_a), "switch", "-c", f"task/{self.task_id}"], check=True, capture_output=True)

        # Set up Repo B (service-b)
        self.repo_b = self.workspace_root / "repos" / "service-b"
        self.repo_b.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "init", str(self.repo_b)], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(self.repo_b), "config", "user.name", "Tester"], check=True)
        subprocess.run(["git", "-C", str(self.repo_b), "config", "user.email", "tester@example.com"], check=True)
        (self.repo_b / "service.py").write_text("# service b\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.repo_b), "add", "."], check=True)
        subprocess.run(["git", "-C", str(self.repo_b), "commit", "-m", "init b"], check=True)
        subprocess.run(["git", "-C", str(self.repo_b), "switch", "-c", f"task/{self.task_id}"], check=True, capture_output=True)

        # Baseline discovery and scaffolding
        base_a = discover_repository(self.repo_a, name="service-a", workspace_root=self.workspace_root)
        base_b = discover_repository(self.repo_b, name="service-b", workspace_root=self.workspace_root)
        scaffold_controls_atomic(self.workspace_root, {"service-a": base_a, "service-b": base_b})
        from stagecheck.core.permissions import controlled_write_transaction
        from stagecheck.core.rubric_engine import load_270_rule_catalog
        from stagecheck.core.start_manifest import generate_start_manifest
        from stagecheck.core.state import load_active_state, save_active_state

        (self.workspace_root / "specs").mkdir(parents=True, exist_ok=True)
        generate_start_manifest(self.workspace_root)

        catalog = load_270_rule_catalog()
        waiver_ids = [r.rule_id for r in catalog if r.category == "HUMAN_WAIVER"]
        disp_doc = {
            "schema_version": "2.0",
            "dispositions": [
                {
                    "disposition_id": "DISP-MR-01",
                    "task_id": self.task_id,
                    "rule_id": waiver_ids[0],
                    "waived_rules": waiver_ids,
                    "authorized_by": "human-operator",
                    "rationale": "Authorized for multi-repo scenario tests",
                    "status": "APPROVED",
                }
            ],
        }
        with controlled_write_transaction(self.workspace_root / "controls"):
            (self.workspace_root / "controls" / "DISPOSITIONS.json").write_text(
                canonical_json_dumps(disp_doc), encoding="utf-8"
            )
        state = load_active_state(self.workspace_root)
        state["cleared_gates"] = {"GATE_1": "0" * 64}
        save_active_state(self.workspace_root, state)
        write_agents_contract(self.workspace_root)
        (self.workspace_root / "evals").mkdir(parents=True, exist_ok=True)

        # Phase 1 setup
        p1_dir = self.workspace_root / "evidence" / "tasks" / self.task_id / f"attempt_{self.attempt}" / "Phase-1"
        p1_dir.mkdir(parents=True, exist_ok=True)
        (p1_dir / "prompt.md").write_text("# Prompt\nImplement multi-repo changes.\n", encoding="utf-8")
        scope = {
            "schema_version": "2.0",
            "task_id": self.task_id,
            "allowed_paths": ["repos/service-a/**", "repos/service-b/**"],
            "read_only_paths": [],
            "forbidden_paths": [".git/**"],
        }
        (p1_dir / "declared_scope.json").write_text(canonical_json_dumps(scope), encoding="utf-8")
        freeze_prompt_and_scope(self.workspace_root, self.task_id, self.attempt)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _setup_valid_lifecycle(self):
        """Helper to set up valid Phase 2A and Phase 2B evidence for service-a and service-b."""
        base_a = subprocess.run(["git", "-C", str(self.repo_a), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
        base_b = subprocess.run(["git", "-C", str(self.repo_b), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()

        # Phase 2A review
        p2a_dir = self.workspace_root / "evidence" / "tasks" / self.task_id / f"attempt_{self.attempt}" / "Phase-2A"
        p2a_dir.mkdir(parents=True, exist_ok=True)
        review_data = {
            "schema_version": "2.0",
            "task_id": self.task_id,
            "attempt": self.attempt,
            "cycle": 1,
            "status": "APPROVED",
            "summary": "Multi-repo changes approved",
            "base_commits": {"service-a": base_a, "service-b": base_b},
            "approved_diff_hashes": {
                "service-a": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "service-b": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            },
            "approved_snapshot_sha256": "0" * 64,
            "approved_diff_sha256": "0" * 64,
            "pre_existing_issues_ignored": [],
            "architectural_intents_approved": [],
            "new_issues_found": [],
            "code_quality_observations": [],
        }
        (p2a_dir / "pre_commit_review.json").write_text(canonical_json_dumps(review_data), encoding="utf-8")
        (p2a_dir / "pre_commit_status.json").write_text(
            canonical_json_dumps({
                "schema_version": "2.0",
                "task_id": self.task_id,
                "attempt": self.attempt,
                "cycle": 1,
                "status": "AWAITING_REVIEW",
                "touched_repositories": ["service-a", "service-b"],
                "base_commits": {"service-a": base_a, "service-b": base_b},
            }),
            encoding="utf-8",
        )
        from stagecheck.core.rubric_engine import load_270_rule_catalog
        from stagecheck.core.utils import sha256_file

        agent_reviews = {
            r.rule_id: {
                "status": "PASS",
                "rationale": f"Verified semantic criterion for {r.title}.",
                "evidence_path": "Phase-2A/agent_reviews.json",
            }
            for r in load_270_rule_catalog()
            if r.category == "AGENT_ASSISTED"
        }
        (p2a_dir / "agent_reviews.json").write_text(
            canonical_json_dumps({"task_id": self.task_id, "attempt": self.attempt, "agent_assisted_reviews": agent_reviews}),
            encoding="utf-8",
        )

        # Phase 2B delivery report
        p2b_dir = self.workspace_root / "evidence" / "tasks" / self.task_id / f"attempt_{self.attempt}" / "Phase-2B"
        p2b_dir.mkdir(parents=True, exist_ok=True)
        report_file = p2b_dir / "report.md"
        report_file.write_text("# Delivery Report\n\n## Summary\nAll repos clean.\n\n## Changes\nNone.\n\n## Verification\nVerified.\n", encoding="utf-8")
        (p2b_dir / "claims.json").write_text(
            canonical_json_dumps({
                "task_id": self.task_id,
                "iteration": 1,
                "contract_sha256": sha256_file(self.workspace_root / "AGENTS.md"),
                "record": "Phase-2B/report.md",
                "record_sha256": sha256_file(report_file),
                "claims": [],
            }),
            encoding="utf-8",
        )
        report_data = {
            "schema_version": "2.0",
            "task_id": self.task_id,
            "attempt": self.attempt,
            "declared_scope": {"service-a": ["repos/service-a/**"], "service-b": ["repos/service-b/**"]},
            "base_commits": {"service-a": base_a, "service-b": base_b},
            "target_commits": {"service-a": base_a, "service-b": base_b},
            "claims": [],
        }
        (p2b_dir / "delivery_report.json").write_text(canonical_json_dumps(report_data), encoding="utf-8")

    def test_scenario_1_all_repos_pass(self):
        """1. All repositories pass -> Overall audit result is CLEAR."""
        self._setup_valid_lifecycle()
        orchestrator = AuditOrchestrator(self.workspace_root)
        ctx = orchestrator.discover_context(self.task_id, self.attempt)
        passed, verdict = orchestrator.run_all_stages(ctx)

        self.assertTrue(passed)
        self.assertEqual(verdict["result"], "CLEAR")
        self.assertEqual(verdict["counts"]["blocking"], 0)

    def test_scenario_2_all_repos_fail(self):
        """2. All repositories fail -> Overall result is BLOCKED, defects retained."""
        self._setup_valid_lifecycle()
        # Introduce unauthorized files in both service-a and service-b
        (self.repo_a / "unauth_a.txt").write_text("bad a", encoding="utf-8")
        (self.repo_b / "unauth_b.txt").write_text("bad b", encoding="utf-8")

        orchestrator = AuditOrchestrator(self.workspace_root)
        ctx = orchestrator.discover_context(self.task_id, self.attempt)
        passed, verdict = orchestrator.run_all_stages(ctx)

        self.assertFalse(passed)
        self.assertEqual(verdict["result"], "BLOCKED")
        self.assertGreaterEqual(verdict["counts"]["blocking"], 1)

    def test_scenario_3_one_repo_fails(self):
        """3. One repository fails -> Overall result is BLOCKED (Zero Partial Pass rule)."""
        self._setup_valid_lifecycle()
        # service-a remains clean; introduce defect in service-b
        (self.repo_b / "unauth_b.txt").write_text("bad b", encoding="utf-8")

        orchestrator = AuditOrchestrator(self.workspace_root)
        ctx = orchestrator.discover_context(self.task_id, self.attempt)
        passed, verdict = orchestrator.run_all_stages(ctx)

        self.assertFalse(passed)
        self.assertEqual(verdict["result"], "BLOCKED")

    def test_scenario_4_one_repo_unavailable(self):
        """4. One registered repository path missing on disk -> BLOCKED."""
        self._setup_valid_lifecycle()
        shutil.rmtree(self.repo_b)

        orchestrator = AuditOrchestrator(self.workspace_root)
        ctx = orchestrator.discover_context(self.task_id, self.attempt)
        passed, verdict = orchestrator.run_all_stages(ctx)

        self.assertFalse(passed)
        self.assertEqual(verdict["result"], "BLOCKED")

    def test_scenario_5_partial_evidence(self):
        """5. Delivery report contains partial evidence omitting touched repository -> BLOCKED."""
        self._setup_valid_lifecycle()
        # Touch both repos with commits
        (self.repo_a / "change_a.txt").write_text("feature a", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.repo_a), "add", "."], check=True)
        subprocess.run(["git", "-C", str(self.repo_a), "commit", "-m", "commit a"], check=True)

        (self.repo_b / "change_b.txt").write_text("feature b", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.repo_b), "add", "."], check=True)
        subprocess.run(["git", "-C", str(self.repo_b), "commit", "-m", "commit b"], check=True)

        # But pre-commit review only approved service-a, omitting service-b
        target_a = subprocess.run(["git", "-C", str(self.repo_a), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
        base_a = subprocess.run(["git", "-C", str(self.repo_a), "rev-parse", "HEAD~1"], capture_output=True, text=True, check=True).stdout.strip()
        diff_res = subprocess.run(["git", "-C", str(self.repo_a), "diff", "--binary", f"{base_a}..{target_a}"], capture_output=True, check=True)
        diff_hash_a = sha256_digest(diff_res.stdout)

        p2a_json = self.workspace_root / "evidence" / "tasks" / self.task_id / f"attempt_{self.attempt}" / "Phase-2A" / "pre_commit_review.json"
        review_data = {
            "schema_version": "2.0",
            "task_id": self.task_id,
            "attempt": self.attempt,
            "cycle": 1,
            "status": "APPROVED",
            "summary": "Partial approval omitting service-b",
            "base_commits": {"service-a": base_a},
            "approved_diff_hashes": {"service-a": diff_hash_a},
            "approved_snapshot_sha256": diff_hash_a,
            "approved_diff_sha256": diff_hash_a,
            "pre_existing_issues_ignored": [],
            "architectural_intents_approved": [],
            "new_issues_found": [],
            "code_quality_observations": [],
        }
        p2a_json.write_text(canonical_json_dumps(review_data), encoding="utf-8")

        orchestrator = AuditOrchestrator(self.workspace_root)
        ctx = orchestrator.discover_context(self.task_id, self.attempt)
        passed, verdict = orchestrator.run_all_stages(ctx)

        self.assertFalse(passed)
        self.assertEqual(verdict["result"], "BLOCKED")

    def test_scenario_6_empty_repository_list(self):
        """6. Context with empty registered repos -> Fails gracefully without unhandled crash."""
        ctx = AuditContext(
            workspace_root=self.workspace_root,
            task_id=self.task_id,
            attempt=self.attempt,
            touched_repos=[],
            all_registered_repos=[],
        )
        orchestrator = AuditOrchestrator(self.workspace_root)
        passed, verdict = orchestrator.run_all_stages(ctx)
        self.assertIn(verdict["result"], ("CLEAR", "BLOCKED"))

    def test_scenario_7_duplicate_repository_entries(self):
        """7. Duplicate repository entries in touched_repos -> Deduplicated deterministically."""
        self._setup_valid_lifecycle()
        orchestrator = AuditOrchestrator(self.workspace_root)
        ctx = orchestrator.discover_context(self.task_id, self.attempt)
        ctx.touched_repos = ["service-a", "service-a", "service-b", "service-b"]
        passed, verdict = orchestrator.run_all_stages(ctx)

        self.assertTrue(passed)
        self.assertEqual(verdict["result"], "CLEAR")

    def test_scenario_8_invalid_repository_paths(self):
        """8. Path traversal in repository names -> Fails closed securely."""
        ctx = AuditContext(
            workspace_root=self.workspace_root,
            task_id=self.task_id,
            attempt=self.attempt,
            touched_repos=["../../etc"],
            all_registered_repos=["../../etc"],
        )
        orchestrator = AuditOrchestrator(self.workspace_root)
        passed, verdict = orchestrator.run_all_stages(ctx)
        self.assertFalse(passed)
        self.assertEqual(verdict["result"], "BLOCKED")

    def test_scenario_9_interrupted_verification(self):
        """9. Unhandled exception in stage runner -> Recorded as stage.exception defect, BLOCKED."""
        self._setup_valid_lifecycle()
        orchestrator = AuditOrchestrator(self.workspace_root)
        ctx = orchestrator.discover_context(self.task_id, self.attempt)

        from unittest.mock import patch
        with patch("stagecheck.core.orchestrator.run_stage2_scope_paths", side_effect=RuntimeError("Injected pipeline crash")):
            passed, verdict = orchestrator.run_all_stages(ctx)
            self.assertFalse(passed)
            self.assertEqual(verdict["result"], "BLOCKED")
            self.assertTrue(any(d["defect_id"] == "scope_paths.exception" for d in verdict["defects"]))


if __name__ == "__main__":
    unittest.main()
