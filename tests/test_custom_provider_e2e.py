"""End-to-End Integration Verification for Arbitrary Custom AI Providers (Item 3, Spec 05, 06).

Verifies that any arbitrary custom AI provider (e.g., 'gemini', 'cursor', 'custom-agent'):
1. Registers cleanly in ACTIVE_STATE.json governance without code changes.
2. Resolves dedicated evidence directories under evidence/responses/<provider_slug>.
3. Successfully passes through response hooks, claims processing, and turn tracking.
4. Executes cooperative pre-commit review and nine-stage audit verification seamlessly.
"""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from stagecheck.checks.base import AuditContext
from stagecheck.core.agents import (
    AgentRole,
    load_registered_agents,
    resolve_agent_response_dir,
    validate_agent_slug,
)
from stagecheck.core.cooperative_review import record_pre_commit_review
from stagecheck.core.git import discover_repository
from stagecheck.core.orchestrator import AuditOrchestrator
from stagecheck.core.prompt_gate import freeze_prompt_and_scope
from stagecheck.core.scaffold import scaffold_controls_atomic
from stagecheck.core.utils import canonical_json_dumps, sha256_digest


class TestCustomProviderE2E(unittest.TestCase):
    """End-to-end verification of universal arbitrary provider support."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workspace_root = Path(self.temp_dir.name).resolve()
        self.task_id = "task-custom-prov-01"
        self.attempt = 1

        # Setup git repository for testing
        self.repo_dir = self.workspace_root / "repos" / "core-app"
        self.repo_dir.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "init", str(self.repo_dir)], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(self.repo_dir), "config", "user.name", "Tester"], check=True)
        subprocess.run(["git", "-C", str(self.repo_dir), "config", "user.email", "tester@example.com"], check=True)

        (self.repo_dir / "app.py").write_text("# Core app\nprint('hello')\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.repo_dir), "add", "."], check=True)
        subprocess.run(["git", "-C", str(self.repo_dir), "commit", "-m", "init"], check=True)
        subprocess.run(["git", "-C", str(self.repo_dir), "switch", "-c", f"task/{self.task_id}"], check=True, capture_output=True)

        baseline = discover_repository(self.repo_dir, name="core-app", workspace_root=self.workspace_root)
        scaffold_controls_atomic(self.workspace_root, {"core-app": baseline})
        (self.workspace_root / "evals").mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_custom_provider_registration_and_directory_containment(self):
        """Test arbitrary custom provider slugs register and resolve contained evidence dirs."""
        custom_slugs = ["gemini-pro-15", "cursor-agent-v2", "enterprise-custom-coder"]

        for slug in custom_slugs:
            # 1. Slug validation
            norm_slug = validate_agent_slug(slug)
            self.assertEqual(norm_slug, slug)

            # 2. Evidence response directory resolution
            resp_dir = resolve_agent_response_dir(self.workspace_root, slug, ensure_exists=True)
            self.assertTrue(resp_dir.is_dir())
            self.assertTrue(resp_dir.is_relative_to(self.workspace_root / "evidence" / "responses"))

        # 3. Active state governance registration
        active_state_path = self.workspace_root / "controls" / "ACTIVE_STATE.json"
        state_data = json.loads(active_state_path.read_text(encoding="utf-8"))
        state_data["registered_agents"] = [
            {"name": "gemini-pro-15", "role": "code_implementation", "comment": "Primary AI coder"},
            {"name": "cursor-agent-v2", "role": "prompt_and_audit", "comment": "Independent AI reviewer"},
        ]
        active_state_path.write_text(canonical_json_dumps(state_data), encoding="utf-8")

        registered = load_registered_agents(state_data)
        self.assertEqual(len(registered), 2)
        self.assertEqual(registered[0].name, "gemini-pro-15")
        self.assertEqual(registered[0].role, AgentRole.CODE_IMPLEMENTATION)
        self.assertEqual(registered[1].name, "cursor-agent-v2")
        self.assertEqual(registered[1].role, AgentRole.PROMPT_AND_AUDIT)

    def test_custom_provider_full_lifecycle_governance(self):
        """Test full task lifecycle with custom agents: prompt, review, delivery, and audit."""
        from stagecheck.core.agents_md import write_agents_contract
        from stagecheck.core.permissions import controlled_write_transaction
        from stagecheck.core.rubric_engine import load_270_rule_catalog
        from stagecheck.core.start_manifest import generate_start_manifest
        from stagecheck.core.utils import sha256_file

        (self.workspace_root / "evals").mkdir(parents=True, exist_ok=True)
        (self.workspace_root / "specs").mkdir(parents=True, exist_ok=True)
        generate_start_manifest(self.workspace_root)
        from stagecheck.core.dispositions import build_waiver_entry, record_waiver_in_replay_ledger
        from stagecheck.core.rubric_engine import build_agent_reviews_artifact

        waiver_evidence = self.workspace_root / "evidence" / "waiver_custom.txt"
        with controlled_write_transaction(self.workspace_root / "evidence"):
            waiver_evidence.parent.mkdir(parents=True, exist_ok=True)
            waiver_evidence.write_text("Approved waiver evidence for custom provider test.\n", encoding="utf-8")
            if not (self.workspace_root / "evidence" / "issue_history.json").is_file():
                (self.workspace_root / "evidence" / "issue_history.json").write_text(
                    canonical_json_dumps({"schema_version": "1.0", "issues": []}),
                    encoding="utf-8",
                )

        catalog = load_270_rule_catalog()
        waiver_ids = [r.rule_id for r in catalog if r.category == "HUMAN_WAIVER"]
        w_entry = build_waiver_entry(
            workspace_root=self.workspace_root,
            task_id=self.task_id,
            defect_id=waiver_ids[0],
            rationale="Authorized for custom provider E2E governance test",
            authorized_by="owner@stagecheck.local",
            attempt=self.attempt,
            evidence_path="evidence/waiver_custom.txt",
            rule_id=waiver_ids[0],
            waived_rules=waiver_ids,
        )
        disp_doc = {
            "schema_version": "2.0",
            "dispositions": [w_entry],
        }
        active_state_path = self.workspace_root / "controls" / "ACTIVE_STATE.json"
        with controlled_write_transaction(self.workspace_root / "controls"):
            (self.workspace_root / "controls" / "DISPOSITIONS.json").write_text(
                canonical_json_dumps(disp_doc), encoding="utf-8"
            )
            state_data = json.loads(active_state_path.read_text(encoding="utf-8"))
            state_data["task_id"] = self.task_id
            state_data["attempt_index"] = self.attempt
            state_data["cleared_gates"] = {"GATE_1": "0" * 64}
            state_data["registered_agents"] = [
                {"name": "gemini-coder", "role": "code_implementation"},
                {"name": "custom-auditor", "role": "prompt_and_audit"},
            ]
            active_state_path.write_text(canonical_json_dumps(state_data), encoding="utf-8")
        record_waiver_in_replay_ledger(self.workspace_root, w_entry)
        write_agents_contract(self.workspace_root)

        # Phase 1: Prompt & Scope freeze
        p1_dir = self.workspace_root / "evidence" / "tasks" / self.task_id / f"attempt_{self.attempt}" / "Phase-1"
        p1_dir.mkdir(parents=True, exist_ok=True)
        (p1_dir / "prompt.md").write_text("# Feature Task\nCustom agent delivery.\n", encoding="utf-8")
        scope = {
            "schema_version": "2.0",
            "task_id": self.task_id,
            "allowed_paths": ["repos/core-app/**"],
            "read_only_paths": [],
            "forbidden_paths": [".git/**"],
        }
        (p1_dir / "declared_scope.json").write_text(canonical_json_dumps(scope), encoding="utf-8")
        freeze_prompt_and_scope(self.workspace_root, self.task_id, self.attempt)

        # Agent implementation commit (with real positive/negative/malformed/duplicate tests)
        (self.repo_dir / "app.py").write_text("# Core app\nprint('hello from gemini')\n", encoding="utf-8")
        (self.repo_dir / "test_app.py").write_text(
            "import unittest\n\n\n"
            "def check_val(x):\n"
            "    if not isinstance(x, int):\n"
            "        raise TypeError('int expected')\n"
            "    if x < 0:\n"
            "        raise ValueError('negative disallowed')\n"
            "    return x\n\n\n"
            "class TestApp(unittest.TestCase):\n"
            "    def test_positive(self):\n"
            "        self.assertEqual(check_val(1), 1)\n\n"
            "    def test_negative_boundary(self):\n"
            "        with self.assertRaises(ValueError):\n"
            "            check_val(-1)\n\n"
            "    def test_malformed_input(self):\n"
            "        with self.assertRaises(TypeError):\n"
            "            check_val(None)\n\n"
            "    def test_duplicate_replay_idempotent(self):\n"
            "        self.assertEqual(check_val(2), check_val(2))\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "-C", str(self.repo_dir), "add", "."], check=True)
        subprocess.run(["git", "-C", str(self.repo_dir), "commit", "-m", "gemini feature commit"], check=True)

        base_sha = subprocess.run(
            ["git", "-C", str(self.repo_dir), "rev-parse", "HEAD~1"],
            capture_output=True, text=True, check=True
        ).stdout.strip()
        target_sha = subprocess.run(
            ["git", "-C", str(self.repo_dir), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True
        ).stdout.strip()

        # Phase 2A: Pre-commit review with custom reviewer
        diff_res = subprocess.run(
            ["git", "-C", str(self.repo_dir), "diff", "--binary", f"{base_sha}..{target_sha}"],
            capture_output=True, check=True
        )
        diff_hash = sha256_digest(diff_res.stdout)
        p2a_dir = self.workspace_root / "evidence" / "tasks" / self.task_id / f"attempt_{self.attempt}" / "Phase-2A"
        p2a_dir.mkdir(parents=True, exist_ok=True)
        review_data = {
            "schema_version": "2.0",
            "task_id": self.task_id,
            "attempt": self.attempt,
            "cycle": 1,
            "status": "APPROVED",
            "summary": "Custom auditor approval of gemini changes",
            "base_commits": {"core-app": base_sha},
            "approved_diff_hashes": {"core-app": diff_hash},
            "approved_snapshot_sha256": diff_hash,
            "approved_diff_sha256": diff_hash,
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
                "touched_repositories": ["core-app"],
                "base_commits": {"core-app": base_sha},
            }),
            encoding="utf-8",
        )
        agent_reviews = {
            r.rule_id: {
                "status": "PASS",
                "rationale": f"Verified semantic criterion for {r.title}.",
                "evidence_path": "Phase-2A/agent_reviews.json",
            }
            for r in catalog
            if r.category == "AGENT_ASSISTED"
        }
        reviews_artifact = build_agent_reviews_artifact(
            workspace_root=self.workspace_root,
            task_id=self.task_id,
            attempt=self.attempt,
            reviews=agent_reviews,
            reviewer="custom-auditor",
            reviewer_role="prompt_and_audit",
        )
        (p2a_dir / "agent_reviews.json").write_text(
            canonical_json_dumps(reviews_artifact),
            encoding="utf-8",
        )

        # Phase 2B: Delivery report
        p2b_dir = self.workspace_root / "evidence" / "tasks" / self.task_id / f"attempt_{self.attempt}" / "Phase-2B"
        p2b_dir.mkdir(parents=True, exist_ok=True)
        report_file = p2b_dir / "report.md"
        report_content = (
            "# Task Delivery Report\n\n"
            "## Summary\nSuccessfully implemented feature by gemini.\n\n"
            "## Changes\nModified app.py cleanly.\n\n"
            "## Verification\nRan verification suite.\n"
        )
        report_file.write_text(report_content, encoding="utf-8")
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
            "declared_scope": {"core-app": ["repos/core-app/**"]},
            "base_commits": {"core-app": base_sha},
            "target_commits": {"core-app": target_sha},
            "claims": [
                {
                    "claim_id": "CLAIM-001",
                    "statement": "Implemented feature cleanly",
                    "citations": [
                        {
                            "repo": "core-app",
                            "file_path": "repos/core-app/app.py",
                            "line_start": 2,
                            "line_end": 2,
                            "snippet": "print('hello from gemini')",
                        }
                    ],
                }
            ],
        }
        (p2b_dir / "delivery_report.json").write_text(canonical_json_dumps(report_data), encoding="utf-8")

        # Phase 3: Nine-stage audit execution
        orchestrator = AuditOrchestrator(self.workspace_root)
        ctx = orchestrator.discover_context(self.task_id, self.attempt)
        passed, verdict = orchestrator.run_all_stages(ctx)

        self.assertTrue(passed)
        self.assertEqual(verdict["result"], "CLEAR")
        self.assertEqual(verdict["counts"]["blocking"], 0)


if __name__ == "__main__":
    unittest.main()
