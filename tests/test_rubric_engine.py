"""Unit and Integration Tests for 270-Rule Rubric Evaluator and Exemption Engine (FR-03 / Spec 02 / Task 3.2).

Verifies:
1. Exact 270-rule catalog loading across 9 domains (30 rules each).
2. Category allocation: exactly 162 Automated, 64 Evidence, 34 Agent-Assisted, 10 Human Waiver.
3. Performance benchmark: full catalog evaluation completes well under the 200ms SLA.
4. Deterministic structural exemption predicates (e.g. PREDICATE_NO_REACT_DEPENDENCY).
5. Fail-closed rejection of illegal or unverified agent self-exemptions (InvalidRubricExemptionError).
6. CLI 'stagecheck check-rubric' exit codes, terminal output, and artifact updates.
"""

from __future__ import annotations

import io
import json
import subprocess
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from stagecheck.cli.main import main
from stagecheck.core.git import discover_repository
from stagecheck.core.rubric_engine import (
    EXEMPTION_PREDICATES,
    InvalidRubricExemptionError,
    load_270_rule_catalog,
    run_rubric_evaluation,
    update_rubric_artifacts,
    validate_rubric_evaluation_payload,
)
from stagecheck.core.scaffold import scaffold_controls_atomic
from stagecheck.core.start_manifest import generate_start_manifest
from stagecheck.core.state import load_active_state, save_active_state
from stagecheck.schemas.validator import validate_rubric_evaluation


class TestRubricEngine(unittest.TestCase):
    """Test suite covering the 270-rule rubric catalog, deterministic exemptions, and CLI runner."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp_dir.name).resolve()
        self.task_id = "task-rubric-test"
        self.attempt = 1

        # Mock repo without React
        self.repo_dir = self.workspace / "repos" / "backend"
        self.repo_dir.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "init"], cwd=str(self.repo_dir), check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Tester"], cwd=str(self.repo_dir), check=True)
        subprocess.run(["git", "config", "user.email", "tester@test.local"], cwd=str(self.repo_dir), check=True)
        (self.repo_dir / "service.py").write_text("def run(): pass\n", encoding="utf-8")
        (self.repo_dir / "requirements.txt").write_text("fastapi==0.100.0\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=str(self.repo_dir), check=True)
        subprocess.run(["git", "commit", "-m", "init"], cwd=str(self.repo_dir), check=True)

        baselines = {
            "backend": discover_repository(self.repo_dir, name="backend", workspace_root=self.workspace)
        }
        scaffold_controls_atomic(self.workspace, baselines)
        generate_start_manifest(self.workspace)

        state = load_active_state(self.workspace)
        state["task_id"] = self.task_id
        state["attempt_index"] = self.attempt
        state["phase"] = "PHASE_2A_CODING"
        save_active_state(self.workspace, state)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_catalog_accountability_and_category_allocation(self) -> None:
        """Verify exactly 270 rules are accounted for with exact 162/64/34/10 category allocation (FR-03)."""
        catalog = load_270_rule_catalog()
        self.assertEqual(len(catalog), 270, "Catalog must contain exactly 270 rules.")

        # Check domains (30 per domain)
        domain_counts: dict[str, int] = {}
        category_counts: dict[str, int] = {}

        for rule in catalog:
            domain_counts[rule.domain] = domain_counts.get(rule.domain, 0) + 1
            category_counts[rule.category] = category_counts.get(rule.category, 0) + 1

        self.assertEqual(len(domain_counts), 9, "Must span exactly 9 specialized domains.")
        for domain, count in domain_counts.items():
            self.assertEqual(count, 30, f"Domain '{domain}' must contain exactly 30 rules.")

        # Verify mathematical category allocation:
        # 162 Automated + 64 Evidence + 34 Agent-Assisted + 10 Human Waiver = 270
        self.assertEqual(category_counts.get("AUTOMATED"), 162, "Must allocate exactly 162 Automated rules.")
        self.assertEqual(category_counts.get("EVIDENCE"), 64, "Must allocate exactly 64 Evidence rules.")
        self.assertEqual(category_counts.get("AGENT_ASSISTED"), 34, "Must allocate exactly 34 Agent-Assisted rules.")
        self.assertEqual(category_counts.get("HUMAN_WAIVER"), 10, "Must allocate exactly 10 Human Waiver rules.")
        self.assertEqual(sum(category_counts.values()), 270)

    def test_evaluation_performance_under_200ms(self) -> None:
        """Verify 270-rule evaluation executes well within the 200ms performance SLA (FR-03)."""
        payload, elapsed_ms = run_rubric_evaluation(self.workspace, self.task_id, self.attempt)
        self.assertLess(elapsed_ms, 200.0, f"Evaluation time {elapsed_ms:.1f}ms exceeded 200ms SLA.")
        self.assertEqual(payload["counts"]["total_rules"], 270)

    def test_deterministic_structural_exemption_predicates(self) -> None:
        """Verify backend repo without React correctly evaluates React rules to NOT_APPLICABLE (DEC-026)."""
        payload, _ = run_rubric_evaluation(self.workspace, self.task_id, self.attempt)
        evaluations = payload["evaluations"]

        na_rules = [e for e in evaluations if e["status"] == "NOT_APPLICABLE"]
        self.assertGreater(len(na_rules), 0, "Backend repo should trigger structural exemptions.")

        for na in na_rules:
            self.assertIn("exemption_predicate", na)
            self.assertIn(na["exemption_predicate"], EXEMPTION_PREDICATES)
            self.assertTrue(na.get("rationale"), "Exemption must include explanatory rationale.")
            self.assertTrue(na.get("evidence_path"), "Exemption must include verified evidence_path.")

    def test_reject_arbitrary_agent_self_exemption(self) -> None:
        """Verify fail-closed rejection of illegal or unverified NOT_APPLICABLE exemptions (DEC-026)."""
        # Case 1: missing predicate
        illegal_payload = [
            {"rule_id": "TEST_ADEQUACY-018", "status": "NOT_APPLICABLE", "rationale": "I don't need this."}
        ]
        with self.assertRaises(InvalidRubricExemptionError):
            validate_rubric_evaluation_payload(illegal_payload)

        # Case 2: unknown fabricated predicate
        fabricated_payload = [
            {
                "rule_id": "TEST_ADEQUACY-018",
                "status": "NOT_APPLICABLE",
                "exemption_predicate": "PREDICATE_AGENT_DISCRETION",
                "rationale": "Agent chose to skip.",
                "evidence_path": "repos/backend",
            }
        ]
        with self.assertRaises(InvalidRubricExemptionError):
            validate_rubric_evaluation_payload(fabricated_payload)

        # Case 3: missing evidence_path
        missing_evidence = [
            {
                "rule_id": "TEST_ADEQUACY-018",
                "status": "NOT_APPLICABLE",
                "exemption_predicate": "PREDICATE_NO_REACT_DEPENDENCY",
                "rationale": "No react.",
            }
        ]
        with self.assertRaises(InvalidRubricExemptionError):
            validate_rubric_evaluation_payload(missing_evidence)

    def test_cli_check_rubric_and_artifact_updates(self) -> None:
        """Verify 'stagecheck check-rubric --update-json' outputs report and writes artifacts."""
        p2a_dir = self.workspace / "evidence" / "tasks" / self.task_id / f"attempt_{self.attempt}" / "Phase-2A"
        p2a_dir.mkdir(parents=True, exist_ok=True)
        (p2a_dir / "pre_commit_review.json").write_text(
            json.dumps({
                "schema_version": "2.0.0",
                "task_id": self.task_id,
                "attempt": self.attempt,
                "cycle": 1,
                "status": "AWAITING_REVIEW",
            }),
            encoding="utf-8",
        )

        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main([
                "check-rubric",
                "--task", self.task_id,
                "--update-json",
                "--workspace", str(self.workspace),
            ])
        self.assertEqual(rc, 0)

        out = buf.getvalue()
        self.assertIn("STAGECHECK AUTOMATED AUDIT RUBRIC EVALUATOR", out)
        self.assertIn("Total Evaluated: 270 Rules", out)

        # Verify rubric_evaluation.json created
        rubric_file = p2a_dir / "rubric_evaluation.json"
        self.assertTrue(rubric_file.is_file())
        r_data = json.loads(rubric_file.read_text(encoding="utf-8"))
        self.assertEqual(r_data["counts"]["total_rules"], 270)
        validate_rubric_evaluation(r_data)

        # Verify pre_commit_review.json updated with rubric summary
        rev_data = json.loads((p2a_dir / "pre_commit_review.json").read_text(encoding="utf-8"))
        self.assertIn("rubric_summary", rev_data)
        self.assertEqual(rev_data["rubric_summary"]["total_evaluated"], 270)


if __name__ == "__main__":
    unittest.main()
