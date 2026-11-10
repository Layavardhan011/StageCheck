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

    def test_rule_with_no_evaluator_cannot_pass_by_default(self) -> None:
        """Verify an unsupported or unmapped rule returns NOT_EVALUATED and cannot pass by default (Gap A)."""
        from stagecheck.core.rubric_engine import RubricRule, evaluate_rubric_rule
        unsupported_rule = RubricRule(
            rule_id="UNKNOWN_DOMAIN-001",
            domain="NON_EXISTENT_DOMAIN",
            title="Bogus Rule",
            question="Does this pass?",
            category="AUTOMATED",
        )
        res = evaluate_rubric_rule(unsupported_rule, self.workspace, self.repo_dir)
        self.assertEqual(res.status, "NOT_EVALUATED")
        self.assertEqual(res.evaluator, "unsupported_fallback")
        self.assertNotEqual(res.status, "PASS")

        # Also verify that validate_rubric_evaluation_payload rejects any pass from unsupported_fallback
        from stagecheck.core.rubric_engine import RubricEvaluationError
        with self.assertRaises(RubricEvaluationError):
            validate_rubric_evaluation_payload([
                {
                    "rule_id": "UNKNOWN_DOMAIN-001",
                    "status": "PASS",
                    "evaluator": "unsupported_fallback",
                }
            ])

    def test_missing_evidence_cannot_result_in_unjustified_pass(self) -> None:
        """Verify evidence-dependent rules fail safely when evidence is missing (Gap A)."""
        from stagecheck.core.rubric_engine import RubricRule, evaluate_rubric_rule
        evidence_rule = RubricRule(
            rule_id="CLAIM_SUPPORT-001",
            domain="CLAIM_SUPPORT",
            title="Verifiable Evidence Entailment",
            question="Is evidence present?",
            category="EVIDENCE",
            primary_witness="Phase-2B/claims.json",
        )
        # Context indicates missing evidence artifact
        ctx = {"missing_evidence": ["CLAIM_SUPPORT-001"]}
        res = evaluate_rubric_rule(evidence_rule, self.workspace, self.repo_dir, context=ctx)
        self.assertEqual(res.status, "FAIL")
        self.assertEqual(res.evaluator, "phase_evidence_validator")
        self.assertIn("Missing required evidence", res.message)

    def test_rule_specific_failure_is_reported_correctly(self) -> None:
        """Verify domain-specific evaluators report failures with witnesses and messages (Gap A)."""
        from stagecheck.core.rubric_engine import RubricRule, evaluate_rubric_rule
        # Test UPSTREAM_REUSE failure with unpinned dependencies
        upstream_rule = RubricRule(
            rule_id="UPSTREAM_REUSE-001",
            domain="UPSTREAM_REUSE",
            title="Discrete Version Pinning",
            question="Are dependencies pinned?",
            category="AUTOMATED",
        )
        ctx = {"unpinned_dependencies": ["fastapi>=0.0.0"]}
        res = evaluate_rubric_rule(upstream_rule, self.workspace, self.repo_dir, context=ctx)
        self.assertEqual(res.status, "FAIL")
        self.assertEqual(res.evaluator, "upstream_reuse_dependency_analyzer")
        self.assertEqual(res.witness, "fastapi>=0.0.0")
        self.assertIn("Unpinned wildcard dependency detected", res.message)

    def test_valid_rule_specific_pass_is_reported_correctly(self) -> None:
        """Verify passing rules report their explicit evaluator and witness metadata (Gap A)."""
        from stagecheck.core.rubric_engine import RubricRule, evaluate_rubric_rule
        blast_rule = RubricRule(
            rule_id="BLAST_RADIUS-001",
            domain="BLAST_RADIUS",
            title="Scope Containment Verification",
            question="Are changes within scope?",
            category="AUTOMATED",
        )
        res = evaluate_rubric_rule(blast_rule, self.workspace, self.repo_dir, context={})
        self.assertEqual(res.status, "PASS")
        self.assertEqual(res.evaluator, "blast_radius_containment")
        self.assertEqual(res.witness, "scope_containment_verified")

    def test_evaluation_errors_handled_safely(self) -> None:
        """Verify evaluation exceptions fail closed with FAIL status rather than crashing or passing (Gap A)."""
        from stagecheck.core.rubric_engine import RubricRule, evaluate_rubric_rule
        # Simulate rule evaluation fault with faulty predicate
        faulty_rule = RubricRule(
            rule_id="TEST_FAULT-001",
            domain="FAILURE_CLASS",
            title="Fault Rule",
            question="Will it fail safely?",
            category="AUTOMATED",
            exemption_predicate="FAULTY_PREDICATE",
        )
        # Register temporary faulty predicate
        from stagecheck.core.rubric_engine import EXEMPTION_PREDICATES
        EXEMPTION_PREDICATES["FAULTY_PREDICATE"] = lambda ws, r: (_ for _ in ()).throw(RuntimeError("Simulated fault"))
        try:
            res = evaluate_rubric_rule(faulty_rule, self.workspace, self.repo_dir)
            self.assertEqual(res.status, "FAIL")
            self.assertIn("Evaluation execution failure", res.message)
        finally:
            del EXEMPTION_PREDICATES["FAULTY_PREDICATE"]

    def test_rubric_coverage_is_measurable(self) -> None:
        """Verify catalog maps 100% of 270 rules across the 9 formal domain evaluators (Gap A)."""
        from stagecheck.core.rubric_engine import EVALUATOR_MAP, load_270_rule_catalog
        catalog = load_270_rule_catalog()
        self.assertEqual(len(catalog), 270)
        for rule in catalog:
            self.assertIn(rule.domain, EVALUATOR_MAP, f"Rule '{rule.rule_id}' must belong to an evaluated domain.")
            self.assertTrue(EVALUATOR_MAP[rule.domain], f"Domain '{rule.domain}' must have a non-empty evaluator.")


if __name__ == "__main__":
    unittest.main()
