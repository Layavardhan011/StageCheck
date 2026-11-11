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
    RubricEvaluationError,
    RuleEvaluationResult,
    aggregate_rubric_results,
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

    def _seed_full_compliant_workspace(self) -> None:
        """Populate authentic Phase-1, Phase-2A, Phase-2B, Phase-3, test, review, and waiver artifacts."""
        from stagecheck.core.agents_md import write_agents_contract
        from stagecheck.core.permissions import controlled_write_transaction
        from stagecheck.core.prompt_gate import freeze_prompt_and_scope
        from stagecheck.core.utils import canonical_json_dumps, sha256_file

        # 1. Real test suite with positive, negative, malformed, and duplicate/idempotency tests
        (self.repo_dir / "test_service.py").write_text(
            "import unittest\n\n\n"
            "def process_item(val):\n"
            "    if not isinstance(val, int):\n"
            "        raise TypeError('expected int')\n"
            "    if val < 0:\n"
            "        raise ValueError('negative disallowed')\n"
            "    return val * 2\n\n\n"
            "class TestService(unittest.TestCase):\n"
            "    def test_positive_calculation(self):\n"
            "        self.assertEqual(process_item(4), 8)\n\n"
            "    def test_negative_boundary_rejected(self):\n"
            "        with self.assertRaises(ValueError):\n"
            "            process_item(-1)\n\n"
            "    def test_malformed_input_invalid_type(self):\n"
            "        with self.assertRaises(TypeError):\n"
            "            process_item(None)\n\n"
            "    def test_duplicate_replay_idempotent(self):\n"
            "        first = process_item(5)\n"
            "        second = process_item(5)\n"
            "        self.assertEqual(first, second)\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "add", "test_service.py"], cwd=str(self.repo_dir), check=True)
        subprocess.run(["git", "commit", "-m", "add compliant tests"], cwd=str(self.repo_dir), check=True)
        head_sha = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=str(self.repo_dir), check=True, capture_output=True, text=True
        ).stdout.strip()

        # 2. Eval dir
        (self.workspace / "evals").mkdir(parents=True, exist_ok=True)

        # 3. Phase-1 artifacts + prompt freeze
        p1_dir = self.workspace / "evidence" / "tasks" / self.task_id / f"attempt_{self.attempt}" / "Phase-1"
        p1_dir.mkdir(parents=True, exist_ok=True)
        (p1_dir / "prompt.md").write_text("# Task Blueprint\nImplement service cleanly.\n", encoding="utf-8")
        (p1_dir / "declared_scope.json").write_text(
            canonical_json_dumps({
                "schema_version": "2.0",
                "task_id": self.task_id,
                "allowed_paths": ["repos/backend/**"],
                "read_only_paths": [],
                "forbidden_paths": [".git/**", "controls/**"],
            }),
            encoding="utf-8",
        )
        freeze_prompt_and_scope(self.workspace, self.task_id, self.attempt)

        # Mark Gate-1 cleared in ACTIVE_STATE
        state = load_active_state(self.workspace)
        state["cleared_gates"] = {"GATE_1": "0" * 64}
        save_active_state(self.workspace, state)

        # Issue history ledger
        (self.workspace / "evidence" / "issue_history.json").write_text(
            canonical_json_dumps({"schema_version": "1.0", "issues": []}),
            encoding="utf-8",
        )

        # 4. Human waivers (all 10 HUMAN_WAIVER rules) + AGENTS contract digest update
        catalog = load_270_rule_catalog()
        waiver_ids = [r.rule_id for r in catalog if r.category == "HUMAN_WAIVER"]
        disp_doc = {
            "schema_version": "2.0",
            "dispositions": [
                {
                    "disposition_id": "DISP-RUBRIC-001",
                    "task_id": self.task_id,
                    "rule_id": waiver_ids[0],
                    "waived_rules": waiver_ids,
                    "authorized_by": "human-operator",
                    "rationale": "Explicit operator authorization for test workspace",
                    "status": "APPROVED",
                }
            ],
        }
        with controlled_write_transaction(self.workspace / "controls"):
            (self.workspace / "controls" / "DISPOSITIONS.json").write_text(
                canonical_json_dumps(disp_doc), encoding="utf-8"
            )
        write_agents_contract(self.workspace)

        from stagecheck.core.utils import load_json_file
        prod_repos = load_json_file(self.workspace / "controls" / "PRODUCT_REPOSITORIES.json")
        baseline_sha = prod_repos["repositories"]["backend"]["baseline_head"]

        # 5. Phase-2A status + recorded Agent 1 semantic reviews for all 34 AGENT_ASSISTED rules
        p2a_dir = self.workspace / "evidence" / "tasks" / self.task_id / f"attempt_{self.attempt}" / "Phase-2A"
        p2a_dir.mkdir(parents=True, exist_ok=True)
        (p2a_dir / "pre_commit_status.json").write_text(
            canonical_json_dumps({
                "schema_version": "2.0",
                "task_id": self.task_id,
                "attempt": self.attempt,
                "cycle": 1,
                "status": "AWAITING_REVIEW",
                "touched_repositories": ["backend"],
                "base_commits": {"backend": baseline_sha},
                "summary": "Ready for pre-commit rubric verification",
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
        (p2a_dir / "agent_reviews.json").write_text(
            canonical_json_dumps({"task_id": self.task_id, "attempt": self.attempt, "agent_assisted_reviews": agent_reviews}),
            encoding="utf-8",
        )

        # 6. Phase-2B report & schema-valid claims
        p2b_dir = self.workspace / "evidence" / "tasks" / self.task_id / f"attempt_{self.attempt}" / "Phase-2B"
        p2b_dir.mkdir(parents=True, exist_ok=True)
        report_path = p2b_dir / "report.md"
        report_path.write_text("# Delivery Report\n\n## Summary\nVerified backend service and tests.\n", encoding="utf-8")
        (p2b_dir / "claims.json").write_text(
            canonical_json_dumps({
                "task_id": self.task_id,
                "iteration": 1,
                "contract_sha256": sha256_file(self.workspace / "AGENTS.md"),
                "record": "Phase-2B/report.md",
                "record_sha256": sha256_file(report_path),
                "claims": [],
            }),
            encoding="utf-8",
        )

        # 7. Phase-3 execution, scanner, verdict evidence
        p3_dir = self.workspace / "evidence" / "tasks" / self.task_id / f"attempt_{self.attempt}" / "Phase-3"
        p3_dir.mkdir(parents=True, exist_ok=True)
        (p3_dir / "test_execution.json").write_text(
            canonical_json_dumps({
                "schema_version": "2.0",
                "task_id": self.task_id,
                "attempt": self.attempt,
                "status": "PASS",
                "repositories": {"backend": {"status": "PASS", "exit_code": 0}},
            }),
            encoding="utf-8",
        )
        (p3_dir / "scanner_report.json").write_text(
            canonical_json_dumps({"schema_version": "2.0", "status": "CLEAN", "findings": []}),
            encoding="utf-8",
        )
        (p3_dir / "verdict.json").write_text(
            canonical_json_dumps({"schema_version": "2.0", "result": "CLEAR", "counts": {"blocking": 0}}),
            encoding="utf-8",
        )

    def test_cli_check_rubric_and_artifact_updates(self) -> None:
        """Verify 'stagecheck check-rubric --update-json' fails closed on incomplete state and passes on compliant state."""
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

        # 1. Incomplete workspace MUST fail closed (rc=1, REVISION_REQUIRED)
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc_inc = main([
                "check-rubric",
                "--task", self.task_id,
                "--update-json",
                "--workspace", str(self.workspace),
            ])
        self.assertEqual(rc_inc, 1)

        out = buf.getvalue()
        self.assertIn("STAGECHECK AUTOMATED AUDIT RUBRIC EVALUATOR", out)
        self.assertIn("Total Evaluated: 270 Rules", out)

        rubric_file = p2a_dir / "rubric_evaluation.json"
        self.assertTrue(rubric_file.is_file())
        r_inc = json.loads(rubric_file.read_text(encoding="utf-8"))
        self.assertEqual(r_inc["counts"]["total_rules"], 270)
        self.assertEqual(r_inc["overall_verdict"], "FAIL")
        validate_rubric_evaluation(r_inc)

        rev_inc = json.loads((p2a_dir / "pre_commit_review.json").read_text(encoding="utf-8"))
        self.assertIn("rubric_summary", rev_inc)
        self.assertEqual(rev_inc["rubric_summary"]["total_evaluated"], 270)
        self.assertEqual(rev_inc["status"], "REVISION_REQUIRED")

        # 2. Fully compliant workspace MUST pass all 270 rules (rc=0, overall_verdict=PASS)
        self._seed_full_compliant_workspace()
        buf_ok = io.StringIO()
        with redirect_stdout(buf_ok):
            rc_ok = main([
                "check-rubric",
                "--task", self.task_id,
                "--update-json",
                "--workspace", str(self.workspace),
            ])
        self.assertEqual(rc_ok, 0, f"Expected full pass on compliant workspace, stdout:\n{buf_ok.getvalue()}")

        r_ok = json.loads(rubric_file.read_text(encoding="utf-8"))
        self.assertEqual(r_ok["overall_verdict"], "PASS")
        self.assertEqual(r_ok["counts"]["failed"], 0)
        self.assertEqual(r_ok["counts"]["blocked"], 0)
        self.assertEqual(r_ok["counts"]["not_evaluated"], 0)
        self.assertEqual(r_ok["counts"]["passed"] + r_ok["counts"]["not_applicable"], 270)
        validate_rubric_evaluation(r_ok)

        rev_ok = json.loads((p2a_dir / "pre_commit_review.json").read_text(encoding="utf-8"))
        self.assertEqual(rev_ok["rubric_summary"]["failed"], 0)
        self.assertEqual(rev_ok["rubric_summary"]["blocked"], 0)
        self.assertEqual(rev_ok["rubric_summary"]["not_evaluated"], 0)
        self.assertEqual(
            rev_ok["rubric_summary"]["passed"] + rev_ok["rubric_summary"]["not_applicable"], 270
        )

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

    def test_verdict_aggregation_all_pass_produces_pass(self) -> None:
        """Verify all required rules passing produces overall PASS (GAP-01)."""
        evals = [
            RuleEvaluationResult("R1", "BLAST_RADIUS", "AUTOMATED", "PASS", "blast_eval"),
            RuleEvaluationResult("R2", "BLAST_RADIUS", "AUTOMATED", "PASS", "blast_eval"),
            RuleEvaluationResult("R3", "FAILURE_CLASS", "AUTOMATED", "NOT_APPLICABLE", "structural_predicate_evaluator"),
        ]
        verdict, counts, domains = aggregate_rubric_results(evals)
        self.assertEqual(verdict, "PASS")
        self.assertEqual(counts["passed"], 2)
        self.assertEqual(counts["not_applicable"], 1)
        self.assertEqual(counts["failed"], 0)
        self.assertEqual(domains["BLAST_RADIUS"]["status"], "PASS")
        self.assertEqual(domains["FAILURE_CLASS"]["status"], "PASS")

    def test_verdict_aggregation_single_fail_produces_fail(self) -> None:
        """Verify a single FAIL result causes overall verdict and domain to FAIL (GAP-01)."""
        evals = [
            RuleEvaluationResult("R1", "BLAST_RADIUS", "AUTOMATED", "PASS", "blast_eval"),
            RuleEvaluationResult("R2", "BLAST_RADIUS", "AUTOMATED", "FAIL", "blast_eval", message="Scope violation"),
        ]
        verdict, counts, domains = aggregate_rubric_results(evals)
        self.assertEqual(verdict, "FAIL")
        self.assertEqual(counts["failed"], 1)
        self.assertEqual(domains["BLAST_RADIUS"]["status"], "FAIL")

    def test_verdict_aggregation_unevaluated_cannot_produce_pass(self) -> None:
        """Verify a required rule returning NOT_EVALUATED cannot produce an overall PASS (GAP-01)."""
        evals = [
            RuleEvaluationResult("R1", "BLAST_RADIUS", "AUTOMATED", "PASS", "blast_eval"),
            RuleEvaluationResult("R2", "BLAST_RADIUS", "AGENT_ASSISTED", "NOT_EVALUATED", "agent_assisted_evaluator"),
        ]
        verdict, counts, domains = aggregate_rubric_results(evals)
        self.assertEqual(verdict, "FAIL", "Unevaluated required rule must not silently produce PASS.")
        self.assertEqual(counts["not_evaluated"], 1)
        self.assertEqual(domains["BLAST_RADIUS"]["status"], "NOT_EVALUATED")

    def test_verdict_aggregation_blocked_cannot_produce_pass(self) -> None:
        """Verify a required rule returning BLOCKED cannot produce an overall PASS (GAP-01)."""
        evals = [
            RuleEvaluationResult("R1", "BLAST_RADIUS", "AUTOMATED", "PASS", "blast_eval"),
            RuleEvaluationResult("R2", "BLAST_RADIUS", "HUMAN_WAIVER", "BLOCKED", "human_waiver_evaluator"),
        ]
        verdict, counts, domains = aggregate_rubric_results(evals)
        self.assertEqual(verdict, "FAIL", "Blocked required rule must not silently produce PASS.")
        self.assertEqual(counts["blocked"], 1)
        self.assertEqual(domains["BLAST_RADIUS"]["status"], "BLOCKED")

    def test_domain_summary_cannot_report_pass_when_rules_unevaluated(self) -> None:
        """Verify domain summaries cannot report PASS when rules are unevaluated or blocked (GAP-03)."""
        evals = [
            RuleEvaluationResult("R1", "CLAIM_SUPPORT", "AUTOMATED", "PASS", "claim_eval"),
            RuleEvaluationResult("R2", "CLAIM_SUPPORT", "EVIDENCE", "NOT_EVALUATED", "phase_evidence_validator"),
            RuleEvaluationResult("R3", "ORCHESTRATOR", "HUMAN_WAIVER", "BLOCKED", "human_waiver_evaluator"),
        ]
        verdict, counts, domains = aggregate_rubric_results(evals)
        self.assertEqual(domains["CLAIM_SUPPORT"]["status"], "NOT_EVALUATED")
        self.assertEqual(domains["ORCHESTRATOR"]["status"], "BLOCKED")
        self.assertEqual(verdict, "FAIL")

    def test_domain_and_overall_counts_are_consistent(self) -> None:
        """Verify mathematical consistency between overall counts and domain counts (GAP-01/03)."""
        evals = [
            RuleEvaluationResult("R1", "BLAST_RADIUS", "AUTOMATED", "PASS", "eval1"),
            RuleEvaluationResult("R2", "BLAST_RADIUS", "AUTOMATED", "FAIL", "eval1"),
            RuleEvaluationResult("R3", "TEST_ADEQUACY", "AUTOMATED", "NOT_APPLICABLE", "eval2"),
            RuleEvaluationResult("R4", "TEST_ADEQUACY", "AGENT_ASSISTED", "NOT_EVALUATED", "eval2"),
            RuleEvaluationResult("R5", "FAILURE_CLASS", "HUMAN_WAIVER", "BLOCKED", "eval3"),
        ]
        verdict, counts, domains = aggregate_rubric_results(evals)

        # Check total rules sum
        sum_domain_total = sum(d["counts"]["total_rules"] for d in domains.values())
        sum_domain_passed = sum(d["counts"]["passed"] for d in domains.values())
        sum_domain_failed = sum(d["counts"]["failed"] for d in domains.values())
        sum_domain_na = sum(d["counts"]["not_applicable"] for d in domains.values())
        sum_domain_not_eval = sum(d["counts"]["not_evaluated"] for d in domains.values())
        sum_domain_blocked = sum(d["counts"]["blocked"] for d in domains.values())

        self.assertEqual(counts["total_rules"], sum_domain_total)
        self.assertEqual(counts["passed"], sum_domain_passed)
        self.assertEqual(counts["failed"], sum_domain_failed)
        self.assertEqual(counts["not_applicable"], sum_domain_na)
        self.assertEqual(counts["not_evaluated"], sum_domain_not_eval)
        self.assertEqual(counts["blocked"], sum_domain_blocked)

    def test_mixed_domain_statuses_aggregation(self) -> None:
        """Verify domain aggregation with mixed rule statuses follows strict priority: FAIL > BLOCKED > NOT_EVALUATED > PASS (GAP-03)."""
        # Domain with PASS and FAIL -> FAIL
        mix_fail = [
            RuleEvaluationResult("R1", "D1", "AUTOMATED", "PASS", "eval"),
            RuleEvaluationResult("R2", "D1", "AUTOMATED", "BLOCKED", "eval"),
            RuleEvaluationResult("R3", "D1", "AUTOMATED", "FAIL", "eval"),
        ]
        _, _, d_fail = aggregate_rubric_results(mix_fail)
        self.assertEqual(d_fail["D1"]["status"], "FAIL")

        # Domain with PASS, NOT_EVALUATED, and BLOCKED (no FAIL) -> BLOCKED
        mix_blocked = [
            RuleEvaluationResult("R1", "D2", "AUTOMATED", "PASS", "eval"),
            RuleEvaluationResult("R2", "D2", "AUTOMATED", "NOT_EVALUATED", "eval"),
            RuleEvaluationResult("R3", "D2", "AUTOMATED", "BLOCKED", "eval"),
        ]
        _, _, d_blk = aggregate_rubric_results(mix_blocked)
        self.assertEqual(d_blk["D2"]["status"], "BLOCKED")

        # Domain with PASS and NOT_EVALUATED (no FAIL or BLOCKED) -> NOT_EVALUATED
        mix_noteval = [
            RuleEvaluationResult("R1", "D3", "AUTOMATED", "PASS", "eval"),
            RuleEvaluationResult("R2", "D3", "AUTOMATED", "NOT_EVALUATED", "eval"),
        ]
        _, _, d_ne = aggregate_rubric_results(mix_noteval)
        self.assertEqual(d_ne["D3"]["status"], "NOT_EVALUATED")

    def test_audit_matrix_completeness_and_no_bogus_exemptions(self) -> None:
        """Verify 270-rule audit matrix completeness, schema fields, and absence of mismatched React/Flask exemptions (GAP-01)."""
        from stagecheck.core.rubric_engine import get_rule_strategy, load_270_rule_audit_matrix

        matrix = load_270_rule_audit_matrix()
        catalog = load_270_rule_catalog()
        self.assertEqual(len(matrix), 270)
        self.assertEqual([e["rule_id"] for e in matrix], [r.rule_id for r in catalog])

        required_fields = (
            "rule_id",
            "domain",
            "category",
            "original_criterion",
            "evaluation_strategy",
            "evaluator_implementation",
            "required_inputs",
            "required_evidence",
            "evidence_validation_method",
            "expected_result_statuses",
            "corresponding_tests",
            "verification_outcome",
        )
        cat_counts: dict[str, int] = {}
        for entry in matrix:
            for field in required_fields:
                self.assertIn(field, entry)
                val = entry[field]
                if isinstance(val, str):
                    self.assertTrue(val.strip(), f"Empty {field} for {entry['rule_id']}")
                elif isinstance(val, (list, dict)):
                    self.assertTrue(len(val) > 0, f"Empty {field} for {entry['rule_id']}")
            self.assertEqual(entry["verification_outcome"], "VERIFIED")
            cat_counts[entry["category"]] = cat_counts.get(entry["category"], 0) + 1
            self.assertIsNotNone(get_rule_strategy(entry["rule_id"]))

        self.assertEqual(cat_counts, {"AUTOMATED": 162, "EVIDENCE": 64, "AGENT_ASSISTED": 34, "HUMAN_WAIVER": 10})

        # Ensure generic test/error/scope rules were stripped of bogus React/Flask/TSX predicates
        for rid in ("TEST_ADEQUACY-018", "TEST_ADEQUACY-019", "FAILURE_CLASS-029", "BLAST_RADIUS-030"):
            strat = get_rule_strategy(rid)
            self.assertIsNotNone(strat)
            self.assertIsNone(strat.get("exemption_predicate"), f"Rule {rid} must not carry bogus exemption predicate")

    def test_human_waiver_rules_require_real_approved_dispositions(self) -> None:
        """Verify all 10 HUMAN_WAIVER rules return BLOCKED without task-scoped APPROVED waiver and PASS with one."""
        from stagecheck.core.permissions import controlled_write_transaction
        from stagecheck.core.utils import canonical_json_dumps

        # Without dispositions -> all 10 COMMON-001..010 are BLOCKED
        payload_missing, _ = run_rubric_evaluation(self.workspace, self.task_id, self.attempt)
        waiver_evals = [e for e in payload_missing["evaluations"] if e["category"] == "HUMAN_WAIVER"]
        self.assertEqual(len(waiver_evals), 10)
        self.assertTrue(all(e["status"] == "BLOCKED" for e in waiver_evals))
        self.assertEqual(payload_missing["overall_verdict"], "FAIL")

        # Disposition for another task or non-APPROVED status must NOT satisfy
        with controlled_write_transaction(self.workspace / "controls"):
            (self.workspace / "controls" / "DISPOSITIONS.json").write_text(
                canonical_json_dumps({
                    "schema_version": "2.0",
                    "dispositions": [
                        {
                            "disposition_id": "DISP-OTHER",
                            "task_id": "other-task",
                            "rule_id": "COMMON-001",
                            "waived_rules": [f"COMMON-{i:03d}" for i in range(1, 11)],
                            "authorized_by": "human-operator",
                            "rationale": "Wrong task scope",
                            "status": "APPROVED",
                        },
                        {
                            "disposition_id": "DISP-PENDING",
                            "task_id": self.task_id,
                            "rule_id": "COMMON-001",
                            "waived_rules": [f"COMMON-{i:03d}" for i in range(1, 11)],
                            "authorized_by": "human-operator",
                            "rationale": "Pending only",
                            "status": "PENDING",
                        },
                    ],
                }),
                encoding="utf-8",
            )
        payload_wrong, _ = run_rubric_evaluation(self.workspace, self.task_id, self.attempt)
        waiver_wrong = [e for e in payload_wrong["evaluations"] if e["category"] == "HUMAN_WAIVER"]
        self.assertTrue(all(e["status"] == "BLOCKED" for e in waiver_wrong))

        # Approved disposition scoped to active task -> PASS
        with controlled_write_transaction(self.workspace / "controls"):
            (self.workspace / "controls" / "DISPOSITIONS.json").write_text(
                canonical_json_dumps({
                    "schema_version": "2.0",
                    "dispositions": [
                        {
                            "disposition_id": "DISP-ACTIVE",
                            "task_id": self.task_id,
                            "rule_id": "COMMON-001",
                            "waived_rules": [f"COMMON-{i:03d}" for i in range(1, 11)],
                            "authorized_by": "human-operator",
                            "rationale": "Operator approved",
                            "status": "APPROVED",
                        }
                    ],
                }),
                encoding="utf-8",
            )
        payload_ok, _ = run_rubric_evaluation(self.workspace, self.task_id, self.attempt)
        waiver_ok = [e for e in payload_ok["evaluations"] if e["category"] == "HUMAN_WAIVER"]
        self.assertTrue(all(e["status"] == "PASS" for e in waiver_ok))

    def test_agent_assisted_rules_require_real_recorded_reviews(self) -> None:
        """Verify AGENT_ASSISTED rules fail closed when missing, report FAIL on negative review, and block self-exemption."""
        from stagecheck.core.rubric_engine import evaluate_rubric_rule
        from stagecheck.core.utils import canonical_json_dumps

        # Without recorded reviews -> all 34 AGENT_ASSISTED rules are NOT_EVALUATED
        payload_missing, _ = run_rubric_evaluation(self.workspace, self.task_id, self.attempt)
        aa_missing = [e for e in payload_missing["evaluations"] if e["category"] == "AGENT_ASSISTED"]
        self.assertEqual(len(aa_missing), 34)
        self.assertTrue(all(e["status"] == "NOT_EVALUATED" for e in aa_missing))

        # Record a FAIL review for one rule and PASS for another
        p2a_dir = self.workspace / "evidence" / "tasks" / self.task_id / f"attempt_{self.attempt}" / "Phase-2A"
        p2a_dir.mkdir(parents=True, exist_ok=True)
        aa_rule_ids = [r.rule_id for r in load_270_rule_catalog() if r.category == "AGENT_ASSISTED"]
        reviews = {
            aa_rule_ids[0]: {"status": "FAIL", "rationale": "Semantic flaw detected in module."},
            aa_rule_ids[1]: {"status": "PASS", "rationale": "Reviewed and verified clean."},
        }
        (p2a_dir / "agent_reviews.json").write_text(
            canonical_json_dumps({"agent_assisted_reviews": reviews}), encoding="utf-8"
        )
        payload_mixed, _ = run_rubric_evaluation(self.workspace, self.task_id, self.attempt)
        by_id = {e["rule_id"]: e for e in payload_mixed["evaluations"]}
        self.assertEqual(by_id[aa_rule_ids[0]]["status"], "FAIL")
        self.assertEqual(by_id[aa_rule_ids[1]]["status"], "PASS")
        self.assertEqual(by_id[aa_rule_ids[2]]["status"], "NOT_EVALUATED")

        # Self NOT_APPLICABLE inside AGENT_ASSISTED review must raise InvalidRubricExemptionError
        aa_rule = next(r for r in load_270_rule_catalog() if r.rule_id == aa_rule_ids[0])
        with self.assertRaises(InvalidRubricExemptionError):
            evaluate_rubric_rule(
                aa_rule,
                self.workspace,
                self.repo_dir,
                context={"agent_reviews": {aa_rule_ids[0]: {"status": "NOT_APPLICABLE", "rationale": "skip"}}},
            )

    def test_real_ast_hygiene_and_evidence_failures_detected(self) -> None:
        """Verify AST checks and phase evidence checks catch real defects rather than auto-passing."""
        self._seed_full_compliant_workspace()

        # 1. Inject weak assertion, sleep, and skip into test_service.py -> TEST_ADEQUACY-006/010/021 FAIL
        (self.repo_dir / "test_service.py").write_text(
            "import time\nimport unittest\n\n"
            "class TestWeak(unittest.TestCase):\n"
            "    @unittest.skip('flaky')\n"
            "    def test_bad(self):\n"
            "        time.sleep(0.01)\n"
            "        assert True\n",
            encoding="utf-8",
        )
        # 2. Unpinned requirement -> UPSTREAM_REUSE-001 FAIL
        (self.repo_dir / "requirements.txt").write_text("requests>=2.0.0\n", encoding="utf-8")
        # 3. Remove Phase-2B/claims.json -> CLAIM_SUPPORT-001 FAIL
        (self.workspace / "evidence" / "tasks" / self.task_id / f"attempt_{self.attempt}" / "Phase-2B" / "claims.json").unlink()
        # 4. Remove Phase-3/test_execution.json -> TEST_ADEQUACY-026 FAIL
        (self.workspace / "evidence" / "tasks" / self.task_id / f"attempt_{self.attempt}" / "Phase-3" / "test_execution.json").unlink()

        payload, _ = run_rubric_evaluation(self.workspace, self.task_id, self.attempt)
        by_id = {e["rule_id"]: e for e in payload["evaluations"]}

        self.assertEqual(payload["overall_verdict"], "FAIL")
        self.assertEqual(by_id["TEST_ADEQUACY-006"]["status"], "FAIL")
        self.assertEqual(by_id["TEST_ADEQUACY-010"]["status"], "FAIL")
        self.assertEqual(by_id["TEST_ADEQUACY-017"]["status"], "FAIL")
        self.assertEqual(by_id["TEST_ADEQUACY-018"]["status"], "FAIL")
        self.assertEqual(by_id["TEST_ADEQUACY-019"]["status"], "FAIL")
        self.assertEqual(by_id["TEST_ADEQUACY-021"]["status"], "FAIL")
        self.assertEqual(by_id["UPSTREAM_REUSE-001"]["status"], "FAIL")
        self.assertEqual(by_id["CLAIM_SUPPORT-001"]["status"], "FAIL")
        self.assertEqual(by_id["TEST_ADEQUACY-026"]["status"], "FAIL")

    def test_review_precommit_blocks_when_rubric_has_blocked_or_unevaluated_rules(self) -> None:
        """Verify review-precommit fails closed (REVISION_REQUIRED) if BLOCKED or NOT_EVALUATED rules exist even with failed=0."""
        from unittest.mock import patch
        from stagecheck.core.gate_engine import GateId, advance_gate_atomic
        from stagecheck.core.prompt_gate import freeze_prompt_and_scope
        from stagecheck.core.utils import canonical_json_dumps

        self._seed_full_compliant_workspace()
        state = load_active_state(self.workspace)
        state["phase"] = "PHASE_1_PLANNING"
        state["cleared_gates"] = {}
        save_active_state(self.workspace, state)
        # Re-freeze Phase-1 after setup and advance Gate-1 legitimately
        freeze_prompt_and_scope(self.workspace, self.task_id, self.attempt)
        advance_gate_atomic(self.workspace, GateId.GATE_1, self.task_id, self.attempt)

        fake_incomplete_payload = {
            "schema_version": "2.0.0",
            "task_id": self.task_id,
            "attempt": self.attempt,
            "cycle": 1,
            "overall_verdict": "FAIL",
            "evaluation_duration_ms": 1.0,
            "counts": {"total_rules": 270, "passed": 268, "failed": 0, "not_applicable": 0, "not_evaluated": 1, "blocked": 1},
            "domains": {},
            "evaluations": [
                {"rule_id": "COMMON-001", "domain": "COMMON", "category": "HUMAN_WAIVER", "status": "BLOCKED", "witness": "controls/DISPOSITIONS.json", "message": "Missing waiver"},
                {"rule_id": "BLAST_RADIUS-005", "domain": "BLAST_RADIUS", "category": "AGENT_ASSISTED", "status": "NOT_EVALUATED", "witness": "Phase-2A/agent_reviews.json", "message": "Missing review"},
            ],
        }
        p2a_dir = self.workspace / "evidence" / "tasks" / self.task_id / f"attempt_{self.attempt}" / "Phase-2A"
        with patch("stagecheck.core.rubric_engine.run_rubric_evaluation", return_value=(fake_incomplete_payload, 1.0)):
            rc = main(["review-precommit", "--task", self.task_id, "--attempt", str(self.attempt), "--workspace", str(self.workspace)])
        self.assertEqual(rc, 1)
        rev = json.loads((p2a_dir / "pre_commit_review.json").read_text(encoding="utf-8"))
        self.assertEqual(rev["status"], "REVISION_REQUIRED")
        self.assertEqual(len(rev["new_issues_found"]), 2)


if __name__ == "__main__":
    unittest.main()
