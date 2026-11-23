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
        from stagecheck.core.dispositions import build_waiver_entry, record_waiver_in_replay_ledger
        from stagecheck.core.rubric_engine import build_agent_reviews_artifact

        waiver_evidence = self.workspace / "evidence" / "waiver_evidence.txt"
        waiver_evidence.parent.mkdir(parents=True, exist_ok=True)
        waiver_evidence.write_text("Approved human waiver supporting evidence.\n", encoding="utf-8")

        catalog = load_270_rule_catalog()
        waiver_ids = [r.rule_id for r in catalog if r.category == "HUMAN_WAIVER"]
        w_entry = build_waiver_entry(
            workspace_root=self.workspace,
            task_id=self.task_id,
            defect_id=waiver_ids[0],
            rationale="Explicit operator authorization for test workspace",
            authorized_by="owner@stagecheck.local",
            attempt=self.attempt,
            evidence_path="evidence/waiver_evidence.txt",
            rule_id=waiver_ids[0],
            waived_rules=waiver_ids,
        )
        disp_doc = {
            "schema_version": "2.0",
            "dispositions": [w_entry],
        }
        with controlled_write_transaction(self.workspace / "controls"):
            (self.workspace / "controls" / "DISPOSITIONS.json").write_text(
                canonical_json_dumps(disp_doc), encoding="utf-8"
            )
        record_waiver_in_replay_ledger(self.workspace, w_entry)
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
        reviews_artifact = build_agent_reviews_artifact(
            workspace_root=self.workspace,
            task_id=self.task_id,
            attempt=self.attempt,
            reviews=agent_reviews,
            reviewer="agent1",
            reviewer_role="prompt_and_audit",
        )
        (p2a_dir / "agent_reviews.json").write_text(
            canonical_json_dumps(reviews_artifact),
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
        """Verify evidence-dependent rules fail safely when evidence is missing (Gap A / GAP-01)."""
        from stagecheck.core.rubric_engine import evaluate_rubric_rule
        evidence_rule = next(r for r in load_270_rule_catalog() if r.rule_id == "CLAIM_SUPPORT-001")
        # Context indicates missing evidence artifact
        ctx = {"missing_evidence": ["CLAIM_SUPPORT-001"]}
        res = evaluate_rubric_rule(evidence_rule, self.workspace, self.repo_dir, context=ctx)
        self.assertEqual(res.status, "FAIL")
        self.assertEqual(res.evaluator, "phase_evidence_validator")
        self.assertEqual(res.evaluation_strategy, "claim_evidence_literal_entailment_check")
        self.assertIn("Missing required evidence", res.message)

    def test_rule_specific_failure_is_reported_correctly(self) -> None:
        """Verify domain-specific evaluators report failures with witnesses and messages (Gap A / GAP-01)."""
        from stagecheck.core.rubric_engine import evaluate_rubric_rule
        # Test UPSTREAM_REUSE failure with unpinned dependencies
        upstream_rule = next(r for r in load_270_rule_catalog() if r.rule_id == "UPSTREAM_REUSE-001")
        ctx = {"unpinned_dependencies": ["fastapi>=0.0.0"]}
        res = evaluate_rubric_rule(upstream_rule, self.workspace, self.repo_dir, context=ctx)
        self.assertEqual(res.status, "FAIL")
        self.assertEqual(res.evaluator, "upstream_reuse_dependency_analyzer")
        self.assertEqual(res.evaluation_strategy, "upstream_reuse_exact_baseline_pin_and_policy_check")
        self.assertEqual(res.witness, "fastapi>=0.0.0")
        self.assertIn("Unpinned wildcard dependency detected", res.message)

    def test_valid_rule_specific_pass_is_reported_correctly(self) -> None:
        """Verify passing rules report their explicit evaluator, strategy, and witness metadata (Gap A / GAP-01)."""
        from stagecheck.core.rubric_engine import evaluate_rubric_rule
        from stagecheck.core.utils import canonical_json_dumps

        p1_dir = self.workspace / "evidence" / "tasks" / self.task_id / f"attempt_{self.attempt}" / "Phase-1"
        p1_dir.mkdir(parents=True, exist_ok=True)
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
        blast_rule = next(r for r in load_270_rule_catalog() if r.rule_id == "BLAST_RADIUS-001")
        res = evaluate_rubric_rule(blast_rule, self.workspace, self.repo_dir, context={})
        self.assertEqual(res.status, "PASS")
        self.assertEqual(res.evaluator, "blast_radius_containment")
        self.assertEqual(res.evaluation_strategy, "blast_radius_producer_boundary_ast_and_scope_check")
        self.assertEqual(res.witness, "scope_containment_verified")

    def test_evaluation_errors_handled_safely(self) -> None:
        """Verify evaluation exceptions fail closed with FAIL status rather than crashing or passing (Gap A / GAP-01)."""
        from stagecheck.core.rubric_engine import EXEMPTION_PREDICATES, evaluate_rubric_rule

        canonical_rule = next(r for r in load_270_rule_catalog() if r.rule_id == "BLAST_RADIUS-013")
        orig_pred = EXEMPTION_PREDICATES["PREDICATE_NO_BLOCKCHAIN_PROTOCOL"]
        EXEMPTION_PREDICATES["PREDICATE_NO_BLOCKCHAIN_PROTOCOL"] = (
            lambda ws, r: (_ for _ in ()).throw(RuntimeError("Simulated fault"))
        )
        try:
            res = evaluate_rubric_rule(canonical_rule, self.workspace, self.repo_dir)
            self.assertEqual(res.status, "FAIL")
            self.assertIn("Evaluation execution failure", res.message)
        finally:
            EXEMPTION_PREDICATES["PREDICATE_NO_BLOCKCHAIN_PROTOCOL"] = orig_pred

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
        """Verify clean tasks do not block on HUMAN_WAIVER (GOV-002), while required waivers enforce provenance."""
        from stagecheck.core.permissions import controlled_write_transaction
        from stagecheck.core.utils import canonical_json_dumps

        # Clean task with no active waiver requirement -> COMMON-001..010 do NOT block (GOV-002)
        payload_clean, _ = run_rubric_evaluation(self.workspace, self.task_id, self.attempt)
        waiver_clean = [e for e in payload_clean["evaluations"] if e["category"] == "HUMAN_WAIVER"]
        self.assertEqual(len(waiver_clean), 10)
        self.assertTrue(all(e["status"] == "PASS" for e in waiver_clean))

        # When waivers ARE required without dispositions -> all 10 COMMON-001..010 are BLOCKED
        payload_missing, _ = run_rubric_evaluation(
            self.workspace,
            self.task_id,
            self.attempt,
            context={"require_human_waivers": True},
        )
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
        payload_wrong, _ = run_rubric_evaluation(
            self.workspace,
            self.task_id,
            self.attempt,
            context={"require_human_waivers": True},
        )
        waiver_wrong = [e for e in payload_wrong["evaluations"] if e["category"] == "HUMAN_WAIVER"]
        self.assertTrue(all(e["status"] in ("BLOCKED", "FAIL") for e in waiver_wrong))

        # Approved disposition scoped to active task with valid provenance -> PASS
        from stagecheck.core.agents_md import write_agents_contract
        from stagecheck.core.dispositions import build_waiver_entry, record_waiver_in_replay_ledger

        waiver_evidence = self.workspace / "evidence" / "waiver_active.txt"
        waiver_evidence.parent.mkdir(parents=True, exist_ok=True)
        waiver_evidence.write_text("Approved waiver evidence artifact.\n", encoding="utf-8")
        waiver_ids = [f"COMMON-{i:03d}" for i in range(1, 11)]
        w_active = build_waiver_entry(
            workspace_root=self.workspace,
            task_id=self.task_id,
            defect_id="COMMON-001",
            rationale="Operator approved waiver with verified provenance",
            authorized_by="owner@stagecheck.local",
            attempt=self.attempt,
            evidence_path="evidence/waiver_active.txt",
            rule_id="COMMON-001",
            waived_rules=waiver_ids,
        )
        with controlled_write_transaction(self.workspace / "controls"):
            (self.workspace / "controls" / "DISPOSITIONS.json").write_text(
                canonical_json_dumps({
                    "schema_version": "2.0",
                    "dispositions": [w_active],
                }),
                encoding="utf-8",
            )
        record_waiver_in_replay_ledger(self.workspace, w_active)
        write_agents_contract(self.workspace)
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
        from stagecheck.core.rubric_engine import build_agent_reviews_artifact

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
                "summary": "Pre-commit ready for semantic review",
            }),
            encoding="utf-8",
        )
        aa_rule_ids = [r.rule_id for r in load_270_rule_catalog() if r.category == "AGENT_ASSISTED"]
        reviews = {
            aa_rule_ids[0]: {"status": "FAIL", "rationale": "Semantic flaw detected in module."},
            aa_rule_ids[1]: {"status": "PASS", "rationale": "Reviewed and verified clean."},
        }
        reviews_artifact = build_agent_reviews_artifact(
            workspace_root=self.workspace,
            task_id=self.task_id,
            attempt=self.attempt,
            reviews=reviews,
            reviewer="agent1",
            reviewer_role="prompt_and_audit",
        )
        (p2a_dir / "agent_reviews.json").write_text(
            canonical_json_dumps(reviews_artifact), encoding="utf-8"
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

        # Advance to PHASE_3_AUDIT so Phase-2B/Phase-3 artifact requirements are strictly enforced
        state = load_active_state(self.workspace)
        state["phase"] = "PHASE_3_AUDIT"
        save_active_state(self.workspace, state)

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

    def test_gap02_complete_vs_partial_classification_duplicates_and_stale_rejection(self) -> None:
        """Verify GAP-02 COMPLETE/PARTIAL classification, duplicate rejection, binding, and staleness checks."""
        import datetime
        from stagecheck.core.rubric_engine import (
            DuplicateRuleEvaluationError,
            RuleEvaluationResult,
            aggregate_rubric_results,
            validate_rubric_evaluation_payload,
            verify_complete_rubric_evaluation,
        )
        from stagecheck.core.utils import canonical_json_dumps

        self._seed_full_compliant_workspace()

        # 1. Partial domain evaluation explicitly classified PARTIAL with missing_rules and FAIL verdict
        partial_payload, _ = run_rubric_evaluation(
            self.workspace,
            self.task_id,
            self.attempt,
            target_domain="COMMON",
        )
        self.assertEqual(partial_payload["evaluation_completeness"], "PARTIAL")
        self.assertEqual(partial_payload["expected_rule_count"], 270)
        self.assertEqual(partial_payload["evaluated_rule_count"], 30)
        self.assertEqual(len(partial_payload["missing_rules"]), 240)
        self.assertEqual(partial_payload["duplicate_rules"], [])
        self.assertEqual(partial_payload["target_domain"], "COMMON")
        self.assertEqual(partial_payload["overall_verdict"], "FAIL")

        # 2. Full evaluation classifies COMPLETE with 270/270 rules and PASS verdict
        full_payload, _ = run_rubric_evaluation(self.workspace, self.task_id, self.attempt)
        self.assertEqual(full_payload["evaluation_completeness"], "COMPLETE")
        self.assertEqual(full_payload["expected_rule_count"], 270)
        self.assertEqual(full_payload["evaluated_rule_count"], 270)
        self.assertEqual(full_payload["missing_rules"], [])
        self.assertEqual(full_payload["duplicate_rules"], [])
        self.assertEqual(full_payload["overall_verdict"], "PASS")

        p2a_dir = self.workspace / "evidence" / "tasks" / self.task_id / f"attempt_{self.attempt}" / "Phase-2A"
        rubric_file = p2a_dir / "rubric_evaluation.json"
        rubric_file.write_text(canonical_json_dumps(full_payload), encoding="utf-8")

        ok_fresh, reasons_fresh, _ = verify_complete_rubric_evaluation(
            self.workspace, rubric_file, self.task_id, self.attempt, cycle=1
        )
        self.assertTrue(ok_fresh, f"Expected fresh COMPLETE verification to pass: {reasons_fresh}")

        # 3. Duplicate rule rejection
        dup_item = RuleEvaluationResult(
            rule_id="COMMON-001", domain="COMMON", category="HUMAN_WAIVER", status="PASS", message="ok"
        )
        with self.assertRaises(DuplicateRuleEvaluationError):
            validate_rubric_evaluation_payload([dup_item, dup_item])
        with self.assertRaises(DuplicateRuleEvaluationError):
            aggregate_rubric_results([dup_item, dup_item])

        tampered_dup = dict(full_payload)
        tampered_dup["evaluations"] = list(full_payload["evaluations"][:-1]) + [dict(full_payload["evaluations"][0])]
        rubric_file.write_text(canonical_json_dumps(tampered_dup), encoding="utf-8")
        ok_dup, dup_reasons, _ = verify_complete_rubric_evaluation(
            self.workspace, rubric_file, self.task_id, self.attempt, cycle=1
        )
        self.assertFalse(ok_dup)
        self.assertTrue(any("duplicate" in r.lower() for r in dup_reasons))

        # 4. Task / attempt / cycle binding mismatch rejection
        rubric_file.write_text(canonical_json_dumps(full_payload), encoding="utf-8")
        ok_task, _, _ = verify_complete_rubric_evaluation(self.workspace, rubric_file, "wrong-task", self.attempt)
        ok_att, _, _ = verify_complete_rubric_evaluation(self.workspace, rubric_file, self.task_id, self.attempt + 1)
        ok_cyc, _, _ = verify_complete_rubric_evaluation(self.workspace, rubric_file, self.task_id, self.attempt, cycle=9)
        self.assertFalse(ok_task)
        self.assertFalse(ok_att)
        self.assertFalse(ok_cyc)

        # 5. Stale age rejection
        stale_age = dict(full_payload)
        stale_age["evaluated_at"] = (
            datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=48)
        ).isoformat().replace("+00:00", "Z")
        rubric_file.write_text(canonical_json_dumps(stale_age), encoding="utf-8")
        ok_old, old_reasons, _ = verify_complete_rubric_evaluation(
            self.workspace, rubric_file, self.task_id, self.attempt, max_age_seconds=3600
        )
        self.assertFalse(ok_old)
        self.assertTrue(any("stale" in r.lower() or "expired" in r.lower() for r in old_reasons))

        # 6. Stale context_digest rejection after modifying repository source
        rubric_file.write_text(canonical_json_dumps(full_payload), encoding="utf-8")
        (self.repo_dir / "service.py").write_text("def add(a, b):\n    return a + b + 1\n", encoding="utf-8")
        ok_dirty, dirty_reasons, _ = verify_complete_rubric_evaluation(
            self.workspace, rubric_file, self.task_id, self.attempt, require_fresh_context=True
        )
        self.assertFalse(ok_dirty)
        self.assertTrue(any("context_digest" in r or "stale" in r.lower() for r in dirty_reasons))

    def test_gap02_gates_reject_partial_rubric_evaluations(self) -> None:
        """Verify approve-review, Gate-2A, and Gate-3 reject partial 30-rule rubric payloads."""
        from stagecheck.core.gate_engine import GateId, advance_gate_atomic, check_gate_preconditions
        from stagecheck.core.prompt_gate import freeze_prompt_and_scope
        from stagecheck.core.utils import canonical_json_dumps

        self._seed_full_compliant_workspace()
        state = load_active_state(self.workspace)
        state["phase"] = "PHASE_1_PLANNING"
        state["cleared_gates"] = {}
        save_active_state(self.workspace, state)
        freeze_prompt_and_scope(self.workspace, self.task_id, self.attempt)
        advance_gate_atomic(self.workspace, GateId.GATE_1, self.task_id, self.attempt)

        # Write a partial (COMMON-only) rubric payload marked artificially PASS to test fail-closed gates
        partial_payload, _ = run_rubric_evaluation(
            self.workspace, self.task_id, self.attempt, target_domain="COMMON"
        )
        spoofed_partial = dict(partial_payload)
        spoofed_partial["overall_verdict"] = "PASS"

        p2a_dir = self.workspace / "evidence" / "tasks" / self.task_id / f"attempt_{self.attempt}" / "Phase-2A"
        (p2a_dir / "rubric_evaluation.json").write_text(
            canonical_json_dumps(spoofed_partial), encoding="utf-8"
        )

        # 1. approve-review must reject partial rubric_evaluation.json
        rc_appr = main([
            "approve-review",
            "--task", self.task_id,
            "--attempt", str(self.attempt),
            "--workspace", str(self.workspace),
        ])
        self.assertEqual(rc_appr, 1)

        # 2. Gate-2A must reject partial rubric_evaluation.json even with fake pre_commit_review.json APPROVED
        (p2a_dir / "pre_commit_review.json").write_text(
            canonical_json_dumps({
                "schema_version": "2.0",
                "task_id": self.task_id,
                "attempt": self.attempt,
                "cycle": 1,
                "status": "APPROVED",
                "summary": "Spoofed",
            }),
            encoding="utf-8",
        )
        rep2a = check_gate_preconditions(self.workspace, GateId.GATE_2A, self.task_id, self.attempt)
        self.assertFalse(rep2a.passed)
        self.assertTrue(any("PARTIAL" in r or "270" in r for r in rep2a.failure_reasons))

    def test_gap01_270_rule_matrix_enforcement_and_tamper_rejection(self) -> None:
        """Verify all 228 strategies and 9 evaluators execute at runtime and fail closed on mismatches/tampering (GAP-01)."""
        from dataclasses import replace
        from stagecheck.core.rubric_engine import (
            EVALUATOR_REGISTRY,
            RubricEvaluationError,
            STRATEGY_REGISTRY,
            evaluate_rubric_rule,
            get_rule_strategy,
            load_270_rule_audit_matrix,
        )

        matrix = load_270_rule_audit_matrix()
        catalog = load_270_rule_catalog()
        self.assertEqual(len(matrix), 270)
        self.assertEqual(len(EVALUATOR_REGISTRY), 9)
        self.assertEqual(len(STRATEGY_REGISTRY), 228)

        # 1. All 270 rules resolve to one matrix entry and valid strategy/evaluator in registries
        cat_counts: dict[str, int] = {}
        for r in catalog:
            cat_counts[r.category] = cat_counts.get(r.category, 0) + 1
            entry = get_rule_strategy(r.rule_id)
            self.assertIsNotNone(entry)
            assert entry is not None
            self.assertIn(entry["evaluator_implementation"], EVALUATOR_REGISTRY)
            self.assertIn(entry["evaluation_strategy"], STRATEGY_REGISTRY)
        self.assertEqual(
            cat_counts,
            {"AUTOMATED": 162, "EVIDENCE": 64, "AGENT_ASSISTED": 34, "HUMAN_WAIVER": 10},
        )

        # 2. Full compliant run records every rule's actual evaluation_strategy across all 228 strategies
        self._seed_full_compliant_workspace()
        payload, elapsed_ms = run_rubric_evaluation(self.workspace, self.task_id, self.attempt)
        self.assertLess(elapsed_ms, 200.0)
        self.assertEqual(payload["overall_verdict"], "PASS")
        recorded_strategies = {e.get("evaluation_strategy") for e in payload["evaluations"]}
        self.assertEqual(recorded_strategies, set(STRATEGY_REGISTRY.keys()))

        # 3. Mismatched category, domain, criterion, and predicate fail closed
        target_rule = next(r for r in catalog if r.rule_id == "BLAST_RADIUS-001")
        bad_cat = replace(target_rule, category="EVIDENCE")
        res_cat = evaluate_rubric_rule(bad_cat, self.workspace, self.repo_dir)
        self.assertEqual(res_cat.status, "FAIL")
        self.assertIn("Category mismatch", res_cat.message or "")

        bad_dom = replace(target_rule, domain="FAILURE_CLASS")
        res_dom = evaluate_rubric_rule(bad_dom, self.workspace, self.repo_dir)
        self.assertEqual(res_dom.status, "FAIL")
        self.assertIn("Domain mismatch", res_dom.message or "")

        bad_crit = replace(target_rule, title="Tampered Criterion Title")
        res_crit = evaluate_rubric_rule(bad_crit, self.workspace, self.repo_dir)
        self.assertEqual(res_crit.status, "FAIL")
        self.assertIn("Original criterion mismatch", res_crit.message or "")

        bad_pred = replace(target_rule, exemption_predicate="PREDICATE_NO_REACT_DEPENDENCY")
        res_pred = evaluate_rubric_rule(bad_pred, self.workspace, self.repo_dir)
        self.assertEqual(res_pred.status, "FAIL")
        self.assertIn("Exemption predicate mismatch", res_pred.message or "")

        # 4. Matrix tampering (mismatched strategy, evaluator, duplicate entry) fails closed
        tampered_strat_ctx = {
            "_raw_matrix_by_id": {
                target_rule.rule_id: [
                    {
                        **get_rule_strategy(target_rule.rule_id),
                        "evaluation_strategy": "non_existent_bogus_strategy",
                    }
                ]
            }
        }
        res_strat = evaluate_rubric_rule(target_rule, self.workspace, self.repo_dir, context=tampered_strat_ctx)
        self.assertEqual(res_strat.status, "FAIL")
        self.assertIn("unregistered evaluation_strategy", res_strat.message or "")

        tampered_eval_ctx = {
            "_raw_matrix_by_id": {
                target_rule.rule_id: [
                    {
                        **get_rule_strategy(target_rule.rule_id),
                        "evaluator_implementation": "tampered_evaluator",
                    }
                ]
            }
        }
        res_ev_tamper = evaluate_rubric_rule(target_rule, self.workspace, self.repo_dir, context=tampered_eval_ctx)
        self.assertEqual(res_ev_tamper.status, "FAIL")
        self.assertIn("Evaluator implementation mismatch", res_ev_tamper.message or "")

        dup_matrix_ctx = {
            "_raw_matrix_by_id": {
                target_rule.rule_id: [
                    get_rule_strategy(target_rule.rule_id),
                    get_rule_strategy(target_rule.rule_id),
                ]
            }
        }
        res_dup_m = evaluate_rubric_rule(target_rule, self.workspace, self.repo_dir, context=dup_matrix_ctx)
        self.assertEqual(res_dup_m.status, "FAIL")
        self.assertIn("resolved to 2 entries", res_dup_m.message or "")

        # 5. Missing required_evidence fails closed even when code hygiene is clean
        p1_scope = self.workspace / "evidence" / "tasks" / self.task_id / f"attempt_{self.attempt}" / "Phase-1" / "declared_scope.json"
        p1_scope.unlink()
        res_no_scope = evaluate_rubric_rule(target_rule, self.workspace, self.repo_dir)
        self.assertEqual(res_no_scope.status, "FAIL")
        self.assertIn("Required evidence unavailable", res_no_scope.message or "")

        # 6. Payload validation rejects PASS without registered/matching evaluation_strategy
        with self.assertRaises(RubricEvaluationError):
            validate_rubric_evaluation_payload([
                {
                    "rule_id": "BLAST_RADIUS-001",
                    "domain": "BLAST_RADIUS",
                    "category": "AUTOMATED",
                    "status": "PASS",
                    "evaluator": "blast_radius_containment",
                }
            ])
        with self.assertRaises(RubricEvaluationError):
            validate_rubric_evaluation_payload([
                {
                    "rule_id": "BLAST_RADIUS-001",
                    "domain": "BLAST_RADIUS",
                    "category": "AUTOMATED",
                    "status": "PASS",
                    "evaluator": "blast_radius_containment",
                    "evaluation_strategy": "failure_class_observed_event_register_and_hygiene_check",
                }
            ])

    def test_phase2a_scope_defers_phase2b_and_phase3_artifacts(self) -> None:
        """Verify PHASE_2A_CODING does not fail/deadlock on missing Phase-2B or Phase-3 artifacts (D-03 / GOV-004)."""
        self._seed_full_compliant_workspace()
        attempt_dir = self.workspace / "evidence" / "tasks" / self.task_id / f"attempt_{self.attempt}"
        for rel_p in (
            "Phase-2B/report.md",
            "Phase-2B/claims.json",
            "Phase-3/test_execution.json",
            "Phase-3/scanner_report.json",
            "Phase-3/verdict.json",
        ):
            target = attempt_dir / rel_p
            if target.exists():
                target.unlink()

        payload, _ = run_rubric_evaluation(self.workspace, self.task_id, self.attempt)
        self.assertEqual(payload["overall_verdict"], "PASS", f"Expected PASS in PHASE_2A_CODING, got counts={payload['counts']}")

    def test_go_repository_test_adequacy_supported(self) -> None:
        """Verify Go repositories with *_test.go satisfy TEST_ADEQUACY without Python test files (GOV-003)."""
        self._seed_full_compliant_workspace()
        for py_file in self.repo_dir.glob("*.py"):
            py_file.unlink()
        (self.repo_dir / "go.mod").write_text("module example.com/zkready\n\ngo 1.26.0\n", encoding="utf-8")
        (self.repo_dir / "main.go").write_text("package main\n\nfunc Add(a, b int) int { return a + b }\n", encoding="utf-8")
        (self.repo_dir / "main_test.go").write_text(
            "package main\n\nimport \"testing\"\n\n"
            "func TestAddPositive(t *testing.T) {\n"
            "    if got := Add(2, 3); got != 5 { t.Fatalf(\"unexpected %d\", got) }\n"
            "}\n"
            "func TestMalformedAndDuplicateInput(t *testing.T) {\n"
            "    // malformed invalid input and duplicate replay idempotency guard\n"
            "    var err error\n"
            "    if err != nil { t.Error(err) }\n"
            "}\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "add", "."], cwd=str(self.repo_dir), check=True)
        subprocess.run(["git", "commit", "-m", "switch to go"], cwd=str(self.repo_dir), check=True, capture_output=True)

        payload, _ = run_rubric_evaluation(self.workspace, self.task_id, self.attempt)
        ta_evals = [e for e in payload["evaluations"] if e["domain"] == "TEST_ADEQUACY"]
        self.assertTrue(
            all(e["status"] in ("PASS", "NOT_APPLICABLE") for e in ta_evals),
            f"Non-passing TEST_ADEQUACY in Go repo: {[e for e in ta_evals if e['status'] not in ('PASS', 'NOT_APPLICABLE')]}",
        )
        self.assertTrue(any(e["status"] == "PASS" for e in ta_evals))

    def test_untouched_preexisting_go_sleep_does_not_fail_docs_task(self) -> None:
        """Verify untouched pre-existing *_test.go time.Sleep() does not fail TEST_ADEQUACY on a README task."""
        self._seed_full_compliant_workspace()
        for py_file in self.repo_dir.glob("*.py"):
            py_file.unlink()
        (self.repo_dir / "go.mod").write_text("module example.com/zkready\n\ngo 1.26.0\n", encoding="utf-8")
        (self.repo_dir / "main.go").write_text("package main\n\nfunc Add(a, b int) int { return a + b }\n", encoding="utf-8")
        (self.repo_dir / "common_test.go").write_text(
            "package main\n\nimport (\n    \"testing\"\n    \"time\"\n)\n\n"
            "func TestPreExistingSleep(t *testing.T) {\n"
            "    time.Sleep(5 * time.Millisecond)\n"
            "    // malformed invalid duplicate replay\n"
            "    var err error\n"
            "    if err != nil { t.Error(err) }\n"
            "    if got := Add(1, 2); got != 3 { t.Fatalf(\"%d\", got) }\n"
            "}\n",
            encoding="utf-8",
        )
        (self.repo_dir / "README.md").write_text("# ZK Ready\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=str(self.repo_dir), check=True)
        subprocess.run(["git", "commit", "-m", "baseline go repo"], cwd=str(self.repo_dir), check=True, capture_output=True)

        # Update PRODUCT_REPOSITORIES.json baseline_head to this baseline commit
        new_base = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=str(self.repo_dir), check=True, capture_output=True, text=True
        ).stdout.strip()
        from stagecheck.core.permissions import controlled_write_transaction
        prod_path = self.workspace / "controls" / "PRODUCT_REPOSITORIES.json"
        prod_data = json.loads(prod_path.read_text(encoding="utf-8"))
        prod_data["repositories"]["backend"]["baseline_head"] = new_base
        with controlled_write_transaction(self.workspace / "controls"):
            prod_path.write_text(json.dumps(prod_data, indent=2), encoding="utf-8")

        # Task only modifies README.md (does NOT touch common_test.go)
        (self.repo_dir / "README.md").write_text("# ZK Ready\n\nUpdated docs.\n", encoding="utf-8")

        payload, _ = run_rubric_evaluation(self.workspace, self.task_id, self.attempt)
        ta_evals = [e for e in payload["evaluations"] if e["domain"] == "TEST_ADEQUACY"]
        self.assertTrue(
            all(e["status"] in ("PASS", "NOT_APPLICABLE") for e in ta_evals),
            f"Unexpected TEST_ADEQUACY failure from untouched common_test.go: {[e for e in ta_evals if e['status'] not in ('PASS', 'NOT_APPLICABLE')]}",
        )

    def test_automated_rule_honors_provenance_verified_human_waiver(self) -> None:
        """Verify AUTOMATED rules honor provenance-verified APPROVED waivers in controls/DISPOSITIONS.json."""
        from stagecheck.core.agents_md import write_agents_contract
        from stagecheck.core.dispositions import build_waiver_entry, record_waiver_in_replay_ledger
        from stagecheck.core.permissions import controlled_write_transaction
        from stagecheck.core.utils import canonical_json_dumps

        self._seed_full_compliant_workspace()
        # Introduce unpinned dependency -> UPSTREAM_REUSE-001 FAILs in Phase-2A
        (self.repo_dir / "requirements.txt").write_text("requests>=2.0.0\n", encoding="utf-8")

        payload_fail, _ = run_rubric_evaluation(self.workspace, self.task_id, self.attempt)
        by_id_fail = {e["rule_id"]: e for e in payload_fail["evaluations"]}
        self.assertEqual(by_id_fail["UPSTREAM_REUSE-001"]["status"], "FAIL")

        # Add provenance-verified APPROVED waiver for UPSTREAM_REUSE-001
        waiver_evidence = self.workspace / "evidence" / "waiver_upstream.txt"
        waiver_evidence.parent.mkdir(parents=True, exist_ok=True)
        waiver_evidence.write_text("Approved unpinned dependency waiver.\n", encoding="utf-8")
        entry = build_waiver_entry(
            workspace_root=self.workspace,
            task_id=self.task_id,
            attempt=self.attempt,
            defect_id="UPSTREAM_REUSE-001",
            rule_id="UPSTREAM_REUSE-001",
            waived_rules=["UPSTREAM_REUSE-001"],
            rationale="Temporary unpinned range approved by owner.",
            authorized_by="owner@stagecheck.local",
            evidence_path="evidence/waiver_upstream.txt",
        )
        record_waiver_in_replay_ledger(self.workspace, entry)
        with controlled_write_transaction(self.workspace / "controls"):
            (self.workspace / "controls" / "DISPOSITIONS.json").write_text(
                canonical_json_dumps({"schema_version": "2.0", "dispositions": [entry]}),
                encoding="utf-8",
            )
            write_agents_contract(self.workspace)

        payload_waived, _ = run_rubric_evaluation(self.workspace, self.task_id, self.attempt)
        by_id_waived = {e["rule_id"]: e for e in payload_waived["evaluations"]}
        self.assertEqual(by_id_waived["UPSTREAM_REUSE-001"]["status"], "PASS")
        self.assertIn("Waived by provenance-verified human disposition", by_id_waived["UPSTREAM_REUSE-001"]["message"])


if __name__ == "__main__":
    unittest.main()
