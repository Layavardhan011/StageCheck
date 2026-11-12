"""Unit and Integration Tests for State Machine & Gate Criteria Evaluator (FR-01 / Spec 01 / DEC-001).

Tests lifecycle states, transition matrix, non-mutating gate inspection,
fail-closed prerequisite errors, and gate criteria evaluation across Gate 1-4.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from stagecheck.core.gate_engine import (
    GateAdvanceResult,
    GateCheckReport,
    GateCriteriaFailedError,
    GateId,
    InvalidTransitionError,
    LifecyclePhase,
    advance_gate_atomic,
    check_gate_preconditions,
    normalize_gate_id,
    validate_gate_transition_allowed,
)
from stagecheck.core.git import RepoBaseline
from stagecheck.core.scaffold import scaffold_controls_atomic
from stagecheck.core.state import load_active_state, save_active_state
from stagecheck.core.utils import canonical_json_dumps, sha256_file
from stagecheck.schemas.validator import validate_active_state


class TestGateEngine(unittest.TestCase):
    """Test suite for Gate Engine, State Machine, and Non-Mutating Gate Inspection."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp_dir.name).resolve()
        self.task_id = "task-gate-test"
        self.attempt = 1

        # Baseline repo mock
        self.repo_dir = self.workspace / "repos" / "core"
        self.repo_dir.mkdir(parents=True, exist_ok=True)

        self.baselines = {
            "core": RepoBaseline(
                name="core",
                rel_path="repos/core",
                abs_path=self.repo_dir,
                git_dir=self.repo_dir / ".git",
                head_commit="c" * 40,
                branch="task/task-gate-test",
                is_dirty=False,
                is_unborn=False,
                is_worktree=False,
            )
        }

        scaffold_controls_atomic(
            workspace_root=self.workspace,
            baselines=self.baselines,
            manifest_sha256="0" * 64,
        )

        # Set initial active state to PHASE_1_PLANNING
        state = load_active_state(self.workspace)
        state["task_id"] = self.task_id
        state["phase"] = "PHASE_1_PLANNING"
        state["attempt_index"] = self.attempt
        save_active_state(self.workspace, state)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_normalize_gate_id_variants(self) -> None:
        """Verify normalization of various user-supplied gate string formats."""
        self.assertEqual(normalize_gate_id("Gate-1"), GateId.GATE_1)
        self.assertEqual(normalize_gate_id("gate1"), GateId.GATE_1)
        self.assertEqual(normalize_gate_id("GATE_1"), GateId.GATE_1)
        self.assertEqual(normalize_gate_id("Gate-2A"), GateId.GATE_2A)
        self.assertEqual(normalize_gate_id("gate2b"), GateId.GATE_2B)
        self.assertEqual(normalize_gate_id("Gate-3"), GateId.GATE_3)
        self.assertEqual(normalize_gate_id("Gate-4"), GateId.GATE_4)

        with self.assertRaises(ValueError):
            normalize_gate_id("Gate-5")

    def test_transition_matrix_valid_and_invalid(self) -> None:
        """Verify allowed and disallowed transitions in canonical transition matrix."""
        # Gate 1 allowed from PHASE_1_PLANNING
        validate_gate_transition_allowed("PHASE_1_PLANNING", GateId.GATE_1)

        # Gate 2A allowed from PHASE_2A_CODING
        validate_gate_transition_allowed("PHASE_2A_CODING", GateId.GATE_2A)

        # Gate 2B allowed from PHASE_2B_COMMITTING or PHASE_2A_CODING
        validate_gate_transition_allowed("PHASE_2B_COMMITTING", GateId.GATE_2B)

        # Gate 3 allowed from PHASE_3_AUDIT
        validate_gate_transition_allowed("PHASE_3_AUDIT", GateId.GATE_3)

        # Gate 4 allowed from GATE_4_SEALING
        validate_gate_transition_allowed("GATE_4_SEALING", GateId.GATE_4)

        # Out-of-order transitions must fail closed
        with self.assertRaises(InvalidTransitionError):
            validate_gate_transition_allowed("PHASE_1_PLANNING", GateId.GATE_2B)

        with self.assertRaises(InvalidTransitionError):
            validate_gate_transition_allowed("PHASE_1_PLANNING", GateId.GATE_3)

        with self.assertRaises(InvalidTransitionError):
            validate_gate_transition_allowed("IDLE", GateId.GATE_4)

    def test_gate_check_is_strictly_non_mutating(self) -> None:
        """Verify check_gate_preconditions inspects criteria without mutating state or files."""
        # Snapshot directory state before inspection
        state_before = load_active_state(self.workspace)

        # Run non-mutating inspection for Gate 1
        report = check_gate_preconditions(self.workspace, "Gate-1")
        self.assertIsInstance(report, GateCheckReport)
        self.assertEqual(report.gate_id, "GATE_1")
        self.assertFalse(report.passed)  # Artifacts missing, so correctly reports failure

        # Assert ACTIVE_STATE.json is byte-identical
        state_after = load_active_state(self.workspace)
        self.assertEqual(state_before, state_after)

        # Assert no gate receipt was written to disk
        p1_receipt = self.workspace / "evidence" / "tasks" / self.task_id / "attempt_1" / "Phase-1" / "gate_1_receipt.json"
        self.assertFalse(p1_receipt.exists())

    def test_evaluate_gate_1_criteria_workflow(self) -> None:
        """Verify Gate 1 criteria evaluation: missing -> invalid -> valid."""
        p1_dir = self.workspace / "evidence" / "tasks" / self.task_id / f"attempt_{self.attempt}" / "Phase-1"
        p1_dir.mkdir(parents=True, exist_ok=True)

        # 1. Initially missing prompt, scope, and verification
        rep1 = check_gate_preconditions(self.workspace, "Gate-1")
        self.assertFalse(rep1.passed)
        self.assertTrue(any("gate1.prompt_exists" in r for r in rep1.failure_reasons))

        # 2. Add prompt.md and declared_scope with prohibited wildcard
        (p1_dir / "prompt.md").write_text("# Feature prompt\nImplement logic.\n", encoding="utf-8")
        (p1_dir / "declared_scope.json").write_text(json.dumps({
            "schema_version": "2.0",
            "task_id": self.task_id,
            "allowed_paths": ["**"],  # Prohibited top-level wildcard
        }), encoding="utf-8")

        rep2 = check_gate_preconditions(self.workspace, "Gate-1")
        self.assertFalse(rep2.passed)
        self.assertTrue(any("gate1.scope_discrete" in r for r in rep2.failure_reasons))

        # 3. Fix declared_scope and add prompt_verified.json
        (p1_dir / "declared_scope.json").write_text(json.dumps({
            "schema_version": "2.0",
            "task_id": self.task_id,
            "allowed_paths": ["repos/core/main.py"],
        }), encoding="utf-8")
        (p1_dir / "prompt_verified.json").write_text(json.dumps({
            "schema_version": "2.0",
            "task_id": self.task_id,
            "attempt": self.attempt,
            "status": "VERIFIED",
            "prompt_sha256": sha256_file(p1_dir / "prompt.md"),
            "scope_sha256": sha256_file(p1_dir / "declared_scope.json"),
        }), encoding="utf-8")

        rep3 = check_gate_preconditions(self.workspace, "Gate-1")
        self.assertTrue(rep3.passed)
        self.assertEqual(len(rep3.failure_reasons), 0)
        self.assertEqual(len(rep3.deliverables), 3)

    def test_evaluate_gate_3_verdict_criteria(self) -> None:
        """Verify Gate 3 criteria evaluation against Phase-3/verdict.json."""
        # Set state to PHASE_3_AUDIT
        state = load_active_state(self.workspace)
        state["phase"] = "PHASE_3_AUDIT"
        save_active_state(self.workspace, state)

        p3_dir = self.workspace / "evidence" / "tasks" / self.task_id / f"attempt_{self.attempt}" / "Phase-3"
        p3_dir.mkdir(parents=True, exist_ok=True)

        # 1. Missing verdict
        rep1 = check_gate_preconditions(self.workspace, "Gate-3")
        self.assertFalse(rep1.passed)

        # 2. Failing verdict
        (p3_dir / "verdict.json").write_text(json.dumps({
            "schema_version": "2.0",
            "task_id": self.task_id,
            "attempt": self.attempt,
            "result": "BLOCKED",
            "counts": {"blocking": 1, "report_only": 0},
            "defects": [{"defect_id": "test.fail", "blocking": True}],
        }), encoding="utf-8")

        rep2 = check_gate_preconditions(self.workspace, "Gate-3")
        self.assertFalse(rep2.passed)

        # 3. Passing verdict WITHOUT complete Phase-3/rubric_evaluation.json -> FAIL (GAP-02)
        (p3_dir / "verdict.json").write_text(json.dumps({
            "schema_version": "2.0",
            "task_id": self.task_id,
            "attempt": self.attempt,
            "result": "PASSED",
            "counts": {"blocking": 0, "report_only": 0},
            "defects": [],
        }), encoding="utf-8")

        rep_no_rubric = check_gate_preconditions(self.workspace, "Gate-3")
        self.assertFalse(rep_no_rubric.passed)

        # 4. Partial Phase-3/rubric_evaluation.json MUST NOT satisfy Gate-3 (GAP-02)
        import datetime
        from stagecheck.core.rubric_engine import compute_rubric_context_digest, load_270_rule_catalog

        catalog = load_270_rule_catalog()
        now_iso = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        ctx_digest = compute_rubric_context_digest(self.workspace, self.task_id, self.attempt)
        partial_evals = [
            {
                "rule_id": r.rule_id,
                "domain": r.domain,
                "category": r.category,
                "status": "PASS",
                "message": "ok",
            }
            for r in catalog[:30]
        ]
        (p3_dir / "rubric_evaluation.json").write_text(canonical_json_dumps({
            "schema_version": "2.0.0",
            "task_id": self.task_id,
            "attempt": self.attempt,
            "cycle": 1,
            "evaluated_at": now_iso,
            "overall_verdict": "PASS",
            "evaluation_completeness": "PARTIAL",
            "expected_rule_count": 270,
            "evaluated_rule_count": 30,
            "missing_rules": [r.rule_id for r in catalog[30:]],
            "duplicate_rules": [],
            "target_domain": "COMMON",
            "context_digest": ctx_digest,
            "counts": {"total_rules": 30, "passed": 30, "failed": 0, "not_applicable": 0, "not_evaluated": 0, "blocked": 0},
            "domains": {"COMMON": {"total": 30, "passed": 30, "failed": 0, "not_applicable": 0, "verdict": "PASS"}},
            "evaluations": partial_evals,
        }), encoding="utf-8")

        rep_partial = check_gate_preconditions(self.workspace, "Gate-3")
        self.assertFalse(rep_partial.passed)

        # 5. Passing verdict WITH COMPLETE 270/270 PASS Phase-3/rubric_evaluation.json -> PASS
        from stagecheck.core.rubric_engine import get_rule_strategy

        full_evals = []
        for r in catalog:
            spec = get_rule_strategy(r.rule_id) or {}
            full_evals.append({
                "rule_id": r.rule_id,
                "domain": r.domain,
                "category": r.category,
                "status": "PASS",
                "evaluator": spec.get("evaluator_implementation", "phase_evidence_validator"),
                "evaluation_strategy": spec.get("evaluation_strategy", ""),
                "message": "Verified passing criterion.",
            })
        domain_counts = {}
        for r in catalog:
            d = domain_counts.setdefault(r.domain, {"total": 0, "passed": 0, "failed": 0, "not_applicable": 0, "verdict": "PASS"})
            d["total"] += 1
            d["passed"] += 1
        (p3_dir / "rubric_evaluation.json").write_text(canonical_json_dumps({
            "schema_version": "2.0.0",
            "task_id": self.task_id,
            "attempt": self.attempt,
            "cycle": 1,
            "evaluated_at": now_iso,
            "overall_verdict": "PASS",
            "evaluation_completeness": "COMPLETE",
            "expected_rule_count": 270,
            "evaluated_rule_count": 270,
            "missing_rules": [],
            "duplicate_rules": [],
            "target_domain": None,
            "context_digest": ctx_digest,
            "counts": {"total_rules": 270, "passed": 270, "failed": 0, "not_applicable": 0, "not_evaluated": 0, "blocked": 0},
            "domains": domain_counts,
            "evaluations": full_evals,
        }), encoding="utf-8")

        from unittest.mock import patch
        import json as _json
        expected_eval = _json.loads((p3_dir / "rubric_evaluation.json").read_text(encoding="utf-8"))
        with patch("stagecheck.core.rubric_engine.run_rubric_evaluation", return_value=(expected_eval, 1.0)):
            rep3 = check_gate_preconditions(self.workspace, "Gate-3")
        self.assertTrue(rep3.passed, f"Expected Gate-3 to pass, failures={rep3.failure_reasons}")

    def test_active_state_schema_synchronization(self) -> None:
        """Verify active_state.schema.json validates all LifecyclePhase enum values."""
        state = load_active_state(self.workspace)
        for phase in LifecyclePhase:
            state["phase"] = phase.value
            # Must validate without raising SchemaValidationError
            validate_active_state(state)

    def test_invalid_gate_transitions_rejected_by_advance_atomic(self) -> None:
        """Verify advance_gate_atomic fails closed when attempting out-of-order gate transitions (Spec 01)."""
        # Attempting Gate-2A, Gate-2B, Gate-3, or Gate-4 while in PHASE_1_PLANNING must fail closed
        for invalid_gate in ("Gate-2A", "Gate-2B", "Gate-3", "Gate-4"):
            with self.subTest(gate=invalid_gate):
                with self.assertRaises(GateCriteriaFailedError) as ctx:
                    advance_gate_atomic(self.workspace, invalid_gate, self.task_id, self.attempt)
                self.assertTrue(
                    any("transition" in r.lower() or "allowed" in r.lower() for r in ctx.exception.failure_reasons),
                    f"Expected transition failure reason, got {ctx.exception.failure_reasons}",
                )

    def test_prerequisite_gate_receipt_tampering_or_absence_fails_closed(self) -> None:
        """Verify advancing a later gate fails if prerequisite gate receipts are missing or tampered."""
        # Set state to PHASE_2B_COMMITTING with cleared_gates pointing to fake/tampered hash
        state = load_active_state(self.workspace)
        state["phase"] = "PHASE_2B_COMMITTING"
        state["cleared_gates"] = {"GATE_1": "a" * 64, "GATE_2A": "b" * 64}
        save_active_state(self.workspace, state)

        # Gate-2B should fail closed because actual prerequisite receipts do not exist or mismatch
        with self.assertRaises(GateCriteriaFailedError):
            advance_gate_atomic(self.workspace, "Gate-2B", self.task_id, self.attempt)

    def test_gate_advance_receipt_cryptographic_binding_and_repeat_calls(self) -> None:
        """Verify gate advancement creates cryptographic receipts and prevents repeated advancement."""
        p1_dir = self.workspace / "evidence" / "tasks" / self.task_id / f"attempt_{self.attempt}" / "Phase-1"
        p1_dir.mkdir(parents=True, exist_ok=True)
        (p1_dir / "prompt.md").write_text("# Feature prompt\nImplement logic.\n", encoding="utf-8")
        (p1_dir / "declared_scope.json").write_text(json.dumps({
            "schema_version": "2.0",
            "task_id": self.task_id,
            "allowed_paths": ["repos/core/main.py"],
        }), encoding="utf-8")
        (p1_dir / "prompt_verified.json").write_text(json.dumps({
            "schema_version": "2.0",
            "task_id": self.task_id,
            "attempt": self.attempt,
            "status": "VERIFIED",
            "prompt_sha256": sha256_file(p1_dir / "prompt.md"),
            "scope_sha256": sha256_file(p1_dir / "declared_scope.json"),
        }), encoding="utf-8")

        # 1. Advance Gate-1 successfully
        res = advance_gate_atomic(self.workspace, "Gate-1", self.task_id, self.attempt)
        self.assertEqual(res.gate_id, "GATE_1")
        self.assertEqual(res.to_phase, "PHASE_2A_CODING")
        self.assertTrue(res.receipt_path.is_file())
        self.assertEqual(sha256_file(res.receipt_path), res.receipt_sha256)

        # Receipt should contain deliverables with digests
        receipt_data = json.loads(res.receipt_path.read_text(encoding="utf-8"))
        self.assertEqual(receipt_data["task_id"], self.task_id)
        self.assertEqual(receipt_data["attempt"], self.attempt)
        self.assertEqual(receipt_data["gate_id"], "GATE_1")
        self.assertIn("deliverables", receipt_data)

        # 2. Repeated advance of Gate-1 from now-advanced PHASE_2A_CODING phase fails closed
        with self.assertRaises(GateCriteriaFailedError):
            advance_gate_atomic(self.workspace, "Gate-1", self.task_id, self.attempt)


if __name__ == "__main__":
    unittest.main()

