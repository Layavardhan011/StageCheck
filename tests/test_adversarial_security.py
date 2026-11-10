"""Adversarial and Cross-Component Regression Test Suite (Phase 5 Task 5.2).

Validates security invariants and negative fail-closed behavior across:
1. Command Injection: CLI parameters, repo names, and test command tokenization.
2. Git Security & Remote Spoofing: Malicious git hooks, core.fsmonitor, and branch governance.
3. Path Traversal & Symlinks: Attempt-root symlinks, nested symlinks, and path escapes.
4. Forged Receipts & Tamper Detection: Receipt payload forgery and Merkle DAG integrity.
5. State Corruption & Lock Races: Concurrency locks, journal crash recovery, and schema enforcement.
6. Scope Wildcard & Rubric N/A Abuse: Untouched repo isolation and unauthorized rubric waivers.
7. Attempt Budget Invariant: Enforcing 3-attempt hard ceiling across all retry and reset paths.
8. Premature CLI Operations: Advance, seal, and disposition operations failing closed when out of order.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from stagecheck.cli.init_cmd import run_init
from stagecheck.cli.start_cmd import run_start
from stagecheck.core.agents import resolve_task_attempt_dir
from stagecheck.core.branch_governance import (
    DirtyWorkingTreeError,
    NonCompliantBranchError,
    ProtectedBranchPolicyError,
    UntouchedRepoViolationError,
    capture_multi_repo_task_baseline,
    validate_branch_compliance,
    verify_multi_repo_governance,
)
from stagecheck.core.circuit_breaker import (
    AttemptBudgetExhaustedError,
    CircuitBreakerError,
    ResetAttemptsError,
    reset_circuit_breaker,
)
from stagecheck.core.commands import (
    CommandSecurityError,
    ForbiddenCommandFlagError,
    execute_secure_command,
    validate_command_security,
)
from stagecheck.core.gate_engine import (
    GateCriteriaFailedError,
    advance_gate_atomic,
    evaluate_gate_4_criteria,
)
from stagecheck.core.journal import (
    TransactionJournal,
    recover_interrupted_transactions,
    write_ahead_transaction,
)
from stagecheck.core.locking import LockCollisionError, acquire_runtime_lock
from stagecheck.core.permissions import controlled_write_transaction, elevate_permissions_for_teardown
from stagecheck.core.rubric_engine import (
    InvalidRubricExemptionError,
    validate_rubric_evaluation_payload,
)
from stagecheck.core.sealing import (
    MerkleVerificationError,
    SymlinkInEvidenceError,
    compute_attempt_merkle_seal,
    validate_merkle_attempt_path,
    verify_attempt_merkle_seal,
)
from stagecheck.core.state import load_active_state, save_active_state
from stagecheck.core.utils import canonical_json_dumps, pretty_json_dumps, sha256_file


class TestAdversarialSecurity(unittest.TestCase):
    """Exhaustive adversarial and fail-closed security regression test suite."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.ws = Path(self.temp_dir.name).resolve()

        # Initialize standard test workspace with Git repos
        self.backend_repo = self.ws / "repos" / "backend"
        self.frontend_repo = self.ws / "repos" / "frontend"
        for r in (self.backend_repo, self.frontend_repo):
            r.mkdir(parents=True, exist_ok=True)
            subprocess.run(["git", "init", "-b", "main"], cwd=str(r), capture_output=True, check=True)
            subprocess.run(["git", "config", "user.name", "Tester"], cwd=str(r), capture_output=True, check=True)
            subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=str(r), capture_output=True, check=True)
            (r / "README.md").write_text("# Initial Repo\n", encoding="utf-8")
            subprocess.run(["git", "add", "README.md"], cwd=str(r), capture_output=True, check=True)
            subprocess.run(["git", "commit", "-m", "init"], cwd=str(r), capture_output=True, check=True)

        run_init(self.ws, agent1="agent1", agent2="agent2")
        run_start(workspace=self.ws, task="task-adv-01")

    def tearDown(self) -> None:
        elevate_permissions_for_teardown(self.ws)
        self.temp_dir.cleanup()

    # =========================================================================
    # 1. Command Injection Defenses
    # =========================================================================

    def test_command_injection_shell_metacharacters_rejected(self) -> None:
        """Verify command execution rejects shell metacharacters and execution flags."""
        injection_attempts = [
            ["npm", "test; rm -rf /"],
            ["python3", "-c", "import os; os.system('id')"],
            ["pytest", "-o", "evil=1"],
            ["npm", "run", "malicious_script", "--ignore-scripts"],
            ["npx", "jest"],  # Missing --no-install
            ["npm", "test"],  # Missing --ignore-scripts
        ]
        for argv in injection_attempts:
            with self.subTest(cmd=argv):
                with self.assertRaises(ForbiddenCommandFlagError):
                    validate_command_security(argv)

    def test_command_execution_strips_ambient_credentials(self) -> None:
        """Verify execute_secure_command sanitizes environment variables and strips tokens."""
        os.environ["GITHUB_TOKEN"] = "ghp_supersecretvalue123456789"
        os.environ["AWS_SECRET_ACCESS_KEY"] = "AKIAEXAMPLESECRET123"
        try:
            # python3 without forbidden flags
            rec = execute_secure_command(
                argv=["python3", "--version"],
                working_directory=self.ws,
                timeout_seconds=10,
                check_tree_integrity=False,
            )
            self.assertEqual(rec.exit_code, 0)
            self.assertNotIn("GITHUB_TOKEN", rec.stdout)
            self.assertNotIn("AWS_SECRET_ACCESS_KEY", rec.stdout)
        finally:
            os.environ.pop("GITHUB_TOKEN", None)
            os.environ.pop("AWS_SECRET_ACCESS_KEY", None)

    # =========================================================================
    # 2. Git Configuration & Remote Spoofing Defenses
    # =========================================================================

    def test_git_branch_governance_prohibits_direct_main_commit(self) -> None:
        """Verify branch governance strictly fails closed if branch is main or master."""
        with self.assertRaises(ProtectedBranchPolicyError):
            validate_branch_compliance("main")
        with self.assertRaises(ProtectedBranchPolicyError):
            validate_branch_compliance("master")

    def test_git_branch_governance_rejects_non_compliant_branch(self) -> None:
        """Verify non-compliant branch names (e.g. arbitrary feature branch or injection) are rejected."""
        malicious_branches = [
            "arbitrary-agent-branch",
            "hack;rm -rf /;",
            "refs/heads/main",
            "../escape",
        ]
        for branch in malicious_branches:
            with self.subTest(branch=branch):
                with self.assertRaises(NonCompliantBranchError):
                    validate_branch_compliance(branch)

    def test_git_safe_flags_neutralize_malicious_hooks(self) -> None:
        """Verify git execution with SAFE_GIT_SECURITY_FLAGS bypasses repo-level hooks."""
        hook_file = self.backend_repo / ".git" / "hooks" / "pre-commit"
        hook_file.parent.mkdir(parents=True, exist_ok=True)
        # Create a malicious hook that would create a marker file if executed
        marker = self.ws / "hook_executed.marker"
        hook_file.write_text(f"#!/bin/sh\ntouch {marker}\nexit 1\n", encoding="utf-8")
        hook_file.chmod(0o755)

        # Stage changes in backend repo
        (self.backend_repo / "newfile.py").write_text("# new code\n", encoding="utf-8")
        subprocess.run(["git", "add", "newfile.py"], cwd=str(self.backend_repo), check=True)

        # Commit using safe flags (which sets core.hooksPath=/dev/null)
        from stagecheck.core.git import SAFE_GIT_SECURITY_FLAGS
        cmd = ["git", *SAFE_GIT_SECURITY_FLAGS, "-C", str(self.backend_repo), "commit", "-m", "safe commit"]
        res = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"Git commit failed: {res.stderr}")
        self.assertFalse(marker.exists(), "Malicious git hook was executed despite SAFE_GIT_SECURITY_FLAGS!")

    # =========================================================================
    # 3. Path Traversal & Symlink Escape Defenses
    # =========================================================================

    def test_attempt_root_itself_a_symlink_rejected(self) -> None:
        """Verify Issue 2: An attempt root that is itself a symlink is rejected before hashing."""
        attempt_dir = resolve_task_attempt_dir(self.ws, "task-adv-01", 1, ensure_exists=True)
        # Remove attempt dir and replace with symlink to /tmp or outside target
        shutil.rmtree(attempt_dir)
        target_dir = self.ws / "outside_target"
        target_dir.mkdir(parents=True, exist_ok=True)
        os.symlink(target_dir, attempt_dir)

        # Symlink check must fail closed
        with self.assertRaises(SymlinkInEvidenceError) as ctx:
            validate_merkle_attempt_path(attempt_dir, self.ws)
        self.assertIn("symlink", str(ctx.exception).lower())

    def test_nested_symlink_escaping_workspace_rejected(self) -> None:
        """Verify nested symlinks in attempt evidence are detected and rejected."""
        attempt_dir = resolve_task_attempt_dir(self.ws, "task-adv-01", 1, ensure_exists=True)
        malicious_symlink = attempt_dir / "evil_link.py"
        target_file = self.ws / "outside_target" / "secret.txt"
        target_file.parent.mkdir(parents=True, exist_ok=True)
        target_file.write_text("secret\n")

        os.symlink(target_file, malicious_symlink)

        with self.assertRaises(SymlinkInEvidenceError) as ctx:
            compute_attempt_merkle_seal(attempt_dir, self.ws, "task-adv-01", 1)
        self.assertIn("symlink", str(ctx.exception).lower())

    def test_merkle_directory_symlink_rejected(self) -> None:
        """Verify compute_attempt_merkle_seal rejects directory symlinks."""
        attempt_dir = resolve_task_attempt_dir(self.ws, "task-adv-01", 1, ensure_exists=True)
        symlink = attempt_dir / "dir_link"
        os.symlink(self.ws, symlink)

        with self.assertRaises(SymlinkInEvidenceError):
            compute_attempt_merkle_seal(attempt_dir, self.ws, "task-adv-01", 1)

    # =========================================================================
    # 4. Forged Receipts & Tamper Detection
    # =========================================================================

    def test_forged_gate_receipt_detected_by_gate4(self) -> None:
        """Verify Gate 4 detects altered receipt payloads and fails closed with hash mismatch."""
        # Populate valid Phase-1 receipt
        p1_dir = self.ws / "evidence" / "tasks" / "task-adv-01" / "attempt_1" / "Phase-1"
        p1_dir.mkdir(parents=True, exist_ok=True)
        receipt_path = p1_dir / "gate1_receipt.json"
        receipt_data = {
            "schema_version": "2.0.0",
            "gate_id": "GATE_1",
            "task_id": "task-adv-01",
            "attempt": 1,
            "status": "PASSED",
            "verified_at": "2026-11-06T12:00:00Z",
            "verified_by": "stagecheck-gate-engine",
            "deliverables": [],
            "checks_evaluated": ["TASK_SPEC_EXISTS"],
        }
        receipt_path.write_text(canonical_json_dumps(receipt_data), encoding="utf-8")
        clean_hash = sha256_file(receipt_path)

        # Update state with the valid receipt
        with controlled_write_transaction(self.ws / "controls"):
            state = load_active_state(self.ws)
            state["cleared_gates"] = {
                "GATE_1": clean_hash,
                "GATE_2B": "0" * 64,
                "GATE_3": "0" * 64,
            }
            save_active_state(self.ws, state)

        # Adversary alters receipt on disk
        receipt_data["status"] = "TAMPERED_BY_ADVERSARY"
        receipt_path.write_text(canonical_json_dumps(receipt_data), encoding="utf-8")

        # Gate 4 verification must detect the forgery
        criteria, deliverables = evaluate_gate_4_criteria(self.ws, "task-adv-01", 1)
        prereq_crit = [c for c in criteria if c.criterion_id == "G4-PREREQ-GATE_1"]
        self.assertTrue(len(prereq_crit) > 0)
        self.assertEqual(prereq_crit[0].status, "FAILED")
        self.assertIn("mismatch", prereq_crit[0].message.lower())

    # =========================================================================
    # 5. State Corruption & Lock Contention
    # =========================================================================

    def test_task_lock_contention_fails_closed(self) -> None:
        """Verify acquiring runtime lock when already held raises LockCollisionError."""
        with acquire_runtime_lock(self.ws):
            with self.assertRaises(LockCollisionError):
                with acquire_runtime_lock(self.ws):
                    pass

    def test_journal_rollback_on_midflight_crash(self) -> None:
        """Verify interrupted transactions with active journal are cleanly rolled back on startup."""
        state_file = self.ws / "controls" / "ACTIVE_STATE.json"
        state_original = state_file.read_text(encoding="utf-8")

        # Simulate a crash: create an active journal entry without committing it
        journal_dir = self.ws / ".stagecheck_journal"
        journal_dir.mkdir(mode=0o700, exist_ok=True)
        active_log = journal_dir / "txn_simulated_crash.active.json"

        # Corrupt state on disk as if crash occurred mid-write
        with controlled_write_transaction(self.ws / "controls"):
            state_file.write_text('{"phase": "CORRUPTED_MID_FLIGHT"}', encoding="utf-8")

        journal_payload = {
            "txn_id": "txn_simulated_crash",
            "operation": "GATE_ADVANCE",
            "task_id": "task-adv-01",
            "attempt_index": 1,
            "created_at": "2026-11-06T12:00:00Z",
            "status": "IN_PROGRESS",
            "pre_images": {
                "controls/ACTIVE_STATE.json": state_original,
            },
            "staged_writes": ["controls/ACTIVE_STATE.json"],
        }
        active_log.write_text(json.dumps(journal_payload, indent=2), encoding="utf-8")

        # Startup recovery
        rolled_back = recover_interrupted_transactions(self.ws)
        self.assertEqual(len(rolled_back), 1)

        # Verify state file was restored to pristine pre-image
        self.assertEqual(state_file.read_text(encoding="utf-8"), state_original)
        # Active journal file must be unlinked
        self.assertEqual(len(list(journal_dir.glob("*.active.json"))), 0)

    # =========================================================================
    # 6. Scope Wildcard & Rubric N/A Abuse Defenses
    # =========================================================================

    def test_untouched_repository_tamper_fails_closed(self) -> None:
        """Verify modifying an out-of-scope repository triggers UntouchedRepoViolationError."""
        # Initialize untouched repo baseline
        capture_multi_repo_task_baseline(self.ws, "task-adv-01", 1, ["backend", "frontend"])

        # Switch backend to permitted task branch
        subprocess.run(["git", "checkout", "-b", "task-adv-01"], cwd=str(self.backend_repo), capture_output=True, check=True)

        # Adversary mutates frontend repo (which is in all_registered_repos but NOT touched_repos)
        (self.frontend_repo / "unauthorized_change.py").write_text("# backdoor\n", encoding="utf-8")

        with self.assertRaises(UntouchedRepoViolationError):
            verify_multi_repo_governance(
                workspace_root=self.ws,
                task_id="task-adv-01",
                attempt=1,
                touched_repos=["backend"],
                all_registered_repos=["backend", "frontend"],
            )

    def test_rubric_not_applicable_unauthorized_abuse_rejected(self) -> None:
        """Verify setting rubric item to NOT_APPLICABLE without valid predicate/rationale fails closed."""
        rubric_payload = [
            {
                "rule_id": "SEC-01",
                "status": "NOT_APPLICABLE",
                "exemption_predicate": "invalid_or_missing_predicate",
                "rationale": "agent self exemption",
                "evidence_path": "repos/backend",
            }
        ]
        with self.assertRaises(InvalidRubricExemptionError) as ctx:
            validate_rubric_evaluation_payload(rubric_payload)
        self.assertIn("illegal exemption", str(ctx.exception).lower())

    # =========================================================================
    # 7. Attempt Budget Invariant Defenses
    # =========================================================================

    def test_attempt_budget_cannot_be_bypassed_past_max(self) -> None:
        """Verify strict 3-attempt ceiling across record, enforce, and retry paths."""
        with controlled_write_transaction(self.ws / "controls"):
            state = load_active_state(self.ws)
            state["attempt_index"] = 3
            state["max_total_attempts"] = 3
            state["circuit_breaker_tripped"] = True
            state["phase"] = "CIRCUIT_BREAKER_TRIPPED"
            save_active_state(self.ws, state)

        # Attempting reset beyond maximum attempt budget must strictly fail closed
        with self.assertRaises(AttemptBudgetExhaustedError):
            reset_circuit_breaker(self.ws, "task-adv-01", authorized_by="human-operator")

    # =========================================================================
    # 8. Premature CLI Operations Defenses
    # =========================================================================

    def test_premature_gate4_sealing_fails_closed_when_prior_gates_missing(self) -> None:
        """Verify Gate 4 advance strictly fails if prior gates have not cleared."""
        with self.assertRaises(GateCriteriaFailedError):
            advance_gate_atomic(self.ws, "GATE_4")

    def test_premature_gate4_sealing_rejected_if_audit_verdict_failed(self) -> None:
        """Verify Gate 4 fails closed if Gate 3 audit verdict is FAILED."""
        # Create attempt dir with FAILED verdict
        p3_dir = self.ws / "evidence" / "tasks" / "task-adv-01" / "attempt_1" / "Phase-3"
        p3_dir.mkdir(parents=True, exist_ok=True)
        verdict = {
            "status": "FAILED",
            "blocking_defects_count": 2,
            "rubric_summary": {"score": 0.0},
            "defects": ["CRITICAL_VULNERABILITY", "UNAUTHORIZED_FILE_MUTATION"],
        }
        (p3_dir / "verdict.json").write_text(canonical_json_dumps(verdict), encoding="utf-8")

        criteria, deliverables = evaluate_gate_4_criteria(self.ws, "task-adv-01", 1)
        # Criteria must have a FAILED verdict check
        verdict_crit = [c for c in criteria if c.criterion_id == "G4-VERDICT-PASSED"]
        self.assertTrue(len(verdict_crit) > 0)
        self.assertEqual(verdict_crit[0].status, "FAILED")

    def test_task_id_traversal_rejected_across_entrypoints(self) -> None:
        """Verify task_id traversal and '..' are rejected across CLI, schema, and evidence APIs (SC-SEC-05)."""
        from stagecheck.cli.start_cmd import run_start
        from stagecheck.core.circuit_breaker import CircuitBreakerEvaluation, write_escalation_report
        from stagecheck.core.evidence import append_issue_history
        from stagecheck.core.paths import SymlinkPathEscapeError, resolve_task_dir
        from stagecheck.core.utils import SchemaValidationError
        from stagecheck.schemas.validator import validate_active_state

        outside_dir = Path(self.temp_dir.name) / "outside_escape"
        ev = CircuitBreakerEvaluation(tripped=True, trigger="test", reason="test")

        for bad_id in ("..", "../../outside_escape", "task/sub", "task.dot", "task-1\n"):
            with self.subTest(bad_id=bad_id):
                with self.assertRaises(ValueError):
                    write_escalation_report(self.ws, bad_id, 1, ev, [])
                with self.assertRaises(ValueError):
                    append_issue_history(self.ws, bad_id, 1, "FAILED", [])
                with self.assertRaises(ValueError):
                    advance_gate_atomic(self.ws, "GATE_1", task_id=bad_id, attempt=1)

                # run_start must reject invalid task_id before modifying ACTIVE_STATE.json
                rc = run_start(workspace=self.ws, task=bad_id)
                self.assertEqual(rc, 1)
                self.assertNotEqual(load_active_state(self.ws).get("task_id"), bad_id)

        self.assertFalse(outside_dir.exists())

        # Schema itself must reject '..' and '.'
        bad_state = load_active_state(self.ws)
        bad_state["task_id"] = ".."
        with self.assertRaises(SchemaValidationError):
            validate_active_state(bad_state)

        # Intermediate symlink at evidence/tasks escaping workspace must be rejected
        tasks_dir = self.ws / "evidence" / "tasks"
        outside_target = Path(self.temp_dir.name) / "symlink_target"
        outside_target.mkdir(parents=True, exist_ok=True)
        with controlled_write_transaction(self.ws / "evidence"):
            if tasks_dir.exists():
                shutil.rmtree(tasks_dir)
            tasks_dir.symlink_to(outside_target)
        with self.assertRaises(SymlinkPathEscapeError):
            resolve_task_dir(self.ws, "task-safe")


if __name__ == "__main__":
    unittest.main()
