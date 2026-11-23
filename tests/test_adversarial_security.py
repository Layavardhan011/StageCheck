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
                allow_cwd_write=False,
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
            reset_circuit_breaker(self.ws, "task-adv-01", authorized_by="owner@stagecheck.local")

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

    def test_adversarial_agent_cannot_tamper_with_controls_without_lock_and_permissions(self) -> None:
        """Verify direct write to controls raises PermissionError under defense-in-depth DAC (Gap B)."""
        state_file = self.ws / "controls" / "ACTIVE_STATE.json"
        self.assertTrue(state_file.is_file())
        with self.assertRaises(PermissionError):
            with open(state_file, "w", encoding="utf-8") as f:
                f.write('{"tampered": true}\n')

    def test_adversarial_symlink_injection_in_controls_rejected(self) -> None:
        """Verify symlink injection inside controls boundary is strictly caught (Gap B)."""
        from stagecheck.core.permissions import VerifierIsolationError, assert_verifier_isolation
        state_file = self.ws / "controls" / "ACTIVE_STATE.json"

        # Replace ACTIVE_STATE.json with symlink to /etc/passwd
        with controlled_write_transaction(self.ws / "controls"):
            state_file.unlink()
            state_file.symlink_to("/etc/passwd")

        with self.assertRaises(VerifierIsolationError) as ctx:
            assert_verifier_isolation(self.ws)
        self.assertIn("cannot be a symbolic link", str(ctx.exception))

    def test_adversarial_tampering_with_prior_frozen_phase_detected_by_gate_advance(self) -> None:
        """Verify tampering with Phase-1 deliverables causes gate advance to fail closed (Gap B)."""
        from stagecheck.core.gate_engine import advance_gate_atomic, GateCriteriaFailedError
        # Advance Gate 1 legitimately
        p1_dir = self.ws / "evidence" / "tasks" / "task-adv-01" / "attempt_1" / "Phase-1"
        p1_dir.mkdir(parents=True, exist_ok=True)
        (p1_dir / "prompt.md").write_text("# Requirements\nDiscrete scope.\n", encoding="utf-8")
        (p1_dir / "declared_scope.json").write_text(json.dumps({
            "schema_version": "2.0",
            "task_id": "task-adv-01",
            "allowed_paths": ["repos/backend/README.md"],
        }), encoding="utf-8")
        from stagecheck.core.prompt_gate import freeze_prompt_and_scope
        freeze_prompt_and_scope(self.ws, "task-adv-01", 1)

        # Gate 1 advance succeeds
        res1 = advance_gate_atomic(self.ws, "GATE_1", task_id="task-adv-01", attempt=1)
        self.assertEqual(res1.to_phase, "PHASE_2A_CODING")

        # Now adversary tampers with Phase-1 declared_scope.json by elevating permissions
        scope_file = p1_dir / "declared_scope.json"
        scope_file.chmod(0o644)
        scope_file.write_text(json.dumps({
            "schema_version": "2.0.0",
            "task_id": "task-adv-01",
            "allowed_paths": ["repos/backend/**"],
        }), encoding="utf-8")

        # Gate 2A advance fails closed due to tampered scope hash mismatch
        with self.assertRaises(GateCriteriaFailedError):
            advance_gate_atomic(self.ws, "GATE_2A", task_id="task-adv-01", attempt=1)

    def test_adversarial_tampering_with_evidence_manifest_rejected(self) -> None:
        """Verify tampering with EVIDENCE_MANIFEST.json is rejected by manifest and chain verifiers (Gap B)."""
        from stagecheck.core.evidence import verify_evidence_manifest
        manifest_file = self.ws / "evidence" / "EVIDENCE_MANIFEST.json"
        with controlled_write_transaction(self.ws / "evidence"):
            manifest_file.write_text(json.dumps({
                "schema_version": "2.0.0",
                "entries": {
                    "evidence/tasks/task-adv-01/attempt_1/output.txt": {
                        "sha256": "0" * 64,
                        "size_bytes": 100,
                    }
                }
            }), encoding="utf-8")

        # Verification detects missing seal or hash mismatch
        is_valid, violations = verify_evidence_manifest(self.ws)
        self.assertFalse(is_valid)
        self.assertTrue(len(violations) > 0)

    def test_adversarial_batch4_symlink_lockfile_rejected(self) -> None:
        """Symlinked runtime or bootstrap lockfile must fail closed with LockError."""
        from stagecheck.core.locking import LockError, acquire_bootstrap_lock
        lock_path = self.ws / ".stagecheck.lock"
        lock_path.unlink(missing_ok=True)
        lock_path.symlink_to(self.ws / "controls" / "ACTIVE_STATE.json")
        with self.assertRaises(LockError):
            with acquire_runtime_lock(self.ws / "controls"):
                pass
        lock_path.unlink(missing_ok=True)

        boot_lock = self.ws / ".stagecheck-init.lock"
        boot_lock.unlink(missing_ok=True)
        boot_lock.symlink_to(self.ws / "README_NONEXISTENT.md")
        with self.assertRaises(LockError):
            with acquire_bootstrap_lock(self.ws):
                pass
        boot_lock.unlink(missing_ok=True)

    def test_adversarial_batch4_teardown_active_task_guard(self) -> None:
        """commit_safe_teardown blocks active IN_PROGRESS task unless abort_active=True."""
        from stagecheck.core.permissions import ActiveTaskTeardownBlockedError, commit_safe_teardown
        with controlled_write_transaction(self.ws / "controls"):
            state = load_active_state(self.ws)
            state["task_id"] = "task-active-teardown"
            state["phase"] = "PHASE_2A_CODING"
            state["status"] = "IN_PROGRESS"
            save_active_state(self.ws, state)

        with self.assertRaises(ActiveTaskTeardownBlockedError):
            commit_safe_teardown(self.ws, abort_active=False)

        commit_safe_teardown(self.ws, abort_active=True, elevate=True)
        final_state = load_active_state(self.ws)
        self.assertEqual(final_state["status"], "ABORTED")

    def test_adversarial_batch4_topology_and_stage4_stage7_symlinks(self) -> None:
        """Topology, Stage 4 report lint, and Stage 7 qual naming must reject symlinks."""
        from stagecheck.checks.base import AuditContext
        from stagecheck.checks.stage4_report_lint import run_stage4_report_lint
        from stagecheck.checks.stage7_qual_naming import run_stage7_qual_naming
        from stagecheck.core.paths import StageCheckPathError
        from stagecheck.core.topology import validate_worktree_hierarchy

        wt_root = self.ws / ".stagecheck_worktrees"
        outside = Path(self.temp_dir.name) / "outside_dir"
        outside.mkdir(parents=True, exist_ok=True)
        if wt_root.exists() or wt_root.is_symlink():
            if wt_root.is_symlink() or wt_root.is_file():
                wt_root.unlink()
            else:
                shutil.rmtree(wt_root)
        wt_root.symlink_to(outside)
        with self.assertRaises((StageCheckPathError, Exception)):
            validate_worktree_hierarchy(self.ws, wt_root)

        task_dir = resolve_task_attempt_dir(self.ws, "task-sym-47", 1)
        p3_dir = task_dir / "Phase-3"
        p3_dir.mkdir(parents=True, exist_ok=True)
        target_secret = self.ws / "repos" / "backend" / "README.md"
        (p3_dir / "report.md").symlink_to(target_secret)

        ctx = AuditContext(
            workspace_root=self.ws,
            task_id="task-sym-47",
            attempt=1,
            touched_repos=["backend"],
            all_registered_repos=["backend", "frontend"],
        )
        res4 = run_stage4_report_lint(ctx)
        self.assertFalse(res4.is_clear)

        qual_dir = self.ws / "evals"
        qual_dir.mkdir(parents=True, exist_ok=True)
        (qual_dir / "test_fake.py").symlink_to(target_secret)
        res7 = run_stage7_qual_naming(ctx)
        self.assertFalse(res7.is_clear)
        self.assertTrue(any("unauthorized_symlink" in d.defect_id for d in res7.defects))

    def test_adversarial_batch4_prompt_gate_and_evidence_symlink_guards(self) -> None:
        """Prompt gate rejects symlinked prompt.md and mismatched task_id scope; manifest rejects missing seal."""
        from stagecheck.core.evidence import verify_evidence_manifest
        from stagecheck.core.prompt_gate import PromptGateError, freeze_prompt_and_scope

        p1_dir = self.ws / "evidence" / "tasks" / "task-pg-sym" / "attempt_1" / "Phase-1"
        p1_dir.mkdir(parents=True, exist_ok=True)
        (p1_dir / "prompt.md").symlink_to(self.ws / "repos" / "backend" / "README.md")
        (p1_dir / "declared_scope.json").write_text(
            json.dumps({"schema_version": "2.0.0", "task_id": "task-pg-sym", "allowed_paths": ["repos/backend/README.md"]}),
            encoding="utf-8",
        )
        with self.assertRaises(PromptGateError):
            freeze_prompt_and_scope(self.ws, "task-pg-sym", 1)

        (p1_dir / "prompt.md").unlink()
        (p1_dir / "prompt.md").write_text("# Valid prompt\n", encoding="utf-8")
        (p1_dir / "declared_scope.json").write_text(
            json.dumps({"schema_version": "2.0.0", "task_id": "other-task", "allowed_paths": ["repos/backend/README.md"]}),
            encoding="utf-8",
        )
        with self.assertRaises(PromptGateError):
            freeze_prompt_and_scope(self.ws, "task-pg-sym", 1)

        # EVIDENCE_MANIFEST.json indexing a missing seal.json fails closed
        manifest_file = self.ws / "evidence" / "EVIDENCE_MANIFEST.json"
        with controlled_write_transaction(self.ws / "evidence"):
            manifest_file.write_text(
                json.dumps({
                    "schema_version": "2.0.0",
                    "sealed_tasks": {
                        "task-missing-seal": {
                            "attempt_1": {
                                "seal_sha256": "a" * 64,
                                "merkle_root_sha256": "b" * 64,
                                "total_files": 0,
                            }
                        }
                    },
                }),
                encoding="utf-8",
            )
        is_valid, violations = verify_evidence_manifest(self.ws)
        self.assertFalse(is_valid)
        self.assertTrue(any("missing or symlinked" in v for v in violations))

    def test_adversarial_batch4_journal_symlink_and_corrupt_preimages_quarantined(self) -> None:
        """Symlinked journal fails closed; non-dict pre_images quarantined; rollback restores read-only mode."""
        from stagecheck.core.journal import JournalError

        controls_file = self.ws / "controls" / "ACTIVE_STATE.json"
        orig_text = controls_file.read_text(encoding="utf-8")
        with self.assertRaises(RuntimeError):
            with write_ahead_transaction(self.ws, "ROLLBACK_MODE_CHECK") as j:
                j.record_pre_image(controls_file)
                controls_file.chmod(0o644)
                controls_file.write_text("{}", encoding="utf-8")
                raise RuntimeError("boom")
        self.assertEqual(controls_file.read_text(encoding="utf-8"), orig_text)
        self.assertEqual(controls_file.stat().st_mode & 0o777, 0o444)

        jdir = self.ws / ".stagecheck_journal"
        jdir.mkdir(parents=True, exist_ok=True)
        bad_txn = jdir / "bad_txn.active.json"
        bad_txn.write_text(json.dumps({
            "txn_id": "bad-01",
            "operation": "TEST",
            "pre_images": ["not-a-dict"],
            "pre_modes": {},
        }), encoding="utf-8")
        recs = recover_interrupted_transactions(self.ws)
        self.assertTrue(any(r.txn_id == "bad-01" and r.status == "CORRUPTED" for r in recs))
        self.assertFalse(bad_txn.exists())

        shutil.rmtree(jdir)
        outside = Path(self.temp_dir.name) / "outside_journal"
        outside.mkdir(parents=True, exist_ok=True)
        jdir.symlink_to(outside)
        with self.assertRaises(JournalError):
            recover_interrupted_transactions(self.ws)

    # =========================================================================
    # Batch 6 Regression Guards (Findings 13, 23, 24, 25, 28, 29, 32, 33, 35, 36)
    # =========================================================================

    def test_adversarial_batch6_dual_role_and_single_agent_fail_closed(self) -> None:
        """[13] dual_role cannot spoof prompt_and_audit; single_agent_mode fails dual-agent rules."""
        from stagecheck.core.rubric_engine import (
            _collect_rubric_context,
            build_agent_reviews_artifact,
            evaluate_rubric_rule,
            load_270_rule_catalog,
            validate_agent_review_provenance,
        )

        solo_ws = Path(self.temp_dir.name) / "solo_ws"
        solo_repo = solo_ws / "repos" / "app"
        solo_repo.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "-C", str(solo_repo), "init"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(solo_repo), "config", "user.name", "Tester"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(solo_repo), "config", "user.email", "tester@example.com"], check=True, capture_output=True)
        (solo_repo / "app.py").write_text("x = 1\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(solo_repo), "add", "app.py"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(solo_repo), "commit", "-m", "init"], check=True, capture_output=True)

        self.assertEqual(run_init(solo_ws, agent1="solo", agent2="solo"), 0)
        self.assertEqual(run_start(workspace=solo_ws, task="task-solo-01"), 0)

        p2a_dir = solo_ws / "evidence" / "tasks" / "task-solo-01" / "attempt_1" / "Phase-2A"
        p2a_dir.mkdir(parents=True, exist_ok=True)
        reviews_doc = build_agent_reviews_artifact(
            workspace_root=solo_ws,
            task_id="task-solo-01",
            attempt=1,
            reviews={},
            reviewer="solo",
            reviewer_role="prompt_and_audit",
        )
        (p2a_dir / "agent_reviews.json").write_text(json.dumps(reviews_doc), encoding="utf-8")
        ok, _, reason = validate_agent_review_provenance(
            workspace_root=solo_ws,
            src_doc=reviews_doc,
            src_rel_path="Phase-2A/agent_reviews.json",
            task_id="task-solo-01",
            attempt=1,
            active_state=load_active_state(solo_ws),
            pre_commit_status={
                "task_id": "task-solo-01",
                "attempt": 1,
                "touched_repositories": ["app"],
                "base_commits": reviews_doc["head_commits"],
            },
            repo_heads=reviews_doc["head_commits"],
            diff_snapshot_sha256=reviews_doc["diff_snapshot_sha256"],
        )
        self.assertFalse(ok)
        self.assertIn("role", reason.lower())

        catalog = {r.rule_id: r for r in load_270_rule_catalog()}
        ctx = _collect_rubric_context(solo_ws, task_id="task-solo-01", attempt=1)
        for rid in ("CLAIM_SUPPORT-013", "INDEPENDENT_RERUN-001"):
            res = evaluate_rubric_rule(catalog[rid], solo_ws, ctx)
            self.assertEqual(res.status, "FAIL", f"{rid} must fail in single_agent_mode: {res}")

    def test_adversarial_batch6_forged_rubric_and_prompt_scope_invariance(self) -> None:
        """[28, 32, 36] Reject forged 270/270 rubric, wrong N/A predicates, deleted prompt.md, and scope task mismatch."""
        from stagecheck.core.prompt_gate import freeze_prompt_and_scope
        from stagecheck.core.rubric_engine import (
            InvalidRubricExemptionError,
            _collect_rubric_context,
            compute_rubric_context_digest,
            evaluate_rubric_rule,
            load_270_rule_catalog,
            validate_rubric_evaluation_payload,
            verify_complete_rubric_evaluation,
        )

        p1_dir = self.ws / "evidence" / "tasks" / "task-adv-01" / "attempt_1" / "Phase-1"
        p1_dir.mkdir(parents=True, exist_ok=True)
        (p1_dir / "prompt.md").write_text("# Task\nImplement hardened verification checks.\n", encoding="utf-8")
        (p1_dir / "declared_scope.json").write_text(
            json.dumps({"schema_version": "2.0", "task_id": "task-adv-01", "allowed_paths": ["repos/backend/main.py"]}),
            encoding="utf-8",
        )
        freeze_prompt_and_scope(self.ws, "task-adv-01", 1)

        catalog = load_270_rule_catalog()
        by_id = {r.rule_id: r for r in catalog}

        # [36a] Forged NOT_APPLICABLE using wrong evaluator/exemption_predicate rejected
        with self.assertRaises(InvalidRubricExemptionError):
            validate_rubric_evaluation_payload([
                {
                    "rule_id": catalog[0].rule_id,
                    "title": catalog[0].title,
                    "category": catalog[0].category,
                    "domain": catalog[0].domain,
                    "status": "NOT_APPLICABLE",
                    "severity": "BLOCKING",
                    "evaluator": "forged_evaluator",
                    "evidence_path": "",
                    "message": "fake na",
                    "exemption_predicate": "fake_predicate",
                }
            ])

        # [36b] Forged 270/270 PASS JSON with genuine context_digest caught by live re-evaluation
        ctx_digest = compute_rubric_context_digest(self.ws, "task-adv-01", 1)
        forged_doc = {
            "schema_version": "2.0",
            "task_id": "task-adv-01",
            "attempt": 1,
            "cycle": 1,
            "context_digest": ctx_digest,
            "overall_verdict": "PASS",
            "counts": {
                "total": len(catalog),
                "pass": len(catalog),
                "fail": 0,
                "not_applicable": 0,
                "evaluated": len(catalog),
            },
            "evaluations": [
                {
                    "rule_id": r.rule_id,
                    "title": r.title,
                    "category": r.category,
                    "domain": r.domain,
                    "status": "PASS",
                    "severity": "BLOCKING",
                    "evaluator": r.domain.lower() + "_evaluator",
                    "evidence_path": "Phase-1/prompt.md",
                    "message": "forged pass",
                }
                for r in catalog
            ],
        }
        p2a_rubric = self.ws / "evidence" / "tasks" / "task-adv-01" / "attempt_1" / "Phase-2A" / "rubric_evaluation.json"
        p2a_rubric.parent.mkdir(parents=True, exist_ok=True)
        p2a_rubric.write_text(json.dumps(forged_doc), encoding="utf-8")
        v_ok, _, v_reasons = verify_complete_rubric_evaluation(
            self.ws, p2a_rubric, task_id="task-adv-01", attempt=1
        )
        self.assertFalse(v_ok)
        self.assertTrue(v_reasons)

        # [32] Deleting prompt.md after prompt_verified.json fails COMMON-025
        (p1_dir / "prompt.md").unlink()
        ctx_missing = _collect_rubric_context(self.ws, task_id="task-adv-01", attempt=1)
        res_025 = evaluate_rubric_rule(by_id["COMMON-025"], self.ws, ctx_missing)
        self.assertEqual(res_025.status, "FAIL")

        # [28] Replacing declared_scope.json with mismatched task_id fails Gate-1
        from stagecheck.core.gate_engine import evaluate_gate_1_criteria
        (p1_dir / "prompt.md").write_text("# Task\nImplement hardened verification checks.\n", encoding="utf-8")
        os.chmod(p1_dir / "declared_scope.json", 0o644)
        (p1_dir / "declared_scope.json").write_text(
            json.dumps({"schema_version": "2.0", "task_id": "other-task", "allowed_paths": ["repos/backend/main.py"]}),
            encoding="utf-8",
        )
        criteria, _ = evaluate_gate_1_criteria(self.ws, "task-adv-01", 1)
        self.assertTrue(any(c.status == "FAILED" for c in criteria))

    def test_adversarial_batch6_waiver_finalization_on_breaker(self) -> None:
        """[29] Tripping the circuit breaker finalizes attempt waivers against replay."""
        from stagecheck.core.circuit_breaker import CircuitBreakerEvaluation, trip_circuit_breaker
        from stagecheck.core.dispositions import (
            DispositionReplayError,
            build_waiver_entry,
            record_waiver_in_replay_ledger,
            validate_waiver_provenance,
        )

        proof = self.ws / "evidence" / "waiver_b6.txt"
        with controlled_write_transaction(self.ws / "evidence"):
            proof.write_text("Approved waiver proof\n", encoding="utf-8")
        entry = build_waiver_entry(
            workspace_root=self.ws,
            task_id="task-adv-01",
            defect_id="sec.test_waiver",
            rationale="Verified temporary waiver",
            authorized_by="owner@stagecheck.local",
            attempt=1,
            evidence_path="evidence/waiver_b6.txt",
            rule_id="SECRETS-001",
            waived_rules=["SECRETS-001"],
        )
        record_waiver_in_replay_ledger(self.ws, entry)

        trip_circuit_breaker(
            self.ws,
            "task-adv-01",
            1,
            CircuitBreakerEvaluation(tripped=True, trigger="stagnant_defects", reason="Stagnant"),
            [],
        )
        ok_w, msg_w = validate_waiver_provenance(self.ws, entry, "task-adv-01", 1)
        self.assertFalse(ok_w)
        self.assertIn("replay", msg_w.lower())

    def test_adversarial_batch6_resume_and_circuit_breaker_guards(self) -> None:
        """[24, 25] Resume requires AWAITING_HUMAN_DISPOSITION + verdict.json; breaker reset requires granted human."""
        from stagecheck.cli.main import main
        from stagecheck.core.circuit_breaker import CircuitBreakerEvaluation, trip_circuit_breaker
        from stagecheck.core.dispositions import DispositionError, resume_after_disposition

        # [25a] Wrong phase fails closed
        with self.assertRaises(DispositionError):
            resume_after_disposition(self.ws, "task-adv-01")

        # [25b] Missing Phase-3/verdict.json fails closed even in AWAITING_HUMAN_DISPOSITION
        with controlled_write_transaction(self.ws / "controls"):
            st = load_active_state(self.ws)
            st["phase"] = "AWAITING_HUMAN_DISPOSITION"
            save_active_state(self.ws, st)
        with self.assertRaises(DispositionError):
            resume_after_disposition(self.ws, "task-adv-01")

        # [25c] Valid verdict.json resumes cleanly to PHASE_3_AUDIT without schema-invalid fields
        p3_dir = self.ws / "evidence" / "tasks" / "task-adv-01" / "attempt_1" / "Phase-3"
        p3_dir.mkdir(parents=True, exist_ok=True)
        (p3_dir / "verdict.json").write_text(json.dumps({"result": "PASSED", "defects": []}), encoding="utf-8")
        res = resume_after_disposition(self.ws, "task-adv-01")
        self.assertEqual(res["resumed_phase"], "PHASE_3_AUDIT")
        updated = load_active_state(self.ws)
        self.assertEqual(updated["phase"], "PHASE_3_AUDIT")
        self.assertNotIn("resume_reason", updated)
        self.assertNotIn("resumed_at", updated)

        # [24] Circuit breaker reset rejects ungranted/agent/empty/unconfirmed/non-TTY calls
        trip_circuit_breaker(
            self.ws,
            "task-adv-01",
            2,
            CircuitBreakerEvaluation(tripped=True, trigger="stagnant_defects", reason="Stagnant"),
            [],
        )
        for bad_id in ("agent2", "human-operator", ""):
            with self.assertRaises(ResetAttemptsError):
                reset_circuit_breaker(self.ws, "task-adv-01", authorized_by=bad_id)
        with self.assertRaises(ResetAttemptsError):
            reset_circuit_breaker(
                self.ws,
                "task-adv-01",
                authorized_by="owner@stagecheck.local",
                require_tty=True,
                confirmed=False,
            )
        rc = main(["disposition", "--task", "task-adv-01", "--action", "retry", "--workspace", str(self.ws), "--yes"])
        self.assertNotEqual(rc, 0)

    def test_adversarial_batch6_merkle_chain_and_plan_start_guards(self) -> None:
        """[23, 33, 35] Enforce Merkle seal chain, ignore unindexed plan seals, and block task restarts."""
        from contextlib import redirect_stdout
        import io
        from stagecheck.checks.base import AuditContext
        from stagecheck.checks.stage9_carry_forward import run_stage9_carry_forward
        from stagecheck.cli.plan_cmd import run_plan
        from stagecheck.core.sealing import SealingError, compute_attempt_merkle_seal, index_seal_in_manifest

        att1 = self.ws / "evidence" / "tasks" / "task-adv-01" / "attempt_1"
        att2 = self.ws / "evidence" / "tasks" / "task-adv-01" / "attempt_2"
        att3 = self.ws / "evidence" / "tasks" / "task-adv-01" / "attempt_3"
        (att1 / "Phase-1").mkdir(parents=True, exist_ok=True)
        (att1 / "Phase-1" / "prompt.md").write_text("# A1\nOriginal prompt.\n", encoding="utf-8")
        (att2 / "Phase-1").mkdir(parents=True, exist_ok=True)
        (att2 / "Phase-1" / "prompt.md").write_text("# A2\nRetry prompt.\n", encoding="utf-8")
        att3.mkdir(parents=True, exist_ok=True)

        seal1_rec = compute_attempt_merkle_seal(att1, self.ws, "task-adv-01", 1, write_seal_file=True)
        index_seal_in_manifest(self.ws, "task-adv-01", 1, seal1_rec)
        seal2_rec = compute_attempt_merkle_seal(att2, self.ws, "task-adv-01", 2, write_seal_file=True)
        index_seal_in_manifest(self.ws, "task-adv-01", 2, seal2_rec)

        # [23a] Tampering attempt_1/seal.json fails attempt_2 seal generation
        seal1_path = att1 / "seal.json"
        s1_obj = json.loads(seal1_path.read_text(encoding="utf-8"))
        s1_obj["merkle_root_sha256"] = "0" * 64
        os.chmod(att1, 0o755)
        os.chmod(seal1_path, 0o644)
        seal1_path.write_text(json.dumps(s1_obj), encoding="utf-8")
        with self.assertRaises(SealingError):
            compute_attempt_merkle_seal(att2, self.ws, "task-adv-01", 2, write_seal_file=True)

        # [23b] Stage 9 on attempt=3 catches tampered attempt_1 even when attempt_2 used Merkle seal
        s9_res = run_stage9_carry_forward(
            AuditContext(
                workspace_root=self.ws,
                task_id="task-adv-01",
                attempt=3,
                touched_repos=["backend"],
                all_registered_repos=["backend", "frontend"],
            )
        )
        self.assertEqual(s9_res.status, "FAIL")

        # [33] plan next ignores unindexed seal.json files under evidence/tasks
        plan_file = self.ws / "specs" / "TASK_PLAN.json"
        plan_obj = json.loads(plan_file.read_text(encoding="utf-8"))
        plan_obj["tasks"] = [
            {
                "task_id": "task-adv-01",
                "title": "First",
                "description": "First task in dependency chain.",
                "priority": "HIGH",
                "target_repositories": ["backend"],
                "dependencies": [],
                "status": "planned",
            },
            {
                "task_id": "task-next-02",
                "title": "Second",
                "description": "Second task blocked on task-adv-01.",
                "priority": "HIGH",
                "target_repositories": ["backend"],
                "dependencies": ["task-adv-01"],
                "status": "planned",
            },
        ]
        with controlled_write_transaction(self.ws / "specs"):
            plan_file.write_text(json.dumps(plan_obj), encoding="utf-8")
        forged_seal_dir = self.ws / "evidence" / "tasks" / "task-fake" / "attempt_1"
        forged_seal_dir.mkdir(parents=True, exist_ok=True)
        (forged_seal_dir / "seal.json").write_text(json.dumps({"task_id": "task-adv-01"}), encoding="utf-8")
        out_buf = io.StringIO()
        with redirect_stdout(out_buf):
            rc_plan = run_plan("next", workspace=str(self.ws))
        self.assertEqual(rc_plan, 0)
        self.assertIn("task-adv-01", out_buf.getvalue())

        # [35] start rejects restarting completed/attempted task, allows fresh next task
        with controlled_write_transaction(self.ws / "controls"):
            st = load_active_state(self.ws)
            st["phase"] = "COMPLETED"
            st["status"] = "SEALED_PASSED"
            st["halt_reason"] = "old"
            save_active_state(self.ws, st)
        self.assertEqual(run_start(workspace=self.ws, task="task-adv-01"), 1)
        self.assertEqual(run_start(workspace=self.ws, task="task-next-02"), 0)
        new_st = load_active_state(self.ws)
        self.assertEqual(new_st["task_id"], "task-next-02")
        self.assertNotIn("halt_reason", new_st)


if __name__ == "__main__":
    unittest.main()
