"""End-to-End Lifecycle and Adversarial Integration Scenarios (Spec 11/12/13/14, P5-T3).

Covers:
1. Complete happy path: init -> verify-prompt -> scoped implementation -> review -> audit -> seal.
2. Adversarial tampering detection: post-seal modification of verdict or evidence triggers seal corruption.
3. Adversarial scope escape: unauthorized file modification outside declared scope blocked by Stage 2.
4. Multi-repo dual-agent partial failure: zero partial pass rule blocks aggregate when any repo fails.
5. Circuit breaker escalation & reset-attempts recovery: 3 attempt failures trip breaker, human unlatches.
"""
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from stagecheck.cli.init_cmd import run_init
from stagecheck.cli.start_cmd import run_start
from stagecheck.cli.prompt_cmd import run_verify_prompt
from stagecheck.cli.gate_cmd import run_gate_advance
from stagecheck.cli.review_cmd import run_approve_review, run_review_precommit
from stagecheck.cli.audit_cmd import run_audit_cmd
from stagecheck.cli.reset_cmd import run_reset_attempts
from stagecheck.cli.disposition_cmd import run_disposition_add
from stagecheck.cli.resume_cmd import run_resume
from stagecheck.core.circuit_breaker import CircuitBreakerEvaluation, trip_circuit_breaker
from stagecheck.core.evidence import create_task_seal, verify_seal_chain, verify_evidence_manifest
from stagecheck.core.permissions import controlled_write_transaction
from stagecheck.core.state import load_active_state, save_active_state


def run_git(args, cwd: Path) -> subprocess.CompletedProcess:
    """Helper to run git commands in a target repository."""
    return subprocess.run(
        ["git", "-C", str(cwd)] + args,
        capture_output=True,
        text=True,
        check=True,
    )


class TestEndToEndLifecycle(unittest.TestCase):
    """Full lifecycle and adversarial regression test scenarios."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="stagecheck-e2e-")
        self.ws = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _setup_git_repo(self, repo_rel_path: str, initial_file: str = "main.py") -> Path:
        """Initializes a real git repo with an initial commit."""
        repo_dir = self.ws / repo_rel_path
        repo_dir.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "init", str(repo_dir)], check=True, capture_output=True)
        run_git(["config", "user.name", "Tester"], cwd=repo_dir)
        run_git(["config", "user.email", "tester@example.com"], cwd=repo_dir)
        (repo_dir / initial_file).write_text("# Initial commit\n")
        run_git(["add", "."], cwd=repo_dir)
        run_git(["commit", "-m", "Initial commit"], cwd=repo_dir)
        return repo_dir

    def test_e2e_scenario1_clean_lifecycle_to_seal(self):
        """Scenario 1: Happy path lifecycle (init -> verify-prompt -> review -> audit -> seal)."""
        # 1. Setup repository and initialize
        self._setup_git_repo("repos/core-service", "service.py")
        rc = run_init(self.ws, agent1="agent1", agent2="agent2")
        self.assertEqual(rc, 0, "stagecheck init failed")

        # 2. Start task-101
        rc = run_start(workspace=self.ws, task="task-101")
        self.assertEqual(rc, 0, "stagecheck start failed")

        state = load_active_state(self.ws)
        self.assertEqual(state["task_id"], "task-101")
        self.assertEqual(state["phase"], "PHASE_1_PLANNING")
        self.assertEqual(state["attempt_index"], 1)

        # 3. Create prompt blueprint and declared scope
        task_dir = self.ws / "evidence/tasks/task-101/attempt_1/Phase-1"
        task_dir.mkdir(parents=True, exist_ok=True)

        specs_dir = self.ws / "specs"
        specs_dir.mkdir(parents=True, exist_ok=True)
        (specs_dir / "TASK_PLAN.md").write_text("# Plan for task-101\n")
        (specs_dir / "ARCHITECTURE.md").write_text("# Architecture for task-101\n")
        from stagecheck.core.start_manifest import update_spec_manifest
        update_spec_manifest(self.ws)

        scope_data = {
            "schema_version": "2.0",
            "task_id": "task-101",
            "allowed_paths": ["repos/core-service/service.py", "repos/core-service/test_service.py"],
        }
        (task_dir / "declared_scope.json").write_text(json.dumps(scope_data, indent=2) + "\n")
        (task_dir / "prompt.md").write_text("# Prompt for task-101\nImplement service logic.\n")

        # 4. Verify prompt
        rc = run_verify_prompt("task-101", attempt=1, workspace=str(self.ws))
        self.assertEqual(rc, 0, "verify-prompt failed")
        self.assertTrue((task_dir / "prompt_verified.json").is_file())

        # Advance Gate 1 (PHASE_1_PLANNING -> PHASE_2A_CODING)
        rc = run_gate_advance("Gate-1", task="task-101", attempt=1, workspace=str(self.ws))
        self.assertEqual(rc, 0, "Gate-1 advance failed")

        # Ensure qualification dir exists
        (self.ws / "evals").mkdir(parents=True, exist_ok=True)

        # 5. Scoped Implementation in core-service on task branch
        repo_dir = self.ws / "repos/core-service"
        run_git(["switch", "-c", "task/task-101"], cwd=repo_dir)
        base_commit = run_git(["rev-parse", "HEAD"], cwd=repo_dir).stdout.strip()
        (repo_dir / "service.py").write_text("def run_service():\n    return 'OK'\n")
        (repo_dir / "test_service.py").write_text("def test_service():\n    assert True\n")
        run_git(["add", "."], cwd=repo_dir)

        # 6. Prepare Phase 2A pre-commit review status and approve review
        phase2a_dir = self.ws / "evidence/tasks/task-101/attempt_1/Phase-2A"
        phase2a_dir.mkdir(parents=True, exist_ok=True)
        status_data = {
            "schema_version": "1.0.0",
            "task_id": "task-101",
            "attempt": 1,
            "cycle": 1,
            "status": "AWAITING_REVIEW",
            "touched_repositories": ["core-service"],
            "base_commits": {"core-service": base_commit},
            "summary": "Implementation completed and ready for review",
        }
        (phase2a_dir / "pre_commit_status.json").write_text(json.dumps(status_data, indent=2) + "\n")

        rc = run_approve_review("task-101", attempt=1, workspace=str(self.ws))
        self.assertEqual(rc, 0, "approve-review failed")
        self.assertTrue((phase2a_dir / "pre_commit_review.json").is_file())

        # 7. Commit approved changes locally (post-approval)
        run_git(["add", "."], cwd=repo_dir)
        run_git(["commit", "-m", "feat: implement service logic"], cwd=repo_dir)
        head_commit = run_git(["rev-parse", "HEAD"], cwd=repo_dir).stdout.strip()

        # Delivery report for Phase 2B
        phase2b_dir = self.ws / "evidence/tasks/task-101/attempt_1/Phase-2B"
        phase2b_dir.mkdir(parents=True, exist_ok=True)
        (phase2b_dir / "report.md").write_text("# Delivery report\nImplemented service.py and tests.\n")

        # Advance Gate 2B (PHASE_2A_CODING -> PHASE_3_AUDIT)
        rc = run_gate_advance("Gate-2B", task="task-101", attempt=1, workspace=str(self.ws))
        self.assertEqual(rc, 0, "Gate-2B advance failed")

        # 8. Audit (Phase 3 9-stage verification)
        rc = run_audit_cmd("task-101", attempt=1, workspace=str(self.ws))
        self.assertEqual(rc, 0, "audit failed")

        verdict_file = self.ws / "evidence/tasks/task-101/attempt_1/Phase-3/verdict.json"
        self.assertTrue(verdict_file.exists())
        verdict = json.loads(verdict_file.read_text())
        self.assertEqual(verdict["result"], "CLEAR")

        # Advance Gate 3 (PHASE_3_AUDIT -> GATE_4_SEALING)
        rc = run_gate_advance("Gate-3", task="task-101", attempt=1, workspace=str(self.ws))
        self.assertEqual(rc, 0, "Gate-3 advance failed")

        # 9. Seal Attempt & Advance Gate 4 (GATE_4_SEALING -> SEALED_PASSED)
        rc = run_gate_advance("Gate-4", task="task-101", attempt=1, workspace=str(self.ws))
        self.assertEqual(rc, 0, "Gate-4 advance failed")

        seal_path = self.ws / "evidence" / "tasks" / "task-101" / "attempt_1" / "seal.json"
        self.assertTrue(seal_path.is_file())

        # Verify unbroken seal chain
        is_valid, violations = verify_seal_chain(self.ws, "task-101", max_attempt=1)
        self.assertTrue(is_valid, f"Seal chain broken: {violations}")

        # Verify evidence manifest integrity
        is_valid, violations = verify_evidence_manifest(self.ws)
        self.assertTrue(is_valid, f"Manifest integrity failed: {violations}")

    def test_e2e_scenario2_adversarial_tampering_detection(self):
        """Scenario 2: Adversarial tampering detected if sealed attempt artifacts are mutated."""
        self._setup_git_repo("repos/core-service", "service.py")
        run_init(self.ws, agent1="agent1", agent2="agent2")
        run_start(workspace=self.ws, task="task-202")

        attempt_dir = self.ws / "evidence/tasks/task-202/attempt_1"
        attempt_dir.mkdir(parents=True, exist_ok=True)
        verdict_file = attempt_dir / "verdict.json"
        verdict_file.write_text('{"verdict": "CLEAR"}\n')

        seal_path = create_task_seal(
            workspace_root=self.ws,
            task_id="task-202",
            attempt=1,
            verdict_data={"verdict": "CLEAR"},
            checked_heads={"core-service": "abc"},
            outcome="PASSED",
        )
        self.assertTrue(seal_path.is_file())

        # Pristine check passes
        is_valid, violations = verify_evidence_manifest(self.ws)
        self.assertTrue(is_valid, f"Pristine manifest check failed: {violations}")

        # Adversary mutates evidence file
        verdict_file.chmod(0o666)
        verdict_file.write_text('{"verdict": "CLEAR", "tampered": true}\n')

        # Manifest verification MUST catch the tampered SHA-256
        is_valid, violations = verify_evidence_manifest(self.ws)
        self.assertFalse(is_valid, "Tampering was not detected by evidence manifest verification!")
        self.assertTrue(any("mismatch" in v.lower() for v in violations))

    def test_e2e_scenario3_adversarial_scope_escape_blocked(self):
        """Scenario 3: Adversarial modification of files outside declared scope is blocked."""
        self._setup_git_repo("repos/core-service", "service.py")
        run_init(self.ws, agent1="agent1", agent2="agent2")
        run_start(workspace=self.ws, task="task-303")

        task_dir = self.ws / "evidence/tasks/task-303/attempt_1/Phase-1"
        task_dir.mkdir(parents=True, exist_ok=True)
        scope_data = {
            "schema_version": "2.0",
            "task_id": "task-303",
            "allowed_paths": ["repos/core-service/service.py"],
        }
        (task_dir / "declared_scope.json").write_text(json.dumps(scope_data, indent=2) + "\n")
        (task_dir / "prompt.md").write_text("# Prompt for task-303\n")
        run_verify_prompt("task-303", attempt=1, workspace=str(self.ws))

        # Advance Gate 1
        rc = run_gate_advance("Gate-1", task="task-303", attempt=1, workspace=str(self.ws))
        self.assertEqual(rc, 0)

        # Adversary attempts scope escape: commits an unauthorized file
        repo_dir = self.ws / "repos/core-service"
        run_git(["switch", "-c", "task/task-303"], cwd=repo_dir)
        (repo_dir / "service.py").write_text("# ok\n")
        (repo_dir / "unauthorized_backdoor.py").write_text("# escape\n")
        run_git(["add", "."], cwd=repo_dir)
        run_git(["commit", "-m", "feat: malicious scope escape"], cwd=repo_dir)

        # Verify authoritative baseline mismatch / unapproved post-commit bypass is rejected by approve-review
        base_commit = json.loads((self.ws / "controls/PRODUCT_REPOSITORIES.json").read_text())["repositories"]["core-service"]["baseline_head"]
        phase2a_dir = self.ws / "evidence/tasks/task-303/attempt_1/Phase-2A"
        phase2a_dir.mkdir(parents=True, exist_ok=True)
        head_commit = run_git(["rev-parse", "HEAD"], cwd=repo_dir).stdout.strip()
        status_data = {
            "schema_version": "1.0.0",
            "task_id": "task-303",
            "attempt": 1,
            "cycle": 1,
            "status": "AWAITING_REVIEW",
            "touched_repositories": ["core-service"],
            "base_commits": {"core-service": head_commit},
            "summary": "Review",
        }
        (phase2a_dir / "pre_commit_status.json").write_text(json.dumps(status_data, indent=2) + "\n")
        self.assertNotEqual(run_approve_review("task-303", attempt=1, workspace=str(self.ws)), 0)

        # Simulate reaching Phase 3 audit with an approved review for defense-in-depth verification
        from stagecheck.core.cooperative_review import record_pre_commit_review
        from stagecheck.core.state import load_active_state, save_active_state
        diff_res = subprocess.run(
            ["git", "-C", str(repo_dir), "diff", "--binary", f"{base_commit}..{head_commit}"],
            capture_output=True, check=True,
        )
        from stagecheck.core.utils import sha256_digest
        diff_sha = sha256_digest(diff_res.stdout)
        (phase2a_dir / "pre_commit_review.json").write_text(json.dumps({
            "schema_version": "2.0",
            "task_id": "task-303",
            "attempt": 1,
            "cycle": 1,
            "status": "APPROVED",
            "summary": "Simulated review to test Phase 3 defense-in-depth",
            "base_commits": {"core-service": base_commit},
            "approved_diff_hashes": {"core-service": diff_sha},
            "approved_snapshot_sha256": diff_sha,
            "approved_diff_sha256": diff_sha,
            "pre_existing_issues_ignored": [],
            "architectural_intents_approved": [],
            "new_issues_found": [],
        }, indent=2))

        # Delivery report for Phase 2B
        phase2b_dir = self.ws / "evidence/tasks/task-303/attempt_1/Phase-2B"
        phase2b_dir.mkdir(parents=True, exist_ok=True)
        (phase2b_dir / "report.md").write_text("# Delivery report\nImplemented changes.\n")

        # Advance Gate 2B
        rc = run_gate_advance("Gate-2B", task="task-303", attempt=1, workspace=str(self.ws))
        self.assertEqual(rc, 0)

        # Audit MUST reject with BLOCKED verdict
        rc = run_audit_cmd("task-303", attempt=1, workspace=str(self.ws))
        self.assertEqual(rc, 1, "Audit should have failed due to scope escape!")

        verdict_file = self.ws / "evidence/tasks/task-303/attempt_1/Phase-3/verdict.json"
        verdict = json.loads(verdict_file.read_text())
        self.assertEqual(verdict["result"], "BLOCKED")

        defects = verdict.get("defects", [])
        defect_codes = [d.get("defect_id", "") for d in defects]
        self.assertIn("scope_paths.out_of_scope_modification", defect_codes)

        # Attempting Gate 3 advance MUST be rejected because verdict is BLOCKED
        rc = run_gate_advance("Gate-3", task="task-303", attempt=1, workspace=str(self.ws))
        self.assertEqual(rc, 1, "Gate 3 advance must fail when audit verdict is BLOCKED")

    def test_e2e_scenario4_multi_repo_atomic_partial_failure(self):
        """Scenario 4: Multi-repo aggregate audit rejects completely if any repo fails."""
        self._setup_git_repo("repos/backend", "api.py")
        self._setup_git_repo("repos/frontend", "App.js")
        run_init(self.ws, agent1="agent1", agent2="agent2")
        run_start(workspace=self.ws, task="task-404")

        task_dir = self.ws / "evidence/tasks/task-404/attempt_1/Phase-1"
        task_dir.mkdir(parents=True, exist_ok=True)
        scope_data = {
            "schema_version": "2.0",
            "task_id": "task-404",
            "allowed_paths": ["repos/backend/api.py", "repos/frontend/App.js"],
        }
        (task_dir / "declared_scope.json").write_text(json.dumps(scope_data, indent=2) + "\n")
        (task_dir / "prompt.md").write_text("# Multi-repo prompt\n")
        run_verify_prompt("task-404", attempt=1, workspace=str(self.ws))

        # Advance Gate 1
        rc = run_gate_advance("Gate-1", task="task-404", attempt=1, workspace=str(self.ws))
        self.assertEqual(rc, 0)

        # Backend is clean
        backend_dir = self.ws / "repos/backend"
        run_git(["switch", "-c", "task/task-404"], cwd=backend_dir)
        (backend_dir / "api.py").write_text("def api(): return 200\n")
        run_git(["add", "."], cwd=backend_dir)
        run_git(["commit", "-m", "feat: clean backend"], cwd=backend_dir)

        # Frontend commits a forbidden hardcoded secret token
        frontend_dir = self.ws / "repos/frontend"
        run_git(["switch", "-c", "task/task-404"], cwd=frontend_dir)
        (frontend_dir / "App.js").write_text(
            "const secret = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890';\n"
        )
        run_git(["add", "."], cwd=frontend_dir)
        run_git(["commit", "-m", "feat: frontend with secret leak"], cwd=frontend_dir)

        prod_repos = json.loads((self.ws / "controls/PRODUCT_REPOSITORIES.json").read_text())["repositories"]
        base_backend = prod_repos["backend"]["baseline_head"]
        base_frontend = prod_repos["frontend"]["baseline_head"]
        head_backend = run_git(["rev-parse", "HEAD"], cwd=backend_dir).stdout.strip()
        head_frontend = run_git(["rev-parse", "HEAD"], cwd=frontend_dir).stdout.strip()

        phase2a_dir = self.ws / "evidence/tasks/task-404/attempt_1/Phase-2A"
        phase2a_dir.mkdir(parents=True, exist_ok=True)
        status_data = {
            "schema_version": "1.0.0",
            "task_id": "task-404",
            "attempt": 1,
            "cycle": 1,
            "status": "AWAITING_REVIEW",
            "touched_repositories": ["backend", "frontend"],
            "base_commits": {"backend": head_backend, "frontend": head_frontend},
            "summary": "Multi repo review",
        }
        (phase2a_dir / "pre_commit_status.json").write_text(json.dumps(status_data, indent=2) + "\n")
        self.assertNotEqual(run_approve_review("task-404", attempt=1, workspace=str(self.ws)), 0)

        from stagecheck.core.utils import sha256_digest
        diff_b = sha256_digest(subprocess.run(["git", "-C", str(backend_dir), "diff", "--binary", f"{base_backend}..{head_backend}"], capture_output=True, check=True).stdout)
        diff_f = sha256_digest(subprocess.run(["git", "-C", str(frontend_dir), "diff", "--binary", f"{base_frontend}..{head_frontend}"], capture_output=True, check=True).stdout)
        (phase2a_dir / "pre_commit_review.json").write_text(json.dumps({
            "schema_version": "2.0",
            "task_id": "task-404",
            "attempt": 1,
            "cycle": 1,
            "status": "APPROVED",
            "summary": "Simulated multi-repo review to test Phase 3 aggregate audit",
            "base_commits": {"backend": base_backend, "frontend": base_frontend},
            "approved_diff_hashes": {"backend": diff_b, "frontend": diff_f},
            "approved_snapshot_sha256": diff_b,
            "approved_diff_sha256": diff_b,
            "pre_existing_issues_ignored": [],
            "architectural_intents_approved": [],
            "new_issues_found": [],
        }, indent=2))

        # Delivery report for Phase 2B
        phase2b_dir = self.ws / "evidence/tasks/task-404/attempt_1/Phase-2B"
        phase2b_dir.mkdir(parents=True, exist_ok=True)
        (phase2b_dir / "report.md").write_text("# Delivery report\nMulti-repo changes.\n")

        # Advance Gate 2B
        rc = run_gate_advance("Gate-2B", task="task-404", attempt=1, workspace=str(self.ws))
        self.assertEqual(rc, 0)

        # Audit MUST return BLOCKED for aggregate
        rc = run_audit_cmd("task-404", attempt=1, workspace=str(self.ws))
        self.assertEqual(rc, 1, "Multi-repo audit should fail due to frontend defect!")

        verdict_file = self.ws / "evidence/tasks/task-404/attempt_1/Phase-3/verdict.json"
        verdict = json.loads(verdict_file.read_text())
        self.assertEqual(verdict["result"], "BLOCKED")

        # Attempting Gate 3 advance MUST fail
        rc = run_gate_advance("Gate-3", task="task-404", attempt=1, workspace=str(self.ws))
        self.assertEqual(rc, 1, "Gate 3 advance must fail when audit verdict is BLOCKED")

    def test_e2e_scenario5_circuit_breaker_and_recovery(self):
        """Scenario 5: 3 attempt failures trip breaker; human reset safely unlatches to attempt 4."""
        self._setup_git_repo("repos/core-service", "service.py")
        run_init(self.ws, agent1="agent1", agent2="agent2")
        run_start(workspace=self.ws, task="task-505")

        # Trip the circuit breaker for task-505 after attempt 2
        eval_tripped = CircuitBreakerEvaluation(
            tripped=True,
            trigger="stagnant_defects",
            reason="Zero defect reduction between attempts",
        )
        trip_circuit_breaker(self.ws, "task-505", 2, eval_tripped, [])

        state = load_active_state(self.ws)
        self.assertTrue(state.get("circuit_breaker_tripped"))

        # Agent cannot proceed automatically - human operator resets attempts to attempt 3
        rc = run_reset_attempts("task-505", authorized_by="owner@company.com", workspace=str(self.ws))
        self.assertEqual(rc, 0, "run_reset_attempts failed")

        # Breaker unlatched, state reset to Attempt 3, PHASE_1_PLANNING
        state = load_active_state(self.ws)
        self.assertFalse(state.get("circuit_breaker_tripped"))
        self.assertEqual(state.get("attempt_index"), 3)
        self.assertEqual(state["phase"], "PHASE_1_PLANNING")

        # Now trip at attempt 3 -> retry is strictly prohibited (DEC-028 / FR-06)
        eval_exhausted = CircuitBreakerEvaluation(
            tripped=True,
            trigger="max_attempts_exhausted",
            reason="Exhausted maximum 3 verification attempts",
        )
        trip_circuit_breaker(self.ws, "task-505", 3, eval_exhausted, [])
        rc_fail = run_reset_attempts("task-505", authorized_by="owner@company.com", workspace=str(self.ws))
        self.assertEqual(rc_fail, 1, "Reset on attempt 3 must be rejected")


if __name__ == "__main__":
    unittest.main()
