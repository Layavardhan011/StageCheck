"""Pre-Commit Cooperative Review CLI Handlers: 'review-precommit' & 'approve-review' (P3-T5).

Handles Phase 2A review iteration coordination, status evaluation, and approval gates.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

from stagecheck.core.agents import resolve_task_attempt_dir
from stagecheck.core.cooperative_review import (
    CommitUnauthorizedError,
    ReviewGateError,
    assert_commit_authorization,
    record_pre_commit_review,
    resolve_governed_repo_path,
    validate_commit_sha,
)
from stagecheck.core.gate_engine import GateId, get_gate_receipt_path, normalize_phase
from stagecheck.core.state import load_active_state
from stagecheck.core.utils import sha256_file, validate_schema
from stagecheck.schemas import get_schema_path


def _validate_and_bind_precommit_status(
    workspace_root: Path,
    task: str,
    attempt: int,
    data: dict,
) -> tuple[list[str], dict[str, str], int]:
    """Validate pre_commit_status.json against schema and authoritative PRODUCT_REPOSITORIES.json baselines."""
    schema_path = get_schema_path("pre_commit_status.schema.json")
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validate_schema(data, schema)

    if data.get("task_id") != task or int(data.get("attempt", 0)) != attempt:
        raise ReviewGateError(
            f"pre_commit_status.json task/attempt mismatch (expected {task} attempt {attempt})."
        )

    touched_repos = list(data.get("touched_repositories") or [])
    base_commits = dict(data.get("base_commits") or {})
    cycle = int(data.get("cycle", 1))

    prod_repos_file = workspace_root / "controls" / "PRODUCT_REPOSITORIES.json"
    if not prod_repos_file.is_file():
        raise ReviewGateError("Missing controls/PRODUCT_REPOSITORIES.json: cannot verify authoritative baselines.")
    prod_data = json.loads(prod_repos_file.read_text(encoding="utf-8"))
    registered = prod_data.get("repositories")
    if not isinstance(registered, dict) or not registered:
        raise ReviewGateError("controls/PRODUCT_REPOSITORIES.json has no registered repositories.")

    bound_commits: dict[str, str] = {}
    for repo_name in touched_repos:
        resolve_governed_repo_path(workspace_root, repo_name)
        if repo_name not in registered:
            raise ReviewGateError(f"Unregistered repository '{repo_name}' in touched_repositories.")
        auth_base = registered[repo_name].get("baseline_head")
        if not auth_base:
            raise ReviewGateError(f"Repository '{repo_name}' lacks baseline_head in PRODUCT_REPOSITORIES.json.")
        validate_commit_sha(auth_base, repo_name)
        supplied_base = base_commits.get(repo_name)
        if not supplied_base:
            raise ReviewGateError(f"Missing required base_commit for '{repo_name}' in pre_commit_status.json.")
        validate_commit_sha(supplied_base, repo_name)
        if supplied_base.lower() != auth_base.lower():
            raise ReviewGateError(
                f"Base commit mismatch for '{repo_name}': status declared '{supplied_base}', expected '{auth_base}'."
            )
        bound_commits[repo_name] = auth_base

    for extra_repo in base_commits:
        if extra_repo not in touched_repos:
            resolve_governed_repo_path(workspace_root, extra_repo)
            if extra_repo not in registered:
                raise ReviewGateError(f"Unregistered repository '{extra_repo}' in base_commits.")

    return touched_repos, bound_commits, cycle


def _check_phase2a_prerequisites(workspace_root: Path, task: str, attempt: int) -> Optional[int]:
    """Verify that workspace is in PHASE_2A_CODING and Gate 1 receipt is valid (Spec 01 §6.1)."""
    try:
        state = load_active_state(workspace_root)
        norm_phase = normalize_phase(state.get("phase", ""))
        if norm_phase != "PHASE_2A_CODING":
            print(
                f"ERROR: [prerequisite.phase_unmet] Cannot execute review in phase '{state.get('phase')}'. "
                "Workspace must be in PHASE_2A_CODING (advance Gate 1 first).",
                file=sys.stderr,
            )
            return 1

        cleared_gates = state.get("cleared_gates", {})
        if "GATE_1" not in cleared_gates:
            print(
                "ERROR: [prerequisite.gate1_unmet] Cannot execute review: Gate 1 planning gate has not been cleared.",
                file=sys.stderr,
            )
            return 1

        g1_receipt_path = get_gate_receipt_path(workspace_root, GateId.GATE_1, task, attempt)
        if not g1_receipt_path.is_file():
            print(
                f"ERROR: [prerequisite.gate1_missing] Gate 1 receipt missing at '{g1_receipt_path}'.",
                file=sys.stderr,
            )
            return 1

        if sha256_file(g1_receipt_path).lower() != cleared_gates["GATE_1"].lower():
            print(
                "ERROR: [prerequisite.gate1_tampered] Gate 1 receipt on disk has been altered.",
                file=sys.stderr,
            )
            return 1
    except Exception as err:
        print(f"ERROR: [prerequisite.state_error] Failed checking state prerequisites: {err}", file=sys.stderr)
        return 1
    return None


def run_review_precommit(
    task: str,
    attempt: int = 1,
    workspace: Optional[str] = None,
) -> int:
    """Evaluate Phase 2A pre-commit status for a task, enforce untracked limits, scope, and rubric."""
    from stagecheck.core.cooperative_review import (
        GitIndexLockedError,
        UntrackedBytesExceededError,
        UntrackedCountExceededError,
        inspect_untracked_files,
        record_pre_commit_review,
        verify_precommit_scope,
    )
    from stagecheck.core.rubric_engine import run_rubric_evaluation, update_rubric_artifacts

    workspace_root = Path(workspace).resolve() if workspace else Path.cwd().resolve()

    # Enforce Gate 1 prerequisite
    rc = _check_phase2a_prerequisites(workspace_root, task, attempt)
    if rc is not None:
        return rc

    attempt_dir = resolve_task_attempt_dir(workspace_root, task, attempt)
    phase2a_dir = attempt_dir / "Phase-2A"
    status_file = phase2a_dir / "pre_commit_status.json"

    if not status_file.is_file():
        print(
            f"ERROR: [review.missing_status] No pre_commit_status.json found at '{status_file}'. "
            "Agent 2 must submit pre-commit status before review can execute.",
            file=sys.stderr,
        )
        return 1

    try:
        data = json.loads(status_file.read_text(encoding="utf-8"))
        touched_repos, base_commits, cycle = _validate_and_bind_precommit_status(
            workspace_root, task, attempt, data
        )
    except Exception as err:
        print(f"ERROR: [review.error] Invalid pre_commit_status.json: {err}", file=sys.stderr)
        return 1

    print(f"================================================================")
    print(f"        STAGECHECK PHASE 2A PRE-COMMIT COOPERATIVE REVIEW       ")
    print(f"================================================================")
    print(f"Task ID:       {task}")
    print(f"Attempt:       {attempt}")
    print(f"Review Cycle:  {cycle}")
    print(f"Repositories:  {', '.join(touched_repos) if touched_repos else '(none - read-only/evidence-only)'}")
    print(f"Summary:       {data.get('summary', 'No summary provided')}")
    print(f"----------------------------------------------------------------")

    # 1. Enforce Scope Containment (FR-09 / ARCH-03)
    scope_violations = verify_precommit_scope(workspace_root, task, attempt, touched_repos, base_commits)
    if scope_violations:
        print("ERROR: [review.scope_escape] Pre-commit changes violate declared scope:", file=sys.stderr)
        for v in scope_violations:
            print(f"  ├── {v}", file=sys.stderr)
        return 127

    # 2. Enforce Untracked Files Limits & Index Lock Contention (FR-09 / ARCH-03)
    for r_name in touched_repos:
        try:
            r_path = resolve_governed_repo_path(workspace_root, r_name)
        except ReviewGateError as err:
            print(f"ERROR: [review.repo_invalid] {err}", file=sys.stderr)
            return 1
        if r_path.is_dir():
            try:
                untracked, u_count, u_bytes = inspect_untracked_files(r_path)
                u_mb = u_bytes / (1024 * 1024)
                print(f"Repository '{r_name}': {u_count} untracked files ({u_mb:.2f} MiB). Invariants verified.")
            except (GitIndexLockedError, UntrackedCountExceededError, UntrackedBytesExceededError) as err:
                print(f"ERROR: [review.untracked_limits] {err}", file=sys.stderr)
                return 1

    # 3. Execute Automated 270-Rule Rubric Evaluation
    try:
        rubric_payload, elapsed_ms = run_rubric_evaluation(
            workspace_root=workspace_root,
            task_id=task,
            attempt=attempt,
            cycle=cycle,
        )
    except Exception as err:
        print(f"ERROR: [review.rubric_error] Rubric evaluation failed: {err}", file=sys.stderr)
        return 1

    # Update rubric artifacts
    update_rubric_artifacts(workspace_root, rubric_payload)
    counts = rubric_payload["counts"]
    failed_count = counts["failed"]
    blocked_count = counts.get("blocked", 0)
    not_eval_count = counts.get("not_evaluated", 0)
    non_passing_count = failed_count + blocked_count + not_eval_count

    if rubric_payload.get("overall_verdict") != "PASS" or non_passing_count > 0:
        new_issues = []
        for r_entry in rubric_payload.get("evaluations", []):
            r_status = r_entry.get("status")
            if r_status in ("FAIL", "BLOCKED", "NOT_EVALUATED"):
                new_issues.append({
                    "defect_id": r_entry["rule_id"],
                    "severity": "BLOCKING",
                    "location": r_entry.get("witness", "codebase"),
                    "description": r_entry.get("message", f"Rubric rule non-passing ({r_status})."),
                })
        record_pre_commit_review(
            workspace_root=workspace_root,
            task_id=task,
            attempt=attempt,
            cycle=cycle,
            status="REVISION_REQUIRED",
            summary=(
                f"Review rejected: {non_passing_count} non-passing rubric rules "
                f"(failed={failed_count}, blocked={blocked_count}, not_evaluated={not_eval_count})."
            ),
            base_commits=base_commits,
            new_issues=new_issues,
        )
        print(
            f"RESULT: REVISION_REQUIRED ({non_passing_count} blocking/incomplete rubric rules). "
            "Remediation guidance written to response.json."
        )
        return 1
    else:
        record_pre_commit_review(
            workspace_root=workspace_root,
            task_id=task,
            attempt=attempt,
            cycle=cycle,
            status="APPROVED",
            summary="All pre-commit architectural and rubric criteria satisfied.",
            base_commits=base_commits,
        )
        print("RESULT: APPROVED. All 270 rubric criteria verified. Local Git commit authorized.")
        return 0


def run_approve_review(
    task: str,
    attempt: int = 1,
    workspace: Optional[str] = None,
) -> int:
    """Record human/audit approval for Phase 2A review gate."""
    workspace_root = Path(workspace).resolve() if workspace else Path.cwd().resolve()

    # Enforce Gate 1 prerequisite
    rc = _check_phase2a_prerequisites(workspace_root, task, attempt)
    if rc is not None:
        return rc

    attempt_dir = resolve_task_attempt_dir(workspace_root, task, attempt)
    phase2a_dir = attempt_dir / "Phase-2A"
    status_file = phase2a_dir / "pre_commit_status.json"

    if not status_file.is_file():
        print(
            f"ERROR: [approve.missing_status] Cannot approve review: pre_commit_status.json missing at '{status_file}'.",
            file=sys.stderr,
        )
        return 1

    from stagecheck.core.cooperative_review import (
        GitIndexLockedError,
        UntrackedBytesExceededError,
        UntrackedCountExceededError,
        inspect_untracked_files,
        verify_precommit_scope,
    )

    try:
        status_data = json.loads(status_file.read_text(encoding="utf-8"))
        touched_repos, base_commits, cycle = _validate_and_bind_precommit_status(
            workspace_root, task, attempt, status_data
        )

        # Enforce scope containment and untracked limits before approval
        scope_violations = verify_precommit_scope(workspace_root, task, attempt, touched_repos, base_commits)
        if scope_violations:
            print("ERROR: [approve.scope_escape] Pre-commit changes violate declared scope:", file=sys.stderr)
            for v in scope_violations:
                print(f"  ├── {v}", file=sys.stderr)
            return 127

        for r_name in touched_repos:
            r_path = resolve_governed_repo_path(workspace_root, r_name)
            if r_path.is_dir():
                inspect_untracked_files(r_path)

        # GAP-02: Enforce complete, fresh, duplicate-free 270-rule PASS before approving review
        from stagecheck.core.rubric_engine import verify_complete_rubric_evaluation

        rubric_ok, rubric_reasons, _ = verify_complete_rubric_evaluation(
            workspace_root=workspace_root,
            rubric_path=phase2a_dir / "rubric_evaluation.json",
            task_id=task,
            attempt=attempt,
            cycle=cycle,
            require_fresh_context=True,
        )
        if not rubric_ok:
            print(
                "ERROR: [approve.incomplete_or_failed_rubric] Complete 270-rule rubric evaluation must PASS before approval:",
                file=sys.stderr,
            )
            for reason in rubric_reasons:
                print(f"  ├── {reason}", file=sys.stderr)
            return 1

        print(f"Approving Phase 2A review for Task '{task}' (Attempt {attempt}, Cycle {cycle})...")
        review_path = record_pre_commit_review(
            workspace_root=workspace_root,
            task_id=task,
            attempt=attempt,
            cycle=cycle,
            status="APPROVED",
            summary=f"Pre-commit review approved for cycle {cycle}.",
            base_commits=base_commits,
        )
        print(f"SUCCESS: Pre-commit review APPROVED and recorded at '{review_path}'.")
        return 0
    except (ReviewGateError, GitIndexLockedError, UntrackedCountExceededError, UntrackedBytesExceededError) as err:
        print(f"ERROR: [approve.gate_error] {err}", file=sys.stderr)
        return 1
    except Exception as err:
        print(f"ERROR: [approve.unexpected_error] {err}", file=sys.stderr)
        return 1

