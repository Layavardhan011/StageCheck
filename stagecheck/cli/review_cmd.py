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
)
from stagecheck.core.gate_engine import GateId, get_gate_receipt_path, normalize_phase
from stagecheck.core.state import load_active_state
from stagecheck.core.utils import sha256_file


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
    """Evaluate Phase 2A pre-commit status for a task."""
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
        print(
            f"Phase 2A Pre-Commit Status for Task '{task}' (Attempt {attempt}, Cycle {data.get('cycle', 1)}):\n"
            f"  Status:       {data.get('status')}\n"
            f"  Repositories: {', '.join(data.get('touched_repositories', []))}\n"
            f"  Summary:      {data.get('summary', 'No summary provided')}"
        )
        return 0
    except Exception as err:
        print(f"ERROR: [review.error] Failed to inspect pre_commit_status: {err}", file=sys.stderr)
        return 1


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

    try:
        status_data = json.loads(status_file.read_text(encoding="utf-8"))
        base_commits = status_data.get("base_commits", {})
        cycle = status_data.get("cycle", 1)

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
    except ReviewGateError as err:
        print(f"ERROR: [approve.gate_error] {err}", file=sys.stderr)
        return 1
    except Exception as err:
        print(f"ERROR: [approve.unexpected_error] {err}", file=sys.stderr)
        return 1

