"""Disposition CLI Command Handler: 'stagecheck disposition add' (P4-T5).

Interactive human override hatch recording defect waivers with authorization metadata,
enforcing TTY confirmation (SEC-03), and atomically updating controls/DISPOSITIONS.json.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

from stagecheck.core.dispositions import DispositionError, add_disposition
from stagecheck.core.paths import find_workspace_root


def run_disposition_add(
    task: str,
    defect: str,
    rationale: str,
    action: str = "ACCEPT_AS_INTENTIONAL",
    authorized_by: str = "human-operator",
    yes: bool = False,
    workspace: Optional[str] = None,
) -> int:
    """Execute 'stagecheck disposition add'."""
    workspace_root = Path(workspace).resolve() if workspace else find_workspace_root()

    print("=" * 72)
    print(" [STAGECHECK] HUMAN DEFECT DISPOSITION & OVERRIDE HATCH")
    print(f" Task ID     : {task}")
    print(f" Defect Code : {defect}")
    print(f" Action      : {action}")
    print(f" Authorized  : {authorized_by}")
    print(f" Rationale   : {rationale}")
    print("=" * 72)

    # Interactive confirmation prompt if not pre-confirmed via --yes
    if not yes:
        if not sys.stdin.isatty():
            print(
                "\nERROR: [disposition.non_interactive_blocked] Adding defect waivers requires an "
                "interactive terminal or explicit human confirmation (--yes).",
                file=sys.stderr,
            )
            return 1

        prompt = f"\nAuthorize waiver for defect '{defect}' on task '{task}'? [YES/NO] (Default: NO): "
        try:
            choice = input(prompt).strip().upper()
        except (KeyboardInterrupt, EOFError):
            print("\nDisposition cancelled.")
            return 1

        if choice not in ("YES", "Y"):
            print("Disposition rejected by operator. No changes written.")
            return 1

    try:
        entry = add_disposition(
            workspace_root=workspace_root,
            task_id=task,
            defect_id=defect,
            rationale=rationale,
            action=action,
            authorized_by=authorized_by,
            require_tty=not yes,
            confirmed=True,
        )
        print(f"\nSUCCESS: Defect waiver recorded with ID '{entry['disposition_id']}'.")
        print(f"  File: {workspace_root}/controls/DISPOSITIONS.json")
        print("  Root AGENTS.md contract re-rendered and SHA-256 bound.")
        print("  EVIDENCE_MANIFEST.json updated.")
        print("=" * 72)
        return 0
    except DispositionError as err:
        print(f"\nERROR: [disposition.failed] {err}", file=sys.stderr)
        return 1


def run_disposition(
    task: str,
    action: str = "waive",
    defect: Optional[str] = None,
    rationale: Optional[str] = None,
    authorized_by: str = "human-operator",
    yes: bool = False,
    workspace: Optional[str] = None,
) -> int:
    """Execute 'stagecheck disposition' managing defect waivers, retries, and resumptions (DEC-028 / FR-06).

    Actions:
      waive: Records human defect waiver in controls/DISPOSITIONS.json.
      resume: Resumes task from AWAITING_HUMAN_DISPOSITION without consuming an attempt.
      retry: Resets circuit breaker to Phase 1, enforcing immutable 3-attempt cap.
      abort: Aborts active task to prevent runaway execution.
    """
    try:
        workspace_root = Path(workspace).resolve() if workspace else find_workspace_root()
    except Exception as err:
        print(f"ERROR: [disposition.workspace_error] {err}", file=sys.stderr)
        return 1

    norm_action = action.lower()
    if norm_action in ("abort", "retry") and not yes:
        if not sys.stdin.isatty():
            print(
                f"ERROR: [disposition.non_interactive_blocked] Action '{norm_action}' requires an "
                "interactive terminal or explicit human confirmation (--yes).",
                file=sys.stderr,
            )
            return 1
        choice = input(
            f"\nConfirm disposition action '{norm_action}' on task '{task}'? [YES/NO] (Default: NO): "
        ).strip().upper()
        if choice not in ("YES", "Y"):
            print("Disposition action cancelled by operator.", file=sys.stderr)
            return 1

    if norm_action in ("waive", "accept_as_intentional", "waive_temporary", "not_applicable"):
        if not defect:
            print("ERROR: [disposition.missing_defect] Defect code (--defect) is required for waiver action.", file=sys.stderr)
            return 1
        return run_disposition_add(
            task=task,
            defect=defect,
            rationale=rationale or "Defect waived by operator",
            action="ACCEPT_AS_INTENTIONAL" if norm_action == "waive" else action,
            authorized_by=authorized_by,
            yes=yes,
            workspace=workspace,
        )

    if norm_action == "resume":
        from stagecheck.cli.resume_cmd import run_resume
        return run_resume(task=task, workspace=workspace)

    if norm_action == "retry":
        from stagecheck.core.circuit_breaker import (
            AttemptBudgetExhaustedError,
            CircuitBreakerError,
            reset_circuit_breaker,
        )
        try:
            res = reset_circuit_breaker(workspace_root, task_id=task, authorized_by=authorized_by)
            print(f"SUCCESS: Reset attempts for task '{task}'. Next attempt index: {res['attempt_index']}.")
            return 0
        except AttemptBudgetExhaustedError as err:
            print(f"ERROR: [disposition.budget_exhausted] {err}", file=sys.stderr)
            return 1
        except CircuitBreakerError as err:
            print(f"ERROR: [disposition.retry_failed] {err}", file=sys.stderr)
            return 1

    if norm_action == "abort":
        from stagecheck.core.locking import acquire_runtime_lock
        from stagecheck.core.paths import validate_task_id
        from stagecheck.core.permissions import controlled_write_transaction
        from stagecheck.core.state import load_active_state, save_active_state
        try:
            validate_task_id(task)
        except ValueError as err:
            print(f"ERROR: [disposition.invalid_task] {err}", file=sys.stderr)
            return 1
        controls_dir = workspace_root / "controls"
        with acquire_runtime_lock(controls_dir):
            state = load_active_state(workspace_root)
            if state.get("task_id") != task:
                print(
                    f"ERROR: [disposition.task_mismatch] Active task is '{state.get('task_id')}', not '{task}'.",
                    file=sys.stderr,
                )
                return 1
            with controlled_write_transaction(controls_dir):
                state["phase"] = "ABORTED"
                state["status"] = "FAILED_EXHAUSTED"
                state["turn"] = "IDLE"
                save_active_state(workspace_root, state)
        print(f"SUCCESS: Task '{task}' aborted by operator.")
        return 0

    print(f"ERROR: [disposition.invalid_action] Unsupported action '{action}'. Choose from: waive, resume, retry, abort.", file=sys.stderr)
    return 1

