"""CLI Command Handlers for Phase Gate Checkpoints: 'stagecheck gate check' & 'stagecheck gate advance' (FR-01 / Spec 01 / DEC-001).

Provides:
  stagecheck gate check <Gate-1|Gate-2A|Gate-2B|Gate-3|Gate-4> [--task <id>] [--attempt <n>]
  stagecheck gate advance <Gate-1|Gate-2A|Gate-2B|Gate-3|Gate-4> [--task <id>] [--attempt <n>]
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

from stagecheck.core.gate_engine import (
    GateCriteriaFailedError,
    GateError,
    InvalidTransitionError,
    advance_gate_atomic,
    check_gate_preconditions,
    normalize_gate_id,
)
from stagecheck.core.paths import find_workspace_root


def run_gate_check(
    gate: str,
    task: Optional[str] = None,
    attempt: Optional[int] = None,
    workspace: Optional[str] = None,
) -> int:
    """Non-mutating inspection of gate preconditions and criteria."""
    try:
        ws_root = Path(workspace).resolve() if workspace else find_workspace_root()
    except Exception as err:
        print(f"Error: Could not locate workspace root: {err}", file=sys.stderr)
        return 1

    try:
        report = check_gate_preconditions(
            workspace_root=ws_root,
            gate=gate,
            task_id=task,
            attempt=attempt,
        )
    except Exception as err:
        print(f"Error evaluating gate criteria: {err}", file=sys.stderr)
        return 1

    print("================================================================")
    print("               STAGECHECK PHASE GATE INSPECTION                 ")
    print("================================================================")
    print(f"Task ID:       {report.task_id}")
    print(f"Attempt:       {report.attempt}")
    print(f"Current Phase: {report.current_phase}")
    print(f"Target Gate:   {report.gate_id} ({report.current_phase} -> {report.target_phase})")
    print("----------------------------------------------------------------")
    print("Criteria Evaluation:")
    for c in report.criteria:
        status_tag = f"[{c.status}]"
        print(f"  {status_tag:<8} {c.description}: {c.message}")
    print("----------------------------------------------------------------")

    if report.passed:
        print("RESULT: ALL CRITERIA SATISFIED. Ready to advance via 'stagecheck gate advance'.")
        return 0
    else:
        print("RESULT: GATE BLOCKED. Complete missing criteria before advancing.", file=sys.stderr)
        if report.failure_reasons:
            print("\nBlocking Reasons:", file=sys.stderr)
            for r in report.failure_reasons:
                print(f"  ├── [BLOCKING] {r}", file=sys.stderr)
        return 1


def run_gate_advance(
    gate: str,
    task: Optional[str] = None,
    attempt: Optional[int] = None,
    workspace: Optional[str] = None,
) -> int:
    """Advance the workspace across the specified gate and record immutable receipt."""
    try:
        ws_root = Path(workspace).resolve() if workspace else find_workspace_root()
    except Exception as err:
        print(f"Error: Could not locate workspace root: {err}", file=sys.stderr)
        return 1

    try:
        res = advance_gate_atomic(
            workspace_root=ws_root,
            gate=gate,
            task_id=task,
            attempt=attempt,
        )
        print("================================================================")
        print("               STAGECHECK PHASE GATE ADVANCED                   ")
        print("================================================================")
        print(f"Task ID:       {res.task_id}")
        print(f"Attempt:       {res.attempt}")
        print(f"Gate Cleared:  {res.gate_id}")
        print(f"New Phase:     {res.to_phase}")
        print(f"Turn:          {res.turn}")
        print(f"Receipt:       {res.receipt_path.relative_to(ws_root)}")
        print(f"Receipt SHA:   {res.receipt_sha256}")
        print("----------------------------------------------------------------")
        print("SUCCESS: Gate advanced successfully. Receipts recorded and manifest updated.")
        return 0
    except InvalidTransitionError as err:
        print(f"ERROR: [gate.invalid_transition] {err}", file=sys.stderr)
        return 1
    except GateCriteriaFailedError as err:
        print(f"ERROR: [gate.criteria_failed] {err}", file=sys.stderr)
        if err.failure_reasons:
            print("\nUnsatisfied Invariants:", file=sys.stderr)
            for r in err.failure_reasons:
                print(f"  ├── {r}", file=sys.stderr)
        return 1
    except GateError as err:
        print(f"ERROR: [gate.error] {err}", file=sys.stderr)
        return 1
    except Exception as err:
        print(f"Unexpected error advancing gate: {err}", file=sys.stderr)
        return 1
