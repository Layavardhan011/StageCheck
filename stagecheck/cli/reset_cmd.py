"""Reset Attempts CLI Command Handler: 'stagecheck reset-attempts' (P4-T4).

Unlatches the tripped circuit breaker, enforces monotonic attempt budgeting
(attempt_budget_base), preserves existing attempt forensics intact, and transitions
state back to PHASE_1_PLANNING (GAP-C3, GAP-L2, GAP-X1).
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

from stagecheck.core.circuit_breaker import ResetAttemptsError, reset_circuit_breaker
from stagecheck.core.paths import find_workspace_root


def run_reset_attempts(
    task: str,
    authorized_by: str,
    workspace: Optional[str] = None,
) -> int:
    """Execute reset-attempts command."""
    workspace_root = Path(workspace).resolve() if workspace else find_workspace_root()

    print("=" * 72)
    print(" [STAGECHECK] CIRCUIT BREAKER RESET & RE-BUDGETING")
    print(f" Task: {task}")
    print(f" Authorized By: {authorized_by}")
    print(f" Workspace: {workspace_root}")
    print("=" * 72)

    try:
        updated_state = reset_circuit_breaker(
            workspace_root=workspace_root,
            task_id=task,
            authorized_by=authorized_by,
        )
        current_attempt = updated_state.get("attempt_index", 3)
        budget_base = updated_state.get("attempt_budget_base", current_attempt)
        next_attempt = current_attempt + 1

        print(f"\nSUCCESS: Circuit breaker unlatched for task '{task}'.")
        print(f"  Attempt budget base set to: {budget_base}")
        print(f"  Next monotonic attempt: attempt_{next_attempt}")
        print(f"  State transitioned to: {updated_state.get('phase')}")
        print("  All prior attempt directories and Git commits preserved intact.")
        print("=" * 72)
        return 0
    except ResetAttemptsError as err:
        print(f"\nERROR: [reset_attempts.failed] {err}", file=sys.stderr)
        return 1
