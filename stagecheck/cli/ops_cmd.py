"""Operational Utility CLI Command Handlers: 'unlock', 'seal', and 'log-quality' (Spec 10)."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

from stagecheck.core.paths import find_workspace_root
from stagecheck.core.permissions import elevate_permissions_for_teardown
from stagecheck.core.evidence import create_task_seal, update_code_quality_ledger


def run_unlock(
    workspace: Optional[str] = None,
    force: bool = False,
    abort_active: bool = False,
) -> int:
    """Elevate workspace permissions for clean teardown or CI cleanup (GAP-J2 / Spec M11)."""
    try:
        workspace_root = Path(workspace).resolve() if workspace else find_workspace_root()
    except Exception as err:
        print(f"ERROR: [unlock.workspace_error] {err}", file=sys.stderr)
        return 1

    try:
        from stagecheck.core.permissions import (
            ActiveTaskTeardownBlockedError,
            NonInteractiveTeardownError,
            assert_safe_teardown_preconditions,
            commit_safe_teardown,
        )
        assert_safe_teardown_preconditions(
            workspace_root,
            force=force,
            abort_active=abort_active,
            commit=False,
        )
    except ActiveTaskTeardownBlockedError as err:
        print(f"ERROR: [unlock.active_task_blocked] {err}", file=sys.stderr)
        return 1
    except NonInteractiveTeardownError as err:
        print(f"ERROR: [unlock.non_interactive_blocked] {err}", file=sys.stderr)
        return 1
    except Exception as err:
        print(f"ERROR: [unlock.precondition_error] {err}", file=sys.stderr)
        return 1

    if not force and sys.stdin.isatty():
        response = input(f"Elevate permissions for workspace '{workspace_root}' to mode 0755/0644? [y/N]: ")
        if response.strip().lower() not in ("y", "yes"):
            print("Aborted by user.")
            return 1

    try:
        commit_safe_teardown(workspace_root, abort_active=abort_active, force=force, elevate=True)
    except Exception as err:
        print(f"ERROR: [unlock.teardown_commit_error] {err}", file=sys.stderr)
        return 1

    print(f"SUCCESS: Elevated workspace permissions for '{workspace_root}'. Ready for clean teardown.")
    return 0


def run_seal(task_id: str, attempt: int = 1, workspace: Optional[str] = None) -> int:
    """Authoritative alias for 'stagecheck gate advance Gate-4' (SEC-02 / Spec 01 / DEC-025).

    Executes transactional Merkle DAG sealing under write-ahead journal, freezes attempt
    evidence hierarchy (dirs 0555, files 0444), and updates manifest downstream.
    Strictly idempotent: returns 0 with existing receipt if already sealed.
    """
    from stagecheck.cli.gate_cmd import run_gate_advance
    return run_gate_advance(gate="Gate-4", task=task_id, attempt=attempt, workspace=workspace)


def run_log_quality(task_id: str, attempt: int = 1, workspace: Optional[str] = None) -> int:
    """Record code quality observations into cumulative workspace quality ledger (GAP-F2, GAP-M2)."""
    try:
        workspace_root = Path(workspace).resolve() if workspace else find_workspace_root()
    except Exception as err:
        print(f"ERROR: [log_quality.workspace_error] {err}", file=sys.stderr)
        return 1

    try:
        update_code_quality_ledger(
            workspace_root=workspace_root,
            task_id=task_id,
            attempt=attempt,
            observations=[],
        )
        print(f"SUCCESS: Code quality ledger updated for task '{task_id}'.")
        return 0
    except Exception as err:
        print(f"ERROR: [log_quality.failure] Failed to update quality ledger: {err}", file=sys.stderr)
        return 1

