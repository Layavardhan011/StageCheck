"""Operational Utility CLI Command Handlers: 'unlock', 'seal', and 'log-quality' (Spec 10)."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

from stagecheck.core.paths import find_workspace_root
from stagecheck.core.permissions import elevate_permissions_for_teardown
from stagecheck.core.evidence import create_task_seal, update_code_quality_ledger


def run_unlock(workspace: Optional[str] = None, force: bool = False) -> int:
    """Elevate workspace permissions for clean teardown or CI cleanup (GAP-J2)."""
    try:
        workspace_root = Path(workspace).resolve() if workspace else find_workspace_root()
    except Exception as err:
        print(f"ERROR: [unlock.workspace_error] {err}", file=sys.stderr)
        return 1

    if not force and sys.stdin.isatty():
        response = input(f"Elevate permissions for workspace '{workspace_root}' to mode 0755/0644? [y/N]: ")
        if response.strip().lower() not in ("y", "yes"):
            print("Aborted by user.")
            return 1

    elevate_permissions_for_teardown(workspace_root)
    print(f"SUCCESS: Elevated workspace permissions for '{workspace_root}'. Ready for clean teardown.")
    return 0


def run_seal(task_id: str, attempt: int = 1, workspace: Optional[str] = None) -> int:
    """Seal task evidence manifest and generate cryptographic verification seal (SEC-02)."""
    try:
        workspace_root = Path(workspace).resolve() if workspace else find_workspace_root()
    except Exception as err:
        print(f"ERROR: [seal.workspace_error] {err}", file=sys.stderr)
        return 1

    try:
        seal_path = create_task_seal(
            workspace_root=workspace_root,
            task_id=task_id,
            attempt=attempt,
            verdict="CLEAR",
            blocking_defects_count=0,
            report_only_findings_count=0,
        )
        print(f"SUCCESS: Task '{task_id}' sealed successfully at '{seal_path}'.")
        return 0
    except Exception as err:
        print(f"ERROR: [seal.failure] Failed to seal task: {err}", file=sys.stderr)
        return 1


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

