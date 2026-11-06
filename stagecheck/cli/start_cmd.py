"""CLI command implementation for 'stagecheck start'.

Initializes a task under exclusive transaction locking, resets state to Attempt 1
in PHASE_1_PLANNING, and scaffolds task attempt evidence directory.
"""
import sys
from pathlib import Path
from typing import Optional

from stagecheck.core.paths import find_workspace_root
from stagecheck.core.permissions import controlled_write_transaction
from stagecheck.core.state import load_active_state, save_active_state


def run_start(workspace: Optional[Path] = None, task: Optional[str] = None) -> int:
    """Executes 'stagecheck start --task <task_id>'."""
    if not task:
        print("ERROR: --task argument is required for 'stagecheck start'", file=sys.stderr)
        return 1

    try:
        ws_root = find_workspace_root(workspace)
    except Exception as err:
        print(f"ERROR: [start.discovery_failed] {err}", file=sys.stderr)
        return 1

    controls_dir = ws_root / "controls"
    if not controls_dir.is_dir():
        print(f"ERROR: [start.uninitialized] Workspace controls not found at '{controls_dir}'", file=sys.stderr)
        return 1

    try:
        with controlled_write_transaction(controls_dir):
            state = load_active_state(ws_root)
            state["task_id"] = task
            state["phase"] = "PHASE_1_PLANNING"
            state["attempt_index"] = 1
            state["repair_index"] = 0
            state["circuit_breaker_tripped"] = False
            state.pop("attempt", None)
            state.pop("current_task", None)
            state.pop("status", None)
            save_active_state(ws_root, state)

            task_phase1_dir = ws_root / f"evidence/tasks/{task}/attempt_1/Phase-1"
            task_phase1_dir.mkdir(parents=True, exist_ok=True)

        print(f"SUCCESS: Task '{task}' started in attempt 1 (PHASE_1_PLANNING).")
        return 0
    except Exception as err:
        print(f"ERROR: [start.failed] {err}", file=sys.stderr)
        return 1
