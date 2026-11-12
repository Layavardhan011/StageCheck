"""CLI command implementation for 'stagecheck start'.

Initializes a task under exclusive transaction locking, resets state to Attempt 1
in PHASE_1_PLANNING, and scaffolds task attempt evidence directory.
"""
import sys
from pathlib import Path
from typing import Optional

from stagecheck.core.isolation import SandboxUnavailableError, run_bwrap_deployment_preflight
from stagecheck.core.locking import acquire_runtime_lock
from stagecheck.core.paths import find_workspace_root, resolve_task_dir
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
        task_dir = resolve_task_dir(ws_root, task)
        run_bwrap_deployment_preflight(workspace_root=ws_root, raise_on_failure=True)
        with acquire_runtime_lock(controls_dir):
            state = load_active_state(ws_root)
            phase = str(state.get("phase", "NOT_STARTED"))
            if state.get("circuit_breaker_tripped") or phase not in (
                "NOT_STARTED",
                "UNINITIALIZED",
                "IDLE",
                "COMPLETED",
                "SEALED_PASSED",
                "ABORTED",
            ):
                raise RuntimeError(
                    f"Cannot start '{task}': workspace is in phase '{phase}' "
                    f"(circuit_breaker_tripped={state.get('circuit_breaker_tripped')})."
                )
            existing_attempts = [p for p in task_dir.glob("attempt_*") if p.is_dir() or p.is_symlink()]
            if (
                (
                    state.get("task_id") == task
                    and (
                        state.get("status") == "SEALED_PASSED"
                        or phase in ("COMPLETED", "SEALED_PASSED", "ABORTED")
                        or int(state.get("attempt_index", 1)) >= 3
                    )
                )
                or (task_dir / "attempt_3").exists()
                or any((a / "seal.json").exists() or (a / "seal.json").is_symlink() for a in existing_attempts)
                or existing_attempts
            ):
                raise RuntimeError(
                    f"Task '{task}' is already sealed, aborted, or has prior attempt history and cannot be restarted at attempt 1."
                )

            with controlled_write_transaction(controls_dir):
                state["task_id"] = task
                state["phase"] = "PHASE_1_PLANNING"
                state["attempt_index"] = 1
                state["repair_index"] = 0
                state["circuit_breaker_tripped"] = False
                for stale_key in (
                    "attempt",
                    "current_task",
                    "status",
                    "cleared_gates",
                    "resets_authorized",
                    "halt_reason",
                    "resume_reason",
                ):
                    state.pop(stale_key, None)
                save_active_state(ws_root, state)

                task_phase1_dir = task_dir / "attempt_1" / "Phase-1"
                task_phase1_dir.mkdir(parents=True, exist_ok=True)

        print(f"SUCCESS: Task '{task}' started in attempt 1 (PHASE_1_PLANNING).")
        return 0
    except SandboxUnavailableError as err:
        print(f"ERROR: [isolation.preflight_failed] {err}", file=sys.stderr)
        return err.exit_code
    except Exception as err:
        print(f"ERROR: [start.failed] {err}", file=sys.stderr)
        return 1
