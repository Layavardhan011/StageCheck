"""Supervisor CLI Command Handler: 'stagecheck supervisor' (FR-04 / FR-05 / Spec 03 / ARCH-01).

Provides:
  stagecheck supervisor [--watch] [--once] [--task <id>] [--json]
  stagecheck supervisor check-task [--task <id>] [--json]
  stagecheck supervisor check-stability --file <path> [--seconds 30] [--ceiling 300] [--json]
  stagecheck supervisor check-watchdog [--timeout 600] [--json]
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Optional

from stagecheck.core.isolation import find_workspace_root_for_cwd, run_bwrap_deployment_preflight
from stagecheck.core.paths import find_workspace_root
from stagecheck.core.supervisor import (
    PromptDebouncer,
    SupervisorEngine,
    evaluate_watchdog,
)


def run_supervisor_cmd(
    action: Optional[str] = None,
    task: Optional[str] = None,
    attempt: Optional[int] = None,
    workspace: Optional[str] = None,
    watch: bool = False,
    once: bool = False,
    file_path: Optional[str] = None,
    seconds: float = 30.0,
    ceiling: float = 300.0,
    timeout: float = 600.0,
    output_json: bool = False,
) -> int:
    """Execute supervisor commands and workflows."""
    if action == "preflight":
        ws_opt = Path(workspace).resolve() if workspace else find_workspace_root_for_cwd(Path.cwd())
        preflight = run_bwrap_deployment_preflight(workspace_root=ws_opt, raise_on_failure=False)
        if output_json:
            print(json.dumps(preflight.to_dict(), indent=2))
        elif preflight.passed:
            print(f"[ISOLATION PREFLIGHT: PASS] {preflight.reason}")
        else:
            print(f"ERROR: [isolation.preflight_failed] {preflight.reason}", file=sys.stderr)
        return 0 if preflight.passed else 126

    try:
        ws_root = Path(workspace).resolve() if workspace else find_workspace_root()
    except Exception as err:
        print(f"Error: Could not locate workspace root: {err}", file=sys.stderr)
        return 1

    engine = SupervisorEngine(
        workspace_root=ws_root,
        quiet_seconds=seconds,
        max_ceiling_seconds=ceiling,
        watchdog_timeout_seconds=timeout,
    )

    # 1. Action: check-stability
    if action == "check-stability":
        if not file_path:
            print("ERROR: --file argument required for check-stability.", file=sys.stderr)
            return 1
        debouncer = PromptDebouncer(quiet_seconds=seconds, max_ceiling_seconds=ceiling)
        is_stable, reason = debouncer.check_stability(file_path)
        payload = {
            "file": file_path,
            "is_stable": is_stable,
            "freeze_reason": reason,
            "quiet_seconds": seconds,
            "max_ceiling_seconds": ceiling,
        }
        if output_json:
            print(json.dumps(payload, indent=2))
        else:
            if is_stable:
                print(f"[STABLE] File '{file_path}' is stable. Reason: {reason}")
            else:
                print(f"[UNSTABLE] File '{file_path}' is not stable yet.")
        return 0 if is_stable else 1

    # 2. Action: check-watchdog
    elif action == "check-watchdog":
        tripped, halt_msg, meta = evaluate_watchdog(ws_root, timeout_seconds=timeout)
        payload = {
            "watchdog_tripped": tripped,
            "message": halt_msg,
            "metadata": meta,
        }
        if output_json:
            print(json.dumps(payload, indent=2))
        else:
            if tripped:
                print(f"[TRIPPED] {halt_msg}", file=sys.stderr)
            else:
                print(f"[HEALTHY] {halt_msg}")
        return 1 if tripped else 0

    # 3. Action: check-task
    elif action == "check-task":
        report = engine.check_task(task_id=task)
        if output_json:
            print(json.dumps(report, indent=2))
        else:
            print("================================================================")
            print("                 STAGECHECK SUPERVISOR STATUS                   ")
            print("================================================================")
            print(f"Task ID:          {report['task_id']}")
            print(f"Attempt:          {report['attempt']}")
            print(f"Current Phase:    {report['phase']}")
            print(f"Active Turn:      {report['turn']}")
            print(f"Watchdog Status:  {'TRIPPED' if report['watchdog_tripped'] else 'HEALTHY'}")
            if report.get("halt_reason"):
                print(f"Halt Reason:      {report['halt_reason']}")
        return 1 if report["watchdog_tripped"] else 0

    # 4. Standard step execution or continuous loop
    if watch:
        print("Starting continuous autonomous supervisor loop (press Ctrl+C to stop)...")
        try:
            while True:
                res = engine.step(task_id=task, attempt=attempt)
                if output_json:
                    print(json.dumps(res.__dict__))
                else:
                    print(f"[{res.status}] Phase: {res.current_phase} | Action: {res.action_taken} -> {res.message}")

                if res.status in ("COMPLETED", "HALTED", "DEFECTS_DETECTED"):
                    return 0 if res.status == "COMPLETED" else 1

                time.sleep(2.0)
        except KeyboardInterrupt:
            print("\nSupervisor interrupted by operator.")
            return 0
    else:
        res = engine.step(task_id=task, attempt=attempt)
        if output_json:
            print(json.dumps(res.__dict__, indent=2))
        else:
            print(f"[{res.status}] Phase: {res.current_phase} | Action: {res.action_taken} -> {res.message}")
        return 0 if res.status in ("ADVANCED", "COMPLETED", "WAITING", "IDLE") else 1

