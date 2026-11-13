"""Supervisor CLI Command Handler: 'stagecheck supervisor' (FR-04 / FR-05 / Spec 03 / ARCH-01).

Provides:
  stagecheck supervisor [--watch] [--once] [--task <id>] [--json] [--color|--no-color]
  stagecheck supervisor check-task [--task <id>] [--json]
  stagecheck supervisor check-stability --file <path> [--seconds 30] [--ceiling 300] [--json]
  stagecheck supervisor check-watchdog [--timeout 600] [--json]
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Optional, Tuple

from stagecheck.core.isolation import find_workspace_root_for_cwd, run_bwrap_deployment_preflight
from stagecheck.core.paths import find_workspace_root
from stagecheck.core.supervisor import (
    PromptDebouncer,
    SupervisorEngine,
    evaluate_watchdog,
)


def should_use_color(color_opt: Optional[bool] = None, stream=None) -> bool:
    """Determine whether ANSI color escape codes should be emitted."""
    if color_opt is not None:
        return bool(color_opt)
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR") in ("1", "true", "TRUE"):
        return True
    if os.environ.get("CLICOLOR_FORCE") in ("1", "true", "TRUE"):
        return True
    target_stream = stream if stream is not None else sys.stdout
    return getattr(target_stream, "isatty", lambda: False)()


def color_status(status: str, enabled: bool = True) -> str:
    """Format and color a status tag like [WAITING], [ADVANCED], [TRANSITION]."""
    text = f"[{status}]"
    if not enabled:
        return text

    st = status.upper()
    if st in ("WAITING", "WARNING"):
        return f"\033[1;33m{text}\033[0m"  # Bold Yellow
    elif st in ("ADVANCED", "GATE2A_ADVANCED", "GATE2B_ADVANCED", "GATE3_ADVANCED"):
        return f"\033[1;32m{text}\033[0m"  # Bold Green
    elif st in ("COMPLETED", "GATE4_SEALED", "SEALED_PASSED"):
        return f"\033[1;92m{text}\033[0m"  # Bright Green
    elif st in ("TRANSITION",):
        return f"\033[1;35m{text}\033[0m"  # Bold Magenta
    elif st in ("IDLE", "NOT_STARTED"):
        return f"\033[1;36m{text}\033[0m"  # Bold Cyan
    elif st in ("HALTED", "DEFECTS_DETECTED", "ERROR", "TRIPPED", "UNSTABLE", "ABORTED"):
        return f"\033[1;31m{text}\033[0m"  # Bold Red
    elif st in ("STABLE", "HEALTHY"):
        return f"\033[1;32m{text}\033[0m"  # Bold Green
    return f"\033[1;37m{text}\033[0m"  # Bold White


def color_phase(phase: str, enabled: bool = True) -> str:
    """Format and color a phase identifier (e.g. PHASE_1_PLANNING, PHASE_2A_CODING)."""
    if not enabled:
        return phase

    ph = phase.upper()
    if "PHASE_1" in ph or "PHASE-1" in ph or "PHASE-01" in ph:
        return f"\033[1;36m{phase}\033[0m"  # Bold Cyan
    elif "PHASE_2A" in ph or "PHASE-2A" in ph or "PHASE-02A" in ph:
        return f"\033[1;94m{phase}\033[0m"  # Bright Blue
    elif "PHASE_2B" in ph or "PHASE-2B" in ph or "PHASE-02B" in ph:
        return f"\033[1;35m{phase}\033[0m"  # Bold Magenta
    elif "PHASE_3" in ph or "PHASE-3" in ph or "PHASE-03" in ph:
        return f"\033[1;33m{phase}\033[0m"  # Bold Yellow / Amber
    elif "GATE_4" in ph:
        return f"\033[1;93m{phase}\033[0m"  # Bright Yellow
    elif ph in ("SEALED_PASSED", "COMPLETED"):
        return f"\033[1;92m{phase}\033[0m"  # Bright Green
    elif ph in ("AWAITING_HUMAN_DISPOSITION", "CIRCUIT_BREAKER_TRIPPED", "ABORTED"):
        return f"\033[1;31m{phase}\033[0m"  # Bold Red
    elif ph in ("NOT_STARTED", "IDLE"):
        return f"\033[0;90m{phase}\033[0m"  # Dim Gray
    return f"\033[1;37m{phase}\033[0m"  # Bold White


def format_status_line(
    status: str,
    phase: str,
    action: str,
    message: str,
    enabled: bool = True,
) -> str:
    """Format full supervisor status line with clean ANSI color highlights."""
    if not enabled:
        return f"[{status}] Phase: {phase} | Action: {action} -> {message}"

    st_tag = color_status(status, enabled=True)
    ph_tag = color_phase(phase, enabled=True)
    act_tag = f"\033[1;97m{action}\033[0m"
    return f"{st_tag} \033[1mPhase:\033[0m {ph_tag} \033[2m|\033[0m \033[1mAction:\033[0m {act_tag} \033[2m->\033[0m {message}"


def format_completed_line(prefix: str, duration_text: str, enabled: bool = True) -> str:
    """Format completion / elapsed duration line."""
    if not enabled:
        return f"  └── {prefix} in {duration_text}"
    return f"  \033[2;36m└──\033[0m \033[0;36m{prefix} in\033[0m \033[1;36m{duration_text}\033[0m"


def format_attempt_banner(attempt: int, task_id: str, enabled: bool = True) -> str:
    """Format attempt advancement banner."""
    border = "=" * 80
    text = f"            >>> ADVANCING TO ATTEMPT {attempt} (Task: {task_id}) <<<"
    if not enabled:
        return f"\n{border}\n{text}\n{border}\n"
    return f"\n\033[1;36m{border}\033[0m\n\033[1;93m{text}\033[0m\n\033[1;36m{border}\033[0m\n"


def format_transition_line(phase: str, delay_sec: int, enabled: bool = True) -> str:
    """Format phase transition notice."""
    if not enabled:
        return f"[TRANSITION] Phase advanced to {phase}. Pausing {delay_sec}s stability interval between phases..."
    trans_badge = color_status("TRANSITION", enabled=True)
    ph_colored = color_phase(phase, enabled=True)
    return f"{trans_badge} Phase advanced to {ph_colored}. Pausing \033[1m{delay_sec}s\033[0m stability interval between phases..."


def format_duration(seconds: float) -> str:
    """Format duration nicely in seconds and minutes."""
    secs = int(round(seconds))
    if secs < 60:
        return f"{secs} sec"
    mins = secs // 60
    rem = secs % 60
    if rem == 0:
        return f"{mins} min ({secs} sec)"
    return f"{mins} min {rem} sec ({secs} sec)"


def run_supervisor_cmd(
    action: Optional[str] = None,
    task: Optional[str] = None,
    attempt: Optional[int] = None,
    workspace: Optional[str] = None,
    watch: bool = False,
    once: bool = False,
    file_path: Optional[str] = None,
    seconds: float = 60.0,
    ceiling: float = 300.0,
    timeout: float = 1800.0,
    phase_delay: float = 30.0,
    output_json: bool = False,
    color: Optional[bool] = None,
) -> int:
    """Execute supervisor commands and workflows."""
    use_color = should_use_color(color)

    if action == "preflight":
        ws_opt = Path(workspace).resolve() if workspace else find_workspace_root_for_cwd(Path.cwd())
        preflight = run_bwrap_deployment_preflight(workspace_root=ws_opt, raise_on_failure=False)
        if output_json:
            print(json.dumps(preflight.to_dict(), indent=2))
        elif preflight.passed:
            badge = "\033[1;32m[ISOLATION PREFLIGHT: PASS]\033[0m" if use_color else "[ISOLATION PREFLIGHT: PASS]"
            print(f"{badge} {preflight.reason}")
        else:
            err_badge = "\033[1;31mERROR: [isolation.preflight_failed]\033[0m" if use_color else "ERROR: [isolation.preflight_failed]"
            print(f"{err_badge} {preflight.reason}", file=sys.stderr)
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
                badge = "\033[1;32m[STABLE]\033[0m" if use_color else "[STABLE]"
                print(f"{badge} File '{file_path}' is stable. Reason: {reason}")
            else:
                badge = "\033[1;31m[UNSTABLE]\033[0m" if use_color else "[UNSTABLE]"
                print(f"{badge} File '{file_path}' is not stable yet.")
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
                badge = "\033[1;31m[TRIPPED]\033[0m" if use_color else "[TRIPPED]"
                print(f"{badge} {halt_msg}", file=sys.stderr)
            else:
                badge = "\033[1;32m[HEALTHY]\033[0m" if use_color else "[HEALTHY]"
                print(f"{badge} {halt_msg}")
        return 1 if tripped else 0

    # 3. Action: check-task
    elif action == "check-task":
        report = engine.check_task(task_id=task)
        if output_json:
            print(json.dumps(report, indent=2))
        else:
            hdr = "=" * 64
            if use_color:
                print(f"\033[1;36m{hdr}\033[0m")
                print("\033[1;97m                 STAGECHECK SUPERVISOR STATUS                   \033[0m")
                print(f"\033[1;36m{hdr}\033[0m")
            else:
                print(hdr)
                print("                 STAGECHECK SUPERVISOR STATUS                   ")
                print(hdr)
            wd_status = "TRIPPED" if report['watchdog_tripped'] else "HEALTHY"
            wd_formatted = color_status(wd_status, enabled=use_color)
            ph_formatted = color_phase(report['phase'], enabled=use_color)
            print(f"Task ID:          {report['task_id']}")
            print(f"Attempt:          {report['attempt']}")
            print(f"Current Phase:    {ph_formatted}")
            print(f"Active Turn:      {report['turn']}")
            print(f"Watchdog Status:  {wd_formatted}")
            if report.get("halt_reason"):
                print(f"Halt Reason:      {report['halt_reason']}")
        return 1 if report["watchdog_tripped"] else 0

    # 4. Standard step execution or continuous loop
    if watch:
        print("Starting continuous autonomous supervisor loop (press Ctrl+C to stop)...")
        last_state_key: Optional[Tuple[str, str, str, str]] = None
        action_start_time: float = time.time()
        last_attempt: Optional[int] = None
        last_phase: Optional[str] = None

        try:
            while True:
                res = engine.step(task_id=task, attempt=attempt)
                current_time = time.time()
                state_key = (res.status, res.current_phase, res.action_taken, res.message)

                # Highlight moving to next attempt prominently
                if last_attempt is not None and res.attempt != last_attempt:
                    print(format_attempt_banner(res.attempt, res.task_id, enabled=use_color))
                last_attempt = res.attempt

                if output_json:
                    if state_key != last_state_key:
                        print(json.dumps(res.__dict__))
                        last_state_key = state_key
                else:
                    if state_key != last_state_key:
                        # Display duration of previous action when transitioning to a new action
                        if last_state_key is not None:
                            elapsed = current_time - action_start_time
                            prev_status, _, _, _ = last_state_key
                            if prev_status == "WAITING" or elapsed >= 1.0:
                                print(format_completed_line("Completed", format_duration(elapsed), enabled=use_color))

                        # Display new status line once
                        print(
                            format_status_line(
                                res.status,
                                res.current_phase,
                                res.action_taken,
                                res.message,
                                enabled=use_color,
                            )
                        )
                        action_start_time = current_time
                        last_state_key = state_key

                if res.status in ("COMPLETED", "HALTED", "DEFECTS_DETECTED"):
                    if not output_json and last_state_key is not None:
                        elapsed = time.time() - action_start_time
                        if elapsed >= 1.0:
                            print(format_completed_line("Finished", format_duration(elapsed), enabled=use_color))
                    return 0 if res.status == "COMPLETED" else 1

                # Sleep time between phase changes (e.g. 30 sec between each phase)
                if res.status == "ADVANCED" or (last_phase is not None and res.current_phase != last_phase):
                    if phase_delay > 0:
                        if not output_json:
                            print(format_transition_line(res.current_phase, int(phase_delay), enabled=use_color))
                        time.sleep(phase_delay)
                        action_start_time = time.time()

                last_phase = res.current_phase
                time.sleep(2.0)
        except KeyboardInterrupt:
            print("\nSupervisor interrupted by operator.")
            return 0
    else:
        res = engine.step(task_id=task, attempt=attempt)
        if output_json:
            print(json.dumps(res.__dict__, indent=2))
        else:
            print(
                format_status_line(
                    res.status,
                    res.current_phase,
                    res.action_taken,
                    res.message,
                    enabled=use_color,
                )
            )
        return 0 if res.status in ("ADVANCED", "COMPLETED", "WAITING", "IDLE") else 1
