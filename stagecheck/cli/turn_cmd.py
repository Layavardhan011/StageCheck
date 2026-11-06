"""CLI Command Handler for 'stagecheck turn' (FR-07 / Spec 04 / ARCH-04).

Provides:
  stagecheck turn [--task <id>] [--json] [--workspace <path>]
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

from stagecheck.core.paths import find_workspace_root
from stagecheck.core.turn import check_and_record_turn_rate_limit, compute_turn_status


def run_turn(
    task: Optional[str] = None,
    attempt: Optional[int] = None,
    json_output: bool = False,
    workspace: Optional[str] = None,
) -> int:
    """Execute the 'stagecheck turn' status query."""
    try:
        ws_root = Path(workspace).resolve() if workspace else find_workspace_root()
    except Exception as err:
        print(f"Error: Could not locate workspace root: {err}", file=sys.stderr)
        return 1

    # Enforce rate limit (Spec 04 §3.1 / ARCH-04)
    allowed, retry_after = check_and_record_turn_rate_limit(ws_root)
    if not allowed:
        print(
            f"[RATE_LIMITED] Exceeded maximum 3 turn queries within 5-second window. "
            f"Mandatory polling interval is 5 seconds (+/-1s jitter). Retry after {retry_after:.1f}s.",
            file=sys.stderr,
        )
        return 429

    try:
        status = compute_turn_status(
            workspace_root=ws_root,
            task_id=task,
            attempt=attempt,
            reset_watchdog=True,
        )
    except Exception as err:
        print(f"Error computing turn status: {err}", file=sys.stderr)
        return 1

    if json_output:
        print(json.dumps(status.to_dict(), indent=2))
        return 0

    print("================================================================")
    print("                    STAGECHECK TURN STATUS                      ")
    print("================================================================")
    print(f"Task ID:       {status.task_id}")
    print(f"Attempt:       {status.attempt}")
    print(f"Cycle:         {status.cycle}")
    print(f"Phase:         {status.phase}")
    print(f"Active Turn:   {status.active_turn}")
    print(f"Waiting For:   {status.waiting_for}")
    print(f"Retry After:   {status.retry_after_seconds}s (+/-1s jitter)")
    if status.preceding_status:
        print(f"Preceding:     {status.preceding_status}")
    print("----------------------------------------------------------------")
    print(f"Instructions:  {status.instructions_for_active_agent}")
    print("================================================================")
    return 0
