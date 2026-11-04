"""Resume CLI Command Handler: 'stagecheck resume' (P4-T5).

Evaluates remaining defect findings, checks disposition coverage, and deterministically
advances active state from AWAITING_HUMAN_DISPOSITION (GAP-B1).
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

from stagecheck.core.dispositions import DispositionError, resume_after_disposition
from stagecheck.core.paths import find_workspace_root


def run_resume(
    task: str,
    workspace: Optional[str] = None,
) -> int:
    """Execute 'stagecheck resume' command."""
    workspace_root = Path(workspace).resolve() if workspace else find_workspace_root()

    print("=" * 72)
    print(" [STAGECHECK] DETERMINISTIC POST-DISPOSITION RESUME")
    print(f" Task ID   : {task}")
    print(f" Workspace : {workspace_root}")
    print("=" * 72)

    try:
        result = resume_after_disposition(workspace_root=workspace_root, task_id=task)
        resumed_phase = result["resumed_phase"]
        reason = result["reason"]

        print(f"\nSUCCESS: Active state transitioned to '{resumed_phase}'.")
        print(f"  Reason: {reason}")
        print("=" * 72)
        return 0
    except DispositionError as err:
        print(f"\nERROR: [resume.failed] {err}", file=sys.stderr)
        return 1
