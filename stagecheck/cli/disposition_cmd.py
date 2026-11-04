"""Disposition CLI Command Handler: 'stagecheck disposition add' (P4-T5).

Interactive human override hatch recording defect waivers with authorization metadata,
enforcing TTY confirmation (SEC-03), and atomically updating controls/DISPOSITIONS.json.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

from stagecheck.core.dispositions import DispositionError, add_disposition
from stagecheck.core.paths import find_workspace_root


def run_disposition_add(
    task: str,
    defect: str,
    rationale: str,
    action: str = "ACCEPT_AS_INTENTIONAL",
    authorized_by: str = "human-operator",
    yes: bool = False,
    workspace: Optional[str] = None,
) -> int:
    """Execute 'stagecheck disposition add'."""
    workspace_root = Path(workspace).resolve() if workspace else find_workspace_root()

    print("=" * 72)
    print(" [STAGECHECK] HUMAN DEFECT DISPOSITION & OVERRIDE HATCH")
    print(f" Task ID     : {task}")
    print(f" Defect Code : {defect}")
    print(f" Action      : {action}")
    print(f" Authorized  : {authorized_by}")
    print(f" Rationale   : {rationale}")
    print("=" * 72)

    # Interactive confirmation prompt if not pre-confirmed via --yes
    if not yes:
        if not sys.stdin.isatty():
            print(
                "\nERROR: [disposition.non_interactive_blocked] Adding defect waivers requires an "
                "interactive terminal or explicit human confirmation (--yes).",
                file=sys.stderr,
            )
            return 1

        prompt = f"\nAuthorize waiver for defect '{defect}' on task '{task}'? [YES/NO] (Default: NO): "
        try:
            choice = input(prompt).strip().upper()
        except (KeyboardInterrupt, EOFError):
            print("\nDisposition cancelled.")
            return 1

        if choice not in ("YES", "Y"):
            print("Disposition rejected by operator. No changes written.")
            return 1

    try:
        entry = add_disposition(
            workspace_root=workspace_root,
            task_id=task,
            defect_id=defect,
            rationale=rationale,
            action=action,
            authorized_by=authorized_by,
            require_tty=not yes,
            confirmed=True,
        )
        print(f"\nSUCCESS: Defect waiver recorded with ID '{entry['disposition_id']}'.")
        print(f"  File: {workspace_root}/controls/DISPOSITIONS.json")
        print("  Root AGENTS.md contract re-rendered and SHA-256 bound.")
        print("  EVIDENCE_MANIFEST.json updated.")
        print("=" * 72)
        return 0
    except DispositionError as err:
        print(f"\nERROR: [disposition.failed] {err}", file=sys.stderr)
        return 1

