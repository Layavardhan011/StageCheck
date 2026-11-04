"""Audit CLI Command Handler: 'stagecheck audit' (P4-T2).

Executes the nine independent verification stages, prints formatted progress banners,
evaluates human disposition waivers, and enforces zero partial pass semantics across
all repositories.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

from stagecheck.core.orchestrator import run_audit
from stagecheck.core.paths import find_workspace_root


def run_audit_cmd(
    task: str,
    attempt: int = 1,
    workspace: Optional[str] = None,
) -> int:
    """Execute the Phase 3 audit verification CLI command."""
    workspace_root = Path(workspace).resolve() if workspace else find_workspace_root()

    print("=" * 72)
    print(f" [PHASE 3] INDEPENDENT 9-STAGE AUDIT VERIFICATION")
    print(f" Task: {task} | Attempt: {attempt}")
    print(f" Workspace: {workspace_root}")
    print("=" * 72)

    passed, verdict = run_audit(
        workspace_root=workspace_root,
        task_id=task,
        attempt=attempt,
    )

    counts = verdict.get("counts", {})
    blocking = counts.get("blocking", 0)
    report_only = counts.get("report_only", 0)

    print("\n--- Verification Stage Results ---")
    for check in verdict.get("checks", []):
        cid = check.get("id")
        errs = check.get("errors", [])
        status_label = "FAIL" if errs else "PASS"
        print(f"  Stage {cid:<15}: {status_label}")

    if verdict.get("defects"):
        print("\n--- Emitted Findings ---")
        for d in verdict["defects"]:
            mode = d.get("mode", "blocking")
            did = d.get("defect_id")
            stage = d.get("check_id")
            ev_quote = ""
            if d.get("evidence"):
                ev_quote = d["evidence"][0].get("quote", "")
            print(f"  [{mode.upper()}] ({stage}) {did}: {ev_quote}")

    print("-" * 72)
    print(f"Summary: {blocking} blocking defect(s), {report_only} report-only finding(s)")

    if passed:
        print("\n>> VERDICT: CLEAR (All 9 stages passed across all repositories)")
        print("=" * 72)
        return 0
    else:
        print("\n>> VERDICT: BLOCKED (One or more stages failed - zero partial pass)")
        print("=" * 72)
        return 1
