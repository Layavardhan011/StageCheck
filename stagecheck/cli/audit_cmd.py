"""Audit CLI Command Handler: 'stagecheck audit' (P4-T2).

Executes the nine independent verification stages, prints formatted progress banners,
evaluates human disposition waivers, and enforces zero partial pass semantics across
all repositories.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

from stagecheck.core.gate_engine import GateId, get_gate_receipt_path, normalize_phase
from stagecheck.core.orchestrator import run_audit
from stagecheck.core.paths import find_workspace_root
from stagecheck.core.state import load_active_state
from stagecheck.core.utils import sha256_file


def _check_phase3_prerequisites(workspace_root: Path, task: str, attempt: int) -> Optional[int]:
    """Verify that workspace is in PHASE_3_AUDIT and Gate 2B receipt is valid (Spec 01 §6.2)."""
    try:
        state = load_active_state(workspace_root)
        norm_phase = normalize_phase(state.get("phase", ""))
        if norm_phase != "PHASE_3_AUDIT":
            print(
                f"ERROR: [prerequisite.phase_unmet] Cannot run audit in phase '{state.get('phase')}'. "
                "Workspace must be in PHASE_3_AUDIT (advance Gate 2B first).",
                file=sys.stderr,
            )
            return 1

        cleared_gates = state.get("cleared_gates", {})
        if "GATE_2B" not in cleared_gates:
            print(
                "ERROR: [prerequisite.gate2b_unmet] Cannot run audit: Gate 2B commit authority has not been cleared.",
                file=sys.stderr,
            )
            return 1

        g2b_receipt_path = get_gate_receipt_path(workspace_root, GateId.GATE_2B, task, attempt)
        if not g2b_receipt_path.is_file():
            print(
                f"ERROR: [prerequisite.gate2b_missing] Gate 2B receipt missing at '{g2b_receipt_path}'.",
                file=sys.stderr,
            )
            return 1

        if sha256_file(g2b_receipt_path).lower() != cleared_gates["GATE_2B"].lower():
            print(
                "ERROR: [prerequisite.gate2b_tampered] Gate 2B receipt on disk has been altered.",
                file=sys.stderr,
            )
            return 1
    except Exception as err:
        print(f"ERROR: [prerequisite.state_error] Failed checking state prerequisites: {err}", file=sys.stderr)
        return 1
    return None


def run_audit_cmd(
    task: str,
    attempt: int = 1,
    workspace: Optional[str] = None,
) -> int:
    """Execute the Phase 3 audit verification CLI command."""
    workspace_root = Path(workspace).resolve() if workspace else find_workspace_root()

    # Enforce Gate 2B prerequisite
    rc = _check_phase3_prerequisites(workspace_root, task, attempt)
    if rc is not None:
        return rc

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

