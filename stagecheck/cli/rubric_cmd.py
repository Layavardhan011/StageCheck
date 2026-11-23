"""CLI Command Handler for 'stagecheck check-rubric' (FR-03 / Spec 02 / DEC-026).

Provides:
  stagecheck check-rubric [--task-id <id>] [--attempt <n>] [--cycle <c>] [--domain <d>]
                          [--update-json] [--fail-fast] [--quiet] [--workspace <path>]
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

from stagecheck.core.paths import find_workspace_root
from stagecheck.core.rubric_engine import run_rubric_evaluation, update_rubric_artifacts


def run_check_rubric(
    task: Optional[str] = None,
    attempt: Optional[int] = None,
    cycle: Optional[int] = None,
    domain: Optional[str] = None,
    update_json: bool = False,
    fail_fast: bool = False,
    quiet: bool = False,
    workspace: Optional[str] = None,
) -> int:
    """Execute the 'stagecheck check-rubric' evaluation."""
    try:
        ws_root = Path(workspace).resolve() if workspace else find_workspace_root()
    except Exception as err:
        print(f"Error: Could not locate workspace root: {err}", file=sys.stderr)
        return 1

    try:
        payload, elapsed_ms = run_rubric_evaluation(
            workspace_root=ws_root,
            task_id=task,
            attempt=attempt,
            cycle=cycle,
            target_domain=domain,
            fail_fast=fail_fast,
        )
    except Exception as err:
        print(f"Error running rubric evaluation: {err}", file=sys.stderr)
        return 1

    rubric_file = None
    review_file = None
    if update_json:
        rubric_file, review_file = update_rubric_artifacts(ws_root, payload)

    counts = payload["counts"]
    failed = counts["failed"]
    passed = counts["passed"]
    na = counts["not_applicable"]
    total = counts["total_rules"]

    if not quiet:
        print("================================================================")
        print("       STAGECHECK AUTOMATED AUDIT RUBRIC EVALUATOR (v2.0.0)      ")
        print("================================================================")
        print(f"Task ID:       {payload['task_id']}")
        print(f"Attempt:       {payload['attempt']}")
        print(f"Review Cycle:  {payload['cycle']}")
        print(f"Evaluation:    {elapsed_ms:.1f}ms (<200ms target)")
        print("----------------------------------------------------------------")

        for d_name, d_val in payload["domains"].items():
            status_tag = f"[{d_val['status']}]"
            d_rules = d_val["rules"]
            d_non_pass = [r for r in d_rules if r.get("status") not in ("PASS", "NOT_APPLICABLE")]
            if d_non_pass:
                print(f"Domain: {d_name} ({len(d_rules)} Rules) {status_tag}")
                for fr in d_non_pass:
                    st = fr.get("status", "FAIL")
                    print(f"  └── [{st}] {fr['rule_id']}: {fr.get('message', 'Rule requirement not satisfied.')}")
            else:
                print(f"Domain: {d_name} ({len(d_rules)} Rules) {status_tag} - All rules passed or N/A.")

        print("----------------------------------------------------------------")
        print("RESULTS:")
        print(f"  Total Evaluated: {total} Rules")
        print(f"  Passed:          {passed} Rules")
        print(f"  Not Applicable:  {na} Rules")
        print(f"  Failed:          {failed} Rules")
        if counts.get("not_evaluated", 0) > 0:
            print(f"  Not Evaluated:   {counts['not_evaluated']} Rules")
        if counts.get("blocked", 0) > 0:
            print(f"  Blocked:         {counts['blocked']} Rules")
        print(f"  Overall Verdict: {payload['overall_verdict']}")

        if update_json:
            print("\nAUTOMATIC UPDATES:")
            if rubric_file:
                print(f"  [OK] Wrote {rubric_file.relative_to(ws_root)}")
            if review_file:
                print(f"  [OK] Updated {review_file.relative_to(ws_root)}")

        print("================================================================")

    return 0 if payload["overall_verdict"] == "PASS" else 1
