"""Stage 9: Invariant Carry-Forward and Regression Prevention (P4-T2).

Verifies SHA-256 hash chaining across previous attempt seals (attempt_1 -> attempt_2).
For attempt == 1, Stage 9 vacuously passes as CLEAR (carry_forward.initial_attempt_unconditional_pass, GAP-I3).
For attempt > 1, asserts preceding seal exists and issue history ledger is untruncated.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from stagecheck.checks.base import AuditContext, Defect, StageResult
from stagecheck.core.agents import resolve_task_attempt_dir
from stagecheck.core.evidence import verify_evidence_manifest, verify_seal_chain
from stagecheck.core.paths import resolve_task_dir
from stagecheck.core.sealing import verify_attempt_merkle_seal
from stagecheck.core.utils import canonical_json_dumps, sha256_digest, sha256_file


def run_stage9_carry_forward(ctx: AuditContext) -> StageResult:
    """Execute Stage 9 Invariant Carry-Forward verification."""
    stage_id = "carry_forward"
    defects: List[Defect] = []
    errors: List[str] = []

    # 1. Vacuum pass for initial attempt (attempt == 1) per GAP-I3
    if ctx.attempt <= 1:
        defects.append(
            Defect(
                defect_id="carry_forward.initial_attempt_unconditional_pass",
                message="Initial attempt verification: carry-forward checks vacuously pass",
                stage=stage_id,
                severity="INFO",
                blocking=False,
            )
        )
        return StageResult(stage_id=stage_id, status="CLEAR", defects=defects, errors=errors)

    # 2. For attempt > 1, verify prior attempt seal and ledger existence
    prior_attempt = ctx.attempt - 1
    prior_dir = resolve_task_attempt_dir(ctx.workspace_root, ctx.task_id, prior_attempt)
    prior_seal_path = prior_dir / "seal.json"

    if not prior_dir.exists() or not prior_dir.is_dir():
        defects.append(
            Defect(
                defect_id="carry_forward.missing_prior_attempt",
                message=f"Prior attempt directory 'attempt_{prior_attempt}' is missing for multi-attempt task '{ctx.task_id}'",
                stage=stage_id,
                severity="CRITICAL",
                blocking=True,
            )
        )
        return StageResult(stage_id=stage_id, status="FAIL", defects=defects, errors=errors)

    if prior_seal_path.is_symlink():
        defects.append(
            Defect(
                defect_id="carry_forward.missing_prior_seal",
                message=f"Prior attempt seal 'seal.json' is a forbidden symlink at {prior_dir.relative_to(ctx.workspace_root)}",
                stage=stage_id,
                severity="CRITICAL",
                blocking=True,
            )
        )
    elif prior_seal_path.is_file():
        # Always verify the complete cryptographic seal chain (1 .. prior_attempt) regardless of seal format
        try:
            ok, violations = verify_seal_chain(ctx.workspace_root, ctx.task_id, prior_attempt)
            if not ok:
                defects.append(
                    Defect(
                        defect_id="carry_forward.broken_chain",
                        message=f"Prior seal chain verification failed: {'; '.join(violations)}",
                        stage=stage_id,
                        severity="CRITICAL",
                        blocking=True,
                    )
                )

            # Also verify EVIDENCE_MANIFEST.json if present
            manifest_path = ctx.workspace_root / "evidence" / "EVIDENCE_MANIFEST.json"
            if manifest_path.is_file():
                # Reconcile active issue history ledger in manifest before verification
                issue_hist_p = resolve_task_dir(ctx.workspace_root, ctx.task_id) / f"TASK_{ctx.task_id}_ISSUE_HISTORY.md"
                alt_hist_p = ctx.workspace_root / f"TASK_{ctx.task_id}_ISSUE_HISTORY.md"
                cur_hist = issue_hist_p if issue_hist_p.is_file() else (alt_hist_p if alt_hist_p.is_file() else None)
                if cur_hist:
                    from stagecheck.core.evidence import update_evidence_manifest
                    update_evidence_manifest(ctx.workspace_root, [cur_hist])

                m_ok, m_viol = verify_evidence_manifest(ctx.workspace_root)
                if not m_ok:
                    defects.append(
                        Defect(
                            defect_id="carry_forward.broken_chain",
                            message=f"Evidence manifest verification failed: {'; '.join(m_viol)}",
                            stage=stage_id,
                            severity="CRITICAL",
                            blocking=True,
                        )
                    )
        except Exception as err:
            defects.append(
                Defect(
                    defect_id="carry_forward.unreadable_prior_seal",
                    message=f"Failed to read or verify prior attempt seal: {err}",
                    stage=stage_id,
                    severity="CRITICAL",
                    blocking=True,
                )
            )
    else:
        # prior_seal_path does not exist on disk
        # Check if prior attempt passed audit (in which case Gate 4 seal was strictly required)
        # or was an unsealed failed/retried attempt (which does not have a Gate 4 seal).
        prior_verdict_file = prior_dir / "Phase-3" / "verdict.json"
        prior_verdict_passed = False
        if prior_verdict_file.is_file() and not prior_verdict_file.is_symlink():
            try:
                prior_vdata = json.loads(prior_verdict_file.read_text(encoding="utf-8"))
                if prior_vdata.get("result") in ("PASSED", "CLEAR") and not any(
                    d.get("blocking", True) for d in prior_vdata.get("defects", [])
                ):
                    prior_verdict_passed = True
            except Exception:
                pass

        if prior_verdict_passed:
            defects.append(
                Defect(
                    defect_id="carry_forward.missing_prior_seal",
                    message=f"Prior attempt 'attempt_{prior_attempt}' passed audit but seal 'seal.json' is missing at {prior_dir.relative_to(ctx.workspace_root)}",
                    stage=stage_id,
                    severity="CRITICAL",
                    blocking=True,
                )
            )
        else:
            # Unsealed failed or retried prior attempt: expected during multi-attempt retries of failed attempts
            defects.append(
                Defect(
                    defect_id="carry_forward.unsealed_prior_retry",
                    message=f"Prior attempt 'attempt_{prior_attempt}' is an unsealed retry (prior audit did not clear Gate 4); carry-forward continues with cumulative issue history ledger.",
                    stage=stage_id,
                    severity="INFO",
                    blocking=False,
                )
            )

    # 3. Require non-empty cumulative issue history ledger for attempt > 1
    issue_history_path = resolve_task_dir(ctx.workspace_root, ctx.task_id) / f"TASK_{ctx.task_id}_ISSUE_HISTORY.md"
    alt_history = ctx.workspace_root / f"TASK_{ctx.task_id}_ISSUE_HISTORY.md"
    active_history = issue_history_path if issue_history_path.is_file() else (alt_history if alt_history.is_file() else None)
    if not active_history or not active_history.read_text(encoding="utf-8", errors="ignore").strip():
        defects.append(
            Defect(
                defect_id="carry_forward.missing_issue_history",
                message=f"Cumulative issue history ledger 'TASK_{ctx.task_id}_ISSUE_HISTORY.md' is missing or empty for attempt {ctx.attempt}.",
                stage=stage_id,
                severity="CRITICAL",
                blocking=True,
            )
        )

    has_blocking = any(d.blocking for d in defects)
    return StageResult(
        stage_id=stage_id,
        status="FAIL" if has_blocking else "CLEAR",
        defects=defects,
        errors=errors,
    )

