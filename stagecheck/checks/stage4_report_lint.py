"""Stage 4: Delivery Report Linting & Anti-Prompt Injection (P4-T2)."""

from __future__ import annotations

import re
from pathlib import Path

from stagecheck.checks.base import AuditContext, Defect, StageResult
from stagecheck.core.agents import resolve_task_attempt_dir
from stagecheck.core.paths import StageCheckPathError, read_bytes_nofollow, safe_resolve

MAX_REPORT_BYTES = 20 * 1024 * 1024  # 20 MiB

_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(?:all\s+)?(?:previous\s+)?instructions", re.IGNORECASE),
    re.compile(r"system\s+override", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+in\s+developer\s+mode", re.IGNORECASE),
]


def run_stage4_report_lint(ctx: AuditContext) -> StageResult:
    """Execute Stage 4 Report Lint Verification."""
    stage_id = "report_lint"
    defects = []
    errors = []

    rel_report = f"evidence/tasks/{ctx.task_id}/attempt_{ctx.attempt}/Phase-2B/report.md"
    try:
        report_file = safe_resolve(rel_report, ctx.workspace_root, allow_symlinks=False)
    except StageCheckPathError as err:
        defects.append(
            Defect(
                defect_id="report_lint.unsafe_delivery_report_path",
                message=f"Delivery report path failed symlink/containment validation: {err}",
                stage=stage_id,
                severity="CRITICAL",
                blocking=True,
            )
        )
        return StageResult(stage_id=stage_id, status="FAIL", defects=defects, errors=errors)

    if report_file.is_symlink() or not report_file.is_file():
        defects.append(
            Defect(
                defect_id="report_lint.missing_delivery_report",
                message=f"Delivery report '{report_file.relative_to(ctx.workspace_root.resolve())}' is missing or symlinked.",
                stage=stage_id,
                severity="HIGH",
                blocking=True,
            )
        )
        return StageResult(stage_id=stage_id, status="FAIL", defects=defects, errors=errors)

    try:
        content = read_bytes_nofollow(report_file, max_bytes=MAX_REPORT_BYTES).decode("utf-8")
        if len(content.strip()) < 20:
            defects.append(
                Defect(
                    defect_id="report_lint.empty_delivery_report",
                    message="Delivery report is trivial or empty (<20 characters).",
                    stage=stage_id,
                    severity="MEDIUM",
                    blocking=True,
                )
            )

        # Check for prompt injection patterns
        for pattern in _INJECTION_PATTERNS:
            if pattern.search(content):
                defects.append(
                    Defect(
                        defect_id="report_lint.prompt_injection_pattern",
                        message=f"Prompt injection pattern detected in delivery report: '{pattern.pattern}'.",
                        stage=stage_id,
                        severity="CRITICAL",
                        blocking=True,
                    )
                )

    except Exception as err:
        errors.append(f"Failed to read delivery report: {err}")
        defects.append(
            Defect(
                defect_id="report_lint.unreadable_delivery_report",
                message=f"Failed to read or decode delivery report: {err}",
                stage=stage_id,
                severity="HIGH",
                blocking=True,
            )
        )

    status = "FAIL" if (errors or any(d.blocking for d in defects)) else "CLEAR"
    return StageResult(stage_id=stage_id, status=status, defects=defects, errors=errors)
