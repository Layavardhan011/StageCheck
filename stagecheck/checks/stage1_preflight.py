"""Stage 1: Preflight Invariants, Prompt Invariance, and Toolchain Checks (P4-T2)."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

from stagecheck.checks.base import AuditContext, Defect, StageResult
from stagecheck.core.prompt_gate import PromptGateError, assert_prompt_invariance

_PLACEHOLDER_PATTERN = re.compile(r"(\{\{[A-Za-z0-9_]+\}\}|<[A-Za-z0-9_]+_PLACEHOLDER>|TODO_IMPLEMENT)")


def run_stage1_preflight(ctx: AuditContext) -> StageResult:
    """Execute Stage 1 Preflight Verification."""
    stage_id = "preflight"
    defects = []
    errors = []

    # 1. Assert Live Prompt Invariance (GAP-F1)
    try:
        assert_prompt_invariance(ctx.workspace_root, ctx.task_id, ctx.attempt)
    except PromptGateError as err:
        defects.append(
            Defect(
                defect_id="preflight.prompt_tampered_post_verification",
                message=str(err),
                stage=stage_id,
                severity="CRITICAL",
                blocking=True,
            )
        )

    # 2. Assert AGENTS.md contract existence
    agents_md = ctx.workspace_root / "AGENTS.md"
    if not agents_md.is_file():
        defects.append(
            Defect(
                defect_id="preflight.missing_agents_contract",
                message="Root AGENTS.md binding contract is missing from workspace root.",
                stage=stage_id,
                severity="CRITICAL",
                blocking=True,
            )
        )

    # 3. Check for unresolved placeholders in touched repositories
    for repo_name in ctx.touched_repos:
        repo_dir = ctx.workspace_root / "repos" / repo_name
        if repo_dir.is_dir():
            for p in repo_dir.rglob("*"):
                if p.is_file() and not any(part.startswith(".") for part in p.parts):
                    try:
                        text = p.read_text(encoding="utf-8", errors="ignore")
                        if _PLACEHOLDER_PATTERN.search(text):
                            defects.append(
                                Defect(
                                    defect_id="preflight.unresolved_placeholder",
                                    message=f"Unresolved template placeholder detected in '{p.relative_to(ctx.workspace_root)}'.",
                                    stage=stage_id,
                                    severity="CRITICAL",
                                    blocking=True,
                                    repo=repo_name,
                                )
                            )
                    except Exception:
                        pass

    # 4. Gitleaks Binary & Version Check (SEC-L2) - Fail Closed
    from stagecheck.core.scanner import SecretScanner
    scanner = getattr(ctx, "scanner", None) or SecretScanner()
    is_valid, scanner_defects = scanner.verify_scanner_binary(stage=stage_id)
    if not is_valid:
        defects.extend(scanner_defects)

    status = "FAIL" if any(d.blocking for d in defects) else "CLEAR"
    return StageResult(stage_id=stage_id, status=status, defects=defects, errors=errors)

