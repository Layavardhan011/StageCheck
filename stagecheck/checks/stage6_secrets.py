"""Stage 6: Multi-Repository Secret Scanning & Scanner Tamper Defense (P4-T2)."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from stagecheck.checks.base import AuditContext, Defect, StageResult


def run_stage6_secrets(ctx: AuditContext) -> StageResult:
    """Execute Stage 6 Secret Scanning Verification."""
    stage_id = "secrets"
    defects = []
    errors = []

    for repo_name in ctx.touched_repos:
        repo_dir = ctx.workspace_root / "repos" / repo_name
        if not repo_dir.is_dir():
            continue

        # 1. Tamper Defense: check for unauthorized local override configs (SEC-M1)
        for forbidden_cfg in [".gitleaks.toml", ".gitleaksignore"]:
            if (repo_dir / forbidden_cfg).exists():
                defects.append(
                    Defect(
                        defect_id="secrets.unauthorized_scanner_config",
                        message=f"Unauthorized Gitleaks override '{forbidden_cfg}' detected in '{repo_name}'.",
                        stage=stage_id,
                        severity="CRITICAL",
                        blocking=True,
                        repo=repo_name,
                    )
                )

        # 2. Invoke Gitleaks across commit range (SEC-D4, SEC-M1) - Fail Closed
        base_commit = ctx.base_commits.get(repo_name)
        target_commit = ctx.target_commits.get(repo_name, "HEAD")

        if base_commit and target_commit:
            from stagecheck.core.scanner import SecretScanner
            scanner = getattr(ctx, "scanner", None) or SecretScanner()
            scan_res = scanner.scan_commit_range(
                repo_dir=repo_dir,
                base_commit=base_commit,
                target_commit=target_commit,
                repo_name=repo_name,
                stage=stage_id,
                workspace_root=ctx.workspace_root,
            )
            if not scan_res.is_clear:
                defects.extend(scan_res.defects)

    status = "FAIL" if any(d.blocking for d in defects) else "CLEAR"
    return StageResult(stage_id=stage_id, status=status, defects=defects, errors=errors)

