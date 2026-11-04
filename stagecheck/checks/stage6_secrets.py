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

        # 2. Invoke Gitleaks across commit range
        base_commit = ctx.base_commits.get(repo_name)
        target_commit = ctx.target_commits.get(repo_name, "HEAD")

        if base_commit and target_commit:
            gitleaks_bin = shutil.which("gitleaks")
            strict_scanners = (
                os.environ.get("STAGECHECK_STRICT_SECRETS") == "1"
                or getattr(ctx, "strict_scanners", False)
            )

            if not gitleaks_bin or not os.access(gitleaks_bin, os.X_OK):
                if strict_scanners:
                    defects.append(
                        Defect(
                            defect_id="secrets.scanner_unavailable",
                            message=f"Gitleaks scanner binary not found in PATH or not executable; secret scanning blocked for '{repo_name}'.",
                            stage=stage_id,
                            severity="CRITICAL",
                            blocking=True,
                            repo=repo_name,
                        )
                    )
                else:
                    defects.append(
                        Defect(
                            defect_id="secrets.scanner_skipped",
                            message=f"Gitleaks scanner binary not available in environment; secret scanning skipped for '{repo_name}'.",
                            stage=stage_id,
                            severity="HIGH",
                            blocking=False,
                            repo=repo_name,
                        )
                    )
            else:
                cmd = [
                    gitleaks_bin,
                    "detect",
                    f"--source={repo_dir}",
                    f"--log-opts={base_commit}..{target_commit}",
                    "--verbose",
                    "--no-banner",
                ]
                try:
                    env = os.environ.copy()
                    # Purge GITLEAKS ambient env vars (SEC-Q1)
                    env = {k: v for k, v in env.items() if not k.startswith("GITLEAKS_")}
                    res = subprocess.run(cmd, env=env, capture_output=True, text=True, check=False)
                    # Gitleaks exits with code 1 if leaks are found
                    if res.returncode == 1:
                        defects.append(
                            Defect(
                                defect_id="secrets.detected_credential",
                                message=f"Secret credentials detected in '{repo_name}' commit history:\n{res.stdout.strip()[:200]}",
                                stage=stage_id,
                                severity="CRITICAL",
                                blocking=True,
                                repo=repo_name,
                            )
                        )
                    elif res.returncode != 0:
                        if strict_scanners:
                            defects.append(
                                Defect(
                                    defect_id="secrets.scanner_execution_failed",
                                    message=f"Gitleaks scan failed with exit code {res.returncode} for repo '{repo_name}'.",
                                    stage=stage_id,
                                    severity="CRITICAL",
                                    blocking=True,
                                    repo=repo_name,
                                )
                            )
                except (FileNotFoundError, PermissionError, OSError) as e:
                    if strict_scanners:
                        defects.append(
                            Defect(
                                defect_id="secrets.scanner_execution_error",
                                message=f"Failed to execute Gitleaks scan on '{repo_name}': {e}",
                                stage=stage_id,
                                severity="CRITICAL",
                                blocking=True,
                                repo=repo_name,
                            )
                        )
                    else:
                        defects.append(
                            Defect(
                                defect_id="secrets.scanner_skipped",
                                message=f"Gitleaks execution error on '{repo_name}': {e}; secret scanning skipped.",
                                stage=stage_id,
                                severity="HIGH",
                                blocking=False,
                                repo=repo_name,
                            )
                        )

    status = "FAIL" if any(d.blocking for d in defects) else "CLEAR"
    return StageResult(stage_id=stage_id, status=status, defects=defects, errors=errors)

