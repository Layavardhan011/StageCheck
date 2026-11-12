"""Stage 1: Preflight Invariants, Prompt Invariance, and Toolchain Checks (P4-T2)."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

from stagecheck.checks.base import AuditContext, Defect, StageResult
from stagecheck.core.agents_md import verify_agents_contract
from stagecheck.core.prompt_gate import PromptGateError, assert_prompt_invariance
from stagecheck.core.start_manifest import verify_spec_manifest

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

    # 2. Assert AGENTS.md contract existence and cryptographic binding
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
    else:
        agents_res = verify_agents_contract(ctx.workspace_root)
        if not agents_res.get("valid", False):
            mismatches = [m["control"] for m in agents_res.get("mismatches", [])]
            missing_ctrls = agents_res.get("missing", [])
            detail = []
            if mismatches:
                detail.append(f"hash mismatches: {mismatches}")
            if missing_ctrls:
                detail.append(f"missing controls: {missing_ctrls}")
            defects.append(
                Defect(
                    defect_id="preflight.binding_mismatch",
                    message=f"Root AGENTS.md binding verification failed ({'; '.join(detail)}).",
                    stage=stage_id,
                    severity="CRITICAL",
                    blocking=True,
                )
            )

    # 3. Assert Specification Manifest Baseline Invariants (FR-08 / Spec 05 / DEC-008)
    specs_dir = ctx.workspace_root / "specs"
    if specs_dir.is_dir():
        try:
            spec_res = verify_spec_manifest(ctx.workspace_root)
        except Exception as err:
            defects.append(
                Defect(
                    defect_id="preflight.spec_manifest_tampered",
                    message=f"Specification manifest security/verification error: {err}",
                    stage=stage_id,
                    severity="CRITICAL",
                    blocking=True,
                )
            )
            spec_res = {"valid": True}
        if not spec_res.get("valid", False):
            if "START_MANIFEST.md" in spec_res.get("missing", []):
                defects.append(
                    Defect(
                        defect_id="preflight.spec_manifest_missing",
                        message="specs/START_MANIFEST.md baseline manifest is missing.",
                        stage=stage_id,
                        severity="CRITICAL",
                        blocking=True,
                    )
                )
            else:
                tampered = [t["file"] for t in spec_res.get("tampered", [])]
                missing_specs = spec_res.get("missing", [])
                unregistered = spec_res.get("unregistered", [])
                parts = []
                if tampered:
                    parts.append(f"tampered: {tampered}")
                if missing_specs:
                    parts.append(f"missing: {missing_specs}")
                if unregistered:
                    parts.append(f"unregistered additions: {unregistered}")
                defects.append(
                    Defect(
                        defect_id="preflight.spec_manifest_tampered",
                        message=f"Specification baseline manifest integrity violation ({'; '.join(parts)}).",
                        stage=stage_id,
                        severity="CRITICAL",
                        blocking=True,
                    )
                )

    # 4. Check for unresolved placeholders in touched repositories (reject symlinks & >20 MiB reads)
    max_preflight_bytes = 20 * 1024 * 1024
    for repo_name in ctx.touched_repos:
        repo_dir = ctx.workspace_root / "repos" / repo_name
        if repo_dir.is_dir() and not repo_dir.is_symlink():
            for p in repo_dir.rglob("*"):
                if p.is_symlink() or not p.is_file() or any(part.startswith(".") for part in p.relative_to(repo_dir).parts):
                    continue
                try:
                    from stagecheck.core.paths import read_bytes_nofollow
                    text = read_bytes_nofollow(p, max_bytes=max_preflight_bytes).decode("utf-8", errors="ignore")
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

    # 5. Gitleaks Binary & Version Check (SEC-L2) - Fail Closed
    from stagecheck.core.scanner import SecretScanner
    scanner = getattr(ctx, "scanner", None) or SecretScanner()
    is_valid, scanner_defects = scanner.verify_scanner_binary(stage=stage_id)
    if not is_valid:
        defects.extend(scanner_defects)

    status = "FAIL" if any(d.blocking for d in defects) else "CLEAR"
    return StageResult(stage_id=stage_id, status=status, defects=defects, errors=errors)

