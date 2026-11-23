"""Stage 2: Scope Paths, Multi-Repo Invariants & Symlink Security (P4-T2).

Ensures that all committed changes and working tree modifications strictly conform
to declared_scope.json, verifies multi-repo branch governance, and audits for
escaping symlink traversal attacks (SEC-D1).
"""

from __future__ import annotations

import os
import re
import stat
import subprocess
from pathlib import Path
from typing import Any, Dict, List

from stagecheck.checks.base import AuditContext, Defect, StageResult
from stagecheck.core.branch_governance import (
    BranchGovernanceError,
    verify_multi_repo_governance,
)
from stagecheck.core.git import parse_git_porcelain_z, run_safe_git, split_git_nul_paths
from stagecheck.core.paths import is_path_contained, safe_resolve
from stagecheck.core.prompt_gate import is_path_in_scope


def _resolve_repo_for_stage2(workspace_root: Path, repo_name: str) -> Path:
    if repo_name == "root":
        return workspace_root
    return workspace_root / "repos" / repo_name


def run_stage2_scope_paths(ctx: AuditContext) -> StageResult:
    """Execute Stage 2 Scope Paths Verification."""
    stage_id = "scope_paths"
    defects: List[Defect] = []
    errors: List[str] = []

    repos_root = ctx.workspace_root / "repos"
    if repos_root.is_symlink():
        defects.append(
            Defect(
                defect_id="scope_paths.unauthorized_symlink",
                message="Workspace 'repos' directory is a symbolic link.",
                stage=stage_id,
                severity="CRITICAL",
                blocking=True,
            )
        )
        return StageResult(stage_id=stage_id, status="FAIL", defects=defects, errors=errors)

    for repo_name in ctx.touched_repos:
        repo_path = _resolve_repo_for_stage2(ctx.workspace_root, repo_name)
        if repo_path.is_symlink():
            defects.append(
                Defect(
                    defect_id="scope_paths.unauthorized_symlink",
                    message=f"Repository root '{repo_path}' is a symbolic link.",
                    stage=stage_id,
                    severity="CRITICAL",
                    blocking=True,
                    repo=repo_name,
                )
            )
            return StageResult(stage_id=stage_id, status="FAIL", defects=defects, errors=errors)

    # 1. Multi-Repo Branch and Untouched Invariants Audit
    try:
        verify_multi_repo_governance(
            workspace_root=ctx.workspace_root,
            task_id=ctx.task_id,
            attempt=ctx.attempt,
            touched_repos=ctx.touched_repos,
            all_registered_repos=ctx.all_registered_repos,
            base_commits=ctx.base_commits,
        )
    except BranchGovernanceError as err:
        defects.append(
            Defect(
                defect_id="scope_paths.branch_or_untouched_violation",
                message=str(err),
                stage=stage_id,
                severity="CRITICAL",
                blocking=True,
            )
        )

    # 2. Scope Containment Check against declared_scope
    if ctx.declared_scope:
        for repo_name in ctx.touched_repos:
            repo_path = _resolve_repo_for_stage2(ctx.workspace_root, repo_name)
            if not repo_path.is_dir():
                defects.append(
                    Defect(
                        defect_id="scope_paths.missing_repository",
                        message=f"Repository directory missing for '{repo_name}': '{repo_path}'.",
                        stage=stage_id,
                        severity="CRITICAL",
                        blocking=True,
                        repo=repo_name,
                    )
                )
                continue

            base_commit = ctx.base_commits.get(repo_name)
            target_commit = ctx.target_commits.get(repo_name, "HEAD")

            changed_files = set()

            # A. Check committed changes
            if base_commit and (repo_path / ".git").exists():
                if not re.fullmatch(r"[0-9a-fA-F]{40,64}", str(base_commit)) or not re.fullmatch(r"[0-9a-fA-F]{40,64}|HEAD(?:[~^][0-9]*)*", str(target_commit)):
                    defects.append(
                        Defect(
                            defect_id="scope_paths.invalid_revision",
                            message=f"Invalid git revision reference for '{repo_name}'.",
                            stage=stage_id,
                            severity="CRITICAL",
                            blocking=True,
                            repo=repo_name,
                        )
                    )
                    continue
                res = run_safe_git(
                    repo_path,
                    ["diff", "--name-only", "-z", "--end-of-options", f"{base_commit}..{target_commit}", "--"],
                )
                if res.returncode != 0:
                    defects.append(
                        Defect(
                            defect_id="scope_paths.git_diff_failed",
                            message=f"Git diff failed in '{repo_name}': {res.stderr.strip() or f'exit {res.returncode}'}",
                            stage=stage_id,
                            severity="CRITICAL",
                            blocking=True,
                            repo=repo_name,
                        )
                    )
                else:
                    changed_files.update(split_git_nul_paths(res.stdout))

            # B. Check working-tree uncommitted changes and untracked files
            if (repo_path / ".git").exists():
                status_res = run_safe_git(repo_path, ["status", "--porcelain=v1", "-z", "--untracked-files=all"])
                if status_res.returncode != 0:
                    defects.append(
                        Defect(
                            defect_id="scope_paths.git_status_failed",
                            message=f"Git status failed in '{repo_name}': {status_res.stderr.strip() or f'exit {status_res.returncode}'}",
                            stage=stage_id,
                            severity="CRITICAL",
                            blocking=True,
                            repo=repo_name,
                        )
                    )
                else:
                    changed_files.update(parse_git_porcelain_z(status_res.stdout, include_rename_sources=True))

            for changed in changed_files:
                full_rel = f"repos/{repo_name}/{changed}" if repo_name != "root" else changed
                if not is_path_in_scope(full_rel, ctx.declared_scope):
                    defects.append(
                        Defect(
                            defect_id="scope_paths.out_of_scope_modification",
                            message=f"File '{full_rel}' in '{repo_name}' is outside declared_scope.json.",
                            stage=stage_id,
                            severity="CRITICAL",
                            blocking=True,
                            repo=repo_name,
                            citation={"path": full_rel},
                        )
                    )

    # 3. No-Follow Symlink Traversal Audit (SEC-D1)
    for repo_name in ctx.touched_repos:
        repo_path = _resolve_repo_for_stage2(ctx.workspace_root, repo_name)
        if repo_path.is_symlink():
            continue
        if repo_path.is_dir():
            for root, dirs, files in os.walk(str(repo_path)):
                for name in dirs + files:
                    full_p = Path(root) / name
                    st = os.lstat(str(full_p))
                    if stat.S_ISLNK(st.st_mode):
                        try:
                            target = full_p.resolve()
                        except (OSError, RuntimeError) as err:
                            defects.append(
                                Defect(
                                    defect_id="scope_paths.unauthorized_symlink",
                                    message=f"Unresolvable or circular symlink '{full_p.relative_to(ctx.workspace_root)}': {err}",
                                    stage=stage_id,
                                    severity="CRITICAL",
                                    blocking=True,
                                    repo=repo_name,
                                    citation={"path": str(full_p.relative_to(ctx.workspace_root))},
                                )
                            )
                            continue
                        if not is_path_contained(target, repo_path):
                            defects.append(
                                Defect(
                                    defect_id="scope_paths.unauthorized_symlink",
                                    message=f"Symlink '{full_p.relative_to(ctx.workspace_root)}' escapes repository boundary.",
                                    stage=stage_id,
                                    severity="CRITICAL",
                                    blocking=True,
                                    repo=repo_name,
                                    citation={"path": str(full_p.relative_to(ctx.workspace_root))},
                                )
                            )

    status = "FAIL" if any(d.blocking for d in defects) else "CLEAR"
    return StageResult(stage_id=stage_id, status=status, defects=defects, errors=errors)
