"""Stage 2: Scope Paths, Multi-Repo Invariants & Symlink Security (P4-T2).

Ensures that all committed changes and working tree modifications strictly conform
to declared_scope.json, verifies multi-repo branch governance, and audits for
escaping symlink traversal attacks (SEC-D1).
"""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path
from typing import Any, Dict, List

from stagecheck.checks.base import AuditContext, Defect, StageResult
from stagecheck.core.branch_governance import (
    BranchGovernanceError,
    verify_multi_repo_governance,
)
from stagecheck.core.paths import is_path_contained
from stagecheck.core.prompt_gate import is_path_in_scope


def run_stage2_scope_paths(ctx: AuditContext) -> StageResult:
    """Execute Stage 2 Scope Paths Verification."""
    stage_id = "scope_paths"
    defects: List[Defect] = []
    errors: List[str] = []

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
            repo_path = ctx.workspace_root / "repos" / repo_name
            if not repo_path.exists() and repo_name == "app":
                repo_path = ctx.workspace_root / "repos" / "app"
            if not repo_path.exists():
                repo_path = ctx.workspace_root

            base_commit = ctx.base_commits.get(repo_name)
            target_commit = ctx.target_commits.get(repo_name, "HEAD")

            changed_files = set()

            # A. Check committed changes
            if base_commit and (repo_path / ".git").exists():
                cmd = ["git", "-C", str(repo_path), "diff", "--name-only", f"{base_commit}..{target_commit}"]
                res = subprocess.run(cmd, capture_output=True, text=True, check=False)
                if res.returncode == 0:
                    for f in res.stdout.splitlines():
                        if f.strip():
                            changed_files.add(f.strip())

            # B. Check working-tree uncommitted changes and untracked files
            if (repo_path / ".git").exists():
                status_cmd = ["git", "-C", str(repo_path), "status", "--porcelain=v1", "--untracked-files=all"]
                status_res = subprocess.run(status_cmd, capture_output=True, text=True, check=False)
                if status_res.returncode == 0:
                    for line in status_res.stdout.splitlines():
                        if line.strip():
                            raw_path = line[3:].strip()
                            if " -> " in raw_path:
                                raw_path = raw_path.split(" -> ")[1].strip()
                            changed_files.add(raw_path)

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
        repo_path = ctx.workspace_root / "repos" / repo_name
        if not repo_path.exists():
            repo_path = ctx.workspace_root
        if repo_path.is_dir():
            for root, dirs, files in os.walk(str(repo_path)):
                for name in dirs + files:
                    full_p = Path(root) / name
                    st = os.lstat(str(full_p))
                    if stat.S_ISLNK(st.st_mode):
                        target = full_p.resolve()
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
