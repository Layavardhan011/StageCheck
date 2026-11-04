"""Stage 8: Sandboxed Test Rerun and Differential Baseline Auditing (P4-T2).

Independently executes cited test commands under an isolated, minimal environment
allowlist, validates working tree immutability before and after execution (SEC-C1),
and differentiates between pre-existing baseline debt and newly introduced regressions
via ephemeral Git worktree differential comparison (GAP-C5, GAP-N1).
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from stagecheck.checks.base import AuditContext, Defect, StageResult
from stagecheck.core.commands import (
    CommandExecutionRecord,
    capture_git_status_porcelain,
    execute_secure_command,
)


def _extract_command_citations(claims_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract all command-type citations from claims object."""
    commands: List[Dict[str, Any]] = []
    claims_list = claims_data.get("claims", [])
    for claim in claims_list:
        for cit in claim.get("citations", []):
            if cit.get("type") == "command":
                commands.append(cit)
    return commands


def _test_at_base_commit(
    workspace_root: Path,
    repo_path: Path,
    base_commit: str,
    argv: List[str],
    task_id: str,
) -> Optional[int]:
    """Execute command at base_commit using an ephemeral Git worktree."""
    if not base_commit or base_commit.startswith("0" * 20):
        return None

    worktree_parent = workspace_root / ".stagecheck_worktrees"
    worktree_parent.mkdir(parents=True, exist_ok=True)
    repo_name = repo_path.name
    worktree_dir = worktree_parent / f"{repo_name}_base_{task_id}"

    try:
        # Create detached worktree
        add_res = subprocess.run(
            ["git", "-c", "core.hooksPath=/dev/null", "-C", str(repo_path), "worktree", "add", "--detach", str(worktree_dir), base_commit],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if add_res.returncode != 0:
            return None

        # Execute command in ephemeral worktree
        rec = execute_secure_command(
            argv=argv,
            working_directory=worktree_dir,
            timeout_seconds=120,
            check_tree_integrity=False,
        )
        return rec.exit_code
    except Exception:
        return None
    finally:
        if worktree_dir.exists():
            subprocess.run(
                ["git", "-c", "core.hooksPath=/dev/null", "-C", str(repo_path), "worktree", "remove", "--force", str(worktree_dir)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )


def run_stage8_rerun(ctx: AuditContext) -> StageResult:
    """Execute Stage 8 Sandboxed Test Rerun verification."""
    stage_id = "rerun"
    defects: List[Defect] = []
    errors: List[str] = []

    # 1. Extract command citations from claims
    command_citations = _extract_command_citations(ctx.claims)

    if not command_citations:
        # No test commands cited in claims; check if qualification tests exist to run
        return StageResult(stage_id=stage_id, status="CLEAR", defects=[], errors=[])

    # 2. Iterate and re-execute each cited command
    for cit in command_citations:
        argv = cit.get("argv", [])
        rel_cwd = cit.get("cwd", ".")
        expected_exit = cit.get("exit_status", 0)

        if not argv:
            continue

        work_dir = (ctx.workspace_root / rel_cwd).resolve()
        # Security: verify work_dir is within workspace_root
        if not work_dir.is_relative_to(ctx.workspace_root.resolve()):
            defects.append(
                Defect(
                    defect_id="rerun.working_directory_escaped",
                    message=f"Cited command working directory '{rel_cwd}' escapes workspace root",
                    stage=stage_id,
                    severity="CRITICAL",
                    blocking=True,
                )
            )
            continue

        try:
            # Execute command under clean environment and audit tree mutability
            record = execute_secure_command(
                argv=argv,
                working_directory=work_dir,
                timeout_seconds=300,
                check_tree_integrity=True,
            )
        except Exception as err:
            defects.append(
                Defect(
                    defect_id="rerun.execution_error",
                    message=f"Command execution failed to start: {err}",
                    stage=stage_id,
                    severity="CRITICAL",
                    blocking=True,
                    citation={"argv": argv, "cwd": rel_cwd},
                )
            )
            continue

        # Check working tree mutation (SEC-C1)
        if record.tree_mutated:
            defects.append(
                Defect(
                    defect_id="rerun.tree_dirty",
                    message=f"Test execution mutated repository working tree or created untracked artifacts for command: {' '.join(argv)}",
                    stage=stage_id,
                    severity="CRITICAL",
                    blocking=True,
                    citation={"argv": argv, "cwd": rel_cwd},
                )
            )

        # Check execution outcome
        if record.exit_code != expected_exit:
            # Check differential baseline
            matched_repo = None
            for repo_name in ctx.touched_repos:
                candidate = ctx.workspace_root / "repos" / repo_name
                if candidate.is_dir() and work_dir.is_relative_to(candidate.resolve()):
                    matched_repo = (repo_name, candidate)
                    break
            if not matched_repo and (ctx.workspace_root / ".git").is_dir():
                matched_repo = ("root", ctx.workspace_root)

            base_commit = ctx.base_commits.get(matched_repo[0]) if matched_repo else None
            base_exit = None
            if base_commit and matched_repo:
                base_exit = _test_at_base_commit(
                    ctx.workspace_root,
                    matched_repo[1],
                    base_commit,
                    argv,
                    ctx.task_id,
                )

            if base_exit is not None and base_exit == record.exit_code:
                # Pre-existing baseline debt (non-blocking)
                defects.append(
                    Defect(
                        defect_id="rerun.pre_existing_debt_ignored",
                        message=(
                            f"Command failed with exit code {record.exit_code}, but reproduced identical "
                            f"failure at base_commit {base_commit[:8]} (pre-existing debt)"
                        ),
                        stage=stage_id,
                        severity="INFO",
                        blocking=False,
                        citation={"argv": argv, "exit_code": record.exit_code},
                    )
                )
            else:
                # Newly introduced regression defect (blocking)
                defects.append(
                    Defect(
                        defect_id="rerun.regression_defect",
                        message=(
                            f"Command {' '.join(argv)} exited with code {record.exit_code} "
                            f"(expected {expected_exit})"
                        ),
                        stage=stage_id,
                        severity="CRITICAL",
                        blocking=True,
                        citation={"argv": argv, "exit_code": record.exit_code},
                    )
                )

    has_blocking = any(d.blocking for d in defects)
    return StageResult(
        stage_id=stage_id,
        status="FAIL" if has_blocking else "CLEAR",
        defects=defects,
        errors=errors,
    )

