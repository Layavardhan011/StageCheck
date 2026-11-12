"""Stage 5: Authority Check, Review Approval Gate & Diff Fidelity (P4-T2)."""

from __future__ import annotations

from pathlib import Path
from stagecheck.checks.base import AuditContext, Defect, StageResult
from stagecheck.core.cooperative_review import (
    CommitDivergenceError,
    CommitUnauthorizedError,
    ReviewGateError,
    assert_commit_authorization,
    resolve_governed_repo_path,
    verify_committed_diff_fidelity,
)
from stagecheck.core.git import (
    GitError,
    approved_remote,
    get_approved_remote_urls,
    get_repo_remote_push_urls,
)


def run_stage5_authority(ctx: AuditContext) -> StageResult:
    """Execute Stage 5 Authority Verification."""
    stage_id = "authority"
    defects = []
    errors = []

    # 1. Assert Phase 2A Review Approval Gate
    approved_review = None
    try:
        approved_review = assert_commit_authorization(ctx.workspace_root, ctx.task_id, ctx.attempt)
    except CommitUnauthorizedError as err:
        defects.append(
            Defect(
                defect_id="authority.unapproved_commit",
                message=str(err),
                stage=stage_id,
                severity="CRITICAL",
                blocking=True,
            )
        )

    # 2. Verify Committed Diff Fidelity against Approved Review Snapshot (SEC-E1 & GAP-I2)
    if approved_review and (ctx.touched_repos or ctx.target_commits):
        approved_diff_hashes = approved_review.get("approved_diff_hashes", {})

        try:
            verify_committed_diff_fidelity(
                workspace_root=ctx.workspace_root,
                touched_repos=ctx.touched_repos,
                base_commits=ctx.base_commits,
                approved_diff_hashes=approved_diff_hashes,
                target_commits=ctx.target_commits,
            )
        except CommitDivergenceError as err:
            defects.append(
                Defect(
                    defect_id="authority.unreviewed_commit_divergence",
                    message=str(err),
                    stage=stage_id,
                    severity="CRITICAL",
                    blocking=True,
                )
            )

    # 3. Verify Remote Push URL Authority (FP-ORG / SR-08) across all registered & touched repos
    approved_urls = get_approved_remote_urls(ctx.workspace_root)
    repos_to_audit = sorted(set(ctx.all_registered_repos) | set(ctx.touched_repos))
    for repo_name in repos_to_audit:
        try:
            repo_p = resolve_governed_repo_path(Path(ctx.workspace_root), repo_name)
        except ReviewGateError as err:
            defects.append(
                Defect(
                    defect_id="authority.invalid_repository",
                    message=str(err),
                    stage=stage_id,
                    severity="CRITICAL",
                    blocking=True,
                )
            )
            continue
        if (repo_p / ".git").exists():
            try:
                push_urls = get_repo_remote_push_urls(repo_p)
            except GitError as err:
                defects.append(
                    Defect(
                        defect_id="authority.remote_inspection_failed",
                        message=str(err),
                        stage=stage_id,
                        severity="CRITICAL",
                        blocking=True,
                    )
                )
                continue
            for u in push_urls:
                if not approved_remote(u, approved_urls):
                    defects.append(
                        Defect(
                            defect_id="authority.remote",
                            message=f"Unauthorized or blacklisted remote push URL '{u}' in repo '{repo_name}'.",
                            stage=stage_id,
                            severity="CRITICAL",
                            blocking=True,
                        )
                    )

    status = "FAIL" if any(d.blocking for d in defects) else "CLEAR"
    return StageResult(stage_id=stage_id, status=status, defects=defects, errors=errors)

