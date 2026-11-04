"""Phase 2A Pre-Commit Cooperative Review Handshake & Differential Audit (P3-T5).

Coordinates working-tree review cycles between Agent 1 and Agent 2:
- Evaluates uncommitted diffs relative to captured base commits
- Categorizes findings (pre-existing debt, architectural intents, new issues, code quality)
- Binds approved diffs cryptographically (approved_snapshot_sha256)
- Appends new defects to cumulative TASK_<ID>_ISSUE_HISTORY.md
- Enforces strict review gate: local commits are blocked until status is APPROVED
- Review iterations do NOT consume formal task attempts
"""

from __future__ import annotations

import datetime
import json
import os
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from stagecheck.core.agents import resolve_task_attempt_dir
from stagecheck.core.utils import canonical_json_dumps, sha256_digest, validate_schema
from stagecheck.schemas import get_schema_path


class ReviewGateError(Exception):
    """Base error for cooperative review handshake failures."""


class CommitUnauthorizedError(ReviewGateError):
    """Raised when an agent attempts to commit before receiving APPROVED review status."""


class CommitDivergenceError(ReviewGateError):
    """Raised when committed changes diverge from the approved uncommitted review diff."""


class ExcessiveDiffSizeError(ReviewGateError):
    """Raised when uncommitted diff stream exceeds the 20 MiB safety ceiling."""


MAX_DIFF_BYTES = 20 * 1024 * 1024  # 20 MiB (SEC-AC1)


def compute_uncommitted_diff_hashes(
    workspace_root: Union[str, Path],
    touched_repos: List[str],
    base_commits: Dict[str, str],
) -> Tuple[Dict[str, str], str]:
    """Calculate deterministic SHA-256 digests of working tree diffs against base commits.

    Args:
        workspace_root: Root workspace path.
        touched_repos: List of modified repository directory names.
        base_commits: Mapping of repo_name -> base_commit_sha.

    Returns:
        Tuple of (approved_diff_hashes dict, composite approved_snapshot_sha256).

    Raises:
        ExcessiveDiffSizeError: If diff exceeds 20 MiB.
    """
    root = Path(workspace_root).resolve()
    repos_dir = root / "repos"

    approved_diff_hashes: Dict[str, str] = {}
    total_diff_bytes = 0

    for repo_name in sorted(touched_repos):
        repo_path = repos_dir / repo_name
        base_commit = base_commits.get(repo_name)
        if not base_commit:
            raise ReviewGateError(f"Missing required base_commit for repository '{repo_name}'.")

        cmd = [
            "git",
            "-C",
            str(repo_path),
            "diff",
            "--binary",
            "--no-ext-diff",
            "--no-textconv",
            base_commit,
        ]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        diff_bytes = res.stdout

        total_diff_bytes += len(diff_bytes)
        if total_diff_bytes > MAX_DIFF_BYTES:
            raise ExcessiveDiffSizeError(
                f"Uncommitted diff size exceeds 20 MiB safety limit ({total_diff_bytes} bytes). "
                "Clean untracked artifacts before review."
            )

        approved_diff_hashes[repo_name] = sha256_digest(diff_bytes)

    # Compute composite digest
    composite_raw = "|".join(
        f"{r}:{approved_diff_hashes[r]}" for r in sorted(approved_diff_hashes.keys())
    ).encode("utf-8")
    composite_digest = sha256_digest(composite_raw)

    return approved_diff_hashes, composite_digest


def submit_pre_commit_status(
    workspace_root: Union[str, Path],
    task_id: str,
    attempt: int,
    cycle: int,
    touched_repositories: List[str],
    base_commits: Dict[str, str],
    summary: str = "Ready for pre-commit review",
) -> Path:
    """Agent 2 submission of pre_commit_status.json in working tree."""
    root = Path(workspace_root).resolve()
    attempt_dir = resolve_task_attempt_dir(root, task_id, attempt, ensure_exists=True)
    phase2a_dir = attempt_dir / "Phase-2A"
    phase2a_dir.mkdir(parents=True, exist_ok=True)

    status_data = {
        "schema_version": "2.0",
        "task_id": task_id,
        "attempt": attempt,
        "cycle": cycle,
        "status": "AWAITING_REVIEW",
        "touched_repositories": touched_repositories,
        "base_commits": base_commits,
        "summary": summary,
    }

    schema_path = get_schema_path("pre_commit_status.schema.json")
    with schema_path.open("r", encoding="utf-8") as f:
        schema = json.load(f)
    validate_schema(status_data, schema)

    status_file = phase2a_dir / "pre_commit_status.json"
    status_file.write_text(canonical_json_dumps(status_data) + "\n", encoding="utf-8")
    return status_file


def append_to_cumulative_issue_history(
    workspace_root: Path,
    task_id: str,
    attempt: int,
    cycle: int,
    new_issues: List[Dict[str, Any]],
) -> None:
    """Append newly discovered defects to cumulative TASK_<ID>_ISSUE_HISTORY.md."""
    task_dir = workspace_root / "evidence" / "tasks" / task_id
    task_dir.mkdir(parents=True, exist_ok=True)
    history_file = task_dir / f"{task_id.upper()}_ISSUE_HISTORY.md"

    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    lines = [f"\n### Attempt {attempt} - Cycle {cycle} Findings ({timestamp})\n"]
    for issue in new_issues:
        code = issue.get("defect_id", issue.get("code", "DEFECT"))
        desc = issue.get("description", issue.get("message", "Issue description"))
        lines.append(f"- **[{code}]**: {desc}\n")

    with history_file.open("a", encoding="utf-8") as f:
        f.writelines(lines)


def record_pre_commit_review(
    workspace_root: Union[str, Path],
    task_id: str,
    attempt: int,
    cycle: int,
    status: str,
    summary: str,
    base_commits: Dict[str, str],
    pre_existing_issues: Optional[List[Dict[str, Any]]] = None,
    architectural_intents: Optional[List[Dict[str, Any]]] = None,
    new_issues: Optional[List[Dict[str, Any]]] = None,
    code_quality_observations: Optional[List[Dict[str, Any]]] = None,
) -> Path:
    """Record Agent 1 Phase 2A review findings and decision.

    Args:
        workspace_root: Root workspace path.
        task_id: Task identifier.
        attempt: Attempt index.
        cycle: Review cycle number.
        status: 'APPROVED' or 'REVISION_REQUIRED'.
        summary: Review summary string.
        base_commits: Mapping of repo -> base commit SHA.
        pre_existing_issues: Debt items present at base commit.
        architectural_intents: Documented spec expansions.
        new_issues: Newly identified defects.
        code_quality_observations: Non-blocking quality feedback.

    Returns:
        Path to written pre_commit_review.json.
    """
    if status not in ("APPROVED", "REVISION_REQUIRED"):
        raise ReviewGateError(f"Invalid review status '{status}'. Must be APPROVED or REVISION_REQUIRED.")

    root = Path(workspace_root).resolve()
    attempt_dir = resolve_task_attempt_dir(root, task_id, attempt, ensure_exists=True)
    phase2a_dir = attempt_dir / "Phase-2A"
    phase2a_dir.mkdir(parents=True, exist_ok=True)

    pre_existing_issues = pre_existing_issues or []
    architectural_intents = architectural_intents or []
    new_issues = new_issues or []
    code_quality_observations = code_quality_observations or []

    # If new issues found, status must be REVISION_REQUIRED
    if new_issues and status == "APPROVED":
        raise ReviewGateError(
            "Review cannot be APPROVED when new_issues are present. Status must be REVISION_REQUIRED."
        )

    approved_diff_hashes: Dict[str, str] = {}
    approved_snapshot_sha256 = "0" * 64

    touched_repos = list(base_commits.keys())
    if status == "APPROVED":
        approved_diff_hashes, approved_snapshot_sha256 = compute_uncommitted_diff_hashes(
            workspace_root=root,
            touched_repos=touched_repos,
            base_commits=base_commits,
        )

    review_data: Dict[str, Any] = {
        "schema_version": "2.0",
        "task_id": task_id,
        "attempt": attempt,
        "cycle": cycle,
        "status": status,
        "summary": summary,
        "base_commits": base_commits,
        "approved_diff_hashes": approved_diff_hashes,
        "approved_snapshot_sha256": approved_snapshot_sha256,
        "approved_diff_sha256": approved_snapshot_sha256,
        "pre_existing_issues_ignored": pre_existing_issues,
        "architectural_intents_approved": architectural_intents,
        "new_issues_found": new_issues,
        "code_quality_observations": code_quality_observations,
    }

    # Validate against schema
    schema_path = get_schema_path("pre_commit_review.schema.json")
    with schema_path.open("r", encoding="utf-8") as f:
        schema = json.load(f)
    validate_schema(review_data, schema)

    # 1. Write response.json for Agent 2 feedback
    response_file = phase2a_dir / "response.json"
    response_content = {
        "task_id": task_id,
        "attempt": attempt,
        "cycle": cycle,
        "status": status,
        "feedback": summary,
        "remediation_required": [i.get("description", str(i)) for i in new_issues],
    }
    response_file.write_text(canonical_json_dumps(response_content) + "\n", encoding="utf-8")

    # 2. Append to cumulative issue history if new defects found
    if new_issues:
        append_to_cumulative_issue_history(root, task_id, attempt, cycle, new_issues)

    # 3. Write pre_commit_review.json
    review_file = phase2a_dir / "pre_commit_review.json"
    review_file.write_text(canonical_json_dumps(review_data) + "\n", encoding="utf-8")
    return review_file


def assert_commit_authorization(
    workspace_root: Union[str, Path],
    task_id: str,
    attempt: int,
) -> Dict[str, Any]:
    """Assert that Phase 2A review has been completed and holds status APPROVED.

    Enforces that local Git commits are blocked unless approved.

    Args:
        workspace_root: Root workspace path.
        task_id: Task identifier.
        attempt: Attempt index.

    Returns:
        Approved review data dictionary.

    Raises:
        CommitUnauthorizedError: If review is absent, corrupted, or status is REVISION_REQUIRED.
    """
    root = Path(workspace_root).resolve()
    attempt_dir = resolve_task_attempt_dir(root, task_id, attempt)
    review_file = attempt_dir / "Phase-2A" / "pre_commit_review.json"

    if not review_file.is_file():
        raise CommitUnauthorizedError(
            f"Commit unauthorized: No pre-commit review found for task '{task_id}', "
            f"attempt {attempt}. Phase 2A cooperative review must pass with APPROVED status."
        )

    try:
        data = json.loads(review_file.read_text(encoding="utf-8"))
    except Exception as err:
        raise CommitUnauthorizedError(f"Corrupted pre_commit_review.json: {err}") from err

    status = data.get("status")
    if status != "APPROVED":
        raise CommitUnauthorizedError(
            f"Commit blocked: Pre-commit review has status '{status}'. "
            f"Summary: {data.get('summary', 'Revisions required.')}"
        )

    return data


def verify_committed_diff_fidelity(
    workspace_root: Union[str, Path],
    touched_repos: List[str],
    base_commits: Dict[str, str],
    approved_diff_hashes: Dict[str, str],
    target_commits: Dict[str, str],
) -> None:
    """Verify that committed changes match the uncommitted diff approved in Phase 2A.

    Enforces SEC-E1 & GAP-I2 (Stage 5 authority check):
    Guarantees no modifications occurred between review approval and commit.

    Raises:
        CommitDivergenceError: If any repo commit diff diverges from approved diff hash.
    """
    root = Path(workspace_root).resolve()
    repos_dir = root / "repos"

    for repo_name in touched_repos:
        repo_path = repos_dir / repo_name
        base_commit = base_commits.get(repo_name)
        target_commit = target_commits.get(repo_name)
        approved_hash = approved_diff_hashes.get(repo_name)

        if not base_commit or not target_commit or not approved_hash:
            raise CommitDivergenceError(
                f"Missing baseline, target, or approved diff hash for repository '{repo_name}'."
            )

        cmd = [
            "git",
            "-C",
            str(repo_path),
            "diff",
            "--binary",
            "--no-ext-diff",
            "--no-textconv",
            f"{base_commit}..{target_commit}",
        ]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        committed_diff_hash = sha256_digest(res.stdout)

        if committed_diff_hash != approved_hash:
            raise CommitDivergenceError(
                f"Defect [stage5:authority:unreviewed_commit_divergence]: Committed changes in "
                f"'{repo_name}' ({committed_diff_hash[:12]}) differ from uncommitted diff "
                f"approved in Phase 2A ({approved_hash[:12]})."
            )

