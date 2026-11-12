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
import re
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from stagecheck.core.agents import resolve_task_attempt_dir
from stagecheck.core.git import SAFE_GIT_SECURITY_FLAGS, run_safe_git, run_safe_git_bytes, split_git_nul_paths
from stagecheck.core.paths import StageCheckPathError, resolve_task_dir, safe_resolve
from stagecheck.core.utils import canonical_json_dumps, load_json_file, pretty_json_dumps, sha256_digest, validate_schema
from stagecheck.schemas import get_schema_path

_REPO_NAME_RE = re.compile(r"\A[a-zA-Z0-9._-]+\Z")
_COMMIT_SHA_RE = re.compile(r"\A[0-9a-fA-F]{40,64}\Z")


def validate_commit_sha(commit_sha: Any, repo_name: str) -> str:
    """Validate that a commit SHA is a strict 40-64 char hex digest (never a CLI flag)."""
    if not isinstance(commit_sha, str) or not _COMMIT_SHA_RE.match(commit_sha):
        raise ReviewGateError(f"Invalid commit SHA '{commit_sha}' for repository '{repo_name}'.")
    return commit_sha


def resolve_governed_repo_path(root: Path, repo_name: str) -> Path:
    """Resolve repository path safely against workspace repos/ and PRODUCT_REPOSITORIES.json."""
    if not isinstance(repo_name, str) or not _REPO_NAME_RE.match(repo_name) or repo_name in (".", ".."):
        raise ReviewGateError(f"Invalid repository name '{repo_name}'.")

    prod_repos_file = root / "controls" / "PRODUCT_REPOSITORIES.json"
    if prod_repos_file.is_file():
        try:
            p_data = json.loads(prod_repos_file.read_text(encoding="utf-8"))
        except Exception as err:
            raise ReviewGateError(f"Malformed PRODUCT_REPOSITORIES.json: {err}") from err
        registered = p_data.get("repositories")
        if not isinstance(registered, dict):
            raise ReviewGateError("PRODUCT_REPOSITORIES.json missing valid 'repositories' object.")
        if registered:
            if repo_name not in registered:
                raise ReviewGateError(f"Unregistered repository '{repo_name}' in PRODUCT_REPOSITORIES.json.")
            custom_rel = registered[repo_name].get("path")
            if custom_rel:
                try:
                    return safe_resolve(custom_rel, root)
                except StageCheckPathError as err:
                    raise ReviewGateError(f"Repository '{repo_name}' path escapes workspace: {err}") from err

    try:
        repos_dir = safe_resolve("repos", root)
        return safe_resolve(repo_name, repos_dir)
    except StageCheckPathError as err:
        raise ReviewGateError(f"Repository '{repo_name}' path escapes workspace repos/: {err}") from err


class ReviewGateError(Exception):
    """Base error for cooperative review handshake failures."""


class CommitUnauthorizedError(ReviewGateError):
    """Raised when an agent attempts to commit before receiving APPROVED review status."""


class CommitDivergenceError(ReviewGateError):
    """Raised when committed changes diverge from the approved uncommitted review diff."""


class ExcessiveDiffSizeError(ReviewGateError):
    """Raised when uncommitted diff stream exceeds the 20 MiB safety ceiling."""


class UntrackedBytesExceededError(ReviewGateError):
    """Raised when untracked non-ignored file volume exceeds 20 MiB ceiling (ARCH-03)."""


class UntrackedCountExceededError(ReviewGateError):
    """Raised when untracked non-ignored file count exceeds 500 file limit (ARCH-03)."""


class GitIndexLockedError(ReviewGateError):
    """Raised when git index lock (.git/index.lock) is detected in repository."""


class ScopeViolationError(ReviewGateError):
    """Raised when working tree changes modify files outside declared scope."""


MAX_DIFF_BYTES = 20 * 1024 * 1024        # 20 MiB (SEC-AC1)
MAX_UNTRACKED_BYTES = 20 * 1024 * 1024   # 20 MiB (ARCH-03 / FR-09)
MAX_UNTRACKED_COUNT = 500                # 500 files (ARCH-03 / FR-09)
MAX_REPAIR_CYCLES = 3                    # Maximum Phase 2A cooperative review repair cycles

# 8-Category Finding Classification Taxonomy (Spec 04 §4.2)
FINDING_CATEGORIES = {
    "NEWLY_INTRODUCED": "Newly Introduced Issue",
    "PRE_EXISTING_UPSTREAM": "Pre-existing Upstream Issue",
    "PRE_EXISTING_REPO": "Pre-existing Repository Issue",
    "INHERITED_DESIGN": "Inherited Design Constraint",
    "INTEGRATION_ISSUE": "Integration Issue",
    "CONFIG_ENVIRONMENT": "Configuration or Environment Issue",
    "FALSE_POSITIVE": "False Positive",
    "UNVERIFIED_FINDING": "Unverified Finding",
}


def inspect_untracked_files(repo_path: Path) -> Tuple[List[str], int, int]:
    """Inspect untracked non-ignored files in a repository and enforce 20 MiB / 500 file limits.

    Returns:
        (untracked_files_list, count, total_bytes)

    Raises:
        GitIndexLockedError: If .git/index.lock is present.
        UntrackedCountExceededError: If file count > 500.
        UntrackedBytesExceededError: If file volume > 20 MiB.
    """
    index_lock = repo_path / ".git" / "index.lock"
    if index_lock.is_file():
        raise GitIndexLockedError(
            f"Git index lock detected in repository '{repo_path.name}': {index_lock}. "
            "Wait for active git operation to finish or resolve stale lock."
        )

    res = run_safe_git(
        repo_path,
        ["ls-files", "--others", "--exclude-standard", "-z"],
        check=True,
    )
    untracked = split_git_nul_paths(res.stdout)

    if len(untracked) > MAX_UNTRACKED_COUNT:
        raise UntrackedCountExceededError(
            f"Untracked non-ignored file count ({len(untracked)}) exceeds maximum allowed ceiling of 500 files in repository '{repo_path.name}'."
        )

    total_bytes = 0
    for rel_f in untracked:
        target_f = repo_path / rel_f
        if target_f.is_file():
            total_bytes += target_f.stat().st_size
            if total_bytes > MAX_UNTRACKED_BYTES:
                raise UntrackedBytesExceededError(
                    f"Untracked non-ignored file volume ({total_bytes} bytes) exceeds 20 MiB ceiling in repository '{repo_path.name}'."
                )

    return sorted(untracked), len(untracked), total_bytes


def verify_precommit_scope(
    workspace_root: Union[str, Path],
    task_id: str,
    attempt: int,
    touched_repos: List[str],
    base_commits: Dict[str, str],
) -> List[str]:
    """Verify that all uncommitted and modified working tree files match declared_scope.json."""
    from stagecheck.core.prompt_gate import is_path_in_scope

    root = Path(workspace_root).resolve()
    attempt_dir = resolve_task_attempt_dir(root, task_id, attempt)
    scope_file = attempt_dir / "Phase-1" / "declared_scope.json"

    if not scope_file.is_file():
        return ["Missing Phase-1/declared_scope.json: declared scope required for pre-commit review."]

    try:
        scope_data = json.loads(scope_file.read_text(encoding="utf-8"))
    except Exception as err:
        return [f"Failed to load declared_scope.json: {err}"]

    allowed_paths = scope_data.get("allowed_paths", [])
    # Check for illegal top-level wildcards
    if any(p in ("*", "/**", "**") for p in allowed_paths):
        return ["Prohibited top-level wildcard ('*', '**') declared in declared_scope.json allowed_paths."]

    violations: List[str] = []

    if not touched_repos:
        return ["Missing touched_repositories: at least one repository must be evaluated in pre-commit review."]

    for repo_name in touched_repos:
        try:
            repo_path = resolve_governed_repo_path(root, repo_name)
        except ReviewGateError as err:
            violations.append(str(err))
            continue

        if not repo_path.is_dir():
            violations.append(f"Repository directory missing for '{repo_name}': '{repo_path}'.")
            continue

        base_commit = (base_commits or {}).get(repo_name)
        if not base_commit:
            violations.append(f"Missing required base_commit for repository '{repo_name}'.")
            continue
        try:
            validate_commit_sha(base_commit, repo_name)
        except ReviewGateError as err:
            violations.append(str(err))
            continue

        modified_files: Set[str] = set()

        res_tracked = run_safe_git(repo_path, ["diff", "--name-only", "-z", "--end-of-options", base_commit, "--"])
        if res_tracked.returncode != 0:
            violations.append(f"Failed git diff in '{repo_name}' against base '{base_commit}': {res_tracked.stderr.strip()}")
            continue
        modified_files.update(split_git_nul_paths(res_tracked.stdout))

        res_staged = run_safe_git(repo_path, ["diff", "--cached", "--name-only", "-z", "--end-of-options"])
        if res_staged.returncode != 0:
            violations.append(f"Failed git diff --cached in '{repo_name}': {res_staged.stderr.strip()}")
            continue
        modified_files.update(split_git_nul_paths(res_staged.stdout))

        res_untracked = run_safe_git(repo_path, ["ls-files", "--others", "--exclude-standard", "-z"])
        if res_untracked.returncode != 0:
            violations.append(f"Failed git ls-files in '{repo_name}': {res_untracked.stderr.strip()}")
            continue
        modified_files.update(split_git_nul_paths(res_untracked.stdout))

        for rel_file in sorted(modified_files):
            ws_rel = f"repos/{repo_name}/{rel_file}"
            if not is_path_in_scope(ws_rel, scope_data):
                violations.append(f"Out-of-scope modification: '{ws_rel}' is not permitted by declared scope.")

    return violations


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
    repo_untracked_hashes: Dict[str, str] = {}
    total_diff_bytes = 0

    from stagecheck.core.utils import sha256_file

    for repo_name in sorted(touched_repos):
        repo_path = resolve_governed_repo_path(root, repo_name)

        base_commit = validate_commit_sha(base_commits.get(repo_name), repo_name)

        # Inspect untracked non-ignored files & enforce limits (ARCH-03 / FR-09)
        untracked_files, u_count, u_bytes = inspect_untracked_files(repo_path)
        untracked_lines: List[str] = []
        for rel_f in untracked_files:
            f_p = repo_path / rel_f
            if f_p.is_file():
                untracked_lines.append(f"{rel_f}:{sha256_file(f_p)}")
        repo_untracked_hashes[repo_name] = (
            sha256_digest("\n".join(untracked_lines).encode("utf-8")) if untracked_lines else "0" * 64
        )

        res = run_safe_git_bytes(
            repo_path,
            ["diff", "--binary", "--end-of-options", base_commit, "--"],
            check=True,
        )
        diff_bytes = res.stdout

        total_diff_bytes += len(diff_bytes)
        if total_diff_bytes > MAX_DIFF_BYTES:
            raise ExcessiveDiffSizeError(
                f"Uncommitted diff size exceeds 20 MiB safety limit ({total_diff_bytes} bytes). "
                "Clean untracked artifacts before review."
            )

        approved_diff_hashes[repo_name] = sha256_digest(diff_bytes)

    # Compute composite digest: SHA-256(Tracked Git Diff || Untracked Non-Ignored Files Matrix)
    composite_raw = "|".join(
        f"{r}:diff={approved_diff_hashes[r]}:untracked={repo_untracked_hashes[r]}"
        for r in sorted(approved_diff_hashes.keys())
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
    status_file.write_text(pretty_json_dumps(status_data), encoding="utf-8")
    return status_file


def append_to_cumulative_issue_history(
    workspace_root: Path,
    task_id: str,
    attempt: int,
    cycle: int,
    new_issues: List[Dict[str, Any]],
) -> None:
    """Append newly discovered defects to cumulative TASK_<ID>_ISSUE_HISTORY.md."""
    task_dir = resolve_task_dir(workspace_root, task_id)
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
        if not touched_repos:
            raise ReviewGateError("Review cannot be APPROVED with empty base_commits.")
        # 1. Enforce staged secret scanning gate before commit authorization (Spec 08, Spec 14, SEC-M1)
        from stagecheck.core.scanner import SecretScanner
        scanner = SecretScanner()
        for repo_name in touched_repos:
            repo_path = resolve_governed_repo_path(root, repo_name)
            if repo_path.is_dir():
                staged_res = scanner.scan_staged_changes(
                    repo_dir=repo_path,
                    repo_name=repo_name,
                    workspace_root=root,
                )
                if not staged_res.is_clear:
                    error_msg = "; ".join(d.message for d in staged_res.defects)
                    raise ReviewGateError(
                        f"Pre-commit staged secret scan failed for repo '{repo_name}': {error_msg}. "
                        "Commits cannot be authorized when secret scanning fails or leaks are detected."
                    )

        # 2. Compute approved diff hashes
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

    existing_review_file = phase2a_dir / "pre_commit_review.json"
    if existing_review_file.is_file():
        try:
            existing_rev = json.loads(existing_review_file.read_text(encoding="utf-8"))
            if isinstance(existing_rev, dict) and isinstance(existing_rev.get("agent_assisted_reviews"), dict):
                review_data["agent_assisted_reviews"] = existing_rev["agent_assisted_reviews"]
        except Exception:
            pass

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
    response_file.write_text(pretty_json_dumps(response_content), encoding="utf-8")

    # 2. Append to cumulative issue history if new defects found
    if new_issues:
        append_to_cumulative_issue_history(root, task_id, attempt, cycle, new_issues)

    # 3. Write pre_commit_review.json
    review_file = phase2a_dir / "pre_commit_review.json"
    review_file.write_text(pretty_json_dumps(review_data), encoding="utf-8")
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
        data = load_json_file(review_file)
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
        try:
            repo_path = resolve_governed_repo_path(root, repo_name)
        except ReviewGateError as err:
            raise CommitDivergenceError(str(err)) from err

        base_commit = base_commits.get(repo_name)
        target_commit = target_commits.get(repo_name)
        approved_hash = approved_diff_hashes.get(repo_name)

        if not base_commit or not target_commit or not approved_hash:
            raise CommitDivergenceError(
                f"Missing baseline, target, or approved diff hash for repository '{repo_name}'."
            )

        try:
            validate_commit_sha(base_commit, repo_name)
            validate_commit_sha(target_commit, repo_name)
        except ReviewGateError as err:
            raise CommitDivergenceError(str(err)) from err

        res = run_safe_git_bytes(
            repo_path,
            ["diff", "--binary", "--end-of-options", f"{base_commit}..{target_commit}", "--"],
            check=True,
        )
        committed_diff_hash = sha256_digest(res.stdout)

        if committed_diff_hash != approved_hash:
            raise CommitDivergenceError(
                f"Defect [stage5:authority:unreviewed_commit_divergence]: Committed changes in "
                f"'{repo_name}' ({committed_diff_hash[:12]}) differ from uncommitted diff "
                f"approved in Phase 2A ({approved_hash[:12]})."
            )

