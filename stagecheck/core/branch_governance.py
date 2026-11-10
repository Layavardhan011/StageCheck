"""Branch Governance, Multi-Repository Baseline Binding, and Untouched Verification (P3-T3).

Enforces protected default branch policies (prohibiting main/master commits),
validates task sprint branch naming patterns, binds per-repo base commits,
and audits untouched repository invariants.
"""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union

from stagecheck.core.agents import resolve_task_attempt_dir
from stagecheck.core.git import GitError, SAFE_GIT_SECURITY_FLAGS, discover_repository, run_safe_git
from stagecheck.core.utils import canonical_json_dumps, pretty_json_dumps, sha256_digest


class BranchGovernanceError(GitError):
    """Base error for branch governance and baseline binding violations."""


class ProtectedBranchPolicyError(BranchGovernanceError):
    """Raised when committing directly to main or master is attempted."""


class NonCompliantBranchError(BranchGovernanceError):
    """Raised when an active branch does not match allowed task/sprint branch patterns."""


class BaseCommitMismatchError(BranchGovernanceError):
    """Raised when a cited or expected base commit does not match baseline record."""


class DirtyWorkingTreeError(BranchGovernanceError):
    """Raised when a repository has uncommitted changes during verification."""


class UntouchedRepoViolationError(BranchGovernanceError):
    """Raised when an out-of-scope untouched repository is unexpectedly mutated."""


# Default pattern allows <project>/<sprint>, <project>/<task>, task-<id>, or feature branches
DEFAULT_PERMITTED_BRANCH_PATTERN = (
    r"^[a-zA-Z0-9._-]+/(task-[a-zA-Z0-9._-]+|sprint-[a-zA-Z0-9._-]+)$|"
    r"^task-[a-zA-Z0-9._-]+$|"
    r"^feature/[a-zA-Z0-9._-]+$"
)


def validate_branch_compliance(
    branch_name: str,
    permitted_pattern: Optional[str] = None,
    allow_development: bool = True,
) -> None:
    """Validate that branch conforms to StageCheck governance policies.

    Rules:
      - Direct commits to 'main' or 'master' are strictly forbidden.
      - 'Development' branch is allowed when allow_development is True.
      - Other branches must match permitted_pattern.

    Args:
        branch_name: Name of active branch.
        permitted_pattern: Optional regex for task branches.
        allow_development: Whether Development branch is allowed.

    Raises:
        ProtectedBranchPolicyError: If branch is main or master.
        NonCompliantBranchError: If branch fails naming pattern.
    """
    clean_branch = branch_name.strip()

    if clean_branch in ("main", "master"):
        raise ProtectedBranchPolicyError(
            f"Branch governance violation: Committing directly to protected branch '{clean_branch}' "
            "is strictly forbidden. AI agents must create a permitted sprint/task branch."
        )

    if allow_development and clean_branch == "Development":
        return

    pattern = permitted_pattern or DEFAULT_PERMITTED_BRANCH_PATTERN
    if not re.search(pattern, clean_branch):
        raise NonCompliantBranchError(
            f"Branch governance violation: Branch '{clean_branch}' does not conform to "
            f"permitted task branch pattern '{pattern}'."
        )


def _assert_safe_git_rev(rev: str, repo_name: str) -> None:
    if not isinstance(rev, str) or not rev or rev.startswith("-") or not re.fullmatch(r"[0-9a-fA-F]{4,64}|HEAD(?:[~^][0-9]*)*", rev):
        raise BranchGovernanceError(f"Invalid git revision '{rev}' for repository '{repo_name}'.")


def get_git_tree_sha(repo_path: Union[str, Path]) -> str:
    """Extract Git tree root SHA (HEAD^{tree}) for a repository."""
    res = run_safe_git(Path(repo_path), ["rev-parse", "HEAD^{tree}"])
    if res.returncode != 0:
        raise GitError(f"Failed to extract tree SHA for '{repo_path}': {res.stderr.strip()}")
    return res.stdout.strip()


def get_repo_diff(repo_path: Union[str, Path], base_commit: str) -> str:
    """Generate git diff relative to base_commit."""
    _assert_safe_git_rev(base_commit, Path(repo_path).name)
    res = run_safe_git(Path(repo_path), ["diff", "--binary", "--end-of-options", base_commit, "--"])
    if res.returncode != 0:
        raise GitError(f"Failed to generate diff for '{repo_path}': {res.stderr.strip()}")
    return res.stdout


def compute_diff_hash(diff_text: str) -> str:
    """Calculate deterministic SHA-256 digest of diff content."""
    return sha256_digest(diff_text.encode("utf-8"))


def capture_multi_repo_task_baseline(
    workspace_root: Union[str, Path],
    task_id: str,
    attempt: int,
    repo_names: List[str],
) -> Dict[str, Dict[str, Any]]:
    """Capture and record pre-task baseline state for all registered repositories.

    Saves state in evidence/tasks/<task_id>/attempt_<attempt>/repo_baseline.json.

    Args:
        workspace_root: Workspace root directory.
        task_id: Task identifier.
        attempt: Attempt index.
        repo_names: List of all registered repository directory names in repos/.

    Returns:
        Mapping of repo_name -> baseline snapshot dict.
    """
    root = Path(workspace_root).resolve()
    attempt_dir = resolve_task_attempt_dir(root, task_id, attempt, ensure_exists=True)
    baseline_file = attempt_dir / "repo_baseline.json"

    baselines: Dict[str, Dict[str, Any]] = {}
    repos_dir = root / "repos"

    for repo_name in repo_names:
        repo_path = repos_dir / repo_name
        base_info = discover_repository(
            repo_path=repo_path,
            name=repo_name,
            workspace_root=root,
            allow_unborn=False,
            require_clean=False,
        )

        tree_sha = get_git_tree_sha(repo_path) if base_info.head_commit else ("0" * 40)
        baselines[repo_name] = {
            "name": repo_name,
            "path": base_info.rel_path,
            "branch": base_info.branch,
            "head_commit": base_info.head_commit,
            "tree_sha": tree_sha,
            "is_dirty": base_info.is_dirty,
        }

    # Write record
    baseline_file.write_text(pretty_json_dumps(baselines), encoding="utf-8")
    return baselines


def verify_multi_repo_governance(
    workspace_root: Union[str, Path],
    task_id: str,
    attempt: int,
    touched_repos: List[str],
    all_registered_repos: List[str],
    base_commits: Optional[Dict[str, str]] = None,
    permitted_branch_pattern: Optional[str] = None,
) -> Dict[str, Any]:
    """Audit branch compliance, base commit bindings, cleanliness, and untouched invariants.

    Args:
        workspace_root: Root workspace path.
        task_id: Task identifier.
        attempt: Attempt index.
        touched_repos: List of repositories modified for this task.
        all_registered_repos: List of all repositories declared in PRODUCT_REPOSITORIES.
        base_commits: Declared base commits per repository.
        permitted_branch_pattern: Optional regex pattern for task branches.

    Returns:
        Audit report containing approved_diff_hashes, checked_heads, and status.

    Raises:
        ProtectedBranchPolicyError: If touched repo is on main/master.
        NonCompliantBranchError: If touched repo branch is not compliant.
        DirtyWorkingTreeError: If a repo working tree is dirty.
        BaseCommitMismatchError: If base_commit diverges from captured baseline.
        UntouchedRepoViolationError: If an untouched repository was modified.
    """
    root = Path(workspace_root).resolve()
    repos_dir = root / "repos"
    attempt_dir = resolve_task_attempt_dir(root, task_id, attempt)
    baseline_file = attempt_dir / "repo_baseline.json"

    baseline_data: Dict[str, Dict[str, Any]] = {}
    if baseline_file.is_file():
        try:
            loaded = json.loads(baseline_file.read_text(encoding="utf-8"))
        except Exception as err:
            raise BranchGovernanceError(f"Malformed repo_baseline.json at '{baseline_file}': {err}") from err
        if not isinstance(loaded, dict):
            raise BranchGovernanceError(f"Malformed repo_baseline.json at '{baseline_file}': expected JSON object.")
        baseline_data = loaded

    checked_heads: Dict[str, Dict[str, Any]] = {}
    approved_diff_hashes: Dict[str, str] = {}

    # 1. Audit Touched Repositories
    for repo_name in touched_repos:
        repo_path = repos_dir / repo_name
        current_info = discover_repository(
            repo_path=repo_path,
            name=repo_name,
            workspace_root=root,
            allow_unborn=False,
            require_clean=False,
        )

        # Enforce branch governance
        validate_branch_compliance(
            branch_name=current_info.branch or "",
            permitted_pattern=permitted_branch_pattern,
        )

        # Enforce clean working tree
        if current_info.is_dirty:
            raise DirtyWorkingTreeError(
                f"Working tree dirty in repository '{repo_name}'. "
                "All changes must be committed before Phase 3 verification."
            )

        # Check base commit binding
        current_head = current_info.head_commit or ""
        expected_base = None
        if base_commits and repo_name in base_commits:
            expected_base = base_commits[repo_name]
        elif repo_name in baseline_data:
            base_entry = baseline_data[repo_name]
            if not isinstance(base_entry, dict):
                raise BranchGovernanceError(f"Malformed repo_baseline.json entry for '{repo_name}'.")
            expected_base = base_entry.get("head_commit")

        if expected_base and expected_base != current_head:
            _assert_safe_git_rev(expected_base, repo_name)
            res = run_safe_git(
                repo_path,
                ["merge-base", "--is-ancestor", "--end-of-options", expected_base, current_head],
            )
            if res.returncode != 0:
                raise BaseCommitMismatchError(
                    f"Base commit mismatch in '{repo_name}': expected base '{expected_base}' "
                    f"is not an ancestor of current HEAD '{current_head}'."
                )

            # Compute diff hash against base
            diff_text = get_repo_diff(repo_path, expected_base)
            approved_diff_hashes[repo_name] = compute_diff_hash(diff_text)

        tree_sha = get_git_tree_sha(repo_path)
        checked_heads[repo_name] = {
            "commit": current_head,
            "tree": tree_sha,
            "branch": current_info.branch,
            "modified": True,
        }

    # 2. Audit Untouched Repositories
    untouched_repos = set(all_registered_repos) - set(touched_repos)
    for repo_name in untouched_repos:
        repo_path = repos_dir / repo_name
        current_info = discover_repository(
            repo_path=repo_path,
            name=repo_name,
            workspace_root=root,
            allow_unborn=False,
            require_clean=False,
        )

        tree_sha = get_git_tree_sha(repo_path)
        base_record = baseline_data.get(repo_name)
        if base_record is not None and not isinstance(base_record, dict):
            raise BranchGovernanceError(f"Malformed repo_baseline.json entry for '{repo_name}'.")

        expected_untouched_head = (base_commits or {}).get(repo_name) or (
            base_record.get("head_commit") if base_record else None
        )
        if not expected_untouched_head:
            raise UntouchedRepoViolationError(
                f"Untouched repository violation: missing baseline commit for '{repo_name}'."
            )
        if current_info.head_commit != expected_untouched_head:
            raise UntouchedRepoViolationError(
                f"Untouched repository violation: HEAD commit in '{repo_name}' changed from "
                f"'{expected_untouched_head}' to '{current_info.head_commit}'."
            )
        if base_record:
            if base_record.get("head_commit") and current_info.head_commit != base_record.get("head_commit"):
                raise UntouchedRepoViolationError(
                    f"Untouched repository violation: HEAD commit in '{repo_name}' changed from "
                    f"'{base_record.get('head_commit')}' to '{current_info.head_commit}'."
                )
            if base_record.get("tree_sha") and tree_sha != base_record.get("tree_sha"):
                raise UntouchedRepoViolationError(
                    f"Untouched repository violation: Git tree in '{repo_name}' changed from "
                    f"'{base_record.get('tree_sha')}' to '{tree_sha}'."
                )

        if current_info.is_dirty:
            raise UntouchedRepoViolationError(
                f"Untouched repository violation: Repository '{repo_name}' contains uncommitted changes."
            )

        checked_heads[repo_name] = {
            "commit": current_info.head_commit,
            "tree": tree_sha,
            "branch": current_info.branch,
            "modified": False,
        }

    return {
        "status": "CLEAR",
        "checked_heads": checked_heads,
        "approved_diff_hashes": approved_diff_hashes,
    }
