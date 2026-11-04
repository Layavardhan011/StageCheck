"""Git Repository Discovery and Baseline State Capture Primitives (P2-T1).

Implements multi-repository discovery, Git worktree/submodule detection,
unborn HEAD handling, commit baseline capture, and clean working tree validation.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Union


class GitError(Exception):
    """Base exception for Git operations in StageCheck."""


class RepositoryNotFoundError(GitError):
    """Raised when a declared target repository directory does not exist."""


class NotAGitRepositoryError(GitError):
    """Raised when a declared target directory is not a valid Git repository."""


class UnbornRepositoryError(GitError):
    """Raised when a repository has an unborn branch (zero commits recorded)."""


class DirtyRepositoryError(GitError):
    """Raised when a repository contains uncommitted changes during baseline capture."""


@dataclass(frozen=True)
class RepoBaseline:
    """Immutable representation of a captured repository baseline state."""

    name: str
    rel_path: str
    abs_path: Path
    git_dir: Path
    head_commit: Optional[str]
    branch: Optional[str]
    is_dirty: bool
    is_unborn: bool
    is_worktree: bool

    def to_dict(self) -> Dict[str, Union[str, bool, None]]:
        """Serialize baseline to a dictionary format matching PRODUCT_REPOSITORIES schema."""
        return {
            "name": self.name,
            "path": self.rel_path,
            "default_branch": self.branch or "main",
            "baseline_head": self.head_commit,
            "is_dirty": self.is_dirty,
            "is_unborn": self.is_unborn,
            "is_worktree": self.is_worktree,
        }


def _run_git_cmd(repo_path: Path, args: List[str]) -> subprocess.CompletedProcess[str]:
    """Execute a read-only git command in the target repository directory."""
    # Enforce safe read-only environment without leaking tokens
    clean_env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_COUNT": "0",
    }
    return subprocess.run(
        ["git", *args],
        cwd=str(repo_path),
        capture_output=True,
        text=True,
        check=False,
        env=clean_env,
    )


def discover_repository(
    repo_path: Union[str, Path],
    name: Optional[str] = None,
    workspace_root: Optional[Path] = None,
    allow_unborn: bool = False,
    require_clean: bool = False,
) -> RepoBaseline:
    """Discover and capture baseline state of a Git repository without mutating it.

    Supports standard repositories, git worktrees (where .git is a file), and submodules.

    Args:
        repo_path: Filesystem path to the repository directory.
        name: Logical name for the repository. Defaults to directory name.
        workspace_root: Optional root path to compute relative path.
        allow_unborn: If False (default), raises UnbornRepositoryError if repo has no HEAD commit.
        require_clean: If True, raises DirtyRepositoryError if repo has uncommitted changes.

    Returns:
        RepoBaseline containing captured commit SHA, branch, and status.

    Raises:
        RepositoryNotFoundError: If repo_path does not exist or is not a directory.
        NotAGitRepositoryError: If directory is not inside a Git working tree.
        UnbornRepositoryError: If repository has no commits and allow_unborn is False.
        DirtyRepositoryError: If repository has uncommitted changes and require_clean is True.
    """
    path = Path(repo_path).resolve()
    repo_name = name or path.name

    if not path.is_dir():
        raise RepositoryNotFoundError(
            f"Target repository directory not found: '{path}'."
        )

    # 1. Verify Git working tree via git rev-parse --git-dir
    proc_git_dir = _run_git_cmd(path, ["rev-parse", "--git-dir"])
    if proc_git_dir.returncode != 0:
        raise NotAGitRepositoryError(
            f"Directory '{path}' is not a valid Git repository ({proc_git_dir.stderr.strip()})."
        )

    raw_git_dir = proc_git_dir.stdout.strip()
    git_dir_path = (path / raw_git_dir).resolve() if not os.path.isabs(raw_git_dir) else Path(raw_git_dir).resolve()

    # Detect worktree pointer (if .git in working tree is a file rather than a directory)
    git_file = path / ".git"
    is_worktree = git_file.is_file()

    # 2. Check for unborn HEAD
    proc_head = _run_git_cmd(path, ["rev-parse", "--verify", "HEAD"])
    is_unborn = proc_head.returncode != 0
    head_commit: Optional[str] = None

    if is_unborn:
        if not allow_unborn:
            raise UnbornRepositoryError(
                f"Repository '{repo_name}' at '{path}' is empty or on an unborn branch (no commit HEAD found)."
            )
    else:
        head_commit = proc_head.stdout.strip()

    # 3. Resolve active branch name
    proc_branch = _run_git_cmd(path, ["rev-parse", "--abbrev-ref", "HEAD"])
    branch: Optional[str] = None
    if proc_branch.returncode == 0:
        raw_branch = proc_branch.stdout.strip()
        branch = None if raw_branch == "HEAD" else raw_branch

    # 4. Check dirty working tree status (uncommitted staged/unstaged changes or untracked files)
    proc_status = _run_git_cmd(path, ["status", "--porcelain"])
    is_dirty = bool(proc_status.stdout.strip())

    if is_dirty and require_clean:
        raise DirtyRepositoryError(
            f"Repository '{repo_name}' contains uncommitted changes. Clean working tree required."
        )

    # Compute relative path from workspace root if provided
    if workspace_root:
        try:
            rel_path = path.relative_to(workspace_root.resolve()).as_posix()
        except ValueError:
            rel_path = path.name
    else:
        rel_path = path.name

    return RepoBaseline(
        name=repo_name,
        rel_path=rel_path,
        abs_path=path,
        git_dir=git_dir_path,
        head_commit=head_commit,
        branch=branch,
        is_dirty=is_dirty,
        is_unborn=is_unborn,
        is_worktree=is_worktree,
    )


def discover_multi_repositories(
    workspace_root: Union[str, Path],
    declared_repos: List[str],
    allow_unborn: bool = False,
    require_clean: bool = False,
) -> Dict[str, RepoBaseline]:
    """Discover and capture baseline for multiple declared repositories under workspace repos/.

    Args:
        workspace_root: Workspace root directory path.
        declared_repos: List of repository names (e.g. ['payment-service', 'ledger-api']).
        allow_unborn: Whether to allow unborn branches.
        require_clean: Whether to enforce clean working trees.

    Returns:
        Mapping of repo name -> RepoBaseline.
    """
    root = Path(workspace_root).resolve()
    baselines: Dict[str, RepoBaseline] = {}

    for repo_name in declared_repos:
        repo_dir = root / "repos" / repo_name
        baseline = discover_repository(
            repo_path=repo_dir,
            name=repo_name,
            workspace_root=root,
            allow_unborn=allow_unborn,
            require_clean=require_clean,
        )
        baselines[repo_name] = baseline

    return baselines
