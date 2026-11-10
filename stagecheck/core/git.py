"""Git Repository Discovery and Baseline State Capture Primitives (P2-T1).

Implements multi-repository discovery, Git worktree/submodule detection,
unborn HEAD handling, commit baseline capture, and clean working tree validation.
"""

from __future__ import annotations

import configparser
import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Union
from urllib.parse import urlparse


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


SAFE_GIT_SECURITY_FLAGS: List[str] = [
    "-c", "core.fsmonitor=false",
    "-c", "core.pager=cat",
    "-c", "core.hooksPath=/dev/null",
    "-c", "core.editor=cat",
]


def _resolve_git_config_files(repo_path: Path) -> List[Path]:
    """Locate .git/config (and commondir/config for worktrees) without invoking git."""
    git_entry = repo_path / ".git"
    configs: List[Path] = []
    if git_entry.is_dir():
        cfg = git_entry / "config"
        if cfg.is_file():
            configs.append(cfg)
    elif git_entry.is_file():
        try:
            text = git_entry.read_text(encoding="utf-8", errors="replace").strip()
        except OSError as err:
            raise GitError(f"Failed to read gitdir pointer '{git_entry}': {err}") from err
        if text.startswith("gitdir:"):
            raw_dir = text.split(":", 1)[1].strip()
            git_dir = (repo_path / raw_dir).resolve() if not os.path.isabs(raw_dir) else Path(raw_dir).resolve()
            cfg = git_dir / "config"
            if cfg.is_file():
                configs.append(cfg)
            commondir_file = git_dir / "commondir"
            if commondir_file.is_file():
                raw_common = commondir_file.read_text(encoding="utf-8", errors="replace").strip()
                common_dir = (git_dir / raw_common).resolve() if not os.path.isabs(raw_common) else Path(raw_common).resolve()
                common_cfg = common_dir / "config"
                if common_cfg.is_file() and common_cfg not in configs:
                    configs.append(common_cfg)
    return configs


def assert_safe_repo_git_config(repo_path: Path) -> None:
    """Parse repository-local git config safely in Python and fail closed on command-executing keys."""
    for cfg_path in _resolve_git_config_files(repo_path):
        parser = configparser.RawConfigParser(allow_no_value=True, strict=False)
        try:
            parser.read(cfg_path, encoding="utf-8")
        except Exception as err:
            raise GitError(f"Unsafe or unparseable repository git config '{cfg_path}': {err}") from err

        for section in parser.sections():
            sec_lower = section.strip().lower()
            sec_prefix = sec_lower.split()[0].split('"')[0]
            keys = {k.strip().lower() for k in parser[section].keys()}

            if sec_prefix == "filter" and keys & {"clean", "smudge", "process"}:
                raise GitError(
                    f"Security policy violation [UNSAFE_GIT_CONFIG]: Prohibiting filter driver in '{cfg_path}' section [{section}]."
                )
            if sec_prefix == "diff" and keys & {"command", "textconv"}:
                raise GitError(
                    f"Security policy violation [UNSAFE_GIT_CONFIG]: Prohibiting diff driver in '{cfg_path}' section [{section}]."
                )
            if sec_prefix == "merge" and "driver" in keys:
                raise GitError(
                    f"Security policy violation [UNSAFE_GIT_CONFIG]: Prohibiting merge driver in '{cfg_path}' section [{section}]."
                )
            if sec_prefix == "alias" and keys:
                raise GitError(
                    f"Security policy violation [UNSAFE_GIT_CONFIG]: Prohibiting repo alias in '{cfg_path}'."
                )
            if sec_prefix == "credential" and "helper" in keys:
                raise GitError(
                    f"Security policy violation [UNSAFE_GIT_CONFIG]: Prohibiting credential.helper in '{cfg_path}'."
                )
            if sec_prefix == "core" and keys & {"sshcommand", "gitproxy", "alternaterefscommand"}:
                raise GitError(
                    f"Security policy violation [UNSAFE_GIT_CONFIG]: Prohibiting command-executing core setting in '{cfg_path}'."
                )
            if sec_prefix == "gpg" and "program" in keys:
                raise GitError(
                    f"Security policy violation [UNSAFE_GIT_CONFIG]: Prohibiting gpg.program in '{cfg_path}'."
                )
            if sec_prefix == "remote" and keys & {"uploadpack", "receivepack"}:
                raise GitError(
                    f"Security policy violation [UNSAFE_GIT_CONFIG]: Prohibiting remote transport command in '{cfg_path}'."
                )


def _build_safe_git_command(
    repo_path: Path, args: List[str]
) -> tuple[List[str], Dict[str, str]]:
    """Validate repo config and construct hardened git command + sanitized env."""
    assert_safe_repo_git_config(Path(repo_path))
    effective_args = list(args)
    if effective_args and effective_args[0] == "diff":
        for flag in ("--no-textconv", "--no-ext-diff"):
            if flag not in effective_args:
                effective_args.insert(1, flag)

    clean_env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    clean_env.update(
        {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "LANG": "C",
            "LC_ALL": "C",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_COUNT": "0",
        }
    )
    cmd = ["git", *SAFE_GIT_SECURITY_FLAGS, "-C", str(repo_path), *effective_args]
    return cmd, clean_env


def run_safe_git(
    repo_path: Path,
    args: List[str],
    check: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Execute a hardened read-only git command returning decoded UTF-8 text."""
    cmd, clean_env = _build_safe_git_command(Path(repo_path), args)
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=check,
        env=clean_env,
    )


def run_safe_git_bytes(
    repo_path: Path,
    args: List[str],
    check: bool = False,
) -> subprocess.CompletedProcess[bytes]:
    """Execute a hardened read-only git command returning raw stdout bytes."""
    cmd, clean_env = _build_safe_git_command(Path(repo_path), args)
    return subprocess.run(
        cmd,
        capture_output=True,
        check=check,
        env=clean_env,
    )


def _run_git_cmd(repo_path: Path, args: List[str]) -> subprocess.CompletedProcess[str]:
    """Backward-compatible alias for run_safe_git."""
    return run_safe_git(repo_path, args, check=False)


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


def approved_remote(url: str, approved: Union[Set[str], List[str]]) -> bool:
    """Validate git remote push URLs against configuration whitelist (FP-ORG / SR-08)."""
    if url == "DISABLED":
        return True
    if not approved or url not in approved:
        return False

    # Normalize SSH (git@host:path) and URI formats (https://host/path, ssh://host/path)
    if url.startswith("git@"):
        host_and_path = url.split("@", 1)[1]
        host, path = host_and_path.split(":", 1)
        scheme = "ssh"
    else:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        path = parsed.path.lstrip("/")
        scheme = parsed.scheme

    # Disallow blacklisted legacy endpoints while permitting all approved repos
    if host in ("multiversx.com", "elrond.com") or host.endswith(
        (".multiversx.com", ".elrond.com")
    ):
        return False

    return scheme in ("https", "ssh", "git")


def get_repo_remote_push_urls(repo_path: Union[str, Path]) -> List[str]:
    """Inspect all git remote push URLs for a repository."""
    p = Path(repo_path).resolve()
    if not (p / ".git").exists():
        return []
    remotes_proc = _run_git_cmd(p, ["remote"])
    if remotes_proc.returncode != 0 or not remotes_proc.stdout.strip():
        return []
    push_urls: List[str] = []
    for remote_name in remotes_proc.stdout.splitlines():
        remote_name = remote_name.strip()
        if not remote_name:
            continue
        url_proc = _run_git_cmd(p, ["remote", "get-url", "--push", "--all", remote_name])
        if url_proc.returncode == 0:
            for url_line in url_proc.stdout.splitlines():
                u = url_line.strip()
                if u:
                    push_urls.append(u)
    return push_urls


def get_approved_remote_urls(workspace_root: Union[str, Path]) -> Set[str]:
    """Resolve approved push URLs from protected workspace controls (controls/ only)."""
    root = Path(workspace_root).resolve()
    approved: Set[str] = set()

    # 1. controls/remotes.json (protected under 0555/0444 controls/)
    c_remotes = root / "controls" / "remotes.json"
    if c_remotes.is_file():
        try:
            data = json.loads(c_remotes.read_text(encoding="utf-8"))
            for u in data.get("approved_push_urls", []):
                approved.add(u)
        except Exception:
            pass

    # 2. controls/PRODUCT_REPOSITORIES.json (AGENTS.md SHA-256 bound)
    prod_repos = root / "controls" / "PRODUCT_REPOSITORIES.json"
    if prod_repos.is_file():
        try:
            data = json.loads(prod_repos.read_text(encoding="utf-8"))
            for u in data.get("approved_push_urls", []):
                approved.add(u)
            for repo_meta in data.get("repositories", {}).values():
                for u in repo_meta.get("approved_push_urls", []):
                    approved.add(u)
                if repo_meta.get("push_url"):
                    approved.add(repo_meta["push_url"])
        except Exception:
            pass

    return approved

