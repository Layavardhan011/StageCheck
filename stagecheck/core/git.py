"""Git Repository Discovery and Baseline State Capture Primitives (P2-T1).

Implements multi-repository discovery, Git worktree/submodule detection,
unborn HEAD handling, commit baseline capture, and clean working tree validation.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Union
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
    "-c", "diff.external=",
    "-c", "core.quotePath=false",
]


def split_git_nul_paths(raw: str) -> List[str]:
    """Split NUL-delimited Git path output preserving exact filename bytes."""
    return [p for p in raw.split("\0") if p]


def parse_git_porcelain_z(raw: str, include_rename_sources: bool = True) -> List[str]:
    """Parse NUL-delimited `git status --porcelain=v1 -z` records into paths.

    Args:
        raw: Raw stdout from `git status --porcelain=v1 -z`.
        include_rename_sources: When True, includes the extra NUL-terminated original
            path emitted for rename ('R') entries so renames out of forbidden paths
            cannot evade scope checks.
    """
    paths: List[str] = []
    entries = raw.split("\0")
    idx = 0
    while idx < len(entries):
        entry = entries[idx]
        idx += 1
        if not entry:
            continue
        if len(entry) >= 4:
            paths.append(entry[3:])
        x_stat = entry[0]
        y_stat = entry[1] if len(entry) > 1 else " "
        is_rename = x_stat == "R" or y_stat == "R"
        is_copy = x_stat == "C" or y_stat == "C"
        if is_rename or is_copy:
            if idx < len(entries):
                src = entries[idx]
                idx += 1
                if include_rename_sources and is_rename and src:
                    paths.append(src)
    return paths


def _find_repo_root_for_config(path: Path) -> Path:
    """Walk upward from path to find the nearest governing .git directory or file."""
    cur = Path(path).resolve()
    for candidate in (cur, *cur.parents):
        git_marker = candidate / ".git"
        if git_marker.is_symlink() or git_marker.exists():
            return candidate
    return cur


def _append_safe_cfg(configs: List[Path], candidate: Path) -> None:
    if candidate.is_symlink():
        raise GitError(
            f"Security policy violation [UNSAFE_GIT_CONFIG]: Symlinked git config '{candidate}' prohibited."
        )
    if candidate.is_file() and candidate not in configs:
        configs.append(candidate)


def _resolve_git_config_files(repo_path: Path) -> List[Path]:
    """Locate .git/config, worktree commondir/config, and submodule configs without invoking git."""
    root = _find_repo_root_for_config(repo_path)
    git_entry = root / ".git"
    if git_entry.is_symlink():
        raise GitError(
            f"Security policy violation [UNSAFE_GIT_CONFIG]: Symlinked .git entry '{git_entry}' prohibited."
        )
    configs: List[Path] = []
    git_dirs: List[Path] = []
    if git_entry.is_dir():
        git_dirs.append(git_entry)
        _append_safe_cfg(configs, git_entry / "config")
        _append_safe_cfg(configs, git_entry / "config.worktree")
    elif git_entry.is_file():
        try:
            text = git_entry.read_text(encoding="utf-8", errors="replace").strip()
        except OSError as err:
            raise GitError(f"Failed to read gitdir pointer '{git_entry}': {err}") from err
        if text.startswith("gitdir:"):
            raw_dir = text.split(":", 1)[1].strip()
            git_dir = (root / raw_dir).resolve() if not os.path.isabs(raw_dir) else Path(raw_dir).resolve()
            if (root / raw_dir).is_symlink():
                raise GitError(
                    f"Security policy violation [UNSAFE_GIT_CONFIG]: Symlinked gitdir '{raw_dir}' prohibited."
                )
            git_dirs.append(git_dir)
            _append_safe_cfg(configs, git_dir / "config")
            _append_safe_cfg(configs, git_dir / "config.worktree")
            commondir_file = git_dir / "commondir"
            if commondir_file.is_symlink():
                raise GitError(
                    f"Security policy violation [UNSAFE_GIT_CONFIG]: Symlinked commondir '{commondir_file}' prohibited."
                )
            if commondir_file.is_file():
                raw_common = commondir_file.read_text(encoding="utf-8", errors="replace").strip()
                common_dir = (git_dir / raw_common).resolve() if not os.path.isabs(raw_common) else Path(raw_common).resolve()
                git_dirs.append(common_dir)
                _append_safe_cfg(configs, common_dir / "config")
                _append_safe_cfg(configs, common_dir / "config.worktree")

    # Inspect embedded submodule git configs (.git/modules/**/config and config.worktree)
    for gd in git_dirs:
        modules_dir = gd / "modules"
        if modules_dir.is_symlink():
            raise GitError(
                f"Security policy violation [UNSAFE_GIT_CONFIG]: Symlinked modules dir '{modules_dir}' prohibited."
            )
        if modules_dir.is_dir():
            for walk_root, dirs, files in os.walk(modules_dir, followlinks=False):
                for d in dirs:
                    dp = Path(walk_root) / d
                    if dp.is_symlink():
                        raise GitError(
                            f"Security policy violation [UNSAFE_GIT_CONFIG]: Symlink inside modules '{dp}' prohibited."
                        )
                if "config" in files:
                    _append_safe_cfg(configs, Path(walk_root) / "config")
                if "config.worktree" in files:
                    _append_safe_cfg(configs, Path(walk_root) / "config.worktree")

    return configs


_GIT_SECTION_HEADER_RE = re.compile(
    r'^\[([A-Za-z0-9-]+)(?:[ \t]+"((?:[^"\\]|\\.)*)"|[ \t]+([A-Za-z0-9.-]+))?[ \t]*\](.*)$'
)


def _strip_git_config_comment(line: str) -> str:
    """Strip unquoted # or ; comments from a git config line."""
    in_quotes = False
    escaped = False
    for i, ch in enumerate(line):
        if escaped:
            escaped = False
            continue
        if ch == "\\" and in_quotes:
            escaped = True
            continue
        if ch == '"':
            in_quotes = not in_quotes
            continue
        if not in_quotes and ch in ("#", ";"):
            return line[:i]
    return line


def _logical_git_config_lines(raw_text: str) -> List[str]:
    """Join backslash-continued lines cleanly outside comments."""
    lines: List[str] = []
    buf = ""
    for raw_line in raw_text.splitlines():
        cleaned = _strip_git_config_comment(raw_line)
        combined = buf + cleaned
        # Count trailing backslashes
        bs_count = 0
        for ch in reversed(combined):
            if ch == "\\":
                bs_count += 1
            else:
                break
        if bs_count % 2 == 1:
            buf = combined[:-1]
            continue
        buf = ""
        lines.append(combined)
    if buf:
        lines.append(buf)
    return lines


def _iter_git_config_entries(
    raw_text: str, cfg_path: Path
) -> List[Tuple[str, Optional[str], bool, str]]:
    """Strictly tokenize git config sections and (section, key, has_value, value) entries.

    Handles leading indentation on [section] headers (which Python RawConfigParser ignores),
    inline assignments after ']', and fails closed on unparseable section headers or
    include/includeIf directives.
    """
    entries: List[Tuple[str, Optional[str], bool, str]] = []
    current_section: Optional[str] = None

    for line in _logical_git_config_lines(raw_text):
        stripped = line.strip()
        if not stripped:
            continue

        remainder = stripped
        while remainder.startswith("["):
            match = _GIT_SECTION_HEADER_RE.match(remainder)
            if not match:
                raise GitError(
                    f"Security policy violation [UNSAFE_GIT_CONFIG]: Malformed section header in '{cfg_path}'."
                )
            current_section = match.group(1).lower()
            entries.append((current_section, None, False, ""))
            remainder = match.group(4).strip()
        if not remainder:
            continue

        if current_section is None:
            raise GitError(
                f"Security policy violation [UNSAFE_GIT_CONFIG]: Key outside section in '{cfg_path}'."
            )

        if "=" in remainder:
            raw_key, raw_val = remainder.split("=", 1)
            has_val = True
            val = raw_val.strip()
            if len(val) >= 2 and val.startswith('"') and val.endswith('"'):
                val = val[1:-1]
        else:
            raw_key, val, has_val = remainder, "", False

        key = raw_key.strip().lower()
        if not key:
            raise GitError(
                f"Security policy violation [UNSAFE_GIT_CONFIG]: Empty config key in '{cfg_path}'."
            )
        entries.append((current_section, key, has_val, val))

    return entries


def assert_safe_repo_git_config(repo_path: Path) -> None:
    """Parse repository-local git config strictly and fail closed on unsafe or redirective keys."""
    for cfg_path in _resolve_git_config_files(repo_path):
        try:
            raw_text = cfg_path.read_text(encoding="utf-8")
        except Exception as err:
            raise GitError(f"Unsafe or unparseable repository git config '{cfg_path}': {err}") from err

        for sec_prefix, key, has_val, val in _iter_git_config_entries(raw_text, cfg_path):
            if sec_prefix in ("include", "includeif"):
                raise GitError(
                    f"Security policy violation [UNSAFE_GIT_CONFIG]: Prohibiting [{sec_prefix}] directive in '{cfg_path}'."
                )
            if key is None:
                continue

            if sec_prefix == "filter" and key in {"clean", "smudge", "process"}:
                raise GitError(
                    f"Security policy violation [UNSAFE_GIT_CONFIG]: Prohibiting filter driver in '{cfg_path}' section [{sec_prefix}]."
                )
            if sec_prefix == "diff" and key in {"command", "textconv"}:
                raise GitError(
                    f"Security policy violation [UNSAFE_GIT_CONFIG]: Prohibiting diff driver in '{cfg_path}' section [{sec_prefix}]."
                )
            if sec_prefix == "merge" and key == "driver":
                raise GitError(
                    f"Security policy violation [UNSAFE_GIT_CONFIG]: Prohibiting merge driver in '{cfg_path}' section [{sec_prefix}]."
                )
            if sec_prefix == "alias":
                raise GitError(
                    f"Security policy violation [UNSAFE_GIT_CONFIG]: Prohibiting repo alias in '{cfg_path}'."
                )
            if sec_prefix == "credential" and key == "helper":
                raise GitError(
                    f"Security policy violation [UNSAFE_GIT_CONFIG]: Prohibiting credential.helper in '{cfg_path}'."
                )
            if sec_prefix == "core":
                if key in {
                    "sshcommand",
                    "gitproxy",
                    "alternaterefscommand",
                    "worktree",
                    "attributesfile",
                    "excludesfile",
                }:
                    raise GitError(
                        f"Security policy violation [UNSAFE_GIT_CONFIG]: Prohibiting unsafe core.{key} in '{cfg_path}'."
                    )
                if key == "bare" and (
                    not has_val or val.strip().lower() not in {"false", "no", "off", "0"}
                ):
                    raise GitError(
                        f"Security policy violation [UNSAFE_GIT_CONFIG]: Prohibiting core.bare in '{cfg_path}'."
                    )
            if sec_prefix == "gpg" and key == "program":
                raise GitError(
                    f"Security policy violation [UNSAFE_GIT_CONFIG]: Prohibiting gpg.program in '{cfg_path}'."
                )
            if sec_prefix == "remote" and key in {"uploadpack", "receivepack"}:
                raise GitError(
                    f"Security policy violation [UNSAFE_GIT_CONFIG]: Prohibiting remote transport command in '{cfg_path}'."
                )
            if sec_prefix == "uploadpack" and key == "packobjectshook":
                raise GitError(
                    f"Security policy violation [UNSAFE_GIT_CONFIG]: Prohibiting uploadpack.packObjectsHook in '{cfg_path}'."
                )
            if sec_prefix == "sequence" and key == "editor":
                raise GitError(
                    f"Security policy violation [UNSAFE_GIT_CONFIG]: Prohibiting sequence.editor in '{cfg_path}'."
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
    if remotes_proc.returncode != 0:
        raise GitError(f"Failed to list git remotes in '{p}': {remotes_proc.stderr.strip()}")
    if not remotes_proc.stdout.strip():
        return []
    push_urls: List[str] = []
    for remote_name in remotes_proc.stdout.splitlines():
        remote_name = remote_name.strip()
        if not remote_name:
            continue
        url_proc = _run_git_cmd(p, ["remote", "get-url", "--push", "--all", "--", remote_name])
        if url_proc.returncode != 0:
            raise GitError(
                f"Failed to inspect remote '{remote_name}' in '{p}': {url_proc.stderr.strip()}"
            )
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

