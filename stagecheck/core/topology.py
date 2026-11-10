"""Topology-Preserving Multi-Repository Audit Worktrees (P4-T1 / FR-11 / DEC-011).

Implements ephemeral Git worktrees mirroring sibling repository topology under:
    <workspace_root>/.stagecheck_worktrees/<task_id>/attempt_<N>/repos/<repo_name>

Ensures relative sibling imports (e.g. `../shared`) resolve identically to
the developer workspace during independent Phase 3 test reruns and audits,
while strictly enforcing clean baseline requirements, safe Git flags,
and crash-safe teardown lifecycles.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Set, Union

from stagecheck.core.git import (
    SAFE_GIT_SECURITY_FLAGS,
    DirtyRepositoryError,
    GitError,
    RepoBaseline,
    _run_git_cmd,
    assert_safe_repo_git_config,
    discover_repository,
    run_safe_git,
)
from stagecheck.core.paths import safe_resolve


TASK_ID_REGEX = re.compile(r"^[a-zA-Z0-9._-]+$")


class WorktreeTopologyError(Exception):
    """Base error for worktree topology operations."""


class InvalidWorktreePathError(WorktreeTopologyError):
    """Raised when a worktree target path escapes the workspace root or violates security invariants."""


class WorktreeSetupError(WorktreeTopologyError):
    """Raised when git worktree creation fails."""


@dataclass
class EphemeralRepoWorktree:
    """Represents a single ephemeral repository worktree within the topology."""

    name: str
    original_path: Path
    worktree_path: Path
    base_commit: str
    is_symlink: bool = False
    is_active: bool = False


@dataclass
class TopologyWorktreeLayout:
    """Represents the complete multi-repository topology layout for an attempt."""

    workspace_root: Path
    task_id: str
    attempt_index: int
    worktree_root: Path
    repos_root: Path
    worktrees: Dict[str, EphemeralRepoWorktree] = field(default_factory=dict)
    baselines: Dict[str, Dict[str, Union[str, bool, None]]] = field(default_factory=dict)


def validate_worktree_hierarchy(
    workspace_root: Path,
    task_id: str,
    attempt_index: int,
) -> Path:
    """Validate task_id, attempt_index, and return safe repos root under .stagecheck_worktrees.

    Args:
        workspace_root: Root directory of StageCheck workspace.
        task_id: Active task identifier matching ^[a-zA-Z0-9._-]+$.
        attempt_index: 1-based attempt index.

    Returns:
        Path to the topology repos container directory.

    Raises:
        InvalidWorktreePathError: If task_id is invalid or paths escape workspace boundary.
    """
    if not TASK_ID_REGEX.match(task_id):
        raise InvalidWorktreePathError(
            f"Invalid task_id '{task_id}'. Must match pattern ^[a-zA-Z0-9._-]+$"
        )

    if attempt_index < 1:
        raise InvalidWorktreePathError(
            f"Attempt index must be >= 1, got {attempt_index}"
        )

    ws = Path(workspace_root).resolve()
    base_wt = (ws / ".stagecheck_worktrees").resolve()

    target_repos_dir = base_wt / task_id / f"attempt_{attempt_index}" / "repos"

    # Pre-resolution boundary check
    if ".." in task_id:
        raise InvalidWorktreePathError(
            f"Path traversal detected in task_id '{task_id}'"
        )

    try:
        target_repos_dir.relative_to(base_wt)
    except ValueError:
        raise InvalidWorktreePathError(
            f"Target worktree repos directory '{target_repos_dir}' escapes '{base_wt}'"
        )

    return target_repos_dir


class TopologyWorktreeManager:
    """Manages creation, execution context, and teardown of topology-preserving worktrees."""

    def __init__(
        self,
        workspace_root: Union[str, Path],
        task_id: str,
        attempt_index: int = 1,
        enforce_clean_baseline: bool = True,
        touched_repos: Optional[Set[str]] = None,
    ) -> None:
        self.workspace_root = Path(workspace_root).resolve()
        self.task_id = task_id
        self.attempt_index = attempt_index
        self.enforce_clean_baseline = enforce_clean_baseline
        self.touched_repos = touched_repos or set()

        self.repos_container = validate_worktree_hierarchy(
            self.workspace_root, self.task_id, self.attempt_index
        )
        self.attempt_root = self.repos_container.parent
        self.layout: Optional[TopologyWorktreeLayout] = None

    def _load_registered_repos(self) -> Dict[str, Dict[str, Any]]:
        """Load declared repositories from controls/PRODUCT_REPOSITORIES.json or auto-discover."""
        prod_repos_file = self.workspace_root / "controls" / "PRODUCT_REPOSITORIES.json"
        if prod_repos_file.is_file():
            try:
                data = json.loads(prod_repos_file.read_text(encoding="utf-8"))
                return data.get("repositories", {})
            except Exception:
                pass

        # Fallback to scanning repos/
        repos_dir = self.workspace_root / "repos"
        discovered: Dict[str, Dict[str, Any]] = {}
        if repos_dir.is_dir():
            for child in sorted(repos_dir.iterdir()):
                if child.is_dir() and (child / ".git").exists():
                    discovered[child.name] = {"path": f"repos/{child.name}"}
        return discovered

    def setup(self) -> TopologyWorktreeLayout:
        """Create the topology-preserving worktrees for all registered repositories.

        Raises:
            DirtyRepositoryError: If enforce_clean_baseline is True and any repo is dirty.
            WorktreeSetupError: If git worktree creation fails.
        """
        registered = self._load_registered_repos()
        if not registered:
            raise WorktreeTopologyError("No registered repositories found for worktree setup.")

        # Ensure container directory exists
        self.repos_container.mkdir(parents=True, exist_ok=True)

        layout = TopologyWorktreeLayout(
            workspace_root=self.workspace_root,
            task_id=self.task_id,
            attempt_index=self.attempt_index,
            worktree_root=self.attempt_root,
            repos_root=self.repos_container,
        )

        created_worktrees: List[EphemeralRepoWorktree] = []

        try:
            for repo_name, meta in sorted(registered.items()):
                repo_rel_path = meta.get("path", f"repos/{repo_name}")
                original_repo_path = (self.workspace_root / repo_rel_path).resolve()

                if not original_repo_path.is_dir():
                    raise WorktreeSetupError(
                        f"Original repository directory not found: '{original_repo_path}'"
                    )

                # Capture baseline and enforce clean status + safe git config
                assert_safe_repo_git_config(original_repo_path)
                baseline = discover_repository(
                    repo_path=original_repo_path,
                    name=repo_name,
                    workspace_root=self.workspace_root,
                    require_clean=self.enforce_clean_baseline,
                )

                base_commit = meta.get("baseline_head") or baseline.head_commit
                if not base_commit:
                    raise WorktreeSetupError(
                        f"No valid baseline commit found for repository '{repo_name}'"
                    )

                worktree_dest = self.repos_container / repo_name
                layout.baselines[repo_name] = baseline.to_dict()

                # Always create detached ephemeral Git worktrees at baseline commit (never symlink live repos/)
                res = run_safe_git(
                    original_repo_path,
                    ["worktree", "add", "--detach", str(worktree_dest), base_commit],
                    check=False,
                )
                if res.returncode != 0:
                    raise WorktreeSetupError(
                        f"Failed to add git worktree for '{repo_name}' at commit {base_commit}: {res.stderr.strip()}"
                    )
                item = EphemeralRepoWorktree(
                    name=repo_name,
                    original_path=original_repo_path,
                    worktree_path=worktree_dest,
                    base_commit=base_commit,
                    is_symlink=False,
                    is_active=True,
                )

                created_worktrees.append(item)
                layout.worktrees[repo_name] = item

            self.layout = layout
            return layout

        except Exception as err:
            # Teardown any partially created worktrees immediately
            self._teardown_items(created_worktrees)
            raise

    def teardown(self) -> None:
        """Safely remove all ephemeral worktrees and clean up the topology tree."""
        if not self.layout:
            # Attempt best-effort cleanup of any remnants at repos_container
            if self.repos_container.exists():
                self._cleanup_directory_safely(self.attempt_root)
            return

        self._teardown_items(list(self.layout.worktrees.values()))
        self.layout = None

    def _teardown_items(self, items: List[EphemeralRepoWorktree]) -> None:
        """Internal helper to dismantle worktree items and prune git worktrees."""
        base_wt = (self.workspace_root / ".stagecheck_worktrees").resolve()

        for item in items:
            if not item.is_active:
                continue

            try:
                dest = item.worktree_path
                # Security: verify parent is strictly within base_wt before symlink check
                if not dest.parent.resolve().is_relative_to(base_wt):
                    continue

                if item.is_symlink or os.path.islink(dest):
                    dest.unlink(missing_ok=True)
                else:
                    if not dest.resolve().is_relative_to(base_wt):
                        continue
                    run_safe_git(
                        item.original_path,
                        ["worktree", "remove", "--force", str(dest)],
                        check=False,
                    )
                    run_safe_git(
                        item.original_path,
                        ["worktree", "prune"],
                        check=False,
                    )
            except Exception:
                pass
            finally:
                item.is_active = False

        # Finally, remove attempt directory if empty or leftover
        if self.attempt_root.exists():
            self._cleanup_directory_safely(self.attempt_root)

    def _cleanup_directory_safely(self, target_dir: Path) -> None:
        """Safely remove target directory verifying it does not escape .stagecheck_worktrees."""
        base_wt = (self.workspace_root / ".stagecheck_worktrees").resolve()
        resolved = target_dir.resolve()
        if resolved != base_wt and resolved.is_relative_to(base_wt):
            shutil.rmtree(resolved, ignore_errors=True)


@contextmanager
def managed_topology_worktrees(
    workspace_root: Union[str, Path],
    task_id: str,
    attempt_index: int = 1,
    enforce_clean_baseline: bool = True,
    touched_repos: Optional[Set[str]] = None,
) -> Iterator[TopologyWorktreeLayout]:
    """Context manager for creating and automatically dismantling topology worktrees."""
    manager = TopologyWorktreeManager(
        workspace_root=workspace_root,
        task_id=task_id,
        attempt_index=attempt_index,
        enforce_clean_baseline=enforce_clean_baseline,
        touched_repos=touched_repos,
    )
    try:
        layout = manager.setup()
        yield layout
    finally:
        manager.teardown()


def prune_abandoned_worktrees(workspace_root: Union[str, Path]) -> None:
    """Crash recovery helper: clean orphaned worktree directories and prune stale git worktrees."""
    ws = Path(workspace_root).resolve()

    # Clean orphaned worktrees on disk first
    wt_dir = ws / ".stagecheck_worktrees"
    if wt_dir.is_dir():
        for item in wt_dir.iterdir():
            if item.is_dir():
                shutil.rmtree(item, ignore_errors=True)

    # Prune git internal worktree tracking records
    repos_dir = ws / "repos"
    if repos_dir.is_dir():
        for child in repos_dir.iterdir():
            if child.is_dir() and (child / ".git").exists():
                run_safe_git(child, ["worktree", "prune", "--expire", "now"], check=False)
