"""Portable Workspace Root Discovery and Component-Normalized Path Primitives.

Implements robust workspace containment checks, directory-descriptor relative
operations, and traversal rejection to prevent symlink/TOCTOU vulnerabilities.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional, Union


class StageCheckPathError(Exception):
    """Base exception for StageCheck path handling errors."""


class WorkspaceRootNotFoundError(StageCheckPathError):
    """Raised when the governed workspace root cannot be discovered."""


class PathTraversalError(StageCheckPathError):
    """Raised when an input path attempts directory traversal outside boundary."""


class SymlinkPathEscapeError(StageCheckPathError):
    """Raised when a symlink resolves to a target outside the permitted root."""


class PathOutsideBoundaryError(StageCheckPathError):
    """Raised when a candidate path lies outside the expected root boundary."""


def find_workspace_root(start_dir: Optional[Union[str, Path]] = None) -> Path:
    """Discover the governed workspace root by traversing upwards from start_dir.

    Looks for workspace markers:
      1. controls/STAGECHECK_ROOT.json
      2. .stagecheck-init.lock
      3. .stagecheck_root marker

    Args:
        start_dir: Starting directory. Defaults to current working directory.

    Returns:
        Canonical, resolved Path to the discovered workspace root.

    Raises:
        WorkspaceRootNotFoundError: If no governed workspace marker is found.
    """
    if start_dir is None:
        current = Path.cwd().resolve()
    else:
        current = Path(start_dir).resolve()

    # Search current and all parent directories
    for directory in [current, *current.parents]:
        if (directory / "controls" / "STAGECHECK_ROOT.json").is_file():
            return directory
        if (directory / ".stagecheck-init.lock").exists():
            return directory
        if (directory / ".stagecheck_root").exists():
            return directory

    # Fallback check for Git repository root containing controls directory
    for directory in [current, *current.parents]:
        if (directory / ".git").exists() and (directory / "controls").is_dir():
            return directory

    raise WorkspaceRootNotFoundError(
        f"Governed workspace root not found from starting directory: {current}. "
        "Ensure 'controls/STAGECHECK_ROOT.json' exists or specify workspace explicitly."
    )


def is_path_contained(candidate: Union[str, Path], boundary: Union[str, Path]) -> bool:
    """Verify that candidate path is strictly within boundary without string-prefix pitfalls.

    Uses normalized component resolution and Path.is_relative_to rather than
    naive string prefix matching (e.g. avoiding false positives for /root-extra vs /root).

    Args:
        candidate: The path to test.
        boundary: The enclosing boundary directory.

    Returns:
        True if candidate is inside or equal to boundary, False otherwise.
    """
    try:
        resolved_boundary = Path(boundary).resolve()
        resolved_candidate = Path(candidate).resolve()
        return resolved_candidate == resolved_boundary or resolved_candidate.is_relative_to(resolved_boundary)
    except (ValueError, RuntimeError):
        return False


def safe_resolve(
    relative_path: Union[str, Path],
    root: Union[str, Path],
    allow_symlinks: bool = False,
) -> Path:
    """Safely resolve a relative path anchored to root, enforcing containment.

    Args:
        relative_path: User-supplied or configuration relative path string.
        root: The governing root boundary path.
        allow_symlinks: If False (default), symlink components are rejected.

    Returns:
        Canonical, resolved Path object strictly contained within root.

    Raises:
        PathTraversalError: If relative_path contains traversal sequences escaping root.
        SymlinkPathEscapeError: If symlinks resolve outside root or are disallowed.
        PathOutsideBoundaryError: If the final path lies outside root.
    """
    root_path = Path(root).resolve()
    raw_path = Path(relative_path)

    # Reject absolute paths if they attempt to escape root
    if raw_path.is_absolute():
        resolved_absolute = raw_path.resolve()
        if not is_path_contained(resolved_absolute, root_path):
            raise PathOutsideBoundaryError(
                f"Absolute path '{relative_path}' lies outside workspace root '{root_path}'."
            )
        candidate = resolved_absolute
    else:
        # Check normalized components for traversal
        normalized = os.path.normpath(str(relative_path))
        if normalized.startswith("..") or "/../" in normalized or normalized == "..":
            raise PathTraversalError(
                f"Forbidden directory traversal detected in path: '{relative_path}'."
            )
        candidate = (root_path / normalized)

    # Symlink validation
    if candidate.is_symlink():
        if not allow_symlinks:
            raise SymlinkPathEscapeError(
                f"Symlink rejected by security policy on path: '{candidate}'."
            )
        resolved_symlink = candidate.resolve()
        if not is_path_contained(resolved_symlink, root_path):
            raise SymlinkPathEscapeError(
                f"Symlink '{candidate}' resolves outside boundary to '{resolved_symlink}'."
            )
        return resolved_symlink

    resolved_candidate = candidate.resolve()
    if not is_path_contained(resolved_candidate, root_path):
        raise PathOutsideBoundaryError(
            f"Path '{relative_path}' resolves outside root '{root_path}' to '{resolved_candidate}'."
        )

    return resolved_candidate


def to_portable_posix(path: Union[str, Path]) -> str:
    """Convert any filesystem path to a standard forward-slash POSIX relative string."""
    return Path(path).as_posix()

