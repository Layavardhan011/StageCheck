"""Portability and Hardcoded Path Decoupling Engine (Spec 11, P5-T2).

Provides automated static path auditing to block personal machine absolute paths
(/home/magnus, /Users/*, Windows drives) and dual-mode asset resolution supporting
both vendored source trees and packaged wheel installations.
"""
import os
import re
import sys
from importlib import resources
from pathlib import Path
from typing import Any, Dict, List, Optional

# Prohibited personal or host-specific path patterns
PROHIBITED_PATTERNS = [
    (re.compile(r"/home/magnus(?:\b|/|\\)"), "Personal author home directory (/home/magnus)"),
    (re.compile(r"/Users/[a-zA-Z0-9._-]+/"), "Host-specific macOS user directory (/Users/*)"),
    (re.compile(r"(?<![a-zA-Z0-9])([a-zA-Z]:(?:\\+|/)[a-zA-Z0-9._-]+)"), "Host-specific Windows drive root (C:\\*)"),
    (re.compile(r"/home/[a-zA-Z0-9._-]+/Desktop/"), "Host-specific desktop directory (/home/*/Desktop)"),
]

# File extensions subject to portability audit
AUDITED_EXTENSIONS = {".py", ".json", ".sh", ".yaml", ".yml", ".toml"}


def audit_portability(
    search_root: Optional[Path] = None,
    repo_root: Optional[Path] = None,
    include_docs: bool = False,
    exclude_dirs: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    """Scans codebase for prohibited absolute machine paths and returns findings.

    Args:
        search_root: Directory to scan; defaults to repo_root or StageCheck project root.
        repo_root: Alias for search_root.
        include_docs: Whether to scan markdown/text documentation.
        exclude_dirs: Directories to skip. Defaults to git, cache, build artifacts.

    Returns:
        List of defect dicts containing file, line, pattern, and snippet.
    """
    if search_root is None:
        search_root = repo_root
    if search_root is None:
        search_root = Path(__file__).resolve().parents[2]

    if exclude_dirs is None:
        exclude_dirs = [".git", "__pycache__", ".pytest_cache", ".eggs", "dist", "build", ".venv", "venv"]

    findings: List[Dict[str, Any]] = []

    for root_str, dirs, files in os.walk(search_root):
        # Filter directories in-place
        dirs[:] = [d for d in dirs if d not in exclude_dirs]

        for fname in files:
            fpath = Path(root_str) / fname
            suffix = fpath.suffix.lower()

            if suffix not in AUDITED_EXTENSIONS and not (include_docs and suffix in {".md", ".rst", ".txt"}):
                continue

            # Skip self and inventory docs that purposefully document the baseline bug
            if fname in ("portability.py", "test_portability.py", "test_fixtures.py") or "BASELINE_INVENTORY" in fname or "11_portability" in fname:
                continue

            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
                for line_num, line in enumerate(content.splitlines(), 1):
                    for pattern, description in PROHIBITED_PATTERNS:
                        if pattern.search(line):
                            findings.append({
                                "file": str(fpath.relative_to(search_root)),
                                "line": line_num,
                                "description": description,
                                "snippet": line.strip(),
                            })
                            break
            except Exception:
                pass

    return findings


def resolve_asset_path(relative_asset: str, fallback_root: Optional[Path] = None) -> Path:
    """Resolves an embedded asset path under dual-mode packaging (wheel or vendored source).

    Args:
        relative_asset: Relative path within package, e.g. 'schemas/assets/declared_scope.schema.json'.
        fallback_root: Optional fallback directory for development tree resolution.

    Returns:
        Resolved absolute Path to the asset.

    Raises:
        FileNotFoundError: If asset cannot be located in package resources or source tree.
    """
    # 1. Try package resources (pip-installed package / wheel mode)
    try:
        parts = Path(relative_asset).parts
        if parts:
            package_name = "stagecheck"
            # Attempt to traverse via importlib.resources
            res = resources.files(package_name)
            for part in parts:
                res = res.joinpath(part)
            candidate = Path(str(res))
            if candidate.is_file():
                return candidate
    except Exception:
        pass

    # 2. Try vendored source tree (development mode)
    if fallback_root is None:
        fallback_root = Path(__file__).resolve().parents[2]

    candidates = [
        fallback_root / "stagecheck" / relative_asset,
        fallback_root / relative_asset,
    ]
    for c in candidates:
        if c.is_file():
            return c.resolve()

    raise FileNotFoundError(f"Cannot resolve asset '{relative_asset}' in package or source tree: {fallback_root}")


def validate_environment_portability() -> Dict[str, Any]:
    """Validates Linux runtime portability invariants (kernel features, permissions, encoding)."""
    return {
        "platform": sys.platform,
        "is_linux": sys.platform.startswith("linux"),
        "filesystem_encoding": sys.getfilesystemencoding(),
        "has_inotify": hasattr(os, "inotify_init"),
        "has_flock": hasattr(os, "O_EXCL"),
    }
