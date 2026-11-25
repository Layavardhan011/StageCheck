"""Portability and Hardcoded Path Decoupling Engine (Spec 11, P5-T2).

Provides automated static path auditing to block personal machine absolute paths
(/home/magnus, /Users/*, Windows drives) and dual-mode asset resolution supporting
both vendored source trees and packaged wheel installations.
"""
import os
import re
import stat
import sys
import zipfile
from importlib import resources
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from governance.core.paths import read_bytes_nofollow
from governance.core.permissions import _safe_chmod

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
            if fpath.is_symlink():
                continue
            suffix = fpath.suffix.lower()

            if suffix not in AUDITED_EXTENSIONS and not (include_docs and suffix in {".md", ".rst", ".txt"}):
                continue

            # Skip self and inventory docs that purposefully document the baseline bug
            if fname in ("portability.py", "test_portability.py", "test_fixtures.py") or "BASELINE_INVENTORY" in fname or "11_portability" in fname:
                continue

            try:
                from governance.core.paths import read_bytes_nofollow
                content = read_bytes_nofollow(fpath, max_bytes=10 * 1024 * 1024).decode("utf-8", errors="ignore")
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
            package_name = "governance"
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
        fallback_root / "governance" / relative_asset,
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


EXECUTABLE_REPO_PATHS: Tuple[str, ...] = (
    "bin/ci_release_gate.sh",
    "bin/stagecheck.sh",
    "bin/stagecheck_supervisor.sh",
    "tests/bin/gitleaks",
)


def verify_executable_permissions(
    repo_root: Path,
    rel_paths: Sequence[str] = EXECUTABLE_REPO_PATHS,
) -> Dict[str, Any]:
    """Verify required wrapper scripts and bundled binaries retain executable POSIX permissions (0o755)."""
    root = Path(repo_root).resolve()
    missing: List[str] = []
    non_executable: List[str] = []
    modes: Dict[str, str] = {}

    for rel in rel_paths:
        target = root / rel
        if not target.is_file():
            missing.append(rel)
            continue
        mode = stat.S_IMODE(target.stat().st_mode)
        modes[rel] = oct(mode)
        if not (mode & stat.S_IXUSR) or not (mode & stat.S_IXGRP) or not (mode & stat.S_IXOTH):
            non_executable.append(rel)

    return {
        "ok": not missing and not non_executable,
        "missing": missing,
        "non_executable": non_executable,
        "modes": modes,
    }


def restore_executable_permissions(
    repo_root: Path,
    rel_paths: Sequence[str] = EXECUTABLE_REPO_PATHS,
    target_mode: int = 0o755,
) -> Dict[str, Any]:
    """Restore executable POSIX permissions on wrapper scripts and bundled binaries."""
    root = Path(repo_root).resolve()
    restored: List[str] = []
    missing: List[str] = []
    for rel in rel_paths:
        target = root / rel
        if target.is_symlink() or not target.is_file():
            missing.append(rel)
            continue
        _safe_chmod(target, target_mode)
        restored.append(rel)
    verification = verify_executable_permissions(root, rel_paths)
    return {
        "ok": verification["ok"],
        "restored": restored,
        "missing": missing,
        "modes": verification["modes"],
    }


def create_source_zip_preserving_modes(
    source_root: Path,
    zip_path: Path,
    rel_files: Optional[Sequence[str]] = None,
) -> Path:
    """Create a ZIP archive that preserves UNIX POSIX file modes in ZipInfo.external_attr."""
    root = Path(source_root).resolve()
    out_zip = Path(zip_path).resolve()
    if out_zip.parent.is_symlink():
        raise PermissionError(f"Security policy violation: Zip parent directory '{out_zip.parent}' cannot be a symbolic link.")
    out_zip.parent.mkdir(parents=True, exist_ok=True)

    candidates: List[str]
    if rel_files is not None:
        candidates = list(rel_files)
    else:
        candidates = []
        for cur_root, dirs, files in os.walk(root):
            dirs[:] = sorted(d for d in dirs if d not in {".git", ".venv", "__pycache__", "dist", "build", ".pytest_cache"})
            cur_path = Path(cur_root)
            for fname in sorted(files):
                fpath = cur_path / fname
                candidates.append(str(fpath.relative_to(root).as_posix()))

    with zipfile.ZipFile(out_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for rel in candidates:
            full = (root / rel).resolve()
            full.relative_to(root)
            if full.is_symlink() or not full.is_file():
                continue
            st = full.lstat()
            zinfo = zipfile.ZipInfo(rel)
            zinfo.create_system = 3  # UNIX POSIX mode attributes
            file_mode = stat.S_IMODE(st.st_mode)
            zinfo.external_attr = (stat.S_IFREG | file_mode) << 16
            zf.writestr(zinfo, read_bytes_nofollow(full))

    return out_zip


def extract_zip_preserving_modes(
    zip_path: Path,
    dest_dir: Path,
    required_executables: Sequence[str] = EXECUTABLE_REPO_PATHS,
) -> List[Path]:
    """Extract a ZIP archive safely and restore recorded POSIX executable modes."""
    archive = Path(zip_path).resolve()
    dest = Path(dest_dir).resolve()
    if dest.is_symlink():
        raise PermissionError(f"Security policy violation: Destination directory '{dest}' cannot be a symbolic link.")
    dest.mkdir(parents=True, exist_ok=True)
    extracted: List[Path] = []
    req_set = set(required_executables)

    with zipfile.ZipFile(archive, "r") as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            target = (dest / info.filename).resolve()
            try:
                target.relative_to(dest)
            except ValueError:
                raise PermissionError(f"Archive entry '{info.filename}' attempts path traversal outside destination.")
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.is_symlink():
                raise PermissionError(f"Refusing to extract into symbolic link target '{target}'.")

            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(str(target), flags, 0o644)
            try:
                with zf.open(info, "r") as src, os.fdopen(fd, "wb", closefd=False) as dst:
                    total_written = 0
                    max_file_size = 50 * 1024 * 1024  # 50 MB limit per entry to prevent decompression bombs
                    while chunk := src.read(64 * 1024):
                        total_written += len(chunk)
                        if total_written > max_file_size:
                            raise ValueError(f"Decompression bomb detected: file '{info.filename}' exceeds limit.")
                        dst.write(chunk)
            finally:
                os.close(fd)

            posix_mode = (info.external_attr >> 16) & 0o777
            if info.create_system == 3 and posix_mode:
                _safe_chmod(target, posix_mode)
            elif info.filename in req_set:
                raise PermissionError(
                    f"Archive entry '{info.filename}' lacks preserved POSIX executable permissions."
                )
            extracted.append(target)

    for rel in req_set:
        candidate = dest / rel
        if candidate.is_file():
            mode = stat.S_IMODE(candidate.stat().st_mode)
            if not (mode & stat.S_IXUSR):
                raise PermissionError(f"Extracted executable '{rel}' is missing owner execute bit ({oct(mode)}).")

    return extracted
