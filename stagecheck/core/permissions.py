"""Filesystem Permission Controls and Controlled Write Transactions (P2-T5).

Enforces defense-in-depth POSIX security modes across controls/ and evidence/,
providing lock-scoped directory permission elevation for atomic mutations.
"""

from __future__ import annotations

import contextlib
import os
from pathlib import Path
from typing import Generator, List, Union


MODE_DIR_RO = 0o555    # read + execute, no write (defense-in-depth)
MODE_DIR_RW = 0o755    # read + write + execute (temporarily during transaction)
MODE_FILE_RO = 0o444   # read-only files
MODE_FILE_RW = 0o644   # read + write files


def apply_at_rest_permissions(workspace_root: Union[str, Path]) -> None:
    """Apply standard defense-in-depth security modes across controls and evidence.

    Invariants:
      - controls/ directory is mode 0555
      - controls/* files are mode 0444 (except .stagecheck.lock which is 0600)
      - evidence/ directory is mode 0555
      - evidence/tasks/ directory is mode 0755 (writable by agents for task attempts)
    """
    root = Path(workspace_root).resolve()
    controls_dir = root / "controls"
    evidence_dir = root / "evidence"
    tasks_dir = evidence_dir / "tasks"

    # 1. Protect controls/
    if controls_dir.is_dir():
        # First ensure directory is writable so we can chmod files inside it
        try:
            os.chmod(str(controls_dir), MODE_DIR_RW)
            for item in controls_dir.iterdir():
                if item.is_file():
                    if item.name.endswith(".lock"):
                        os.chmod(str(item), 0o600)
                    else:
                        os.chmod(str(item), MODE_FILE_RO)
        finally:
            os.chmod(str(controls_dir), MODE_DIR_RO)

    # 2. Protect evidence/
    if evidence_dir.is_dir():
        try:
            os.chmod(str(evidence_dir), MODE_DIR_RW)
            if tasks_dir.is_dir():
                os.chmod(str(tasks_dir), MODE_DIR_RW)
            for item in evidence_dir.iterdir():
                if item.is_file():
                    if item.name.startswith("sentinel"):
                        os.chmod(str(item), MODE_FILE_RW)
                    else:
                        os.chmod(str(item), MODE_FILE_RO)
        finally:
            os.chmod(str(evidence_dir), MODE_DIR_RO)


def elevate_permissions_for_teardown(workspace_root: Union[str, Path]) -> None:
    """Elevate permissions across all managed directories to permit clean deletion/teardown."""
    root = Path(workspace_root).resolve()
    for dir_name in ["controls", "evidence"]:
        target_dir = root / dir_name
        if target_dir.is_dir():
            try:
                os.chmod(str(target_dir), MODE_DIR_RW)
            except OSError:
                pass
            for item in target_dir.rglob("*"):
                try:
                    if item.is_file():
                        os.chmod(str(item), MODE_FILE_RW)
                    elif item.is_dir():
                        os.chmod(str(item), MODE_DIR_RW)
                except OSError:
                    pass


def freeze_phase_directory(phase_dir: Union[str, Path]) -> None:
    """Freeze a completed phase or attempt directory (0555 dir / 0444 files) per Table 10."""
    p = Path(phase_dir).resolve()
    if not p.is_dir():
        return
    for item in p.rglob("*"):
        try:
            if item.is_file():
                os.chmod(str(item), MODE_FILE_RO)
            elif item.is_dir():
                os.chmod(str(item), MODE_DIR_RO)
        except OSError:
            pass
    try:
        os.chmod(str(p), MODE_DIR_RO)
    except OSError:
        pass


@contextlib.contextmanager
def controlled_write_transaction(target_dir: Path) -> Generator[None, None, None]:
    """Temporarily elevate target directory mode to 0755, restoring 0555 in finally block.

    Args:
        target_dir: Directory to temporarily unlock (e.g. controls/ or evidence/).
    """
    directory = Path(target_dir).resolve()
    if not directory.is_dir():
        yield
        return

    # Temporarily elevate directory to 0755 and existing files to 0644
    os.chmod(str(directory), MODE_DIR_RW)
    for item in directory.iterdir():
        if item.is_file() and not item.name.endswith(".lock"):
            try:
                os.chmod(str(item), MODE_FILE_RW)
            except OSError:
                pass
    try:
        yield
    finally:
        # Re-apply read-only mode to files and restore directory mode to 0555
        for item in directory.iterdir():
            if item.is_file() and not item.name.endswith(".lock"):
                try:
                    if item.name.startswith("sentinel"):
                        os.chmod(str(item), MODE_FILE_RW)
                    else:
                        os.chmod(str(item), MODE_FILE_RO)
                except OSError:
                    pass
        os.chmod(str(directory), MODE_DIR_RO)
