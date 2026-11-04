"""Advisory File Locking Primitives for Bootstrap and Runtime Governance (P2-T5).

Implements non-blocking advisory file locking via fcntl.flock to serialize
initialization (.stagecheck-init.lock) and runtime commands (controls/.stagecheck.lock).
"""

from __future__ import annotations

import contextlib
import fcntl
import os
from pathlib import Path
from typing import Generator, Optional


class LockError(Exception):
    """Base exception for StageCheck locking operations."""


class LockCollisionError(LockError):
    """Raised when an exclusive lock cannot be acquired because another process holds it."""


@contextlib.contextmanager
def acquire_bootstrap_lock(workspace_root: Path) -> Generator[int, None, None]:
    """Acquire the non-blocking bootstrap lock in workspace root before controls/ exists.

    Args:
        workspace_root: Canonical workspace root directory.

    Yields:
        Open file descriptor for the held lock file.

    Raises:
        LockCollisionError: If another initialization process holds the bootstrap lock.
    """
    root = Path(workspace_root).resolve()
    lock_file = root / ".stagecheck-init.lock"

    fd = os.open(str(lock_file), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (BlockingIOError, OSError) as err:
            raise LockCollisionError(
                f"Workspace initialization is already running (locked by .stagecheck-init.lock)."
            ) from err

        yield fd

    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(fd)
        # Attempt to unlink bootstrap lock file on completion
        with contextlib.suppress(OSError):
            lock_file.unlink(missing_ok=True)


@contextlib.contextmanager
def acquire_runtime_lock(controls_dir: Path) -> Generator[int, None, None]:
    """Acquire the shared exclusive non-blocking runtime lock on controls/.stagecheck.lock.

    Args:
        controls_dir: Path to the controls/ directory.

    Yields:
        Open file descriptor for the runtime lock.

    Raises:
        LockCollisionError: If workspace is locked by an active StageCheck audit or operation.
    """
    lock_file = Path(controls_dir).resolve() / ".stagecheck.lock"
    if not lock_file.exists():
        # Pre-create lock file if missing
        fd = os.open(str(lock_file), os.O_RDWR | os.O_CREAT, 0o600)
    else:
        fd = os.open(str(lock_file), os.O_RDWR)

    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (BlockingIOError, OSError) as err:
            raise LockCollisionError(
                "Workspace is locked by another active StageCheck command (.stagecheck.lock busy)."
            ) from err

        yield fd

    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(fd)
