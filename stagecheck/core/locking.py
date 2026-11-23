"""Advisory File Locking Primitives for Bootstrap and Runtime Governance (P2-T5).

Implements non-blocking advisory file locking via fcntl.flock to serialize
initialization (.stagecheck-init.lock) and runtime commands (controls/.stagecheck.lock).
"""

from __future__ import annotations

import contextlib
import fcntl
import os
import stat
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

    open_flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    for _ in range(16):
        if lock_file.is_symlink():
            raise LockError(f"Refusing unsafe symlink bootstrap lock '{lock_file}'.")
        try:
            fd = os.open(str(lock_file), open_flags, 0o600)
        except OSError as err:
            raise LockError(f"Refusing unsafe lock path '{lock_file}': {err}") from err
        locked_current = False
        try:
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise LockError(f"Bootstrap lock path '{lock_file}' is not a regular file.")
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except (BlockingIOError, OSError) as err:
                raise LockCollisionError(
                    "Workspace initialization is already running (locked by .stagecheck-init.lock)."
                ) from err

            try:
                fd_stat = os.fstat(fd)
                path_stat = os.lstat(lock_file)
            except FileNotFoundError:
                path_stat = None

            if (
                path_stat is not None
                and stat.S_ISREG(path_stat.st_mode)
                and (fd_stat.st_dev, fd_stat.st_ino) == (path_stat.st_dev, path_stat.st_ino)
            ):
                locked_current = True
                break
        finally:
            if not locked_current:
                with contextlib.suppress(OSError):
                    fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)
    else:
        raise LockCollisionError("Exceeded retry limit acquiring bootstrap lock.")

    try:
        yield fd

    finally:
        # Unlink only if lock_file still refers to the inode we locked, before unlocking/closing
        with contextlib.suppress(OSError):
            fd_stat = os.fstat(fd)
            path_stat = os.lstat(lock_file)
            if (fd_stat.st_dev, fd_stat.st_ino) == (path_stat.st_dev, path_stat.st_ino):
                lock_file.unlink(missing_ok=True)
        with contextlib.suppress(OSError):
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


@contextlib.contextmanager
def acquire_runtime_lock(target_dir: Path) -> Generator[int, None, None]:
    """Acquire the shared exclusive non-blocking runtime lock on .stagecheck.lock.

    Standardizes on .stagecheck.lock at workspace root (mode 0600) to decouple from
    read-only controls/ (mode 0555) and eliminate TOCTOU races (SEC-05 / SR-06).

    Args:
        target_dir: Path to workspace_root or controls/ directory.

    Yields:
        Open file descriptor for the runtime lock.

    Raises:
        LockCollisionError: If workspace runtime is locked by an active StageCheck operation.
    """
    resolved = Path(target_dir).resolve()
    ws_root = resolved.parent if resolved.name == "controls" else resolved
    lock_file = ws_root / ".stagecheck.lock"

    # Atomic creation and descriptor acquisition with mode 0600 (reject symlinks & non-regular files)
    if lock_file.is_symlink():
        raise LockError(f"Refusing unsafe symlink runtime lock '{lock_file}'.")
    open_flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(str(lock_file), open_flags, 0o600)
    except OSError as err:
        raise LockError(f"Refusing unsafe lock path '{lock_file}': {err}") from err
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise LockError(f"Runtime lock path '{lock_file}' is not a regular file.")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (BlockingIOError, OSError) as err:
            raise LockCollisionError(
                "Workspace runtime is locked by an active StageCheck operation (.stagecheck.lock held)."
            ) from err

        try:
            os.utime(fd, None)
        except OSError:
            pass

        yield fd

    finally:
        try:
            os.utime(fd, None)
        except OSError:
            pass
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(fd)

