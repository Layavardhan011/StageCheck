"""Write-Ahead Transaction Journal and Startup Crash Recovery (P4-T3 / FR-10 / DEC-010).

Implements crash-safe write-ahead journaling for multi-file mutations under:
    <workspace_root>/.stagecheck_journal/txn_<uuid>.active.json

Guarantees:
1. Atomic pre-image capture before any multi-file evidence or state mutations.
2. Immediate deterministic rollback upon unhandled exception.
3. Automatic startup recovery scanning .stagecheck_journal/ for interrupted
   transactions, rolling back uncommitted partial mutations, and printing
   operator-visible console recovery alerts.
4. Zero silent partial writes across state, manifest, and attempt evidence.
"""

from __future__ import annotations

import base64
import errno
import json
import os
import stat
import sys
import uuid
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple, Union

from stagecheck.core.locking import LockCollisionError, acquire_runtime_lock
from stagecheck.core.paths import StageCheckPathError, safe_resolve
from stagecheck.core.permissions import (
    apply_at_rest_permissions,
    elevate_permissions_for_teardown,
)


class JournalError(Exception):
    """Base error for transaction journal operations."""


class TransactionCorruptedError(JournalError):
    """Raised when an active journal record is malformed or unreadable."""


@dataclass
class RecoveryRecord:
    """Represents the recovery action taken for an interrupted transaction."""

    txn_id: str
    operation: str
    files_restored: List[str]
    files_removed: List[str]
    status: str
    message: str


class TransactionJournal:
    """Manages pre-image recording, staged mutations, and rollback for a single transaction."""

    def __init__(
        self,
        workspace_root: Path,
        operation: str,
        task_id: Optional[str] = None,
        attempt_index: Optional[int] = None,
        txn_id: Optional[str] = None,
    ) -> None:
        self.workspace_root = Path(workspace_root).resolve()
        self.operation = operation
        self.task_id = task_id
        self.attempt_index = attempt_index
        self.txn_id = txn_id or f"txn_{operation.lower()}_{uuid.uuid4().hex}"

        self.journal_dir = self.workspace_root / ".stagecheck_journal"
        self.journal_file = self.journal_dir / f"{self.txn_id}.active.json"

        self.pre_images: Dict[str, Optional[str]] = {}  # rel_path -> text/base64 or None if didn't exist
        self.pre_modes: Dict[str, int] = {}             # rel_path -> file mode
        self.pre_encodings: Dict[str, str] = {}         # rel_path -> "utf-8" or "base64"
        self.staged_paths: List[str] = []
        self.is_committed: bool = False
        self.is_rolled_back: bool = False

    def start(self) -> None:
        """Initialize the journal directory and write the initial active transaction record."""
        self.journal_dir.mkdir(mode=0o700, exist_ok=True)
        # Ensure directory permissions are 0700
        try:
            os.chmod(self.journal_dir, 0o700)
        except OSError:
            pass

        data = {
            "txn_id": self.txn_id,
            "operation": self.operation,
            "task_id": self.task_id,
            "attempt_index": self.attempt_index,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "status": "INITIALIZED",
            "pre_images": {},
            "pre_modes": {},
            "pre_encodings": {},
            "staged_paths": [],
        }
        self.journal_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def _validated_rel_path(self, target_path: Union[str, Path]) -> Tuple[Path, str]:
        """Resolve target_path strictly inside workspace_root without following symlinks."""
        try:
            resolved = safe_resolve(target_path, self.workspace_root, allow_symlinks=False)
            rel_path = resolved.relative_to(self.workspace_root).as_posix()
        except (StageCheckPathError, ValueError) as err:
            raise JournalError(f"Invalid journal target path '{target_path}': {err}") from err
        if not rel_path or rel_path == ".":
            raise JournalError(f"Invalid journal target path '{target_path}'.")
        return resolved, rel_path

    def record_pre_image(self, target_path: Union[str, Path]) -> None:
        """Record pre-image snapshot of a target file before modification."""
        p, rel_path = self._validated_rel_path(target_path)

        if rel_path in self.pre_images:
            return  # Already recorded initial state for this file

        try:
            lst = os.lstat(str(p))
        except FileNotFoundError:
            self.pre_images[rel_path] = None
            self.pre_modes[rel_path] = 0o644
            self.pre_encodings[rel_path] = "utf-8"
        else:
            if stat.S_ISLNK(lst.st_mode) or not stat.S_ISREG(lst.st_mode):
                raise JournalError(
                    f"Journal target '{rel_path}' must be a regular non-symlink file."
                )
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(str(p), flags)
            try:
                with os.fdopen(fd, "rb") as stream:
                    raw_bytes = stream.read()
                mode = (lst.st_mode & 0o777) & 0o644
            except Exception:
                raise
            try:
                content = raw_bytes.decode("utf-8")
                encoding = "utf-8"
            except UnicodeDecodeError:
                content = base64.b64encode(raw_bytes).decode("ascii")
                encoding = "base64"
            self.pre_images[rel_path] = content
            self.pre_modes[rel_path] = mode
            self.pre_encodings[rel_path] = encoding

        self._flush_journal()

    def record_staged_write(self, target_path: Union[str, Path]) -> None:
        """Record that a target path has been written to as part of this transaction."""
        _, rel_path = self._validated_rel_path(target_path)

        if rel_path not in self.staged_paths:
            self.staged_paths.append(rel_path)
            self._flush_journal()

    def _flush_journal(self) -> None:
        """Persist in-memory pre-images and progress to active journal file."""
        data = {
            "txn_id": self.txn_id,
            "operation": self.operation,
            "task_id": self.task_id,
            "attempt_index": self.attempt_index,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "status": "IN_PROGRESS",
            "pre_images": self.pre_images,
            "pre_modes": self.pre_modes,
            "pre_encodings": self.pre_encodings,
            "staged_paths": self.staged_paths,
        }
        temp_journal = self.journal_file.with_suffix(".tmp")
        temp_journal.write_text(json.dumps(data, indent=2), encoding="utf-8")
        temp_journal.replace(self.journal_file)

    def commit(self) -> None:
        """Commit transaction: remove the active journal file and mark committed."""
        if self.is_rolled_back:
            raise JournalError("Cannot commit a transaction that has already been rolled back.")
        self.is_committed = True
        if self.journal_file.exists():
            self.journal_file.unlink()

    def rollback(self) -> RecoveryRecord:
        """Rollback all staged mutations using recorded pre-images."""
        if self.is_committed:
            raise JournalError("Cannot rollback a transaction that has already been committed.")

        restored, removed = _restore_pre_images(
            self.workspace_root,
            self.pre_images,
            self.pre_modes,
            self.pre_encodings,
        )

        # Unlink journal active file
        if self.journal_file.exists():
            self.journal_file.unlink()

        self.is_rolled_back = True
        return RecoveryRecord(
            txn_id=self.txn_id,
            operation=self.operation,
            files_restored=restored,
            files_removed=removed,
            status="ROLLED_BACK",
            message=f"Transaction '{self.txn_id}' rolled back ({len(restored)} restored, {len(removed)} removed).",
        )


def _restore_pre_images(
    workspace_root: Path,
    pre_images: Dict[str, Optional[str]],
    pre_modes: Dict[str, int],
    pre_encodings: Dict[str, str],
) -> Tuple[List[str], List[str]]:
    """Restore recorded file pre-images (UTF-8 or Base64) and unlink newly created files."""
    ws_root = Path(workspace_root).resolve()
    restored: List[str] = []
    removed: List[str] = []

    for rel_path, content in reversed(list(pre_images.items())):
        if not isinstance(rel_path, str) or not rel_path or Path(rel_path).is_absolute():
            raise JournalError(f"Refusing non-relative journal path during rollback: '{rel_path}'.")
        try:
            full_path = safe_resolve(rel_path, ws_root, allow_symlinks=False)
            canonical_rel = full_path.relative_to(ws_root).as_posix()
        except (StageCheckPathError, ValueError) as err:
            raise JournalError(
                f"Refusing unsafe journal path '{rel_path}' outside workspace: {err}"
            ) from err
        if not canonical_rel or canonical_rel == ".":
            raise JournalError(f"Refusing invalid journal path '{rel_path}'.")

        raw_mode = pre_modes.get(rel_path, 0o644)
        if isinstance(raw_mode, bool) or not isinstance(raw_mode, int):
            raise JournalError(f"Invalid pre_mode '{raw_mode}' for journal path '{rel_path}'.")
        mode = raw_mode & 0o644
        encoding = pre_encodings.get(rel_path, "utf-8")

        # Ensure workspace-contained parent directories are writable for rollback
        curr = full_path.parent
        while curr != ws_root and curr != curr.parent and curr.is_relative_to(ws_root):
            if os.path.islink(curr):
                raise JournalError(f"Symlink ancestor '{curr}' rejected during journal rollback.")
            if curr.exists():
                with suppress(OSError):
                    os.chmod(curr, 0o755)
            curr = curr.parent

        if content is None:
            # File did not exist prior to transaction -> remove regular file (never follow symlinks)
            try:
                lst = os.lstat(str(full_path))
            except FileNotFoundError:
                lst = None
            if lst is not None:
                if stat.S_ISLNK(lst.st_mode) or stat.S_ISDIR(lst.st_mode):
                    raise JournalError(
                        f"Refusing to unlink symlink or directory '{rel_path}' during rollback."
                    )
                with suppress(OSError):
                    os.chmod(full_path, 0o644)
                full_path.unlink(missing_ok=True)
                removed.append(canonical_rel)
        else:
            # File existed -> restore original content and clamped mode via O_NOFOLLOW
            full_path.parent.mkdir(parents=True, exist_ok=True)
            try:
                lst = os.lstat(str(full_path))
            except FileNotFoundError:
                lst = None
            if lst is not None:
                if stat.S_ISLNK(lst.st_mode) or stat.S_ISDIR(lst.st_mode):
                    raise JournalError(
                        f"Refusing to overwrite symlink or directory '{rel_path}' during rollback."
                    )
                with suppress(OSError):
                    os.chmod(full_path, 0o644)

            payload = base64.b64decode(content.encode("ascii")) if encoding == "base64" else content.encode("utf-8")
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
            try:
                fd = os.open(str(full_path), flags, 0o644)
            except OSError as err:
                if err.errno == errno.ELOOP:
                    raise JournalError(f"Symlink detected opening '{rel_path}' during rollback.") from err
                raise
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload)
            with suppress(OSError):
                os.chmod(full_path, mode)
            restored.append(canonical_rel)

    return restored, removed


@contextmanager
def write_ahead_transaction(
    workspace_root: Union[str, Path],
    operation: str,
    task_id: Optional[str] = None,
    attempt_index: Optional[int] = None,
) -> Iterator[TransactionJournal]:
    """Context manager executing multi-file mutations under write-ahead journal."""
    ws = Path(workspace_root).resolve()
    journal = TransactionJournal(
        workspace_root=ws,
        operation=operation,
        task_id=task_id,
        attempt_index=attempt_index,
    )
    journal.start()
    try:
        yield journal
        if not journal.is_committed and not journal.is_rolled_back:
            journal.commit()
    except Exception:
        if not journal.is_committed and not journal.is_rolled_back:
            journal.rollback()
        raise


def recover_interrupted_transactions(
    workspace_root: Union[str, Path],
    verbose: bool = True,
) -> List[RecoveryRecord]:
    """Scan .stagecheck_journal for active transaction logs and roll back partial mutations.

    Prints operator-visible alerts to stderr/stdout as required by FR-10.
    """
    ws = Path(workspace_root).resolve()
    journal_dir = ws / ".stagecheck_journal"
    if not journal_dir.is_dir() or journal_dir.is_symlink():
        return []

    records: List[RecoveryRecord] = []
    try:
        with acquire_runtime_lock(ws):
            active_items = sorted(journal_dir.glob("*.active.json"))
            if not active_items:
                return []

            processed_any = False
            for item in active_items:
                if item.is_symlink():
                    raise JournalError(f"Symlink journal record '{item.name}' rejected.")
                try:
                    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                    fd = os.open(str(item), flags)
                    with os.fdopen(fd, "r", encoding="utf-8") as stream:
                        data = json.load(stream)
                except Exception as err:
                    # Corrupted journal record
                    if verbose:
                        print(f"[RECOVERY] WARNING: Unreadable active journal record '{item.name}': {err}", file=sys.stderr)
                    item.unlink(missing_ok=True)
                    continue

                if not isinstance(data, dict):
                    item.unlink(missing_ok=True)
                    continue

                txn_id = data.get("txn_id", item.stem)
                operation = data.get("operation", "UNKNOWN")
                pre_images = data.get("pre_images", {})
                pre_modes = data.get("pre_modes", {})
                pre_encodings = data.get("pre_encodings", {})

                restored, removed = _restore_pre_images(ws, pre_images, pre_modes, pre_encodings)
                processed_any = True

                item.unlink(missing_ok=True)

                rec = RecoveryRecord(
                    txn_id=txn_id,
                    operation=operation,
                    files_restored=restored,
                    files_removed=removed,
                    status="RECOVERED",
                    message=f"Cleaned interrupted transaction '{txn_id}' (operation: {operation}). Restored {len(restored)} files, removed {len(removed)} files.",
                )
                records.append(rec)

                if verbose:
                    print(f"[RECOVERY] {rec.message}")

            if processed_any:
                apply_at_rest_permissions(ws)
    except LockCollisionError:
        return []

    return records

