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
import json
import os
import sys
import uuid
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple, Union

from stagecheck.core.permissions import elevate_permissions_for_teardown


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

    def record_pre_image(self, target_path: Union[str, Path]) -> None:
        """Record pre-image snapshot of a target file before modification."""
        p = Path(target_path).resolve()
        try:
            rel_path = p.relative_to(self.workspace_root).as_posix()
        except ValueError:
            rel_path = str(p)

        if rel_path in self.pre_images:
            return  # Already recorded initial state for this file

        if p.is_file():
            raw_bytes = p.read_bytes()
            mode = p.stat().st_mode & 0o777
            try:
                content = raw_bytes.decode("utf-8")
                encoding = "utf-8"
            except UnicodeDecodeError:
                content = base64.b64encode(raw_bytes).decode("ascii")
                encoding = "base64"
            self.pre_images[rel_path] = content
            self.pre_modes[rel_path] = mode
            self.pre_encodings[rel_path] = encoding
        else:
            self.pre_images[rel_path] = None
            self.pre_modes[rel_path] = 0o644
            self.pre_encodings[rel_path] = "utf-8"

        self._flush_journal()

    def record_staged_write(self, target_path: Union[str, Path]) -> None:
        """Record that a target path has been written to as part of this transaction."""
        p = Path(target_path).resolve()
        try:
            rel_path = p.relative_to(self.workspace_root).as_posix()
        except ValueError:
            rel_path = str(p)

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
    restored: List[str] = []
    removed: List[str] = []

    for rel_path, content in reversed(list(pre_images.items())):
        full_path = workspace_root / rel_path
        mode = pre_modes.get(rel_path, 0o644)
        encoding = pre_encodings.get(rel_path, "utf-8")

        # Ensure parent directories are writable for rollback
        curr = full_path.parent
        while curr != workspace_root and curr != curr.parent:
            if curr.exists():
                with suppress(OSError):
                    os.chmod(curr, 0o755)
            curr = curr.parent

        if content is None:
            # File did not exist prior to transaction -> remove it
            if full_path.exists() or os.path.islink(full_path):
                with suppress(OSError):
                    os.chmod(full_path, 0o644)
                full_path.unlink(missing_ok=True)
                removed.append(rel_path)
        else:
            # File existed -> restore original content and mode
            full_path.parent.mkdir(parents=True, exist_ok=True)
            if full_path.exists():
                with suppress(OSError):
                    os.chmod(full_path, 0o644)
            if encoding == "base64":
                full_path.write_bytes(base64.b64decode(content.encode("ascii")))
            else:
                full_path.write_text(content, encoding="utf-8")
            with suppress(OSError):
                os.chmod(full_path, mode)
            restored.append(rel_path)

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
    if not journal_dir.is_dir():
        return []

    records: List[RecoveryRecord] = []

    for item in sorted(journal_dir.glob("*.active.json")):
        try:
            raw_text = item.read_text(encoding="utf-8")
            data = json.loads(raw_text)
        except Exception as err:
            # Corrupted journal record
            if verbose:
                print(f"[RECOVERY] WARNING: Unreadable active journal record '{item.name}': {err}", file=sys.stderr)
            item.unlink(missing_ok=True)
            continue

        txn_id = data.get("txn_id", item.stem)
        operation = data.get("operation", "UNKNOWN")
        pre_images = data.get("pre_images", {})
        pre_modes = data.get("pre_modes", {})
        pre_encodings = data.get("pre_encodings", {})

        restored, removed = _restore_pre_images(ws, pre_images, pre_modes, pre_encodings)

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

    return records

