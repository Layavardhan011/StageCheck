"""Filesystem Permission Controls and Controlled Write Transactions (P2-T5).

Enforces defense-in-depth POSIX security modes across controls/ and evidence/,
providing lock-scoped directory permission elevation for atomic mutations.
"""

from __future__ import annotations

import contextlib
import json
import os
import sys
from pathlib import Path
from typing import Generator, List, Optional, Union


MODE_DIR_RO = 0o555    # read + execute, no write (cooperative at-rest defense-in-depth; same-UID OS isolation is in core.isolation)
MODE_DIR_RW = 0o755    # read + write + execute (temporarily during transaction)
MODE_FILE_RO = 0o444   # read-only files (cooperative at-rest lock)
MODE_FILE_RW = 0o644   # read + write files


class TeardownError(Exception):
    """Base exception for workspace unlock and teardown failures."""


class VerifierIsolationError(Exception):
    """Raised when verifier files, controls, or sealed evidence are compromised or OS isolation is missing."""


def assert_os_sandbox_boundary(unshare_net: bool = True) -> None:
    """Verify kernel-level same-UID sandbox isolation (Bubblewrap namespaces) is operational."""
    from stagecheck.core.isolation import probe_bwrap_sandbox

    probe = probe_bwrap_sandbox(unshare_net=unshare_net)
    if not probe.get("available"):
        raise VerifierIsolationError(
            f"OS-enforced same-UID sandbox boundary unavailable: {probe.get('reason')}"
        )


def assert_verifier_isolation(workspace_root: Union[str, Path]) -> None:
    """Verify that controls, locks, and evidence subtrees are uncompromised and non-symlinked (Gap B)."""
    root = Path(workspace_root).resolve()
    controls_dir = root / "controls"
    if not controls_dir.is_dir() or controls_dir.is_symlink():
        raise VerifierIsolationError("Controls boundary missing or is a prohibited symlink.")

    # Critical control files must exist and not be symlinks
    for ctrl in ("ACTIVE_STATE.json", "STAGECHECK_ROOT.json", "PRODUCT_REPOSITORIES.json", "EVIDENCE_ROOT.json"):
        c_path = controls_dir / ctrl
        if c_path.exists() and c_path.is_symlink():
            raise VerifierIsolationError(f"Control file '{ctrl}' cannot be a symbolic link.")

    evidence_dir = root / "evidence"
    if evidence_dir.exists() and evidence_dir.is_symlink():
        raise VerifierIsolationError("Evidence directory cannot be a symbolic link.")

    # Lock files cannot be symlinks
    for lock in root.glob(".stagecheck*.lock"):
        if lock.is_symlink():
            raise VerifierIsolationError(f"Lock file '{lock.name}' cannot be a symbolic link.")


class ActiveTaskTeardownBlockedError(TeardownError):
    """Raised when stagecheck unlock is executed against an active task without --abort-active-task."""


class NonInteractiveTeardownError(TeardownError):
    """Raised when stagecheck unlock is executed in non-interactive environment without --force or CI."""


def _is_active_task_state(state: dict) -> bool:
    status = state.get("status")
    task_id = state.get("task_id")
    phase = state.get("phase", "")
    return bool(
        task_id
        and (
            status == "IN_PROGRESS"
            or (
                phase not in ("NOT_STARTED", "IDLE", "COMPLETED", "SEALED_PASSED", "ABORTED")
                and status not in ("SEALED_PASSED", "ABORTED")
            )
        )
    )


def assert_safe_teardown_preconditions(
    workspace_root: Union[str, Path],
    force: bool = False,
    abort_active: bool = False,
    commit: bool = True,
) -> None:
    """Validate workspace teardown preconditions per Spec M11 / DEC-011.

    Guards:
    1. Active Task Protection: If task is active or IN_PROGRESS, require explicit --abort-active-task.
    2. Headless TTY / CI Verification: In non-interactive environments, require --force and CI=true or STAGECHECK_CI_MODE=1.
    3. Structured Audit Record: Log event to evidence/teardown.log and terminate Sentinel daemon (when commit=True).
    """
    root = Path(workspace_root).resolve()
    from stagecheck.core.state import load_active_state

    state = load_active_state(root)
    task_id = state.get("task_id")
    is_active = _is_active_task_state(state)

    # Guard 1: Active task check (read-only first!)
    if is_active and not abort_active:
        raise ActiveTaskTeardownBlockedError(
            f"Teardown blocked: Task '{task_id}' is currently IN_PROGRESS. "
            "Unlocking the workspace would compromise active audit evidence. "
            "To force termination, supply explicit flag: --abort-active-task"
        )

    # Guard 2: Headless TTY / CI Verification (must succeed BEFORE any state mutation!)
    if not sys.stdin.isatty():
        is_ci = os.environ.get("CI") == "true" or os.environ.get("STAGECHECK_CI_MODE") == "1"
        if not (force and is_ci):
            raise NonInteractiveTeardownError(
                "Headless workspace teardown rejected: Non-interactive execution must set "
                "--force and run within an authorized CI environment (CI=true)."
            )

    if commit:
        commit_safe_teardown(root, abort_active=abort_active, force=force)


def commit_safe_teardown(
    workspace_root: Union[str, Path],
    abort_active: bool = False,
    force: bool = False,
) -> None:
    """Commit active-task abort, Sentinel termination, and teardown audit log after confirmation."""
    root = Path(workspace_root).resolve()
    from stagecheck.core.locking import acquire_runtime_lock
    from stagecheck.core.state import load_active_state, save_active_state

    controls_dir = root / "controls"
    task_id: Optional[str] = None
    aborted = False

    if controls_dir.is_dir():
        with acquire_runtime_lock(controls_dir):
            state = load_active_state(root)
            task_id = state.get("task_id")
            if _is_active_task_state(state) and abort_active:
                with controlled_write_transaction(controls_dir):
                    state["phase"] = "ABORTED"
                    state["status"] = "ABORTED"
                    state["turn"] = "IDLE"
                    save_active_state(root, state)
                aborted = True
    else:
        state = load_active_state(root)
        task_id = state.get("task_id")

    # Guard 3: Structured audit record & sentinel termination
    log_teardown_audit_event(
        workspace_root=root,
        task_id=task_id,
        aborted=aborted,
        forced=force,
    )


def log_teardown_audit_event(
    workspace_root: Union[str, Path],
    task_id: Optional[str] = None,
    aborted: bool = False,
    forced: bool = False,
) -> Path:
    """Append structured teardown record to evidence/teardown.log and stop Sentinel daemon."""
    root = Path(workspace_root).resolve()
    evidence_dir = root / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    teardown_log = evidence_dir / "teardown.log"

    # Stop Sentinel if running (symlink and PID > 1 guarded)
    sentinel_pid = None
    sentinel_pid_file = root / ".stagecheck_sentinel.pid"
    if sentinel_pid_file.is_file() and not sentinel_pid_file.is_symlink():
        try:
            pid_str = sentinel_pid_file.read_text(encoding="utf-8").strip()
            if pid_str.isdigit():
                cand_pid = int(pid_str)
                if cand_pid > 1:
                    sentinel_pid = cand_pid
                    import signal
                    try:
                        os.kill(sentinel_pid, signal.SIGTERM)
                    except OSError:
                        pass
            sentinel_pid_file.unlink(missing_ok=True)
        except Exception:
            pass

    import getpass
    from datetime import datetime, timezone

    try:
        operator = getpass.getuser()
    except Exception:
        operator = "unknown"

    record = {
        "event": "WORKSPACE_UNLOCKED",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "task_id": task_id,
        "active_task_aborted": aborted,
        "operator": operator,
        "pid": os.getpid(),
        "sentinel_pid_stopped": sentinel_pid,
    }

    with controlled_write_transaction(evidence_dir):
        if teardown_log.is_symlink():
            raise TeardownError(f"Security violation: '{teardown_log}' is a symlink.")
        if teardown_log.is_file():
            try:
                os.chmod(teardown_log, 0o644)
            except OSError:
                pass
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(str(teardown_log), flags, 0o644)
        try:
            with os.fdopen(fd, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
        except Exception:
            raise

    return teardown_log


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

    # 3. Re-freeze any sealed attempt subtrees (preserve immutability at rest)
    if tasks_dir.is_dir():
        for task_entry in tasks_dir.iterdir():
            if not task_entry.is_dir() or task_entry.is_symlink():
                continue
            for attempt_entry in task_entry.iterdir():
                if not attempt_entry.is_dir() or attempt_entry.is_symlink():
                    continue
                if (attempt_entry / "seal.json").is_file():
                    freeze_phase_directory(attempt_entry)
                else:
                    for phase_entry in attempt_entry.iterdir():
                        if phase_entry.is_dir() and not phase_entry.is_symlink():
                            if (
                                (phase_entry / "prompt_verified.json").is_file()
                                or any(phase_entry.glob("gate*_receipt.json"))
                            ):
                                freeze_phase_directory(phase_entry)


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
