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


MODE_DIR_RO = 0o555    # read + execute, no write (defense-in-depth)
MODE_DIR_RW = 0o755    # read + write + execute (temporarily during transaction)
MODE_FILE_RO = 0o444   # read-only files
MODE_FILE_RW = 0o644   # read + write files


class TeardownError(Exception):
    """Base exception for workspace unlock and teardown failures."""


class ActiveTaskTeardownBlockedError(TeardownError):
    """Raised when stagecheck unlock is executed against an active task without --abort-active-task."""


class NonInteractiveTeardownError(TeardownError):
    """Raised when stagecheck unlock is executed in non-interactive environment without --force or CI."""


def assert_safe_teardown_preconditions(
    workspace_root: Union[str, Path],
    force: bool = False,
    abort_active: bool = False,
) -> None:
    """Validate workspace teardown preconditions per Spec M11 / DEC-011.

    Guards:
    1. Active Task Protection: If task is active or IN_PROGRESS, require explicit --abort-active-task.
    2. Headless TTY / CI Verification: In non-interactive environments, require --force and CI=true or STAGECHECK_CI_MODE=1.
    3. Structured Audit Record: Log event to evidence/teardown.log and terminate Sentinel daemon.
    """
    root = Path(workspace_root).resolve()
    from stagecheck.core.state import load_active_state, save_active_state

    state = load_active_state(root)
    status = state.get("status")
    task_id = state.get("task_id")
    phase = state.get("phase", "")

    # Check if task is actively executing
    is_active = (
        status == "IN_PROGRESS"
        or (
            phase not in ("NOT_STARTED", "IDLE", "COMPLETED", "SEALED_PASSED", "ABORTED")
            and status not in ("SEALED_PASSED", "ABORTED")
        )
    )

    if is_active and task_id:
        if not abort_active:
            raise ActiveTaskTeardownBlockedError(
                f"Teardown blocked: Task '{task_id}' is currently IN_PROGRESS. "
                "Unlocking the workspace would compromise active audit evidence. "
                "To force termination, supply explicit flag: --abort-active-task"
            )
        # Record task abortion in active state
        controls_dir = root / "controls"
        with controlled_write_transaction(controls_dir):
            state["phase"] = "ABORTED"
            state["status"] = "ABORTED"
            state["turn"] = "IDLE"
            save_active_state(root, state)

    # Guard 2: Headless TTY / CI Verification
    if not sys.stdin.isatty():
        is_ci = os.environ.get("CI") == "true" or os.environ.get("STAGECHECK_CI_MODE") == "1"
        if not (force and is_ci):
            raise NonInteractiveTeardownError(
                "Headless workspace teardown rejected: Non-interactive execution must set "
                "--force and run within an authorized CI environment (CI=true)."
            )

    # Guard 3: Structured audit record & sentinel termination
    log_teardown_audit_event(
        workspace_root=root,
        task_id=task_id,
        aborted=abort_active if is_active else False,
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

    # Stop Sentinel if running
    sentinel_pid = None
    sentinel_pid_file = root / ".stagecheck_sentinel.pid"
    if sentinel_pid_file.is_file():
        try:
            pid_str = sentinel_pid_file.read_text(encoding="utf-8").strip()
            if pid_str.isdigit():
                sentinel_pid = int(pid_str)
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

    # Open with O_APPEND under permissions
    if teardown_log.is_file():
        try:
            os.chmod(teardown_log, 0o644)
        except OSError:
            pass

    with open(teardown_log, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")

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
