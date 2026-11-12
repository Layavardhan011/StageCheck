"""StageCheck Interactive Live Supervisor, Debounce, and Watchdog Lifecycle (FR-04 / FR-05 / Spec 03 / ARCH-01).

Implements:
1. 30-second sliding debounce on prompt.md with 300-second hard ceiling (ARCH-01).
   Records freeze_reason: 'INOTIFY_SILENCE_30S' or 'HARD_CEILING_300S'.
2. Dual-condition watchdog monitoring active agent phases (PHASE_1_PLANNING, PHASE_2A_CODING, PHASE_2B_COMMITTING).
   Suspended during PHASE_3_AUDIT and GATE_4_SEALING.
   Trips when 600s elapse with zero relevant filesystem activity AND zero turn/heartbeat queries.
   Restores monotonic timing behavior from ACTIVE_STATE.json["watchdog"]["last_active_timestamp"] on restart.
3. Event-driven progression engine for the 4-gate lifecycle.
"""

from __future__ import annotations

import datetime
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from stagecheck.core.agents import resolve_task_attempt_dir
from stagecheck.core.gate_engine import (
    GateCriteriaFailedError,
    GateId,
    _advance_gate_atomic_locked,
    advance_gate_atomic,
    check_gate_preconditions,
    evaluate_gate_1_criteria,
    evaluate_gate_2a_criteria,
    evaluate_gate_2b_criteria,
    evaluate_gate_3_criteria,
    evaluate_gate_4_criteria,
)
from stagecheck.core.locking import LockCollisionError, acquire_runtime_lock
from stagecheck.core.prompt_gate import freeze_prompt_and_scope
from stagecheck.core.rubric_engine import run_rubric_evaluation
from stagecheck.core.state import load_active_state, save_active_state
from stagecheck.core.utils import sha256_file


RELEVANT_PATH_PREFIXES = ("repos/",)
RELEVANT_PATH_SUBSTRINGS = ("/Phase-1/", "/Phase-2A/", "/Phase-2B/")


def _has_unsafe_log_control_chars(value: str) -> bool:
    """Return True for ASCII/C1 control characters and Unicode line/paragraph separators."""
    return any(
        ord(ch) < 0x20 or (0x7F <= ord(ch) <= 0x9F) or ord(ch) in (0x2028, 0x2029)
        for ch in value
    )


def is_relevant_sentinel_path(rel_path: str) -> bool:
    """Check if a filesystem event path represents relevant agent work.

    Only events under product repositories or active phase evidence directories
    count as valid agent activity. Unrelated directories do NOT reset watchdog.
    """
    if not isinstance(rel_path, str):
        return False
    if _has_unsafe_log_control_chars(rel_path):
        return False
    norm = rel_path.strip()
    if norm.startswith(RELEVANT_PATH_PREFIXES):
        return True
    if any(sub in norm for sub in RELEVANT_PATH_SUBSTRINGS):
        return True
    return False


def get_last_relevant_filesystem_timestamp(
    workspace_root: Path,
    max_scan_bytes: int = 1024 * 1024,
) -> Optional[datetime.datetime]:
    """Scan evidence/sentinel.log backwards from EOF in bounded chunks to find most recent relevant timestamp."""
    log_file = workspace_root / "evidence" / "sentinel.log"
    if not log_file.is_file() or log_file.is_symlink():
        return None
    chunk_size = 65536
    now_ref = datetime.datetime.now(datetime.timezone.utc)
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(str(log_file), flags)
        with os.fdopen(fd, "rb") as f:
            f.seek(0, os.SEEK_END)
            file_size = f.tell()
            pos = file_size
            scanned = 0
            remainder = b""

            while pos > 0 and scanned < max_scan_bytes:
                read_len = min(chunk_size, pos, max_scan_bytes - scanned)
                pos -= read_len
                f.seek(pos, os.SEEK_SET)
                buf = f.read(read_len) + remainder
                scanned += read_len

                if pos > 0 and b"\n" in buf:
                    remainder, block = buf.split(b"\n", 1)
                else:
                    remainder, block = b"", buf

                lines = block.decode("utf-8", errors="replace").split("\n")
                for line in reversed(lines):
                    line = line.strip()
                    if not line:
                        continue
                    if _has_unsafe_log_control_chars(line):
                        continue

                    ts_str: Optional[str] = None
                    rel_path: Optional[str] = None
                    if line.startswith("{"):
                        try:
                            obj = json.loads(line)
                            if isinstance(obj, dict):
                                ts_val = obj.get("ts")
                                path_val = obj.get("path")
                                if isinstance(ts_val, str) and isinstance(path_val, str):
                                    ts_str = ts_val
                                    rel_path = path_val
                        except Exception:
                            continue
                    else:
                        # Legacy Format: [2026-11-06T12:00:00+00:00] [Tier 1] [MODIFIED] repos/core/app.py
                        parts = line.split("] ", 3)
                        if len(parts) >= 4:
                            ts_str = parts[0].lstrip("[")
                            rel_path = parts[3].strip()

                    if ts_str and rel_path and is_relevant_sentinel_path(rel_path):
                        try:
                            parsed = datetime.datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                            if parsed.tzinfo is None:
                                parsed = parsed.replace(tzinfo=datetime.timezone.utc)
                            if parsed <= now_ref:
                                return parsed
                        except Exception:
                            pass
    except Exception:
        pass
    return None


def get_last_turn_heartbeat_timestamp(workspace_root: Path) -> Optional[datetime.datetime]:
    """Read last active timestamp recorded by turn query or agent heartbeat."""
    state = load_active_state(workspace_root)
    last_iso = state.get("watchdog", {}).get("last_active_timestamp")
    if last_iso:
        try:
            return datetime.datetime.fromisoformat(last_iso.replace("Z", "+00:00"))
        except Exception:
            pass
    return None


ACTIVE_WATCHDOG_PHASES = (
    "PHASE_1_PLANNING",
    "PHASE_1_REPAIR",
    "PHASE_2A_CODING",
    "PHASE_2A_IMPLEMENTATION",
    "PHASE_2B_COMMITTING",
    "PHASE_2B_DELIVERY",
)


def _compute_watchdog_metrics(
    root: Path,
    state: Dict[str, Any],
    phase: str,
    timeout_seconds: float,
    now: datetime.datetime,
) -> Tuple[float, float, Dict[str, Any]]:
    ts_fs = get_last_relevant_filesystem_timestamp(root)
    ts_turn: Optional[datetime.datetime] = None
    last_iso = state.get("watchdog", {}).get("last_active_timestamp")
    if isinstance(last_iso, str) and last_iso:
        try:
            ts_turn = datetime.datetime.fromisoformat(last_iso.replace("Z", "+00:00"))
        except Exception:
            ts_turn = None

    state_file = root / "controls" / "ACTIVE_STATE.json"
    fallback_time = datetime.datetime.fromtimestamp(state_file.stat().st_mtime, tz=datetime.timezone.utc)
    effective_fs = ts_fs or ts_turn or fallback_time
    effective_turn = ts_turn or ts_fs or fallback_time

    delta_fs = max(0.0, (now - effective_fs).total_seconds())
    delta_turn = max(0.0, (now - effective_turn).total_seconds())
    meta = {
        "active": True,
        "phase": phase,
        "delta_fs_seconds": round(delta_fs, 2),
        "delta_turn_seconds": round(delta_turn, 2),
        "timeout_seconds": timeout_seconds,
    }
    return delta_fs, delta_turn, meta


def _notify_watchdog_timeout(phase: str) -> None:
    try:
        from stagecheck.core.sentinel import send_desktop_notification
        send_desktop_notification(
            title="StageCheck Watchdog Inactivity Timeout",
            message=f"Agent stagnation detected in {phase}. Execution paused safely.",
            urgency="critical",
        )
    except Exception:
        pass


def _evaluate_watchdog_locked(
    root: Path,
    state: Dict[str, Any],
    timeout_seconds: float = 1800.0,
    now_utc: Optional[datetime.datetime] = None,
) -> Tuple[bool, str, Dict[str, Any]]:
    """Evaluate watchdog assuming caller holds acquire_runtime_lock(root)."""
    phase = state.get("phase", "IDLE")
    if phase not in ACTIVE_WATCHDOG_PHASES:
        return False, f"Watchdog suspended in phase '{phase}'.", {"active": False, "phase": phase}

    now = now_utc or datetime.datetime.now(datetime.timezone.utc)
    delta_fs, delta_turn, meta = _compute_watchdog_metrics(root, state, phase, timeout_seconds, now)
    if delta_fs >= timeout_seconds and delta_turn >= timeout_seconds:
        halt_msg = (
            f"WATCHDOG_INACTIVITY_TIMEOUT: {int(timeout_seconds / 60)} minutes elapsed with "
            f"zero filesystem and turn activity in phase {phase}"
        )
        state["phase"] = "AWAITING_HUMAN_DISPOSITION"
        state["halt_reason"] = halt_msg
        state.setdefault("watchdog", {})["tripped_at"] = now.isoformat()
        save_active_state(root, state)
        return True, halt_msg, meta

    return False, f"Watchdog healthy (fs: {int(delta_fs)}s, turn: {int(delta_turn)}s).", meta


def evaluate_watchdog(
    workspace_root: Path,
    timeout_seconds: float = 1800.0,
    now_utc: Optional[datetime.datetime] = None,
) -> Tuple[bool, str, Dict[str, Any]]:
    """Evaluate dual-condition watchdog inactivity (FR-05).

    Invariants:
    1. Active strictly in agent phases (PHASE_1_PLANNING, PHASE_2A_CODING, PHASE_2B_COMMITTING).
    2. Suspended during PHASE_3_AUDIT and GATE_4_SEALING.
    3. Trips only when both conditions hold simultaneously:
       - 600s elapsed since last relevant filesystem activity in sentinel.log
       - 600s elapsed since last agent turn or heartbeat query
    4. Upon tripping: transitions state to AWAITING_HUMAN_DISPOSITION with halt_reason,
       emits native desktop notification via notify-send, preserves attempt count.

    Returns:
        (tripped: bool, message: str, metadata: dict)
    """
    root = Path(workspace_root).resolve()
    state = load_active_state(root)
    phase = state.get("phase", "IDLE")

    if phase not in ACTIVE_WATCHDOG_PHASES:
        return False, f"Watchdog suspended in phase '{phase}'.", {"active": False, "phase": phase}

    now = now_utc or datetime.datetime.now(datetime.timezone.utc)
    delta_fs, delta_turn, meta = _compute_watchdog_metrics(root, state, phase, timeout_seconds, now)

    # Dual condition trigger with locked re-verification (prevents TOCTOU against concurrent turn/fs activity)
    if delta_fs >= timeout_seconds and delta_turn >= timeout_seconds:
        try:
            with acquire_runtime_lock(root):
                fresh_state = load_active_state(root)
                fresh_phase = fresh_state.get("phase", "IDLE")
                if fresh_phase not in ACTIVE_WATCHDOG_PHASES:
                    return (
                        False,
                        f"Watchdog suspended in phase '{fresh_phase}'.",
                        {"active": False, "phase": fresh_phase},
                    )
                if (
                    fresh_phase != phase
                    or fresh_state.get("task_id") != state.get("task_id")
                    or fresh_state.get("attempt_index") != state.get("attempt_index")
                ):
                    return False, "Watchdog evaluation aborted: state changed concurrently.", meta

                tripped, halt_msg, fresh_meta = _evaluate_watchdog_locked(
                    root,
                    fresh_state,
                    timeout_seconds=timeout_seconds,
                    now_utc=now,
                )
                if not tripped:
                    return False, "Watchdog activity refreshed concurrently.", fresh_meta
                meta = fresh_meta
        except LockCollisionError:
            return (
                False,
                "Watchdog timeout transition deferred: runtime lock is held by an active operation.",
                meta,
            )

        _notify_watchdog_timeout(phase)
        return True, halt_msg, meta

    return False, f"Watchdog healthy (fs: {int(delta_fs)}s, turn: {int(delta_turn)}s).", meta


class PromptDebouncer:
    """Manages 30-second sliding debounce on prompt.md with a 300-second hard ceiling (ARCH-01)."""

    def __init__(
        self,
        quiet_seconds: float = 30.0,
        max_ceiling_seconds: float = 300.0,
    ):
        self.quiet_seconds = quiet_seconds
        self.max_ceiling_seconds = max_ceiling_seconds
        self._first_seen_time: Optional[float] = None
        self._last_content_hash: Optional[str] = None
        self._last_change_time: Optional[float] = None

    def reset(self) -> None:
        """Reset debounce state."""
        self._first_seen_time = None
        self._last_content_hash = None
        self._last_change_time = None

    def check_stability(
        self,
        file_path: Union[str, Path],
        now: Optional[float] = None,
    ) -> Tuple[bool, Optional[str]]:
        """Check whether prompt file is stable.

        Returns:
            (is_stable, freeze_reason)
            freeze_reason is "INOTIFY_SILENCE_30S", "HARD_CEILING_300S", or None.
        """
        p = Path(file_path).resolve()
        if not p.is_file() or p.stat().st_size == 0:
            self.reset()
            return False, None

        current_time = now if now is not None else time.time()
        content_hash = sha256_file(p)

        # First observation
        if self._first_seen_time is None:
            self._first_seen_time = current_time
            self._last_content_hash = content_hash
            self._last_change_time = current_time
            return False, None

        # Content mutation detected: resets sliding quiet timer
        if content_hash != self._last_content_hash:
            self._last_content_hash = content_hash
            self._last_change_time = current_time

        elapsed_since_first = current_time - self._first_seen_time
        elapsed_since_change = current_time - (self._last_change_time or current_time)

        # 1. Hard ceiling check: continuous activity >= max_ceiling_seconds (300s)
        if elapsed_since_first >= self.max_ceiling_seconds:
            return True, "HARD_CEILING_300S"

        # 2. Sliding window check: quiet for >= quiet_seconds (30s)
        if elapsed_since_change >= self.quiet_seconds:
            return True, "INOTIFY_SILENCE_30S"

        return False, None


@dataclass
class SupervisorStepResult:
    """Result of a single supervisor progression evaluation."""
    task_id: str
    attempt: int
    current_phase: str
    action_taken: str
    status: str
    message: str
    details: Dict[str, Any] = field(default_factory=dict)


class SupervisorEngine:
    """Autonomous Supervisor Engine coordinating gates, debounce, and watchdog."""

    def __init__(
        self,
        workspace_root: Union[str, Path],
        quiet_seconds: float = 30.0,
        max_ceiling_seconds: float = 300.0,
        watchdog_timeout_seconds: float = 1800.0,
    ):
        self.root = Path(workspace_root).resolve()
        self.debouncer = PromptDebouncer(
            quiet_seconds=quiet_seconds,
            max_ceiling_seconds=max_ceiling_seconds,
        )
        self.watchdog_timeout = watchdog_timeout_seconds

    def check_task(self, task_id: Optional[str] = None) -> Dict[str, Any]:
        """Inspect current state and pending actions."""
        state = load_active_state(self.root)
        task = task_id or state.get("task_id", "default")
        attempt = int(state.get("attempt_index", 1))
        phase = state.get("phase", "IDLE")

        tripped, halt_msg, wd_meta = evaluate_watchdog(
            self.root, timeout_seconds=self.watchdog_timeout
        )

        return {
            "task_id": task,
            "attempt": attempt,
            "phase": phase,
            "turn": state.get("turn", "IDLE"),
            "watchdog": wd_meta,
            "watchdog_tripped": tripped,
            "halt_reason": state.get("halt_reason") if tripped else None,
        }

    def step(
        self,
        task_id: Optional[str] = None,
        attempt: Optional[int] = None,
        now: Optional[float] = None,
    ) -> SupervisorStepResult:
        """Execute a single progression evaluation step atomically under runtime lock."""
        # 0. Mandatory Bubblewrap isolation deployment preflight before autonomous task progression (GAP-03)
        from stagecheck.core.isolation import run_bwrap_deployment_preflight

        preflight = run_bwrap_deployment_preflight(workspace_root=self.root, raise_on_failure=False)
        if not preflight.passed:
            snapshot = load_active_state(self.root)
            return SupervisorStepResult(
                task_id=task_id or snapshot.get("task_id", "task-default"),
                attempt=attempt or int(snapshot.get("attempt_index", 1)),
                current_phase=snapshot.get("phase", "IDLE"),
                action_taken="ISOLATION_PREFLIGHT_FAILED",
                status="HALTED",
                message=f"Mandatory Bubblewrap isolation preflight failed: {preflight.reason}",
                details=preflight.to_dict(),
            )

        tripped_phase: Optional[str] = None
        tripped_result: Optional[SupervisorStepResult] = None

        try:
            with acquire_runtime_lock(self.root):
                state = load_active_state(self.root)
                task = task_id or state.get("task_id", "task-default")
                att = attempt or int(state.get("attempt_index", 1))
                phase = state.get("phase", "IDLE")

                # 1. Watchdog evaluation under runtime lock
                tripped, halt_msg, wd_meta = _evaluate_watchdog_locked(
                    self.root, state, timeout_seconds=self.watchdog_timeout
                )
                if tripped:
                    tripped_phase = phase
                    tripped_result = SupervisorStepResult(
                        task_id=task,
                        attempt=att,
                        current_phase="AWAITING_HUMAN_DISPOSITION",
                        action_taken="WATCHDOG_TRIPPED",
                        status="HALTED",
                        message=halt_msg,
                        details=wd_meta,
                    )
                else:
                    attempt_dir = resolve_task_attempt_dir(self.root, task, att)

                    # 2. Phase-specific progression (serialized under runtime lock)
                    if phase in ("PHASE_1_PLANNING", "PHASE_1_REPAIR"):
                        prompt_file = attempt_dir / "Phase-1" / "prompt.md"
                        scope_file = attempt_dir / "Phase-1" / "declared_scope.json"

                        if not prompt_file.is_file() or not scope_file.is_file():
                            return SupervisorStepResult(
                                task_id=task,
                                attempt=att,
                                current_phase=phase,
                                action_taken="WAITING_FOR_BLUEPRINT",
                                status="WAITING",
                                message="Waiting for Agent 1 to write Phase-1/prompt.md and Phase-1/declared_scope.json.",
                            )

                        is_stable, freeze_reason = self.debouncer.check_stability(prompt_file, now=now)
                        if not is_stable:
                            return SupervisorStepResult(
                                task_id=task,
                                attempt=att,
                                current_phase=phase,
                                action_taken="DEBOUNCING_PROMPT",
                                status="WAITING",
                                message="prompt.md detected. Waiting for 30s stability debounce.",
                            )

                        # Prompt is stable: freeze and verify atomically with Gate 1 advance
                        freeze_prompt_and_scope(
                            workspace_root=self.root,
                            task_id=task,
                            attempt=att,
                            freeze_reason=freeze_reason or "INOTIFY_SILENCE_30S",
                        )
                        _advance_gate_atomic_locked(self.root, GateId.GATE_1, task, att)
                        self.debouncer.reset()

                        return SupervisorStepResult(
                            task_id=task,
                            attempt=att,
                            current_phase="PHASE_2A_CODING",
                            action_taken="PROMPT_VERIFIED_AND_GATE1_ADVANCED",
                            status="ADVANCED",
                            message=f"Prompt verified ({freeze_reason}). Advanced to PHASE_2A_CODING.",
                            details={"freeze_reason": freeze_reason},
                        )

                    elif phase in ("PHASE_2A_CODING", "PHASE_2A_IMPLEMENTATION"):
                        status_file = attempt_dir / "Phase-2A" / "pre_commit_status.json"
                        if not status_file.is_file():
                            return SupervisorStepResult(
                                task_id=task,
                                attempt=att,
                                current_phase=phase,
                                action_taken="WAITING_FOR_PRECOMMIT_STATUS",
                                status="WAITING",
                                message="Waiting for Agent 2 to implement code and submit Phase-2A/pre_commit_status.json.",
                            )

                        pre_report = check_gate_preconditions(self.root, GateId.GATE_2A, task, att)
                        if not pre_report.passed:
                            return SupervisorStepResult(
                                task_id=task,
                                attempt=att,
                                current_phase=phase,
                                action_taken="WAITING_FOR_REVIEW_APPROVAL",
                                status="WAITING",
                                message=f"Gate 2A preconditions unmet: {'; '.join(pre_report.failure_reasons)}",
                            )

                        _advance_gate_atomic_locked(self.root, GateId.GATE_2A, task, att)
                        return SupervisorStepResult(
                            task_id=task,
                            attempt=att,
                            current_phase="PHASE_2B_COMMITTING",
                            action_taken="GATE2A_ADVANCED",
                            status="ADVANCED",
                            message="Gate 2A cleared. Advanced to PHASE_2B_COMMITTING.",
                        )

                    elif phase in ("PHASE_2B_COMMITTING", "PHASE_2B_DELIVERY"):
                        report_file = attempt_dir / "Phase-2B" / "report.md"
                        if not report_file.is_file():
                            return SupervisorStepResult(
                                task_id=task,
                                attempt=att,
                                current_phase=phase,
                                action_taken="WAITING_FOR_DELIVERY_REPORT",
                                status="WAITING",
                                message="Waiting for Agent 2 to write Phase-2B/report.md.",
                            )

                        pre_report = check_gate_preconditions(self.root, GateId.GATE_2B, task, att)
                        if not pre_report.passed:
                            return SupervisorStepResult(
                                task_id=task,
                                attempt=att,
                                current_phase=phase,
                                action_taken="WAITING_FOR_COMMIT_AUTHORIZATION",
                                status="WAITING",
                                message=f"Gate 2B criteria unmet: {'; '.join(pre_report.failure_reasons)}",
                            )

                        _advance_gate_atomic_locked(self.root, GateId.GATE_2B, task, att)
                        return SupervisorStepResult(
                            task_id=task,
                            attempt=att,
                            current_phase="PHASE_3_AUDIT",
                            action_taken="GATE2B_ADVANCED",
                            status="ADVANCED",
                            message="Gate 2B cleared. Advanced to PHASE_3_AUDIT.",
                        )

                    elif phase in ("PHASE_3_AUDIT", "PHASE_3_AUDITING"):
                        verdict_file = attempt_dir / "Phase-3" / "verdict.json"
                        if not verdict_file.is_file():
                            return SupervisorStepResult(
                                task_id=task,
                                attempt=att,
                                current_phase=phase,
                                action_taken="WAITING_FOR_AUDIT",
                                status="WAITING",
                                message="Audit in progress or awaiting 'stagecheck audit' execution.",
                            )

                        pre_report = check_gate_preconditions(self.root, GateId.GATE_3, task, att)
                        if pre_report.passed:
                            _advance_gate_atomic_locked(self.root, GateId.GATE_3, task, att)
                            return SupervisorStepResult(
                                task_id=task,
                                attempt=att,
                                current_phase="GATE_4_SEALING",
                                action_taken="GATE3_ADVANCED",
                                status="ADVANCED",
                                message="Gate 3 cleared. Advanced to GATE_4_SEALING.",
                            )
                        return SupervisorStepResult(
                            task_id=task,
                            attempt=att,
                            current_phase=phase,
                            action_taken="AUDIT_FAILED",
                            status="DEFECTS_DETECTED",
                            message=f"Gate 3 audit check failed: {'; '.join(pre_report.failure_reasons)}",
                        )

                    elif phase == "GATE_4_SEALING":
                        pre_report = check_gate_preconditions(self.root, GateId.GATE_4, task, att)
                        if pre_report.passed:
                            _advance_gate_atomic_locked(self.root, GateId.GATE_4, task, att)
                            return SupervisorStepResult(
                                task_id=task,
                                attempt=att,
                                current_phase="SEALED_PASSED",
                                action_taken="GATE4_SEALED",
                                status="COMPLETED",
                                message="Gate 4 cleared. Task attempt sealed and verified.",
                            )
                        return SupervisorStepResult(
                            task_id=task,
                            attempt=att,
                            current_phase=phase,
                            action_taken="WAITING_FOR_SEAL",
                            status="WAITING",
                            message=f"Gate 4 criteria unmet: {'; '.join(pre_report.failure_reasons)}",
                        )

                    elif phase in ("SEALED_PASSED", "COMPLETED"):
                        return SupervisorStepResult(
                            task_id=task,
                            attempt=att,
                            current_phase=phase,
                            action_taken="NONE",
                            status="COMPLETED",
                            message="Task completed and sealed.",
                        )

                    return SupervisorStepResult(
                        task_id=task,
                        attempt=att,
                        current_phase=phase,
                        action_taken="IDLE",
                        status="IDLE",
                        message=f"Supervisor idle in phase '{phase}'.",
                    )
        except LockCollisionError:
            snapshot = load_active_state(self.root)
            return SupervisorStepResult(
                task_id=task_id or snapshot.get("task_id", "task-default"),
                attempt=attempt or int(snapshot.get("attempt_index", 1)),
                current_phase=snapshot.get("phase", "IDLE"),
                action_taken="LOCK_CONTENDED",
                status="WAITING",
                message="Supervisor step deferred: runtime lock is held by an active operation.",
            )

        if tripped_result is not None and tripped_phase is not None:
            _notify_watchdog_timeout(tripped_phase)
            return tripped_result
        raise AssertionError("Unreachable supervisor state")
