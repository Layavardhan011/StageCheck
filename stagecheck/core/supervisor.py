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


def is_relevant_sentinel_path(rel_path: str) -> bool:
    """Check if a filesystem event path represents relevant agent work.

    Only events under product repositories or active phase evidence directories
    count as valid agent activity. Unrelated directories do NOT reset watchdog.
    """
    norm = rel_path.replace("\\", "/").strip()
    if norm.startswith(RELEVANT_PATH_PREFIXES):
        return True
    if any(sub in norm for sub in RELEVANT_PATH_SUBSTRINGS):
        return True
    return False


def get_last_relevant_filesystem_timestamp(workspace_root: Path) -> Optional[datetime.datetime]:
    """Scan evidence/sentinel.log from end to find most recent relevant activity timestamp."""
    log_file = workspace_root / "evidence" / "sentinel.log"
    if not log_file.is_file():
        return None
    try:
        content = log_file.read_text(encoding="utf-8", errors="replace")
        lines = content.splitlines()
        for line in reversed(lines):
            line = line.strip()
            if not line:
                continue
            # Format: [2026-11-06T12:00:00+00:00] [Tier 1] [MODIFIED] repos/core/app.py
            parts = line.split("] ", 3)
            if len(parts) >= 4:
                ts_str = parts[0].lstrip("[")
                rel_path = parts[3].strip()
                if is_relevant_sentinel_path(rel_path):
                    try:
                        return datetime.datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
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


def evaluate_watchdog(
    workspace_root: Path,
    timeout_seconds: float = 600.0,
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

    active_agent_phases = (
        "PHASE_1_PLANNING",
        "PHASE_1_REPAIR",
        "PHASE_2A_CODING",
        "PHASE_2A_IMPLEMENTATION",
        "PHASE_2B_COMMITTING",
        "PHASE_2B_DELIVERY",
    )

    if phase not in active_agent_phases:
        return False, f"Watchdog suspended in phase '{phase}'.", {"active": False, "phase": phase}

    now = now_utc or datetime.datetime.now(datetime.timezone.utc)
    ts_fs = get_last_relevant_filesystem_timestamp(root)
    ts_turn = get_last_turn_heartbeat_timestamp(root)

    # Fallback to recorded watchdog timestamp or state mtime if events not recorded yet
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

    # Dual condition trigger
    if delta_fs >= timeout_seconds and delta_turn >= timeout_seconds:
        halt_msg = (
            f"WATCHDOG_INACTIVITY_TIMEOUT: {int(timeout_seconds / 60)} minutes elapsed with "
            f"zero filesystem and turn activity in phase {phase}"
        )
        # Serialize state transition through runtime lock to prevent clobbering active CLI transactions
        try:
            with acquire_runtime_lock(root):
                fresh_state = load_active_state(root)
                fresh_phase = fresh_state.get("phase", "IDLE")
                if fresh_phase not in active_agent_phases:
                    return False, f"Watchdog suspended in phase '{fresh_phase}'.", {"active": False, "phase": fresh_phase}
                fresh_state["phase"] = "AWAITING_HUMAN_DISPOSITION"
                fresh_state["halt_reason"] = halt_msg
                fresh_state.setdefault("watchdog", {})["tripped_at"] = now.isoformat()
                save_active_state(root, fresh_state)
        except LockCollisionError:
            return (
                False,
                "Watchdog timeout transition deferred: runtime lock is held by an active operation.",
                meta,
            )

        try:
            from stagecheck.core.sentinel import send_desktop_notification
            send_desktop_notification(
                title="StageCheck Watchdog Inactivity Timeout",
                message=f"Agent stagnation detected in {phase}. Execution paused safely.",
                urgency="critical",
            )
        except Exception:
            pass

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
        watchdog_timeout_seconds: float = 600.0,
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
        """Execute a single progression evaluation step under lock."""
        state = load_active_state(self.root)
        task = task_id or state.get("task_id", "task-default")
        att = attempt or int(state.get("attempt_index", 1))
        phase = state.get("phase", "IDLE")

        # 1. Watchdog evaluation
        tripped, halt_msg, wd_meta = evaluate_watchdog(
            self.root, timeout_seconds=self.watchdog_timeout
        )
        if tripped:
            return SupervisorStepResult(
                task_id=task,
                attempt=att,
                current_phase="AWAITING_HUMAN_DISPOSITION",
                action_taken="WATCHDOG_TRIPPED",
                status="HALTED",
                message=halt_msg,
                details=wd_meta,
            )

        attempt_dir = resolve_task_attempt_dir(self.root, task, att)

        # 2. Phase-specific progression
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

            # Prompt is stable: freeze and verify
            freeze_prompt_and_scope(
                workspace_root=self.root,
                task_id=task,
                attempt=att,
                freeze_reason=freeze_reason or "INOTIFY_SILENCE_30S",
            )
            # Advance Gate 1
            advance_gate_atomic(self.root, GateId.GATE_1, task, att)
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

            # Check review criteria
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

            # Advance Gate 2A
            advance_gate_atomic(self.root, GateId.GATE_2A, task, att)
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

            # Advance Gate 2B
            advance_gate_atomic(self.root, GateId.GATE_2B, task, att)
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
                advance_gate_atomic(self.root, GateId.GATE_3, task, att)
                return SupervisorStepResult(
                    task_id=task,
                    attempt=att,
                    current_phase="GATE_4_SEALING",
                    action_taken="GATE3_ADVANCED",
                    status="ADVANCED",
                    message="Gate 3 cleared. Advanced to GATE_4_SEALING.",
                )
            else:
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
                advance_gate_atomic(self.root, GateId.GATE_4, task, att)
                return SupervisorStepResult(
                    task_id=task,
                    attempt=att,
                    current_phase="SEALED_PASSED",
                    action_taken="GATE4_SEALED",
                    status="COMPLETED",
                    message="Gate 4 cleared. Task attempt sealed and verified.",
                )
            else:
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
