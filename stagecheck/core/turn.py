"""Agent Cooperative Handshake and Turn Protocol (FR-07 / Spec 04 / ARCH-04).

Provides:
- Turn-taking state machine resolving active turns (AGENT_1, AGENT_2, STAGECHECK, HUMAN_OPERATOR, NONE).
- JSON status contract matching turn_status.schema.json.
- Rate limiting enforcing the 5-second polling window (maximum 3 calls per 5s window).
- Watchdog timer reset on valid turn queries during active agent phases.
"""

from __future__ import annotations

import datetime
import fcntl
import json
import os
import sys
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from stagecheck.core.agents import resolve_task_attempt_dir
from stagecheck.core.gate_engine import normalize_phase
from stagecheck.core.locking import acquire_runtime_lock
from stagecheck.core.paths import find_workspace_root
from stagecheck.core.state import load_active_state, save_active_state
from stagecheck.core.utils import canonical_json_dumps, load_json_file
from stagecheck.schemas.validator import validate_turn_status


@dataclass
class TurnStatus:
    """Turn status report conforming to turn_status.schema.json."""

    task_id: str
    attempt: int
    cycle: int
    phase: str
    active_turn: str
    waiting_for: str
    retry_after_seconds: int
    instructions_for_active_agent: str
    preceding_status: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serialize turn status to dictionary."""
        data = asdict(self)
        if self.preceding_status is None:
            data["preceding_status"] = None
        return data


def check_and_record_turn_rate_limit(
    workspace_root: Path,
    max_calls: int = 3,
    window_seconds: float = 5.0,
) -> Tuple[bool, float]:
    """Enforce rate limit of at most max_calls within window_seconds (Spec 04 §3.1).

    Returns:
        (allowed, retry_after)
    """
    tracker_file = workspace_root / ".stagecheck_turn_tracker.json"
    lock_file = workspace_root / ".stagecheck_turn_tracker.lock"

    # Synchronize read-modify-write across concurrent agent processes and threads
    fd = os.open(str(lock_file), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        now = time.time()
        timestamps: List[float] = []

        if tracker_file.is_file():
            try:
                raw = json.loads(tracker_file.read_text(encoding="utf-8"))
                if isinstance(raw, list):
                    timestamps = [float(ts) for ts in raw]
            except Exception:
                timestamps = []

        # Filter timestamps within window
        recent = [ts for ts in timestamps if (now - ts) < window_seconds]

        if len(recent) >= max_calls:
            oldest = min(recent)
            retry_after = max(1.0, window_seconds - (now - oldest))
            return False, retry_after

        recent.append(now)
        tmp_file = tracker_file.with_suffix(f".tmp.{os.getpid()}.{threading.get_ident()}")
        try:
            tmp_file.write_text(json.dumps(recent), encoding="utf-8")
            os.replace(tmp_file, tracker_file)
        except Exception:
            if tmp_file.exists():
                tmp_file.unlink(missing_ok=True)

        return True, 0.0
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(fd)


def compute_turn_status(
    workspace_root: Union[str, Path],
    task_id: Optional[str] = None,
    attempt: Optional[int] = None,
    reset_watchdog: bool = True,
) -> TurnStatus:
    """Evaluate workspace state and artifacts to compute the authoritative active turn."""
    root = Path(workspace_root).resolve()
    state = load_active_state(root)

    resolved_task_id = task_id or state.get("task_id", "unassigned")
    resolved_attempt = attempt or state.get("attempt_index", 1)
    phase_raw = state.get("phase", "NOT_STARTED")
    phase = normalize_phase(phase_raw)

    attempt_dir = resolve_task_attempt_dir(root, resolved_task_id, resolved_attempt)
    p1_dir = attempt_dir / "Phase-1"
    p2a_dir = attempt_dir / "Phase-2A"
    p2b_dir = attempt_dir / "Phase-2B"
    p3_dir = attempt_dir / "Phase-3"

    cycle = 1
    preceding_status: Optional[Dict[str, Any]] = None

    # Handle special halt/error states
    if state.get("circuit_breaker_tripped"):
        active_turn = "HUMAN_OPERATOR"
        waiting_for = "Human operator unlatch and reset-attempts"
        instructions = "Circuit breaker tripped. Human operator must inspect defects and invoke 'stagecheck reset-attempts'."
    elif phase == "AWAITING_HUMAN_DISPOSITION":
        active_turn = "HUMAN_OPERATOR"
        waiting_for = "DISPOSITIONS.json waiver or resume"
        instructions = "Automation paused awaiting human review. Operator must record waiver via 'stagecheck disposition add' or 'stagecheck resume'."
    elif phase in ("NOT_STARTED", "UNINITIALIZED", "IDLE"):
        active_turn = "STAGECHECK"
        waiting_for = "stagecheck start --task <id>"
        instructions = "Workspace idle. Invoke 'stagecheck start --task <task-id>' to activate a task attempt."
    elif phase in ("PHASE_1_PLANNING", "PHASE_1_REPAIR"):
        pv_file = p1_dir / "prompt_verified.json"
        prompt_file = p1_dir / "prompt.md"

        if pv_file.is_file():
            try:
                pv_data = load_json_file(pv_file)
                if pv_data.get("status") == "VERIFIED":
                    active_turn = "STAGECHECK"
                    waiting_for = "Gate-1 advance"
                    instructions = "Prompt verified and frozen. StageCheck supervisor or operator must advance Gate-1."
                    preceding_status = {"file": "Phase-1/prompt_verified.json", "status": "VERIFIED"}
                else:
                    active_turn = "AGENT_1"
                    waiting_for = "Phase-1/prompt.md revision"
                    instructions = f"Prompt verification failed ({pv_data.get('status')}). Agent 1 must revise Phase-1/prompt.md."
            except Exception:
                active_turn = "AGENT_1"
                waiting_for = "Phase-1/prompt.md"
                instructions = "Agent 1 must draft 12-section implementation prompt in Phase-1/prompt.md."
        elif prompt_file.is_file():
            active_turn = "STAGECHECK"
            waiting_for = "prompt_verified.json"
            instructions = "Phase-1/prompt.md detected. StageCheck supervisor will verify prompt and freeze scope after 30s stability."
            preceding_status = {"file": "Phase-1/prompt.md", "status": "DRAFTED"}
        else:
            active_turn = "AGENT_1"
            waiting_for = "Phase-1/prompt.md"
            instructions = "Agent 1 must validate the finding and draft the 12-section implementation prompt in Phase-1/prompt.md."

    elif phase == "PHASE_2A_CODING":
        status_file = p2a_dir / "pre_commit_status.json"
        review_file = p2a_dir / "pre_commit_review.json"

        if not status_file.is_file():
            active_turn = "AGENT_2"
            waiting_for = "Phase-2A/pre_commit_status.json"
            instructions = "Agent 2 must implement solution and submit Phase-2A/pre_commit_status.json (status: AWAITING_REVIEW)."
        else:
            try:
                st_data = load_json_file(status_file)
                cycle = int(st_data.get("cycle", 1))
                st_val = st_data.get("status", "UNKNOWN")
                preceding_status = {"file": "Phase-2A/pre_commit_status.json", "status": st_val}
            except Exception:
                cycle = 1

            if not review_file.is_file():
                active_turn = "AGENT_1"
                waiting_for = "Phase-2A/pre_commit_review.json"
                instructions = "Agent 1 must review uncommitted diff against rubric/taxonomies and write Phase-2A/pre_commit_review.json."
            else:
                try:
                    rev_data = load_json_file(review_file)
                    rev_val = rev_data.get("status", "UNKNOWN")
                    rev_cycle = int(rev_data.get("cycle", 0))
                    if preceding_status:
                        preceding_status["review_status"] = rev_val
                except Exception:
                    rev_val = "UNKNOWN"
                    rev_cycle = 0

                if rev_val == "REVISION_REQUIRED":
                    if cycle > rev_cycle:
                        active_turn = "AGENT_1"
                        waiting_for = "Phase-2A/pre_commit_review.json"
                        instructions = "Agent 1 must review uncommitted diff against rubric/taxonomies and write Phase-2A/pre_commit_review.json."
                    else:
                        active_turn = "AGENT_2"
                        waiting_for = "Phase-2A/pre_commit_status.json"
                        instructions = "Review status is REVISION_REQUIRED. Agent 2 must read Phase-2A/response.json, address defects, increment cycle, and resubmit pre_commit_status.json."
                elif rev_val == "APPROVED":
                    active_turn = "STAGECHECK"
                    waiting_for = "Gate-2A / Gate-2B commit and advance"
                    instructions = "Pre-commit review APPROVED. StageCheck supervisor must commit changes to task branch and advance Gate 2B."
                else:
                    active_turn = "AGENT_1"
                    waiting_for = "Phase-2A/pre_commit_review.json"
                    instructions = "Agent 1 must complete pre-commit review."

    elif phase == "PHASE_2B_COMMITTING":
        report_file = p2b_dir / "report.md"
        if not report_file.is_file():
            active_turn = "AGENT_2"
            waiting_for = "Phase-2B/report.md"
            instructions = "Agent 2 must assemble final delivery report in Phase-2B/report.md."
        else:
            active_turn = "STAGECHECK"
            waiting_for = "Gate-2B advance"
            instructions = "Delivery report submitted. StageCheck must advance Gate 2B to enter Phase 3 independent audit."
            preceding_status = {"file": "Phase-2B/report.md", "status": "SUBMITTED"}

    elif phase == "PHASE_3_AUDIT":
        verdict_file = p3_dir / "verdict.json"
        if not verdict_file.is_file():
            active_turn = "STAGECHECK"
            waiting_for = "Phase-3/verdict.json"
            instructions = "StageCheck orchestrator must execute 9-stage verification audit."
        else:
            active_turn = "STAGECHECK"
            waiting_for = "Gate-3 advance"
            instructions = "Audit verdict recorded. StageCheck must advance Gate 3."
            try:
                v_data = load_json_file(verdict_file)
                preceding_status = {"file": "Phase-3/verdict.json", "result": v_data.get("result", "UNKNOWN")}
            except Exception:
                pass

    elif phase == "GATE_4_SEALING":
        active_turn = "STAGECHECK"
        waiting_for = "seal.json & Gate-4 advance"
        instructions = "Audit cleared. StageCheck must seal attempt evidence and advance Gate 4."

    elif phase in ("SEALED_PASSED", "COMPLETED"):
        active_turn = "NONE"
        waiting_for = "COMPLETED"
        instructions = "Task completed successfully. All gates cleared and evidence sealed."

    else:
        active_turn = "NONE"
        waiting_for = phase
        instructions = f"Current phase is '{phase}'."

    # Watchdog activity reset during active agent phases (FR-05 / Issue 4)
    active_watchdog_phases = ("PHASE_1_PLANNING", "PHASE_1_REPAIR", "PHASE_2A_CODING", "PHASE_2B_COMMITTING")
    if reset_watchdog and phase in active_watchdog_phases:
        try:
            with acquire_runtime_lock(root):
                fresh = load_active_state(root)
                fresh_phase = normalize_phase(fresh.get("phase", "NOT_STARTED"))
                if not fresh.get("circuit_breaker_tripped") and fresh_phase in active_watchdog_phases:
                    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
                    fresh.setdefault("watchdog", {})["last_active_timestamp"] = now_iso
                    fresh.setdefault("watchdog", {})["last_active_monotonic"] = time.monotonic()
                    save_active_state(root, fresh)
        except Exception:
            pass

    turn_status = TurnStatus(
        task_id=resolved_task_id,
        attempt=resolved_attempt,
        cycle=cycle,
        phase=phase,
        active_turn=active_turn,
        waiting_for=waiting_for,
        retry_after_seconds=5,
        instructions_for_active_agent=instructions,
        preceding_status=preceding_status,
    )

    # Validate against schema
    validate_turn_status(turn_status.to_dict())

    return turn_status
