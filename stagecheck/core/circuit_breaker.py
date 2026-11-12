"""StageCheck Circuit Breaker, Defect Progression, and Escalation Protocol (P4-T4).

Enforces maximum total attempt caps (default 3: 1 initial + 2 repairs), detects
stagnation (zero progress), regression (defect reappearance), and anti-timeout masking,
tripping into AWAITING_HUMAN_DISPOSITION and generating escalation reports (GAP-X1, GAP-03, GAP-08).
"""

from __future__ import annotations

import datetime
import json
import os
import re
import shutil
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from stagecheck.core.agents import resolve_task_attempt_dir
from stagecheck.core.git import run_safe_git
from stagecheck.core.locking import acquire_runtime_lock
from stagecheck.core.paths import find_workspace_root, resolve_task_dir
from stagecheck.core.permissions import controlled_write_transaction
from stagecheck.core.utils import canonical_json_dumps, pretty_json_dumps

MAX_DEFAULT_ATTEMPTS = 3


class CircuitBreakerError(Exception):
    """Base exception for circuit breaker and escalation faults."""


class ResetAttemptsError(CircuitBreakerError):
    """Raised when stagecheck reset-attempts preconditions fail."""


class AttemptBudgetExhaustedError(CircuitBreakerError):
    """Raised when an attempt retry is requested but maximum attempt budget (3) is exhausted (FR-06 / DEC-028)."""


@dataclass
class CircuitBreakerEvaluation:
    """Outcome of circuit breaker invariant evaluation."""

    tripped: bool
    trigger: Optional[str] = None
    reason: str = ""
    escalate: bool = False


def _get_defects_from_verdict(verdict_path: Path) -> Set[str]:
    """Extract set of defect_ids from a verdict.json file."""
    if not verdict_path.is_file():
        return set()
    try:
        with open(verdict_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return {d.get("defect_id") for d in data.get("defects", []) if d.get("defect_id") and d.get("mode") == "blocking"}
    except Exception:
        return set()


def _detect_timeout_masking(workspace_root: Path, task_id: str, attempt: int) -> bool:
    """Detect if the only code modification made was increasing timeouts or sleep delays."""
    attempt_dir = resolve_task_attempt_dir(workspace_root, task_id, attempt)
    review_file = attempt_dir / "Phase-2A" / "pre_commit_review.json"
    if not review_file.is_file():
        return False

    # Check git diff in touched repositories
    prod_repos_file = workspace_root / "controls" / "PRODUCT_REPOSITORIES.json"
    if not prod_repos_file.is_file():
        return False

    try:
        with open(prod_repos_file, "r", encoding="utf-8") as f:
            repo_meta = json.load(f).get("repositories", {})
    except Exception:
        return False

    for repo_name, meta in repo_meta.items():
        repo_dir = workspace_root / meta.get("path", f"repos/{repo_name}")
        if not (repo_dir / ".git").is_dir():
            continue

        base_head = meta.get("baseline_head")
        if not base_head:
            continue

        res = run_safe_git(repo_dir, ["diff", "-U0", f"{base_head}..HEAD"])
        if res.returncode != 0:
            continue

        diff_text = res.stdout
        added_lines = [l[1:].strip() for l in diff_text.splitlines() if l.startswith("+") and not l.startswith("+++")]
        removed_lines = [l[1:].strip() for l in diff_text.splitlines() if l.startswith("-") and not l.startswith("---")]

        if not added_lines and not removed_lines:
            continue

        # Look for pure timeout/sleep changes
        timeout_regex = re.compile(r"(timeout\s*=\s*[0-9]+|time\.sleep\([0-9]+\)|setTimeout\(.*[0-9]+\))", re.IGNORECASE)
        only_timeouts = True
        for line in added_lines + removed_lines:
            if not timeout_regex.search(line):
                only_timeouts = False
                break

        if only_timeouts and added_lines:
            return True

    return False


def evaluate_circuit_breaker(
    workspace_root: Path,
    task_id: str,
    attempt: int,
    current_defects: List[Dict[str, Any]],
    active_state: Optional[Dict[str, Any]] = None,
) -> CircuitBreakerEvaluation:
    """Evaluate all 5 circuit breaker triggers at the conclusion of an audit attempt."""
    state = active_state or {}
    budget_base = state.get("attempt_budget_base", 0)
    current_cycle_attempt = attempt - budget_base

    # Trigger 1: Maximum Attempts Reached (Hard Cap - GAP-X1)
    if current_cycle_attempt >= MAX_DEFAULT_ATTEMPTS:
        return CircuitBreakerEvaluation(
            tripped=True,
            trigger="max_attempts_exhausted",
            reason=(
                f"Task '{task_id}' has reached the maximum permitted attempt threshold "
                f"({current_cycle_attempt} of {MAX_DEFAULT_ATTEMPTS}). Agent repair loop halted to prevent token burn."
            ),
            escalate=True,
        )

    # Check prior attempt comparison for stagnation and regression
    if attempt > 1:
        prior_attempt = attempt - 1
        prior_verdict_path = (
            workspace_root
            / "evidence"
            / "tasks"
            / task_id
            / f"attempt_{prior_attempt}"
            / "Phase-3"
            / "verdict.json"
        )
        if not prior_verdict_path.is_file():
            prior_verdict_path = (
                workspace_root
                / "evidence"
                / "tasks"
                / task_id
                / f"attempt_{prior_attempt}"
                / "verdict.json"
            )

        prior_defects = _get_defects_from_verdict(prior_verdict_path)
        current_blocking = {
            d.get("defect_id")
            for d in current_defects
            if d.get("defect_id") and d.get("mode") == "blocking"
        }

        # Trigger 2: Zero Progress Invariant (Stagnant Defects)
        if prior_defects and current_blocking and prior_defects == current_blocking:
            return CircuitBreakerEvaluation(
                tripped=True,
                trigger="stagnant_defects",
                reason=(
                    f"Zero progress detected for task '{task_id}': Attempt {attempt} reproduced the exact "
                    f"same blocking defects as Attempt {prior_attempt}: {sorted(list(current_blocking))}"
                ),
                escalate=True,
            )

        # Trigger 3: Defect Reappearance (Regression Invariant)
        # Check if any defect in attempt N was resolved in N-1 but reappeared from N-2
        if attempt >= 3:
            attempt_1_verdict = (
                workspace_root
                / "evidence"
                / "tasks"
                / task_id
                / "attempt_1"
                / "Phase-3"
                / "verdict.json"
            )
            att1_defects = _get_defects_from_verdict(attempt_1_verdict)
            reappeared = (current_blocking & att1_defects) - prior_defects
            if reappeared:
                return CircuitBreakerEvaluation(
                    tripped=True,
                    trigger="defect_reappearance",
                    reason=(
                        f"Regression detected for task '{task_id}': Defect(s) resolved in Attempt {prior_attempt} "
                        f"reappeared in Attempt {attempt}: {sorted(list(reappeared))}"
                    ),
                    escalate=True,
                )

    # Trigger 4: Anti-Timeout Masking Detection (SEC-10 & GAP-08)
    if _detect_timeout_masking(workspace_root, task_id, attempt):
        return CircuitBreakerEvaluation(
            tripped=True,
            trigger="timeout_masking",
            reason=(
                f"Anti-timeout masking detected: Attempt {attempt} modified execution timeouts without "
                "addressing root-cause test or architectural defects."
            ),
            escalate=True,
        )

    return CircuitBreakerEvaluation(tripped=False)


def write_escalation_report(
    workspace_root: Path,
    task_id: str,
    attempt: int,
    evaluation: CircuitBreakerEvaluation,
    defects: List[Dict[str, Any]],
) -> Path:
    """Generate diagnostic escalation_report.md under evidence/tasks/<task_id>/."""
    from stagecheck.core.paths import find_workspace_root, resolve_task_dir, safe_resolve, write_text_nofollow
    ws_root = Path(workspace_root).resolve()
    safe_resolve(f"evidence/tasks/{task_id}", ws_root, allow_symlinks=False)
    task_dir = resolve_task_dir(ws_root, task_id)
    task_dir.mkdir(parents=True, exist_ok=True)
    report_file = safe_resolve(f"evidence/tasks/{task_id}/escalation_report.md", ws_root, allow_symlinks=False)

    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        f"# StageCheck Escalation Report: Task '{task_id}'\n\n",
        f"**Status:** `CIRCUIT_BREAKER_TRIPPED` (`AWAITING_HUMAN_DISPOSITION`)\n",
        f"**Timestamp:** {timestamp}\n",
        f"**Attempt:** {attempt} of {MAX_DEFAULT_ATTEMPTS}\n",
        f"**Trigger:** `{evaluation.trigger}`\n\n",
        "## Summary of Circuit Breaker Fault\n\n",
        f"{evaluation.reason}\n\n",
        "## Unresolved Blocking Defects\n\n",
    ]

    if defects:
        lines.append("| Defect ID | Stage | Severity | Details |\n")
        lines.append("| :--- | :--- | :--- | :--- |\n")
        for d in defects:
            did = d.get("defect_id", "unknown")
            stg = d.get("check_id") or d.get("stage", "check")
            sev = d.get("severity", "CRITICAL")
            quote = ""
            if d.get("evidence"):
                quote = d["evidence"][0].get("quote", "").replace("\n", " ")
            lines.append(f"| `{did}` | `{stg}` | {sev} | {quote} |\n")
    else:
        lines.append("No defects list attached.\n")

    lines.extend([
        "\n## Actionable Developer Resolution Paths\n\n",
        "- **Option A (Manual Code Fix):** Fix the defect directly in `repos/`, commit locally, and run `stagecheck audit`.\n",
        "- **Option B (Human Disposition):** Waive defect via `stagecheck disposition add --task <task_id> --defect <id>`.\n",
        "- **Option C (Attempt Reset):** Unlatch breaker via `stagecheck reset-attempts --task <task_id>` to allocate Attempt 4+.\n",
        "- **Option D (Permanent Halt):** Discontinue task; all commits and evidence remain permanently preserved.\n",
    ])

    write_text_nofollow(report_file, "".join(lines), append=False, mode=0o644)
    return report_file


def trip_circuit_breaker(
    workspace_root: Path,
    task_id: str,
    attempt: int,
    evaluation: CircuitBreakerEvaluation,
    current_defects: List[Dict[str, Any]],
) -> Path:
    """Trip the circuit breaker, update ACTIVE_STATE.json, and emit alerts."""
    from stagecheck.core.state import load_active_state, save_active_state

    controls_dir = workspace_root / "controls"
    controls_dir.mkdir(parents=True, exist_ok=True)
    with acquire_runtime_lock(controls_dir):
        with controlled_write_transaction(controls_dir):
            state_file = controls_dir / "ACTIVE_STATE.json"
            active_state = load_active_state(workspace_root) if state_file.is_file() else {}
            active_state.pop("halt_trigger", None)
            active_state.pop("last_reset", None)
            active_state["phase"] = "AWAITING_HUMAN_DISPOSITION"
            active_state["circuit_breaker_tripped"] = True
            active_state["halt_reason"] = evaluation.reason
            active_state["task_id"] = task_id
            active_state["attempt_index"] = attempt
            save_active_state(workspace_root, active_state)

    # Generate escalation report
    report_path = write_escalation_report(workspace_root, task_id, attempt, evaluation, current_defects)

    # Optional desktop alert (non-failing)
    try:
        from stagecheck.core.sentinel import send_desktop_notification
        send_desktop_notification(
            title="STAGECHECK CIRCUIT BREAKER TRIPPED",
            message=f"{task_id}: {evaluation.reason[:80]}...",
            urgency="critical",
            icon="dialog-error",
        )
    except Exception:
        pass

    return report_path


def reset_circuit_breaker(
    workspace_root: Path,
    task_id: str,
    authorized_by: str = "human-operator",
) -> Dict[str, Any]:
    """Execute human-authorized reset-attempts command.

    Unlatches breaker state, preserves existing attempt directories intact (no resets),
    sets attempt_budget_base = current_attempt (enabling monotonic Attempt 4+ allocation),
    and transitions state to PHASE_1_PLANNING (GAP-C3, GAP-L2, GAP-X1).
    """
    state_file = workspace_root / "controls" / "ACTIVE_STATE.json"
    if not state_file.is_file():
        raise ResetAttemptsError("ACTIVE_STATE.json not found in controls directory.")

    from stagecheck.core.state import load_active_state, save_active_state

    controls_dir = workspace_root / "controls"
    with acquire_runtime_lock(controls_dir):
        with controlled_write_transaction(controls_dir):
            try:
                active_state = load_active_state(workspace_root)
            except Exception as err:
                raise ResetAttemptsError(f"Failed to read ACTIVE_STATE.json: {err}") from err

            # 1. Task Match Precondition (GAP-L2)
            current_task = active_state.get("task_id") or active_state.get("execution_progress", {}).get("current_task")
            if current_task and current_task != task_id:
                raise ResetAttemptsError(
                    f"Task ID mismatch: CLI requested reset for '{task_id}', but active task is '{current_task}'."
                )

            # 2. State Precondition: Must be tripped or in AWAITING_HUMAN_DISPOSITION
            is_tripped = active_state.get("circuit_breaker_tripped", False)
            phase = active_state.get("phase", "")
            if not is_tripped and phase not in ("AWAITING_HUMAN_DISPOSITION", "CIRCUIT_BREAKER_TRIPPED"):
                raise ResetAttemptsError(
                    f"Cannot reset task '{task_id}': Circuit breaker is not tripped (current phase: '{phase}')."
                )

            # 3. Enforce immutable hard cap of 3 attempts (FR-06 / DEC-028)
            current_attempt = active_state.get("attempt_index", 1)
            if current_attempt >= MAX_DEFAULT_ATTEMPTS:
                raise AttemptBudgetExhaustedError(
                    f"Attempt budget exhausted: task '{task_id}' has reached maximum total attempts "
                    f"({current_attempt}/{MAX_DEFAULT_ATTEMPTS}). Retries are strictly prohibited."
                )

            # 4. Unlatch breaker state with monotonic attempt budgeting and schema-compliant audit entry
            next_attempt = current_attempt + 1
            active_state["circuit_breaker_tripped"] = False
            active_state["halt_reason"] = None
            active_state.pop("halt_trigger", None)
            active_state.pop("last_reset", None)
            active_state["attempt_index"] = next_attempt
            active_state["phase"] = "PHASE_1_PLANNING"
            active_state.setdefault("resets_authorized", []).append({
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "authorized_by": authorized_by,
                "from_attempt": current_attempt,
                "to_attempt": next_attempt,
            })

            save_active_state(workspace_root, active_state)

            return active_state
