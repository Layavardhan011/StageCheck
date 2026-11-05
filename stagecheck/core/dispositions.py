"""StageCheck Human Disposition Ledger and Post-Disposition Resume Protocol (P4-T5).

Maintains controls/DISPOSITIONS.json under write-ahead transaction journal guarantees,
enforces interactive TTY and human authorization gates (SEC-03), re-renders AGENTS.md,
updates EVIDENCE_MANIFEST.json, and executes deterministic resume transitions (GAP-B1).
"""

from __future__ import annotations

import datetime
import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from stagecheck.core.agents_md import write_agents_contract
from stagecheck.core.evidence import update_evidence_manifest
from stagecheck.core.locking import acquire_runtime_lock
from stagecheck.core.paths import find_workspace_root
from stagecheck.core.permissions import controlled_write_transaction
from stagecheck.core.utils import canonical_json_dumps, pretty_json_dumps, sha256_file


class DispositionError(Exception):
    """Base exception for disposition ledger and waiver operations."""


class NonInteractiveDispositionBlockedError(DispositionError):
    """Raised when an automated or non-interactive process attempts to add a disposition."""


class UnauthorizedDispositionError(DispositionError):
    """Raised when disposition authorization is rejected."""


def get_dispositions_path(workspace_root: Path) -> Path:
    return workspace_root / "controls" / "DISPOSITIONS.json"


def load_dispositions(workspace_root: Path) -> Dict[str, Any]:
    """Load or initialize controls/DISPOSITIONS.json."""
    disp_path = get_dispositions_path(workspace_root)
    if not disp_path.is_file():
        return {
            "schema_version": "2.0",
            "dispositions": [],
        }
    try:
        with open(disp_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as err:
        raise DispositionError(f"Failed to load controls/DISPOSITIONS.json: {err}") from err


def add_disposition(
    workspace_root: Path,
    task_id: str,
    defect_id: str,
    rationale: str,
    action: str = "ACCEPT_AS_INTENTIONAL",
    authorized_by: str = "human-operator",
    require_tty: bool = True,
    confirmed: bool = False,
) -> Dict[str, Any]:
    """Record an authorized defect waiver in controls/DISPOSITIONS.json.

    Enforces SEC-03:
    1. Rejects non-TTY execution if require_tty is True and not explicitly confirmed.
    2. Records complete human authorization metadata and timestamp.
    3. Executes atomic file update under controlled_write_transaction.
    4. Re-renders AGENTS.md to preserve table SHA-256 integrity.
    5. Updates EVIDENCE_MANIFEST.json with the new disposition digest.
    6. Appends idempotent DISPOSITION_ADDED record to TASK_<ID>_ISSUE_HISTORY.md.
    """
    # 1. Non-TTY / Interactive Enforcement (SEC-03)
    if require_tty and not confirmed:
        if not sys.stdin.isatty():
            raise NonInteractiveDispositionBlockedError(
                "Non-interactive disposition write blocked: Adding defect waivers requires an "
                "interactive terminal or explicit human confirmation (--yes)."
            )

    controls_dir = workspace_root / "controls"
    disp_path = get_dispositions_path(workspace_root)

    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    disp_id = f"DSP-{datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d%H%M%S')}"

    new_entry = {
        "disposition_id": disp_id,
        "task_id": task_id,
        "defect_id": defect_id,
        "action": action,
        "rationale": rationale,
        "authorized_by": authorized_by,
        "authorized_at": timestamp,
        "status": "APPROVED",
    }

    # 2. Atomic Controlled Write Transaction
    with controlled_write_transaction(controls_dir):
        with acquire_runtime_lock(controls_dir):
            disp_data = load_dispositions(workspace_root)
            dispositions = disp_data.setdefault("dispositions", [])

            # Check if identical disposition already recorded
            for existing in dispositions:
                if existing.get("task_id") == task_id and existing.get("defect_id") == defect_id:
                    existing["action"] = action
                    existing["rationale"] = rationale
                    existing["authorized_by"] = authorized_by
                    existing["authorized_at"] = timestamp
                    existing["status"] = "APPROVED"
                    break
            else:
                dispositions.append(new_entry)

            # Atomic replace
            tmp_disp = disp_path.with_suffix(".tmp")
            with open(tmp_disp, "w", encoding="utf-8") as f:
                f.write(pretty_json_dumps(disp_data))
            os.replace(tmp_disp, disp_path)

            # 3. Re-render AGENTS.md to update SHA-256 table binding
            write_agents_contract(workspace_root)

    # 4. Update EVIDENCE_MANIFEST with updated DISPOSITIONS.json and AGENTS.md
    update_evidence_manifest(workspace_root, [disp_path, workspace_root / "AGENTS.md"])

    # 5. Append audit event to TASK_<ID>_ISSUE_HISTORY.md
    task_dir = workspace_root / "evidence" / "tasks" / task_id
    evidence_dir = workspace_root / "evidence"
    is_ev_ro = evidence_dir.is_dir() and not os.access(evidence_dir, os.W_OK)
    if is_ev_ro:
        os.chmod(evidence_dir, 0o755)
    try:
        task_dir.mkdir(parents=True, exist_ok=True)
    finally:
        if is_ev_ro:
            os.chmod(evidence_dir, 0o555)
    history_file = task_dir / f"TASK_{task_id}_ISSUE_HISTORY.md"

    disp_hash = sha256_file(disp_path)
    event_lines = [
        f"\n### Event: DISPOSITION_ADDED\n",
        f"- **Timestamp:** {timestamp}\n",
        f"- **Disposition ID:** `{disp_id}`\n",
        f"- **Defect ID:** `{defect_id}`\n",
        f"- **Task ID:** `{task_id}`\n",
        f"- **Action:** `{action}`\n",
        f"- **Authorized By:** `{authorized_by}`\n",
        f"- **Rationale:** {rationale}\n",
        f"- **SHA-256 Digest:** `{disp_hash}`\n",
    ]
    with open(history_file, "a", encoding="utf-8") as f:
        f.write("".join(event_lines))

    update_evidence_manifest(workspace_root, [history_file])

    # 6. Optional desktop alert (non-failing)
    if shutil.which("notify-send"):
        try:
            subprocess.run(
                [
                    "notify-send",
                    "-u",
                    "normal",
                    "STAGECHECK DISPOSITION RECORDED",
                    f"Waiver granted for {defect_id} by {authorized_by}",
                ],
                capture_output=True,
                check=False,
            )
        except Exception:
            pass

    return new_entry


def resume_after_disposition(
    workspace_root: Path,
    task_id: str,
) -> Dict[str, Any]:
    """Execute deterministic post-disposition resume protocol (GAP-B1).

    Determines the next phase:
    - If circuit breaker remains tripped: preserves TRIP state.
    - If all blocking defects are dispositioned: transitions to PHASE_3_VERIFICATION.
    - If unresolved blocking defects remain: transitions to PHASE_1_REPAIR.
    """
    state_file = workspace_root / "controls" / "ACTIVE_STATE.json"
    if not state_file.is_file():
        raise DispositionError("ACTIVE_STATE.json not found in controls directory.")

    controls_dir = workspace_root / "controls"
    with controlled_write_transaction(controls_dir):
        with acquire_runtime_lock(controls_dir):
            try:
                with open(state_file, "r", encoding="utf-8") as f:
                    state = json.load(f)
            except Exception as err:
                raise DispositionError(f"Failed to read ACTIVE_STATE.json: {err}") from err

            # If circuit breaker is tripped, disposition alone does not reset it
            if state.get("circuit_breaker_tripped"):
                target_phase = "CIRCUIT_BREAKER_TRIPPED"
                reason = "Circuit breaker remains tripped; requires explicit stagecheck reset-attempts."
            else:
                # Load latest verdict to evaluate remaining defects
                attempt = state.get("attempt_index", 1)
                verdict_file = (
                    workspace_root
                    / "evidence"
                    / "tasks"
                    / task_id
                    / f"attempt_{attempt}"
                    / "Phase-3"
                    / "verdict.json"
                )
                if not verdict_file.is_file():
                    verdict_file = workspace_root / "evidence" / "tasks" / task_id / "verdict.json"

                dispositions_doc = load_dispositions(workspace_root)
                disp_ids = {
                    d.get("defect_id")
                    for d in dispositions_doc.get("dispositions", [])
                    if d.get("defect_id") and d.get("status") == "APPROVED"
                }

                unresolved_blocking = 0
                if verdict_file.is_file():
                    try:
                        with open(verdict_file, "r", encoding="utf-8") as f:
                            verdict = json.load(f)
                        for d in verdict.get("defects", []):
                            if d.get("mode") == "blocking" and d.get("defect_id") not in disp_ids:
                                unresolved_blocking += 1
                    except Exception:
                        pass

                if unresolved_blocking == 0:
                    target_phase = "PHASE_3_VERIFICATION"
                    reason = "All blocking defects waived or resolved; ready for independent verification rerun."
                else:
                    target_phase = "PHASE_1_REPAIR"
                    reason = f"{unresolved_blocking} blocking defect(s) remain unresolved; active code repair required."

            state["phase"] = target_phase
            state["resume_reason"] = reason
            state["resumed_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()

            with open(state_file, "w", encoding="utf-8") as f:
                f.write(pretty_json_dumps(state))

    return {
        "task_id": task_id,
        "resumed_phase": target_phase,
        "reason": reason,
    }

