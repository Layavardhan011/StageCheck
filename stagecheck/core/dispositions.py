"""StageCheck Human Disposition Ledger and Post-Disposition Resume Protocol (P4-T5).

Maintains controls/DISPOSITIONS.json under write-ahead transaction journal guarantees,
enforces interactive TTY and human authorization gates (SEC-03), re-renders AGENTS.md,
updates EVIDENCE_MANIFEST.json, and executes deterministic resume transitions (GAP-B1).
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from stagecheck.core.agents_md import write_agents_contract
from stagecheck.core.evidence import update_evidence_manifest
from stagecheck.core.locking import acquire_runtime_lock
from stagecheck.core.paths import (
    StageCheckPathError,
    find_workspace_root,
    resolve_task_dir,
    safe_resolve,
    validate_task_id,
)
from stagecheck.core.permissions import controlled_write_transaction
from stagecheck.core.utils import canonical_json_dumps, pretty_json_dumps, sha256_file


_TASK_ID_REGEX = re.compile(r"^[a-zA-Z0-9_-]+$")
_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
_TRIVIAL_RATIONALES = frozenset({"ok", "na", "n/a", "none", "skip", "todo", "bypass", "waive", "approved", "pass"})
_NON_HUMAN_IDENTITIES = frozenset({
    "agent",
    "agent1",
    "agent2",
    "agent-1",
    "agent-2",
    "agent_1",
    "agent_2",
    "codex",
    "claude",
    "gemini",
    "copilot",
    "gpt",
    "llm",
    "bot",
    "system",
    "auto",
    "automated",
    "automation",
    "generic",
    "generic_evaluator",
    "subagent",
    "ai",
    "prompt_and_audit",
    "code_implementation",
    "dual_role",
})
_NON_HUMAN_PATTERN = re.compile(r"^(agent[-_ ]?\d+|.*[-_]bot|bot[-_].*|system[-_]?auto)$", re.IGNORECASE)
_BACKTICK_TOKEN_RE = re.compile(r"`([^`]+)`")
_OWNER_LINE_RE = re.compile(r"(?:authorized\s+owner|operator|human\s+owner|approver)\s*:\s*`?([A-Za-z0-9_.@+-]+)`?", re.IGNORECASE)
_PERMISSIONS_SECTION_RE = re.compile(r"permissions\s*:\s*([A-Za-z0-9_, *+-]+)", re.IGNORECASE)


class DispositionError(Exception):
    """Base exception for disposition ledger and waiver operations."""


class NonInteractiveDispositionBlockedError(DispositionError):
    """Raised when an automated or non-interactive process attempts to add a disposition."""


class UnauthorizedDispositionError(DispositionError):
    """Raised when disposition authorization, identity, evidence, or grants fail closed."""


class DispositionReplayError(DispositionError):
    """Raised when a waiver nonce, digest, or revoked/finalized disposition is replayed."""


def _parse_utc_iso(raw: Any) -> Optional[datetime.datetime]:
    """Parse an ISO-8601 timestamp into timezone-aware UTC datetime, or return None."""
    if not isinstance(raw, str) or not raw.strip():
        return None
    val = raw.strip()
    if val.endswith("Z"):
        val = val[:-1] + "+00:00"
    try:
        dt = datetime.datetime.fromisoformat(val)
    except ValueError:
        return None
    if dt.tzinfo is None:
        return None
    return dt.astimezone(datetime.timezone.utc)


def _load_active_state_safe(workspace_root: Path) -> Dict[str, Any]:
    state_file = workspace_root / "controls" / "ACTIVE_STATE.json"
    if not state_file.is_file() or state_file.is_symlink():
        return {}
    try:
        data = json.loads(state_file.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def is_human_identity(
    identity: Any,
    active_state: Optional[Dict[str, Any]] = None,
) -> bool:
    """Return True only when identity represents a distinct human operator, never an AI agent/bot."""
    if not isinstance(identity, str):
        return False
    ident = identity.strip()
    if len(ident) < 3 or ident in ("*", "any", "all"):
        return False
    lower = ident.lower()
    if lower in _NON_HUMAN_IDENTITIES or _NON_HUMAN_PATTERN.match(lower):
        return False
    if any(tok in lower for tok in ("agent-", "agent_", "codex", "claude", "gemini", "llm")):
        return False

    if isinstance(active_state, dict):
        reg = active_state.get("registered_agents")
        if reg is None and isinstance(active_state.get("protected"), dict):
            reg = active_state["protected"].get("registered_agents")
        entries: List[Tuple[Optional[str], Any]] = []
        if isinstance(reg, dict):
            entries = list(reg.items())
        elif isinstance(reg, list):
            entries = [(None, item) for item in reg]
        for key, info in entries:
            if isinstance(key, str) and key.strip().lower() == lower:
                return False
            if isinstance(info, dict):
                for field in ("agent_id", "id", "name", "provider", "model", "role"):
                    val = info.get(field)
                    if isinstance(val, str) and val.strip().lower() == lower:
                        return False
    return True


def parse_owner_grants(workspace_root: Path) -> Dict[str, Set[str]]:
    """Parse human operator identities and permissions strictly from controls/OWNER_GRANTS.md."""
    grants_path = workspace_root.resolve() / "controls" / "OWNER_GRANTS.md"
    if grants_path.is_symlink():
        raise UnauthorizedDispositionError("controls/OWNER_GRANTS.md cannot be a symbolic link.")
    if not grants_path.is_file():
        raise UnauthorizedDispositionError("Missing controls/OWNER_GRANTS.md; cannot verify human waiver grants.")

    try:
        text = grants_path.read_text(encoding="utf-8")
    except Exception as err:
        raise UnauthorizedDispositionError(f"Failed to read controls/OWNER_GRANTS.md: {err}") from err

    active_state = _load_active_state_safe(workspace_root.resolve())
    grants: Dict[str, Set[str]] = {}
    in_identity_section = False

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("#"):
            hdr = line.lstrip("#").strip().lower()
            in_identity_section = any(k in hdr for k in ("operator", "owner", "identity", "identities", "approver"))
            continue

        matched_id: Optional[str] = None
        m = _OWNER_LINE_RE.search(line)
        if m:
            matched_id = m.group(1).strip()
        elif in_identity_section and (line.startswith("*") or line.startswith("-") or line.startswith("|")):
            bt = _BACKTICK_TOKEN_RE.search(line)
            if bt:
                matched_id = bt.group(1).strip()

        if not matched_id:
            continue
        if matched_id in ("*", "any", "all") or not is_human_identity(matched_id, active_state):
            continue

        pm = _PERMISSIONS_SECTION_RE.search(line)
        if pm:
            perms = {
                tok.strip().upper()
                for tok in re.split(r"[,;\s]+", pm.group(1))
                if tok.strip()
            }
        else:
            perms = {"OWNER", "WAIVER_APPROVE", "WAIVER_REVOKE", "GATE_OVERRIDE", "CIRCUIT_BREAKER_RESET"}
        grants.setdefault(matched_id, set()).update(perms)

    return grants


def compute_waiver_digest(entry: Dict[str, Any]) -> str:
    """Compute canonical SHA-256 provenance digest binding a waiver to task, attempt, evidence, and nonce."""
    attempt_val = entry.get("attempt") if entry.get("attempt") is not None else entry.get("attempt_index")
    payload = {
        "disposition_id": entry.get("disposition_id"),
        "task_id": entry.get("task_id"),
        "attempt": attempt_val,
        "defect_id": entry.get("defect_id"),
        "rule_id": entry.get("rule_id"),
        "waived_rules": sorted(str(x) for x in (entry.get("waived_rules") or [])),
        "action": entry.get("action"),
        "authorized_by": entry.get("authorized_by"),
        "authorized_role": entry.get("authorized_role", "OWNER"),
        "permissions": sorted(str(x).upper() for x in (entry.get("permissions") or ["WAIVER_APPROVE"])),
        "explicit_approval": bool(entry.get("explicit_approval")),
        "rationale": entry.get("rationale"),
        "evidence_path": entry.get("evidence_path") or entry.get("evidence"),
        "evidence_sha256": entry.get("evidence_sha256"),
        "authorized_at": entry.get("authorized_at"),
        "expires_at": entry.get("expires_at"),
        "nonce": entry.get("nonce"),
    }
    return hashlib.sha256(canonical_json_dumps(payload).encode("utf-8")).hexdigest()


def _replay_ledger_path(workspace_root: Path) -> Path:
    return workspace_root.resolve() / "evidence" / "waiver_replay_ledger.json"


def _load_replay_ledger(workspace_root: Path) -> Dict[str, Any]:
    path = _replay_ledger_path(workspace_root)
    if path.is_symlink():
        raise DispositionReplayError("evidence/waiver_replay_ledger.json cannot be a symbolic link.")
    if not path.is_file():
        return {"schema_version": "1.0", "nonces": {}, "disposition_ids": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("ledger root must be an object")
        data.setdefault("nonces", {})
        data.setdefault("disposition_ids", {})
        return data
    except Exception as err:
        raise DispositionReplayError(f"Malformed waiver replay ledger: {err}") from err


def _save_replay_ledger(workspace_root: Path, ledger: Dict[str, Any]) -> None:
    evidence_dir = workspace_root.resolve() / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    path = _replay_ledger_path(workspace_root)
    is_ev_ro = not os.access(evidence_dir, os.W_OK)
    if is_ev_ro:
        os.chmod(evidence_dir, 0o755)
    was_file_ro = path.exists() and not os.access(path, os.W_OK)
    if was_file_ro:
        os.chmod(path, 0o644)
    try:
        tmp = path.with_suffix(".tmp")
        tmp.write_text(pretty_json_dumps(ledger), encoding="utf-8")
        os.replace(tmp, path)
    finally:
        if was_file_ro and path.exists():
            os.chmod(path, 0o444)
        if is_ev_ro:
            os.chmod(evidence_dir, 0o555)


def record_waiver_in_replay_ledger(
    workspace_root: Path,
    entry: Dict[str, Any],
    status_override: Optional[str] = None,
    finalized: Optional[bool] = None,
) -> None:
    """Persist waiver nonce & digest state into evidence/waiver_replay_ledger.json."""
    nonce = entry.get("nonce")
    disp_id = entry.get("disposition_id")
    if not nonce or not disp_id:
        return
    ledger = _load_replay_ledger(workspace_root)
    nonces = ledger.setdefault("nonces", {})
    disp_ids = ledger.setdefault("disposition_ids", {})
    prev = nonces.get(nonce, {}) if isinstance(nonces.get(nonce), dict) else {}
    attempt_val = entry.get("attempt") if entry.get("attempt") is not None else entry.get("attempt_index")
    nonces[nonce] = {
        "disposition_id": disp_id,
        "task_id": entry.get("task_id"),
        "attempt": attempt_val,
        "waiver_digest": entry.get("waiver_digest"),
        "status": status_override or entry.get("status", "APPROVED"),
        "finalized": prev.get("finalized", False) if finalized is None else bool(finalized),
        "recorded_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    disp_ids[disp_id] = nonce
    _save_replay_ledger(workspace_root, ledger)


def mark_waivers_finalized(workspace_root: Path, task_id: str, attempt: int) -> None:
    """Seal all waivers belonging to (task_id, attempt) as finalized to prevent cross-attempt replay."""
    disp_data = load_dispositions(workspace_root)
    ledger = _load_replay_ledger(workspace_root)
    changed = False
    for entry in disp_data.get("dispositions", []):
        if not isinstance(entry, dict):
            continue
        ent_attempt = entry.get("attempt") if entry.get("attempt") is not None else entry.get("attempt_index")
        if entry.get("task_id") == task_id and ent_attempt == attempt:
            nonce = entry.get("nonce")
            disp_id = entry.get("disposition_id")
            if nonce:
                rec = ledger.setdefault("nonces", {}).setdefault(nonce, {
                    "disposition_id": disp_id,
                    "task_id": task_id,
                    "attempt": attempt,
                    "waiver_digest": entry.get("waiver_digest"),
                    "status": entry.get("status", "APPROVED"),
                })
                if not rec.get("finalized"):
                    rec["finalized"] = True
                    rec["finalized_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
                    changed = True
                if disp_id:
                    ledger.setdefault("disposition_ids", {})[disp_id] = nonce
    if changed:
        _save_replay_ledger(workspace_root, ledger)


def build_waiver_entry(
    workspace_root: Path,
    task_id: str,
    defect_id: str,
    rationale: str,
    authorized_by: str,
    attempt: int = 1,
    evidence_path: str = "",
    action: str = "ACCEPT_AS_INTENTIONAL",
    authorized_role: str = "OWNER",
    permissions: Optional[List[str]] = None,
    expires_at: Optional[str] = None,
    rule_id: Optional[str] = None,
    waived_rules: Optional[List[str]] = None,
    explicit_approval: bool = True,
) -> Dict[str, Any]:
    """Build a provenance-complete waiver entry with evidence SHA-256, nonce, and waiver_digest."""
    ws = workspace_root.resolve()
    if not evidence_path:
        raise DispositionError("Supporting evidence_path is required to construct a human waiver.")
    resolved_ev = safe_resolve(evidence_path, ws, allow_symlinks=False)
    if resolved_ev.is_symlink() or not resolved_ev.is_file():
        raise DispositionError(f"Supporting waiver evidence file missing or invalid: '{evidence_path}'.")

    now_utc = datetime.datetime.now(datetime.timezone.utc)
    ts = now_utc.isoformat()
    exp_ts = expires_at or (now_utc + datetime.timedelta(hours=24)).isoformat()
    nonce = secrets.token_hex(16)
    disp_id = f"DSP-{now_utc.strftime('%Y%m%d%H%M%S')}-{nonce[:8]}"
    rel_ev = os.path.relpath(resolved_ev, ws).replace("\\", "/")

    entry: Dict[str, Any] = {
        "disposition_id": disp_id,
        "task_id": task_id,
        "attempt": int(attempt),
        "defect_id": defect_id,
        "action": action,
        "rationale": rationale,
        "authorized_by": authorized_by,
        "authorized_role": authorized_role,
        "permissions": list(permissions or ["WAIVER_APPROVE"]),
        "explicit_approval": bool(explicit_approval),
        "evidence_path": rel_ev,
        "evidence_sha256": sha256_file(resolved_ev),
        "authorized_at": ts,
        "expires_at": exp_ts,
        "nonce": nonce,
        "status": "APPROVED",
    }
    if rule_id is not None:
        entry["rule_id"] = rule_id
    if waived_rules is not None:
        entry["waived_rules"] = list(waived_rules)
    entry["waiver_digest"] = compute_waiver_digest(entry)
    return entry


def validate_waiver_provenance(
    workspace_root: Path,
    entry: Dict[str, Any],
    task_id: str,
    attempt: int,
    required_rule_id: Optional[str] = None,
    all_entries: Optional[List[Dict[str, Any]]] = None,
    now_utc: Optional[datetime.datetime] = None,
) -> Tuple[bool, str]:
    """Fail-closed validation of all GAP-03 human-waiver provenance requirements."""
    if not isinstance(entry, dict):
        return False, "Waiver entry must be an object."

    ws = workspace_root.resolve()
    now = now_utc or datetime.datetime.now(datetime.timezone.utc)

    # 1. Explicit approval & non-revoked status
    status = str(entry.get("status", "")).upper()
    if entry.get("revoked_at") or status == "REVOKED":
        return False, f"Waiver '{entry.get('disposition_id')}' has been REVOKED."
    if status != "APPROVED":
        return False, f"Waiver status is '{status or 'MISSING'}', expected 'APPROVED'."
    if entry.get("explicit_approval") is not True:
        return False, "Waiver lacks explicit_approval=true attestation."

    # 2. Task & attempt binding (reject wildcards & missing attempt)
    ent_task = entry.get("task_id")
    if not isinstance(ent_task, str) or ent_task == "*" or ent_task != task_id:
        return False, f"Waiver task_id '{ent_task}' does not match active task '{task_id}'."

    ent_attempt = entry.get("attempt") if entry.get("attempt") is not None else entry.get("attempt_index")
    if isinstance(ent_attempt, bool) or not isinstance(ent_attempt, int) or ent_attempt != attempt:
        return False, f"Waiver attempt '{ent_attempt}' does not match active attempt '{attempt}'."

    if required_rule_id is not None:
        waived_list = entry.get("waived_rules") or []
        if isinstance(waived_list, list) and "*" in waived_list:
            return False, "Wildcard '*' waived_rules is prohibited."
        rule_match = (
            entry.get("rule_id") == required_rule_id
            or entry.get("defect_id") == required_rule_id
            or (isinstance(waived_list, list) and required_rule_id in waived_list)
        )
        if not rule_match:
            return False, f"Waiver does not explicitly name rule/defect '{required_rule_id}'."

    # 3. Human identity & OWNER_GRANTS.md permission check
    authorized_by = entry.get("authorized_by")
    active_state = _load_active_state_safe(ws)
    if not is_human_identity(authorized_by, active_state):
        return False, f"Identity '{authorized_by}' is not a valid human operator identity (agents/bots prohibited)."

    auth_role = str(entry.get("authorized_role", "OWNER")).strip()
    if auth_role.lower() in ("prompt_and_audit", "code_implementation", "dual_role", "agent", "bot"):
        return False, f"Invalid human waiver role '{auth_role}'."

    try:
        grants = parse_owner_grants(ws)
    except UnauthorizedDispositionError as err:
        return False, str(err)

    if authorized_by not in grants:
        return False, f"Operator '{authorized_by}' is not authorized in controls/OWNER_GRANTS.md."

    granted_perms = grants[authorized_by]
    if "WAIVER_APPROVE" not in granted_perms and "OWNER" not in granted_perms and "WAIVER_ALL" not in granted_perms:
        return False, f"Operator '{authorized_by}' lacks WAIVER_APPROVE grant in OWNER_GRANTS.md."

    entry_perms = entry.get("permissions")
    if entry_perms is not None:
        if not isinstance(entry_perms, list) or not any(str(p).upper() in ("WAIVER_APPROVE", "OWNER", "WAIVER_ALL") for p in entry_perms):
            return False, "Waiver permissions list does not include WAIVER_APPROVE."

    # 4. Meaningful rationale
    rationale = entry.get("rationale")
    if not isinstance(rationale, str) or len(rationale.strip()) < 8 or rationale.strip().lower() in _TRIVIAL_RATIONALES:
        return False, "Waiver rationale is missing, trivial, or below minimum justification length (8 chars)."

    # 5. Supporting evidence file & SHA-256 verification
    ev_rel = entry.get("evidence_path") or entry.get("evidence")
    ev_sha = entry.get("evidence_sha256")
    if not isinstance(ev_rel, str) or not ev_rel.strip():
        return False, "Waiver missing supporting evidence_path."
    if not isinstance(ev_sha, str) or not _SHA256_HEX_RE.match(ev_sha):
        return False, "Waiver missing valid 64-hex evidence_sha256."
    try:
        ev_file = safe_resolve(ev_rel, ws, allow_symlinks=False)
    except StageCheckPathError as err:
        return False, f"Unsafe waiver evidence_path '{ev_rel}': {err}"
    if ev_file.is_symlink() or not ev_file.is_file():
        return False, f"Supporting waiver evidence file not found at '{ev_rel}'."
    if sha256_file(ev_file) != ev_sha:
        return False, f"Waiver evidence_sha256 mismatch for '{ev_rel}'."

    # 6. Timestamps & expiry
    auth_dt = _parse_utc_iso(entry.get("authorized_at"))
    exp_dt = _parse_utc_iso(entry.get("expires_at"))
    if auth_dt is None:
        return False, "Waiver missing valid timezone-aware UTC authorized_at timestamp."
    if exp_dt is None:
        return False, "Waiver missing valid timezone-aware UTC expires_at timestamp."
    if auth_dt > now + datetime.timedelta(seconds=60):
        return False, "Waiver authorized_at timestamp is unexpectedly in the future."
    if exp_dt <= auth_dt:
        return False, "Waiver expires_at must be strictly later than authorized_at."
    if exp_dt <= now:
        return False, f"Waiver expired at {entry.get('expires_at')}."

    # 7. Replay prevention: nonce, disposition_id, digest, uniqueness & replay ledger
    disp_id = entry.get("disposition_id")
    nonce = entry.get("nonce")
    waiver_digest = entry.get("waiver_digest")
    if not isinstance(disp_id, str) or not disp_id.strip():
        return False, "Waiver missing disposition_id."
    if not isinstance(nonce, str) or len(nonce.strip()) < 12:
        return False, "Waiver missing valid anti-replay nonce (>=12 chars)."
    if not isinstance(waiver_digest, str) or not _SHA256_HEX_RE.match(waiver_digest):
        return False, "Waiver missing valid 64-hex waiver_digest."
    if compute_waiver_digest(entry) != waiver_digest:
        return False, "Waiver waiver_digest mismatch (tampering or unsigned manual edit detected)."

    if isinstance(all_entries, list):
        same_nonce = sum(1 for e in all_entries if isinstance(e, dict) and e.get("nonce") == nonce)
        same_id = sum(1 for e in all_entries if isinstance(e, dict) and e.get("disposition_id") == disp_id)
        if same_nonce > 1:
            return False, f"Duplicate waiver nonce '{nonce}' detected (replay attempt)."
        if same_id > 1:
            return False, f"Duplicate disposition_id '{disp_id}' detected."

    try:
        ledger = _load_replay_ledger(ws)
    except DispositionReplayError as err:
        return False, str(err)

    nonces_map = ledger.get("nonces", {})
    disp_ids_map = ledger.get("disposition_ids", {})
    if disp_id in disp_ids_map and disp_ids_map[disp_id] != nonce:
        return False, f"Disposition ID '{disp_id}' was previously bound to another nonce (replay attempt)."
    if nonce in nonces_map:
        rec = nonces_map[nonce]
        if rec.get("status") == "REVOKED":
            return False, f"Nonce '{nonce}' belongs to a REVOKED waiver and cannot be reused."
        if rec.get("finalized"):
            return False, f"Nonce '{nonce}' belongs to a finalized attempt and cannot be replayed."
        if (
            rec.get("task_id") != task_id
            or rec.get("attempt") != attempt
            or rec.get("waiver_digest") != waiver_digest
            or rec.get("disposition_id") != disp_id
        ):
            return False, f"Nonce '{nonce}' replay detected across mismatched task/attempt/digest."

    return True, "OK"


def _validate_task_id(task_id: str) -> None:
    """Validate task identifier against strict path-safe slug rules."""
    try:
        validate_task_id(task_id)
    except ValueError as err:
        raise DispositionError(str(err)) from err


def _resolve_task_evidence_dir(workspace_root: Path, task_id: str) -> Path:
    """Validate task_id and safely resolve its directory inside evidence/tasks/."""
    try:
        return resolve_task_dir(workspace_root, task_id)
    except ValueError as err:
        raise DispositionError(str(err)) from err
    except StageCheckPathError as err:
        raise DispositionError(f"Security policy violation [PATH_CONTAINMENT]: {err}") from err


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
    authorized_by: str = "",
    require_tty: bool = True,
    confirmed: bool = False,
    attempt: Optional[int] = None,
    evidence_path: Optional[str] = None,
    expires_at: Optional[str] = None,
    authorized_role: str = "OWNER",
    permissions: Optional[List[str]] = None,
    rule_id: Optional[str] = None,
    waived_rules: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Record a provenance-verified human defect waiver in controls/DISPOSITIONS.json.

    Enforces SEC-03 & GAP-03:
    1. Rejects non-TTY execution if require_tty is True and not explicitly confirmed.
    2. Validates human identity (no AI agents), controls/OWNER_GRANTS.md permission,
       non-trivial rationale, existing supporting evidence SHA-256, attempt binding,
       expiry timestamp, and unique anti-replay nonce/waiver_digest.
    3. Executes atomic file update under controlled_write_transaction & replay ledger.
    4. Re-renders AGENTS.md, updates EVIDENCE_MANIFEST.json, and appends issue history.
    """
    ws = Path(workspace_root).resolve()
    _validate_task_id(task_id)

    # 1. Non-TTY / Interactive Enforcement (SEC-03)
    if require_tty and not confirmed:
        if not sys.stdin.isatty():
            raise NonInteractiveDispositionBlockedError(
                "Non-interactive disposition write blocked: Adding defect waivers requires an "
                "interactive terminal or explicit human confirmation (--yes)."
            )

    active_state = _load_active_state_safe(ws)
    if attempt is None:
        raw_attempt = active_state.get("attempt_index", 1)
        attempt_val = int(raw_attempt) if isinstance(raw_attempt, int) and not isinstance(raw_attempt, bool) and raw_attempt >= 1 else 1
    else:
        if isinstance(attempt, bool) or not isinstance(attempt, int) or attempt < 1:
            raise DispositionError(f"Invalid attempt '{attempt}' for disposition.")
        attempt_val = attempt

    if not is_human_identity(authorized_by, active_state):
        raise UnauthorizedDispositionError(
            f"Authorized identity '{authorized_by}' is missing or belongs to a non-human/agent identifier."
        )

    if authorized_role.strip().lower() in ("prompt_and_audit", "code_implementation", "dual_role", "agent", "bot"):
        raise UnauthorizedDispositionError(f"Invalid human waiver role '{authorized_role}'.")

    grants = parse_owner_grants(ws)
    if authorized_by not in grants:
        raise UnauthorizedDispositionError(
            f"Operator '{authorized_by}' is not authorized in controls/OWNER_GRANTS.md."
        )
    granted_perms = grants[authorized_by]
    if "WAIVER_APPROVE" not in granted_perms and "OWNER" not in granted_perms and "WAIVER_ALL" not in granted_perms:
        raise UnauthorizedDispositionError(
            f"Operator '{authorized_by}' does not hold WAIVER_APPROVE permission in controls/OWNER_GRANTS.md."
        )

    if not isinstance(rationale, str) or len(rationale.strip()) < 8 or rationale.strip().lower() in _TRIVIAL_RATIONALES:
        raise DispositionError(
            "Waiver rationale must be at least 8 non-trivial characters explaining human justification."
        )

    if not isinstance(evidence_path, str) or not evidence_path.strip():
        raise UnauthorizedDispositionError(
            "Supporting evidence file (--evidence / evidence_path) is required for human waiver provenance."
        )

    now_utc = datetime.datetime.now(datetime.timezone.utc)
    if expires_at is not None:
        exp_dt = _parse_utc_iso(expires_at)
        if exp_dt is None or exp_dt <= now_utc:
            raise DispositionError(f"Waiver expires_at '{expires_at}' must be a valid future UTC ISO-8601 timestamp.")

    new_entry = build_waiver_entry(
        workspace_root=ws,
        task_id=task_id,
        defect_id=defect_id,
        rationale=rationale,
        authorized_by=authorized_by,
        attempt=attempt_val,
        evidence_path=evidence_path,
        action=action,
        authorized_role=authorized_role,
        permissions=permissions or ["WAIVER_APPROVE"],
        expires_at=expires_at,
        rule_id=rule_id,
        waived_rules=waived_rules,
        explicit_approval=True,
    )
    ok_prov, reason_prov = validate_waiver_provenance(
        ws, new_entry, task_id=task_id, attempt=attempt_val, now_utc=now_utc
    )
    if not ok_prov:
        raise UnauthorizedDispositionError(reason_prov)

    controls_dir = ws / "controls"
    disp_path = get_dispositions_path(ws)
    timestamp = new_entry["authorized_at"]
    disp_id = new_entry["disposition_id"]

    # 2. Atomic Controlled Write Transaction (lock-first ordering)
    with acquire_runtime_lock(controls_dir):
        with controlled_write_transaction(controls_dir):
            disp_data = load_dispositions(ws)
            dispositions = disp_data.setdefault("dispositions", [])

            # Supersede only active unrevoked entry for identical (task_id, attempt, defect_id);
            # never resurrect REVOKED entries and always rotate nonce/digest.
            superseded: Optional[Dict[str, Any]] = None
            new_list: List[Dict[str, Any]] = []
            for existing in dispositions:
                ex_att = existing.get("attempt") if existing.get("attempt") is not None else existing.get("attempt_index")
                if (
                    existing.get("task_id") == task_id
                    and ex_att == attempt_val
                    and existing.get("defect_id") == defect_id
                    and existing.get("status") == "APPROVED"
                ):
                    superseded = existing
                    continue
                new_list.append(existing)
            new_list.append(new_entry)
            disp_data["dispositions"] = new_list

            # Atomic replace
            tmp_disp = disp_path.with_suffix(".tmp")
            with open(tmp_disp, "w", encoding="utf-8") as f:
                f.write(pretty_json_dumps(disp_data))
            os.replace(tmp_disp, disp_path)

            # 3. Re-render AGENTS.md to update SHA-256 table binding
            write_agents_contract(ws)

    if superseded and superseded.get("nonce"):
        record_waiver_in_replay_ledger(ws, superseded, status_override="SUPERSEDED", finalized=True)
    record_waiver_in_replay_ledger(ws, new_entry, status_override="APPROVED", finalized=False)

    # 4. Update EVIDENCE_MANIFEST with updated DISPOSITIONS.json and AGENTS.md
    update_evidence_manifest(ws, [disp_path, ws / "AGENTS.md", _replay_ledger_path(ws)])

    # 5. Append audit event to TASK_<ID>_ISSUE_HISTORY.md (no symlink follow)
    task_dir = _resolve_task_evidence_dir(ws, task_id)
    evidence_dir = ws / "evidence"
    is_ev_ro = evidence_dir.is_dir() and not os.access(evidence_dir, os.W_OK)
    if is_ev_ro:
        os.chmod(evidence_dir, 0o755)
    try:
        task_dir.mkdir(parents=True, exist_ok=True)
    finally:
        if is_ev_ro:
            os.chmod(evidence_dir, 0o555)
    history_file = safe_resolve(f"TASK_{task_id}_ISSUE_HISTORY.md", task_dir, allow_symlinks=False)
    if history_file.is_symlink():
        raise DispositionError(f"Refusing to follow symlinked issue history '{history_file}'.")

    disp_hash = sha256_file(disp_path)
    event_lines = [
        f"\n### Event: DISPOSITION_ADDED\n",
        f"- **Timestamp:** {timestamp}\n",
        f"- **Disposition ID:** `{disp_id}`\n",
        f"- **Attempt:** {attempt_val}\n",
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
    try:
        from stagecheck.core.sentinel import send_desktop_notification
        send_desktop_notification(
            title="STAGECHECK DISPOSITION RECORDED",
            message=f"Waiver granted for {defect_id} by {authorized_by}",
            urgency="normal",
        )
    except Exception:
        pass

    return new_entry


def revoke_disposition(
    workspace_root: Path,
    task_id: str,
    revoked_by: str,
    reason: str,
    disposition_id: Optional[str] = None,
    defect_id: Optional[str] = None,
    attempt: Optional[int] = None,
    require_tty: bool = True,
    confirmed: bool = False,
) -> Dict[str, Any]:
    """Revoke an active human disposition, bind revocation in replay ledger, and fail closed thereafter."""
    ws = Path(workspace_root).resolve()
    _validate_task_id(task_id)

    if require_tty and not confirmed and not sys.stdin.isatty():
        raise NonInteractiveDispositionBlockedError(
            "Non-interactive disposition revocation blocked: requires TTY or explicit confirmation (--yes)."
        )

    active_state = _load_active_state_safe(ws)
    if not is_human_identity(revoked_by, active_state):
        raise UnauthorizedDispositionError(f"Revoker '{revoked_by}' is not a valid human operator identity.")

    grants = parse_owner_grants(ws)
    if revoked_by not in grants:
        raise UnauthorizedDispositionError(f"Operator '{revoked_by}' is not listed in controls/OWNER_GRANTS.md.")
    perms = grants[revoked_by]
    if "WAIVER_REVOKE" not in perms and "OWNER" not in perms and "WAIVER_ALL" not in perms:
        raise UnauthorizedDispositionError(f"Operator '{revoked_by}' lacks WAIVER_REVOKE grant.")

    if not isinstance(reason, str) or len(reason.strip()) < 5:
        raise DispositionError("Revocation requires a non-empty reason (>=5 chars).")

    if not disposition_id and not defect_id:
        raise DispositionError("Revocation requires either disposition_id or defect_id.")

    controls_dir = ws / "controls"
    disp_path = get_dispositions_path(ws)
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    revoked_entry: Optional[Dict[str, Any]] = None

    with acquire_runtime_lock(controls_dir):
        with controlled_write_transaction(controls_dir):
            disp_data = load_dispositions(ws)
            dispositions = disp_data.setdefault("dispositions", [])
            for entry in dispositions:
                if entry.get("task_id") != task_id:
                    continue
                if attempt is not None:
                    ex_att = entry.get("attempt") if entry.get("attempt") is not None else entry.get("attempt_index")
                    if ex_att != attempt:
                        continue
                if disposition_id and entry.get("disposition_id") != disposition_id:
                    continue
                if defect_id and entry.get("defect_id") != defect_id and entry.get("rule_id") != defect_id:
                    continue
                if entry.get("status") == "REVOKED":
                    continue
                entry["status"] = "REVOKED"
                entry["revoked_at"] = timestamp
                entry["revoked_by"] = revoked_by
                entry["revocation_reason"] = reason
                revoked_entry = entry
                break

            if revoked_entry is None:
                raise DispositionError(
                    f"No active matching disposition found for task '{task_id}' "
                    f"(disposition_id={disposition_id}, defect_id={defect_id})."
                )

            tmp_disp = disp_path.with_suffix(".tmp")
            with open(tmp_disp, "w", encoding="utf-8") as f:
                f.write(pretty_json_dumps(disp_data))
            os.replace(tmp_disp, disp_path)
            write_agents_contract(ws)

    record_waiver_in_replay_ledger(ws, revoked_entry, status_override="REVOKED", finalized=True)
    update_evidence_manifest(ws, [disp_path, ws / "AGENTS.md", _replay_ledger_path(ws)])
    return revoked_entry


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
    _validate_task_id(task_id)
    state_file = workspace_root / "controls" / "ACTIVE_STATE.json"
    if not state_file.is_file():
        raise DispositionError("ACTIVE_STATE.json not found in controls directory.")

    controls_dir = workspace_root / "controls"
    with acquire_runtime_lock(controls_dir):
        with controlled_write_transaction(controls_dir):
            try:
                with open(state_file, "r", encoding="utf-8") as f:
                    state = json.load(f)
            except Exception as err:
                raise DispositionError(f"Failed to read ACTIVE_STATE.json: {err}") from err

            active_task = state.get("task_id")
            if active_task and active_task != task_id:
                raise DispositionError(
                    f"Task mismatch on resume: requested '{task_id}', active state tracks '{active_task}'."
                )

            # If circuit breaker is tripped, disposition alone does not reset it
            if state.get("circuit_breaker_tripped"):
                target_phase = "CIRCUIT_BREAKER_TRIPPED"
                reason = "Circuit breaker remains tripped; requires explicit stagecheck reset-attempts."
            else:
                # Load latest verdict to evaluate remaining defects
                attempt = state.get("attempt_index", 1)
                task_dir = _resolve_task_evidence_dir(workspace_root, task_id)
                verdict_file = (
                    task_dir
                    / f"attempt_{attempt}"
                    / "Phase-3"
                    / "verdict.json"
                )
                if not verdict_file.is_file():
                    verdict_file = task_dir / "verdict.json"

                dispositions_doc = load_dispositions(workspace_root)
                all_disps = dispositions_doc.get("dispositions", [])
                disp_ids: Set[str] = set()
                for d in all_disps:
                    if not isinstance(d, dict) or not d.get("defect_id"):
                        continue
                    ok_w, _ = validate_waiver_provenance(
                        workspace_root,
                        d,
                        task_id=task_id,
                        attempt=attempt,
                        required_rule_id=d.get("defect_id"),
                        all_entries=all_disps,
                    )
                    if ok_w:
                        disp_ids.add(str(d.get("defect_id")))

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

