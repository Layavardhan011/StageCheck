"""StageCheck Evidence Integrity, Task Seals, and Attempt Chain Engine (P4-T3).

Maintains authoritative EVIDENCE_MANIFEST.json with SHA-256 digests, generates
cryptographic task attempt seals (seal.json) binding multi-repository commit vectors
(checked_heads), and enforces immutable Merkle hash chaining across task repair attempts (SEC-02, GAP-I3).
"""

from __future__ import annotations

import datetime
import hmac
import json
import os
import stat
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from stagecheck.core.agents import resolve_task_attempt_dir
from stagecheck.core.locking import acquire_runtime_lock
from stagecheck.core.paths import (
    StageCheckPathError,
    find_workspace_root,
    read_bytes_nofollow,
    resolve_task_dir,
    safe_resolve,
    sha256_file_nofollow,
    write_text_nofollow,
)
from stagecheck.core.permissions import controlled_write_transaction
from stagecheck.core.utils import canonical_json_dumps, pretty_json_dumps, sha256_digest, strict_json_loads


class EvidenceTamperError(Exception):
    """Raised when evidence files or cryptographic seals fail integrity validation."""


class SealChainBrokenError(Exception):
    """Raised when the immutable attempt seal hash chain is broken or missing."""


def get_manifest_path(workspace_root: Path) -> Path:
    return workspace_root / "evidence" / "EVIDENCE_MANIFEST.json"


def load_evidence_manifest(workspace_root: Path) -> Dict[str, Any]:
    """Load or initialize the EVIDENCE_MANIFEST.json structure without following symlinks."""
    manifest_path = get_manifest_path(workspace_root)
    if manifest_path.is_symlink():
        raise EvidenceTamperError(f"Symlinked EVIDENCE_MANIFEST.json rejected: '{manifest_path}'.")
    if not manifest_path.is_file():
        return {
            "schema_version": "2.0",
            "manifest_version": 1,
            "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "entries": {},
        }
    try:
        raw = read_bytes_nofollow(manifest_path).decode("utf-8")
        return strict_json_loads(raw, source=str(manifest_path))
    except Exception as err:
        raise EvidenceTamperError(f"Corrupted or unreadable EVIDENCE_MANIFEST.json: {err}") from err


def update_evidence_manifest(
    workspace_root: Path,
    file_paths: List[Union[str, Path]],
) -> Path:
    """Hash given evidence files and update EVIDENCE_MANIFEST.json atomically."""
    ws_root = Path(workspace_root).resolve()
    manifest = load_evidence_manifest(ws_root)
    entries = manifest.setdefault("entries", {})

    for p in file_paths:
        try:
            abs_p = safe_resolve(p, ws_root, allow_symlinks=False)
        except StageCheckPathError as err:
            raise EvidenceTamperError(f"Refusing unsafe/symlinked evidence path '{p}': {err}") from err
        if abs_p.is_symlink() or not abs_p.is_file():
            continue
        rel_posix = str(abs_p.relative_to(ws_root)).replace("\\", "/")
        digest = sha256_file_nofollow(abs_p)
        size_bytes = abs_p.stat().st_size

        entries[rel_posix] = {
            "sha256": digest,
            "size_bytes": size_bytes,
            "recorded_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }

    manifest["updated_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    manifest_path = safe_resolve("evidence/EVIDENCE_MANIFEST.json", ws_root, allow_symlinks=False)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)

    # Temporary file write + atomic replace under controlled permission transaction
    manifest_dir = manifest_path.parent
    is_ro = not os.access(manifest_dir, os.W_OK)
    if is_ro:
        os.chmod(manifest_dir, 0o755)

    try:
        write_text_nofollow(manifest_path, pretty_json_dumps(manifest), append=False, mode=0o644)
        manifest_path.chmod(0o444)
    finally:
        if is_ro:
            os.chmod(manifest_dir, 0o555)

    return manifest_path


def verify_evidence_manifest(workspace_root: Path) -> Tuple[bool, List[str]]:
    """Verify that all recorded evidence files and sealed_tasks exist and match SHA-256 digests."""
    ws_root = Path(workspace_root).resolve()
    try:
        manifest_path = safe_resolve("evidence/EVIDENCE_MANIFEST.json", ws_root, allow_symlinks=False)
    except StageCheckPathError as err:
        return False, [f"EVIDENCE_MANIFEST.json unsafe path/symlink: {err}"]
    if manifest_path.is_symlink() or not manifest_path.is_file():
        return False, ["EVIDENCE_MANIFEST.json is missing or symlinked."]

    try:
        manifest = load_evidence_manifest(ws_root)
    except EvidenceTamperError as err:
        return False, [str(err)]

    entries = manifest.get("entries", {})
    violations: List[str] = []

    for rel_path, meta in entries.items():
        if not isinstance(meta, dict):
            violations.append(f"Tamper defect: Malformed manifest entry metadata for '{rel_path}'.")
            continue
        expected_hash = meta.get("sha256")
        expected_size = meta.get("size_bytes")
        try:
            abs_path = safe_resolve(rel_path, ws_root, allow_symlinks=False)
        except StageCheckPathError as err:
            violations.append(f"Tamper defect: Evidence file '{rel_path}' failed containment/symlink check: {err}")
            continue

        if abs_path.is_symlink() or not abs_path.is_file():
            violations.append(f"Tamper defect: Evidence file '{rel_path}' is missing or symlinked.")
            continue

        actual_size = abs_path.stat().st_size
        if expected_size is not None and actual_size != expected_size:
            violations.append(
                f"Tamper defect: Evidence file '{rel_path}' size mismatch ({actual_size} != {expected_size})."
            )
            continue

        actual_hash = sha256_file_nofollow(abs_path)
        if actual_hash != expected_hash:
            violations.append(
                f"Tamper defect: Evidence file '{rel_path}' SHA-256 mismatch ({actual_hash[:12]} != {expected_hash[:12]})."
            )

    sealed_tasks = manifest.get("sealed_tasks", {})
    if isinstance(sealed_tasks, dict):
        def _verify_indexed_seal(seal_ref: Union[str, Path], expected_sha: Any, label: str) -> None:
            if not isinstance(expected_sha, str) or not expected_sha:
                violations.append(f"Tamper defect: sealed_tasks entry '{label}' missing seal_sha256.")
                return
            try:
                seal_abs = safe_resolve(seal_ref, ws_root, allow_symlinks=False)
            except StageCheckPathError as err:
                violations.append(f"Tamper defect: Sealed path '{seal_ref}' failed containment/symlink check: {err}")
                return
            if seal_abs.is_symlink() or not seal_abs.is_file():
                violations.append(f"Tamper defect: Indexed seal '{seal_ref}' is missing or symlinked.")
                return
            actual_seal_sha = sha256_file_nofollow(seal_abs)
            if actual_seal_sha != expected_sha:
                violations.append(
                    f"Tamper defect: Indexed seal '{seal_ref}' SHA-256 mismatch ({actual_seal_sha[:12]} != {expected_sha[:12]})."
                )

        for sealed_key, smeta in sealed_tasks.items():
            if not isinstance(smeta, dict):
                violations.append(f"Tamper defect: Malformed sealed_tasks metadata for '{sealed_key}'.")
                continue
            if "seal_path" in smeta or "seal_sha256" in smeta:
                seal_rel = smeta.get("seal_path")
                if not isinstance(seal_rel, str) or not seal_rel:
                    violations.append(f"Tamper defect: sealed_tasks entry '{sealed_key}' missing seal_path.")
                    continue
                _verify_indexed_seal(seal_rel, smeta.get("seal_sha256"), sealed_key)
                continue

            for attempt_key, ameta in smeta.items():
                if not isinstance(ameta, dict):
                    violations.append(
                        f"Tamper defect: Malformed sealed_tasks attempt metadata for '{sealed_key}.{attempt_key}'."
                    )
                    continue
                if not isinstance(attempt_key, str) or not attempt_key.startswith("attempt_") or not attempt_key[8:].isdigit():
                    violations.append(
                        f"Tamper defect: Invalid sealed_tasks attempt key '{attempt_key}' for '{sealed_key}'."
                    )
                    continue
                attempt_idx = int(attempt_key[8:])
                try:
                    seal_target = resolve_task_attempt_dir(ws_root, str(sealed_key), attempt_idx) / "seal.json"
                except Exception as err:
                    violations.append(
                        f"Tamper defect: Invalid sealed_tasks target '{sealed_key}.{attempt_key}': {err}"
                    )
                    continue
                _verify_indexed_seal(seal_target, ameta.get("seal_sha256"), f"{sealed_key}.{attempt_key}")

    return (len(violations) == 0, violations)


def get_task_seal_path(workspace_root: Path, task_id: str, attempt: int) -> Path:
    """Return the authoritative path for a task attempt seal.json."""
    return resolve_task_attempt_dir(workspace_root, task_id, attempt) / "seal.json"


def create_task_seal(
    workspace_root: Path,
    task_id: str,
    attempt: int,
    verdict_data: Dict[str, Any],
    checked_heads: Dict[str, str],
    outcome: str = "PASSED",
) -> Path:
    """Generate and cryptographically bind a task attempt seal.json.

    Links the seal to the prior attempt seal (forming an immutable Merkle chain),
    binds the multi-repository commit vector (checked_heads), computes payload digests,
    and locks the seal into EVIDENCE_MANIFEST.json with mode 0444 (SEC-A5).
    """
    attempt_dir = resolve_task_attempt_dir(workspace_root, task_id, attempt, ensure_exists=True)
    seal_path = attempt_dir / "seal.json"

    # 1. Resolve prior attempt seal for chaining (attempt > 1)
    prior_seal_sha256 = "0" * 64
    if attempt > 1:
        prior_attempt = attempt - 1
        prior_seal_file = get_task_seal_path(workspace_root, task_id, prior_attempt)
        if prior_seal_file.is_symlink() or not prior_seal_file.is_file():
            raise SealChainBrokenError(
                f"Cannot seal attempt {attempt}: Prior attempt {prior_attempt} seal.json is missing or symlinked."
            )
        prior_seal_sha256 = sha256_file_nofollow(prior_seal_file)

    # 2. Extract verdict sha256
    p3_dir = attempt_dir / "Phase-3"
    if p3_dir.is_symlink():
        raise EvidenceTamperError(f"Refusing to follow symlinked Phase-3 directory '{p3_dir}'.")
    verdict_path = p3_dir / "verdict.json"
    if not verdict_path.exists() and not verdict_path.is_symlink():
        verdict_path = attempt_dir / "verdict.json"
    if verdict_path.is_symlink():
        raise EvidenceTamperError(f"Refusing to follow symlinked verdict file '{verdict_path}'.")
    verdict_sha256 = "0" * 64
    if verdict_path.is_file():
        verdict_sha256 = sha256_file_nofollow(verdict_path)

    # 3. Payload and manifest calculation
    payload_to_hash = {
        "task_id": task_id,
        "attempt": attempt,
        "outcome": outcome,
        "verdict_sha256": verdict_sha256,
        "prior_seal_sha256": prior_seal_sha256,
        "checked_heads": dict(sorted(checked_heads.items())),
    }
    payload_sha256 = sha256_digest(canonical_json_dumps(payload_to_hash).encode("utf-8"))

    # Initial manifest sha256
    manifest_path = get_manifest_path(workspace_root)
    if manifest_path.is_symlink():
        raise EvidenceTamperError(f"Refusing to follow symlinked manifest '{manifest_path}'.")
    manifest_sha256 = "0" * 64
    if manifest_path.is_file():
        manifest_sha256 = sha256_file_nofollow(manifest_path)

    seal_data = {
        "schema_version": "2.0",
        "task_id": task_id,
        "attempt": attempt,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "outcome": outcome,
        "verdict_sha256": verdict_sha256,
        "manifest_sha256": manifest_sha256,
        "payload_sha256": payload_sha256,
        "prior_seal_sha256": prior_seal_sha256,
        "checked_heads": dict(sorted(checked_heads.items())),
    }

    # Verify task_id/attempt symlink safety and write seal atomically (O_NOFOLLOW)
    if seal_path.is_symlink():
        raise EvidenceTamperError(f"Refusing to follow symlinked seal file '{seal_path}'.")
    tmp_seal = seal_path.with_suffix(f".tmp.{os.getpid()}")
    tmp_fd = os.open(tmp_seal, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    try:
        os.write(tmp_fd, pretty_json_dumps(seal_data).encode("utf-8"))
    finally:
        os.close(tmp_fd)
    os.replace(tmp_seal, seal_path)

    # Also update Phase-3 copy if Phase-3 directory exists
    p3_dir = attempt_dir / "Phase-3"
    if p3_dir.is_dir() and not p3_dir.is_symlink():
        p3_is_ro = not os.access(p3_dir, os.W_OK)
        if p3_is_ro:
            try:
                os.chmod(str(p3_dir), 0o755)
            except OSError:
                pass
        try:
            p3_seal = p3_dir / "seal.json"
            if p3_seal.is_symlink():
                raise EvidenceTamperError(f"Refusing to follow symlinked Phase-3 seal '{p3_seal}'.")
            if p3_seal.exists():
                os.chmod(str(p3_seal), 0o644)
            p3_fd = os.open(p3_seal, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
            try:
                os.write(p3_fd, pretty_json_dumps(seal_data).encode("utf-8"))
            finally:
                os.close(p3_fd)
            os.chmod(str(p3_seal), stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
        except OSError:
            pass
        finally:
            if p3_is_ro:
                try:
                    os.chmod(str(p3_dir), 0o555)
                except OSError:
                    pass

    # If final PASSED outcome, write master task seal at task root
    if outcome == "PASSED":
        master_seal = resolve_task_dir(workspace_root, task_id) / "seal.json"
        if master_seal.is_symlink():
            raise EvidenceTamperError(f"Refusing to follow symlinked master seal '{master_seal}'.")
        if master_seal.exists():
            try:
                os.chmod(str(master_seal), 0o644)
            except OSError:
                pass
        m_fd = os.open(master_seal, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
        try:
            os.write(m_fd, pretty_json_dumps(seal_data).encode("utf-8"))
        finally:
            os.close(m_fd)

    # Update EVIDENCE_MANIFEST with the new seal and verdict files
    files_to_index = [seal_path]
    if verdict_path.is_file():
        files_to_index.append(verdict_path)
    update_evidence_manifest(workspace_root, files_to_index)

    # Lock read-only mode 0444
    os.chmod(seal_path, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)

    return seal_path


def verify_seal_chain(
    workspace_root: Path,
    task_id: str,
    max_attempt: int,
) -> Tuple[bool, List[str]]:
    """Verify that all attempt seals from 1 to max_attempt form an unbroken cryptographic chain.

    Returns:
        (is_valid, list_of_chain_violations)
    """
    violations: List[str] = []
    prior_expected_hash = "0" * 64

    ws_root = Path(workspace_root).resolve()
    for att in range(1, max_attempt + 1):
        try:
            seal_path = safe_resolve(f"evidence/tasks/{task_id}/attempt_{att}/seal.json", ws_root, allow_symlinks=False)
        except StageCheckPathError as err:
            violations.append(f"Broken seal chain: Attempt {att} seal.json unsafe path/symlink: {err}")
            break
        if seal_path.is_symlink() or not seal_path.is_file():
            violations.append(f"Broken seal chain: Attempt {att} seal.json is missing or symlinked.")
            break

        try:
            seal_raw = read_bytes_nofollow(seal_path).decode("utf-8")
            seal_data = strict_json_loads(seal_raw, source=str(seal_path))
        except Exception as err:
            violations.append(f"Broken seal chain: Attempt {att} seal.json unreadable: {err}")
            break

        if not isinstance(seal_data, dict):
            violations.append(f"Broken seal chain: Attempt {att} seal.json must be a JSON object.")
            break

        if "merkle_root_sha256" in seal_data:
            from stagecheck.core.sealing import verify_attempt_merkle_seal
            if seal_data.get("task_id") != task_id:
                violations.append(
                    f"Attempt {att} seal task_id mismatch: '{seal_data.get('task_id')}' != '{task_id}'."
                )
            if seal_data.get("attempt_index") != att:
                violations.append(
                    f"Attempt {att} seal attempt_index mismatch: '{seal_data.get('attempt_index')}' != {att}."
                )
            if att > 1 and seal_data.get("prior_seal_sha256") != prior_expected_hash:
                violations.append(
                    f"Cryptographic chain broken at attempt {att}: Merkle seal prior_seal_sha256 "
                    f"({str(seal_data.get('prior_seal_sha256'))[:12]}) != attempt {att-1} hash ({prior_expected_hash[:12]})."
                )
            ok, seal_violations = verify_attempt_merkle_seal(seal_path.parent, ws_root)
            if not ok:
                violations.extend(seal_violations)
            prior_expected_hash = sha256_file_nofollow(seal_path)
            continue

        # Validate metadata fields explicitly (fail closed)
        if seal_data.get("task_id") != task_id:
            violations.append(f"Attempt {att} seal task_id mismatch: '{seal_data.get('task_id')}' != '{task_id}'.")
        if seal_data.get("attempt") != att:
            violations.append(f"Attempt {att} seal attempt mismatch: '{seal_data.get('attempt')}' != {att}.")
        outcome = seal_data.get("outcome")
        if outcome not in ("PASSED", "FAILED"):
            violations.append(f"Attempt {att} seal invalid outcome: '{outcome}'.")

        # Require explicit prior_seal_sha256 (no silent default)
        if "prior_seal_sha256" not in seal_data or not isinstance(seal_data.get("prior_seal_sha256"), str):
            violations.append(f"Attempt {att} seal missing required prior_seal_sha256 field.")
            recorded_prior = ""
        else:
            recorded_prior = seal_data["prior_seal_sha256"]

        if att == 1:
            if recorded_prior != "0" * 64:
                violations.append(f"Attempt 1 seal must have zeroed prior_seal_sha256, got: '{recorded_prior}'")
        else:
            if recorded_prior != prior_expected_hash:
                violations.append(
                    f"Cryptographic chain broken at attempt {att}: recorded prior "
                    f"({recorded_prior[:12]}) does not match attempt {att-1} actual hash ({prior_expected_hash[:12]})."
                )

        # Verify verdict_sha256 against Phase-3/verdict.json (fail closed if recorded non-zero but missing/symlinked)
        attempt_dir = seal_path.parent
        recorded_verdict_sha = seal_data.get("verdict_sha256", "")
        verdict_candidates = (
            f"evidence/tasks/{task_id}/attempt_{att}/Phase-3/verdict.json",
            f"evidence/tasks/{task_id}/attempt_{att}/verdict.json",
        )
        verdict_path: Optional[Path] = None
        for vc in verdict_candidates:
            try:
                vp = safe_resolve(vc, ws_root, allow_symlinks=False)
                if vp.is_file():
                    verdict_path = vp
                    break
            except StageCheckPathError as err:
                violations.append(f"Attempt {att} verdict.json unsafe path/symlink: {err}")
                verdict_path = None
                break
        if verdict_path is not None:
            actual_verdict_sha = sha256_file_nofollow(verdict_path)
            if not isinstance(recorded_verdict_sha, str) or not hmac.compare_digest(
                recorded_verdict_sha, actual_verdict_sha
            ):
                violations.append(f"Attempt {att} seal verdict_sha256 mismatch against verdict.json.")
        elif isinstance(recorded_verdict_sha, str) and recorded_verdict_sha and recorded_verdict_sha != "0" * 64:
            violations.append(
                f"Attempt {att} seal records non-zero verdict_sha256 but verdict.json is missing."
            )

        # Recompute and verify payload_sha256 over canonical payload fields
        checked_heads = seal_data.get("checked_heads")
        if not isinstance(checked_heads, dict):
            violations.append(f"Attempt {att} seal missing checked_heads dictionary.")
        else:
            expected_payload = sha256_digest(
                canonical_json_dumps(
                    {
                        "task_id": seal_data.get("task_id"),
                        "attempt": seal_data.get("attempt"),
                        "outcome": outcome,
                        "verdict_sha256": recorded_verdict_sha,
                        "prior_seal_sha256": recorded_prior,
                        "checked_heads": dict(sorted(checked_heads.items())),
                    }
                ).encode("utf-8")
            )
            recorded_payload_sha = seal_data.get("payload_sha256")
            if not isinstance(recorded_payload_sha, str) or not hmac.compare_digest(
                recorded_payload_sha, expected_payload
            ):
                violations.append(
                    f"Attempt {att} seal payload_sha256 mismatch: recorded '{recorded_payload_sha}', computed '{expected_payload}'."
                )

        # Update prior_expected_hash for next iteration
        prior_expected_hash = sha256_file_nofollow(seal_path)

    return (len(violations) == 0, violations)


def append_issue_history(
    workspace_root: Path,
    task_id: str,
    attempt: int,
    outcome: str,
    defects: List[Dict[str, Any]],
) -> Path:
    """Append verification results to cumulative TASK_<ID>_ISSUE_HISTORY.md ledger."""
    task_dir = resolve_task_dir(workspace_root, task_id)
    safe_resolve(f"evidence/tasks/{task_id}", workspace_root, allow_symlinks=False)
    task_dir.mkdir(parents=True, exist_ok=True)
    history_file = safe_resolve(f"evidence/tasks/{task_id}/TASK_{task_id}_ISSUE_HISTORY.md", workspace_root, allow_symlinks=False)

    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        f"\n## Attempt {attempt} Verification Record — {outcome}\n",
        f"- **Timestamp:** {timestamp}\n",
        f"- **Defects Count:** {len(defects)}\n\n",
    ]

    if defects:
        lines.append("| Defect ID | Stage | Severity | Mode | Details |\n")
        lines.append("| :--- | :--- | :--- | :--- | :--- |\n")
        for d in defects:
            did = d.get("defect_id", "unknown")
            stg = d.get("check_id") or d.get("stage", "check")
            sev = d.get("severity", "CRITICAL")
            mode = d.get("mode", "blocking")
            ev_quote = ""
            if d.get("evidence"):
                ev_quote = d["evidence"][0].get("quote", "").replace("\n", " ")
            lines.append(f"| `{did}` | `{stg}` | {sev} | {mode} | {ev_quote} |\n")
    else:
        lines.append("All 9 verification stages passed with zero defects.\n")

    content_to_append = "".join(lines)
    write_text_nofollow(history_file, content_to_append, append=True, mode=0o644)

    # Index history file in evidence manifest
    update_evidence_manifest(workspace_root, [history_file])
    return history_file


def update_code_quality_ledger(
    workspace_root: Path,
    task_id: str,
    attempt: int = 1,
    observations: Optional[List[Dict[str, Any]]] = None,
) -> Path:
    """Record non-blocking maintainability/quality findings in evidence/CODE_QUALITY_REPORT.json (GAP-F2)."""
    ev_dir = Path(workspace_root).resolve() / "evidence"
    ev_dir.mkdir(parents=True, exist_ok=True)
    report_file = ev_dir / "CODE_QUALITY_REPORT.json"

    data: Dict[str, Any] = {"Code Quality issue": []}
    if report_file.is_file():
        try:
            with open(report_file, "r", encoding="utf-8") as f:
                loaded = json.load(f)
                if isinstance(loaded, dict) and "Code Quality issue" in loaded:
                    data = loaded
        except Exception:
            pass

    if observations:
        data["Code Quality issue"].extend(observations)

    tmp_file = report_file.with_suffix(".tmp")
    with open(tmp_file, "w", encoding="utf-8") as f:
        f.write(pretty_json_dumps(data))
    os.replace(tmp_file, report_file)

    update_evidence_manifest(workspace_root, [report_file])
    return report_file


