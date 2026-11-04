"""StageCheck Evidence Integrity, Task Seals, and Attempt Chain Engine (P4-T3).

Maintains authoritative EVIDENCE_MANIFEST.json with SHA-256 digests, generates
cryptographic task attempt seals (seal.json) binding multi-repository commit vectors
(checked_heads), and enforces immutable Merkle hash chaining across task repair attempts (SEC-02, GAP-I3).
"""

from __future__ import annotations

import datetime
import json
import os
import stat
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from stagecheck.core.paths import find_workspace_root
from stagecheck.core.permissions import controlled_write_transaction
from stagecheck.core.utils import canonical_json_dumps, sha256_digest, sha256_file


class EvidenceTamperError(Exception):
    """Raised when evidence files or cryptographic seals fail integrity validation."""


class SealChainBrokenError(Exception):
    """Raised when the immutable attempt seal hash chain is broken or missing."""


def get_manifest_path(workspace_root: Path) -> Path:
    return workspace_root / "evidence" / "EVIDENCE_MANIFEST.json"


def load_evidence_manifest(workspace_root: Path) -> Dict[str, Any]:
    """Load or initialize the EVIDENCE_MANIFEST.json structure."""
    manifest_path = get_manifest_path(workspace_root)
    if not manifest_path.is_file():
        return {
            "schema_version": "2.0",
            "manifest_version": 1,
            "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "entries": {},
        }
    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as err:
        raise EvidenceTamperError(f"Corrupted or unreadable EVIDENCE_MANIFEST.json: {err}") from err


def update_evidence_manifest(
    workspace_root: Path,
    file_paths: List[Union[str, Path]],
) -> Path:
    """Hash given evidence files and update EVIDENCE_MANIFEST.json atomically."""
    manifest = load_evidence_manifest(workspace_root)
    entries = manifest.setdefault("entries", {})

    for p in file_paths:
        abs_p = (workspace_root / p).resolve()
        if not abs_p.is_file():
            continue
        rel_posix = str(abs_p.relative_to(workspace_root.resolve())).replace("\\", "/")
        digest = sha256_file(abs_p)
        size_bytes = abs_p.stat().st_size

        entries[rel_posix] = {
            "sha256": digest,
            "size_bytes": size_bytes,
            "recorded_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }

    manifest["updated_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    manifest_path = get_manifest_path(workspace_root)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)

    # Temporary file write + atomic replace under controlled permission transaction
    manifest_dir = manifest_path.parent
    is_ro = not os.access(manifest_dir, os.W_OK)
    if is_ro:
        os.chmod(manifest_dir, 0o755)

    try:
        temp_path = manifest_path.with_suffix(".tmp")
        with open(temp_path, "w", encoding="utf-8") as f:
            f.write(canonical_json_dumps(manifest) + "\n")
        os.replace(temp_path, manifest_path)
        manifest_path.chmod(0o444)
    finally:
        if is_ro:
            os.chmod(manifest_dir, 0o555)

    return manifest_path


def verify_evidence_manifest(workspace_root: Path) -> Tuple[bool, List[str]]:
    """Verify that all recorded evidence files exist and match their SHA-256 digests.

    Returns:
        (is_valid, list_of_defect_messages)
    """
    manifest_path = get_manifest_path(workspace_root)
    if not manifest_path.is_file():
        return False, ["EVIDENCE_MANIFEST.json is missing."]

    try:
        manifest = load_evidence_manifest(workspace_root)
    except EvidenceTamperError as err:
        return False, [str(err)]

    entries = manifest.get("entries", {})
    violations: List[str] = []

    for rel_path, meta in entries.items():
        expected_hash = meta.get("sha256")
        expected_size = meta.get("size_bytes")
        abs_path = workspace_root / rel_path

        if not abs_path.is_file():
            violations.append(f"Tamper defect: Evidence file '{rel_path}' is missing.")
            continue

        actual_size = abs_path.stat().st_size
        if expected_size is not None and actual_size != expected_size:
            violations.append(
                f"Tamper defect: Evidence file '{rel_path}' size mismatch ({actual_size} != {expected_size})."
            )
            continue

        actual_hash = sha256_file(abs_path)
        if actual_hash != expected_hash:
            violations.append(
                f"Tamper defect: Evidence file '{rel_path}' SHA-256 mismatch ({actual_hash[:12]} != {expected_hash[:12]})."
            )

    return (len(violations) == 0, violations)


def get_task_seal_path(workspace_root: Path, task_id: str, attempt: int) -> Path:
    """Return the authoritative path for a task attempt seal.json."""
    return (
        workspace_root
        / "evidence"
        / "tasks"
        / task_id
        / f"attempt_{attempt}"
        / "seal.json"
    )


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
    attempt_dir = (
        workspace_root
        / "evidence"
        / "tasks"
        / task_id
        / f"attempt_{attempt}"
    )
    attempt_dir.mkdir(parents=True, exist_ok=True)
    seal_path = attempt_dir / "seal.json"

    # 1. Resolve prior attempt seal for chaining (attempt > 1)
    prior_seal_sha256 = "0" * 64
    if attempt > 1:
        prior_attempt = attempt - 1
        prior_seal_file = get_task_seal_path(workspace_root, task_id, prior_attempt)
        if not prior_seal_file.is_file():
            raise SealChainBrokenError(
                f"Cannot seal attempt {attempt}: Prior attempt {prior_attempt} seal.json is missing."
            )
        prior_seal_sha256 = sha256_file(prior_seal_file)

    # 2. Extract verdict sha256
    verdict_path = attempt_dir / "Phase-3" / "verdict.json"
    if not verdict_path.is_file():
        verdict_path = attempt_dir / "verdict.json"
    verdict_sha256 = "0" * 64
    if verdict_path.is_file():
        verdict_sha256 = sha256_file(verdict_path)

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
    manifest_sha256 = "0" * 64
    if manifest_path.is_file():
        manifest_sha256 = sha256_file(manifest_path)

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

    # Write seal atomically
    tmp_seal = seal_path.with_suffix(".tmp")
    with open(tmp_seal, "w", encoding="utf-8") as f:
        f.write(canonical_json_dumps(seal_data) + "\n")
    os.replace(tmp_seal, seal_path)

    # Also update Phase-3 copy if Phase-3 directory exists
    p3_dir = attempt_dir / "Phase-3"
    if p3_dir.is_dir():
        with open(p3_dir / "seal.json", "w", encoding="utf-8") as f:
            f.write(canonical_json_dumps(seal_data) + "\n")

    # If final PASSED outcome, write master task seal at task root
    if outcome == "PASSED":
        master_seal = workspace_root / "evidence" / "tasks" / task_id / "seal.json"
        with open(master_seal, "w", encoding="utf-8") as f:
            f.write(canonical_json_dumps(seal_data) + "\n")

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

    for att in range(1, max_attempt + 1):
        seal_path = get_task_seal_path(workspace_root, task_id, att)
        if not seal_path.is_file():
            violations.append(f"Broken seal chain: Attempt {att} seal.json is missing.")
            break

        try:
            with open(seal_path, "r", encoding="utf-8") as f:
                seal_data = json.load(f)
        except Exception as err:
            violations.append(f"Broken seal chain: Attempt {att} seal.json unreadable: {err}")
            break

        # Check prior link
        recorded_prior = seal_data.get("prior_seal_sha256", "0" * 64)
        if att == 1:
            if recorded_prior != "0" * 64:
                violations.append(f"Attempt 1 seal must have zeroed prior_seal_sha256, got: '{recorded_prior}'")
        else:
            if recorded_prior != prior_expected_hash:
                violations.append(
                    f"Cryptographic chain broken at attempt {att}: recorded prior "
                    f"({recorded_prior[:12]}) does not match attempt {att-1} actual hash ({prior_expected_hash[:12]})."
                )

        # Update prior_expected_hash for next iteration
        prior_expected_hash = sha256_file(seal_path)

    return (len(violations) == 0, violations)


def append_issue_history(
    workspace_root: Path,
    task_id: str,
    attempt: int,
    outcome: str,
    defects: List[Dict[str, Any]],
) -> Path:
    """Append verification results to cumulative TASK_<ID>_ISSUE_HISTORY.md ledger."""
    task_dir = workspace_root / "evidence" / "tasks" / task_id
    task_dir.mkdir(parents=True, exist_ok=True)
    history_file = task_dir / f"TASK_{task_id}_ISSUE_HISTORY.md"

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
    with open(history_file, "a", encoding="utf-8") as f:
        f.write(content_to_append)

    # Index history file in evidence manifest
    update_evidence_manifest(workspace_root, [history_file])
    return history_file

