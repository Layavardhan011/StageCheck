"""Deterministic Acyclic Merkle DAG Sealing & Evidence Manifest (P4-T4 / FR-12 / DEC-012).

Implements deterministic attempt sealing, pre-resolution symlink validation,
canonical Unicode C-collation leaf sorting, and acyclic downstream manifest indexing.

Invariants:
1. Pre-Resolution Validation:
   - No '..' path traversal in attempt path.
   - Attempt root itself is inspected with os.path.islink() BEFORE resolve().
   - Parent components up to workspace_root inspected with os.path.islink() BEFORE resolve().
   - Traversal inspects os.path.islink() on EVERY directory and file entry before following or opening.
   - Any symlink inside attempt directory or root path strictly fails closed with SymlinkInEvidenceError.
2. Canonical Leaf Serialization:
   - Exclusions: seal.json, *.lock, *.tmp, .DS_Store.
   - Relative POSIX paths sorted in ascending Unicode code point order (C collation).
   - JSON serialized strictly without whitespace: separators=(',', ':'), sort_keys=True.
   - Root digest: SHA-256(canonical_json_bytes).
3. Acyclic Manifest Indexing:
   - DAG is strictly acyclic: seal.json hashes attempt evidence; EVIDENCE_MANIFEST.json hashes seal.json.
   - seal.json never hashes the manifest.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from stagecheck.core.paths import (
    PathOutsideBoundaryError,
    PathTraversalError,
    SymlinkPathEscapeError,
    validate_attempt_root_symlinks,
)
from stagecheck.core.permissions import controlled_write_transaction, elevate_permissions_for_teardown


class SealingError(Exception):
    """Base exception for Merkle sealing operations."""


class SymlinkInEvidenceError(SealingError):
    """Raised when a symlink is detected within the attempt hierarchy or attempt path components."""


class MerkleVerificationError(SealingError):
    """Raised when Merkle seal integrity verification fails."""


EXCLUDED_SEAL_NAMES: Set[str] = {"seal.json", ".DS_Store"}
EXCLUDED_EXTENSIONS: Set[str] = {".lock", ".tmp"}


def validate_merkle_attempt_path(attempt_dir: Union[str, Path], workspace_root: Union[str, Path]) -> Path:
    """Validate attempt root and parent hierarchy against symlinks before resolution."""
    try:
        return validate_attempt_root_symlinks(attempt_dir, workspace_root)
    except (SymlinkPathEscapeError, PathTraversalError, PathOutsideBoundaryError) as err:
        raise SymlinkInEvidenceError(f"Attempt path validation failed: {err}") from err


def compute_attempt_merkle_seal(
    attempt_dir: Union[str, Path],
    workspace_root: Union[str, Path],
    task_id: str,
    attempt_index: int,
    verdict_data: Optional[Dict[str, Any]] = None,
    write_seal_file: bool = True,
) -> Dict[str, Any]:
    """Compute deterministic Merkle DAG seal across attempt evidence files.

    Args:
        attempt_dir: Path to attempt directory (e.g. evidence/tasks/task-01/attempt_1).
        workspace_root: Governing workspace root path.
        task_id: Task identifier.
        attempt_index: 1-based attempt index.
        verdict_data: Optional Phase-3 verdict dictionary.
        write_seal_file: Whether to write seal.json (mode 0444) to attempt_dir.

    Returns:
        Dict representing seal_record.

    Raises:
        SymlinkInEvidenceError: If any symlink is found in root, parents, or children.
    """
    ws_root = Path(workspace_root).resolve()
    attempt_path = validate_merkle_attempt_path(attempt_dir, ws_root)

    leaf_entries: List[Dict[str, Any]] = []

    # Traverse attempt hierarchy with followlinks=False
    for root_dir, dirs, files in os.walk(attempt_path, followlinks=False):
        # Inspect directories for symlinks before descending
        for d in dirs:
            dir_full = Path(root_dir) / d
            if os.path.islink(dir_full):
                raise SymlinkInEvidenceError(
                    f"Evidence integrity defect [SYMLINK_IN_EVIDENCE]: Directory symlink '{dir_full}' prohibited."
                )

        # Inspect and hash regular files
        for f in files:
            file_full = Path(root_dir) / f
            if os.path.islink(file_full):
                raise SymlinkInEvidenceError(
                    f"Evidence integrity defect [SYMLINK_IN_EVIDENCE]: File symlink '{file_full}' prohibited."
                )

            if f in EXCLUDED_SEAL_NAMES or file_full.suffix in EXCLUDED_EXTENSIONS:
                continue

            rel_posix = file_full.relative_to(attempt_path).as_posix()
            file_bytes = file_full.read_bytes()
            leaf_entries.append({
                "hash": hashlib.sha256(file_bytes).hexdigest(),
                "path": rel_posix,
                "size": len(file_bytes),
            })

    # Sort leaves in ascending Unicode code point order (C collation)
    leaf_entries.sort(key=lambda item: item["path"])

    # Canonical serialization: sorted keys, no whitespace, UTF-8 encoded
    canonical_json_bytes = json.dumps(
        leaf_entries,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

    merkle_root_sha256 = hashlib.sha256(canonical_json_bytes).hexdigest()

    seal_record: Dict[str, Any] = {
        "schema_version": "2.0.0",
        "task_id": task_id,
        "attempt_index": attempt_index,
        "merkle_root_sha256": merkle_root_sha256,
        "total_files_sealed": len(leaf_entries),
        "verdict": verdict_data or {},
        "leaves": leaf_entries,
    }

    if write_seal_file:
        seal_file = attempt_path / "seal.json"
        # Ensure parent directory is writable to create or overwrite seal.json
        try:
            os.chmod(attempt_path, 0o755)
        except OSError:
            pass

        if seal_file.exists():
            try:
                os.chmod(seal_file, 0o644)
            except OSError:
                pass

        seal_file.write_text(json.dumps(seal_record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        try:
            os.chmod(seal_file, 0o444)
        except OSError:
            pass

    return seal_record


def verify_attempt_merkle_seal(
    attempt_dir: Union[str, Path],
    workspace_root: Union[str, Path],
) -> Tuple[bool, List[str]]:
    """Verify integrity of seal.json against on-disk files in the attempt directory.

    Returns:
        Tuple of (is_valid: bool, violations: List[str]).
    """
    ws_root = Path(workspace_root).resolve()
    violations: List[str] = []

    try:
        attempt_path = validate_merkle_attempt_path(attempt_dir, ws_root)
    except SymlinkInEvidenceError as err:
        return False, [f"Symlink validation failure: {err}"]

    seal_file = attempt_path / "seal.json"
    if not seal_file.is_file():
        return False, [f"Missing seal.json at '{seal_file}'"]

    try:
        seal_data = json.loads(seal_file.read_text(encoding="utf-8"))
    except Exception as err:
        return False, [f"Malformed seal.json: {err}"]

    expected_merkle_root = seal_data.get("merkle_root_sha256")
    recorded_leaves = seal_data.get("leaves", [])

    # Recompute seal in-memory
    try:
        computed_seal = compute_attempt_merkle_seal(
            attempt_dir=attempt_path,
            workspace_root=ws_root,
            task_id=seal_data.get("task_id", ""),
            attempt_index=seal_data.get("attempt_index", 1),
            verdict_data=seal_data.get("verdict"),
            write_seal_file=False,
        )
    except SymlinkInEvidenceError as sym_err:
        return False, [str(sym_err)]

    if computed_seal["merkle_root_sha256"] != expected_merkle_root:
        violations.append(
            f"Merkle root mismatch: expected {expected_merkle_root}, computed {computed_seal['merkle_root_sha256']}"
        )

    # Check leaf-by-leaf
    computed_leaves_map = {l["path"]: l["hash"] for l in computed_seal["leaves"]}
    for leaf in recorded_leaves:
        rel_p = leaf.get("path")
        exp_h = leaf.get("hash")
        if rel_p not in computed_leaves_map:
            violations.append(f"Missing sealed file: '{rel_p}'")
        elif computed_leaves_map[rel_p] != exp_h:
            violations.append(
                f"Tampered sealed file: '{rel_p}' (recorded {exp_h[:12]}, computed {computed_leaves_map[rel_p][:12]})"
            )

    for p in computed_leaves_map:
        if not any(l.get("path") == p for l in recorded_leaves):
            violations.append(f"Unrecorded file present in attempt directory: '{p}'")

    return len(violations) == 0, violations


def index_seal_in_manifest(
    workspace_root: Union[str, Path],
    task_id: str,
    attempt_index: int,
    seal_record: Dict[str, Any],
) -> Path:
    """Acyclically index completed attempt seal into EVIDENCE_MANIFEST.json (FR-12 / DEC-012).

    Manifest hashes seal.json; seal.json hashes attempt directory.
    """
    ws = Path(workspace_root).resolve()
    manifest_file = ws / "evidence" / "EVIDENCE_MANIFEST.json"
    manifest_file.parent.mkdir(parents=True, exist_ok=True)

    seal_file = ws / "evidence" / "tasks" / task_id / f"attempt_{attempt_index}" / "seal.json"
    seal_bytes = seal_file.read_bytes()
    seal_sha256 = hashlib.sha256(seal_bytes).hexdigest()

    with controlled_write_transaction(manifest_file.parent):
        if manifest_file.is_file():
            try:
                manifest_data = json.loads(manifest_file.read_text(encoding="utf-8"))
            except Exception:
                manifest_data = {"schema_version": "2.0.0", "sealed_tasks": {}}
        else:
            manifest_data = {"schema_version": "2.0.0", "sealed_tasks": {}}

        sealed_tasks = manifest_data.setdefault("sealed_tasks", {})
        task_entry = sealed_tasks.setdefault(task_id, {})
        task_entry[f"attempt_{attempt_index}"] = {
            "seal_sha256": seal_sha256,
            "merkle_root_sha256": seal_record["merkle_root_sha256"],
            "total_files": seal_record["total_files_sealed"],
        }

        # Keep entries map synchronized if present
        if "entries" in manifest_data:
            from datetime import datetime, timezone
            rel_posix = seal_file.relative_to(ws).as_posix()
            manifest_data["entries"][rel_posix] = {
                "sha256": seal_sha256,
                "size_bytes": len(seal_bytes),
                "indexed_at": datetime.now(timezone.utc).isoformat(),
            }

        temp_manifest = manifest_file.with_suffix(".tmp")
        temp_manifest.write_text(json.dumps(manifest_data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        try:
            os.chmod(temp_manifest, 0o444)
        except OSError:
            pass
        temp_manifest.replace(manifest_file)
        try:
            os.chmod(manifest_file, 0o444)
        except OSError:
            pass

    return manifest_file

