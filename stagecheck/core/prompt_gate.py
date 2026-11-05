"""Prompt Verification, Freezing, and Declared Scope Gate (P3-T2).

Enforces immutable Phase 1 prompt verification, cryptographic SHA-256 freezing,
path containment validation for declared_scope.json, and live invariance checks.
"""

from __future__ import annotations

import datetime
import json
import os
import re
from fnmatch import fnmatch
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from stagecheck.core.agents import resolve_task_attempt_dir
from stagecheck.core.paths import is_path_contained, safe_resolve
from stagecheck.core.utils import canonical_json_dumps, pretty_json_dumps, sha256_file, validate_schema
from stagecheck.schemas import get_schema_path


class PromptGateError(Exception):
    """Base error for prompt verification and declared scope issues."""


class PromptMissingError(PromptGateError):
    """Raised when prompt.md or declared_scope.json is missing."""


class ScopeValidationError(PromptGateError):
    """Raised when declared_scope.json violates boundary containment rules."""


class PromptTamperedError(PromptGateError):
    """Raised when prompt.md or declared_scope.json differs from verified record."""


class PromptNotVerifiedError(PromptGateError):
    """Raised when coding/audit is attempted without a verified prompt record."""


FORBIDDEN_SCOPE_PREFIXES = (
    "controls/",
    "specs/",
    "stagecheck/",
    ".git/",
    ".stagecheck",
    "AGENTS.md",
)


def validate_declared_scope(
    workspace_root: Union[str, Path],
    declared_scope_data: Dict[str, Any],
    target_repositories: Optional[List[str]] = None,
) -> None:
    """Validate structure and containment of declared_scope dictionary.

    Args:
        workspace_root: Root workspace path.
        declared_scope_data: Loaded declared_scope.json dictionary.
        target_repositories: Optional list of approved repo names (e.g. ['payment-service']).

    Raises:
        ScopeValidationError: If paths escape boundary or violate constraints.
    """
    root = Path(workspace_root).resolve()

    # 1. Validate against schema
    schema_path = get_schema_path("declared_scope.schema.json")
    with schema_path.open("r", encoding="utf-8") as f:
        schema = json.load(f)
    try:
        validate_schema(declared_scope_data, schema)
    except Exception as err:
        raise ScopeValidationError(f"declared_scope.json schema validation failed: {err}") from err

    all_paths = (
        declared_scope_data.get("allowed_paths", [])
        + declared_scope_data.get("read_only_paths", [])
        + declared_scope_data.get("forbidden_paths", [])
    )

    repos_dir = (root / "repos").resolve()

    for path_str in all_paths:
        if not isinstance(path_str, str) or not path_str.strip():
            raise ScopeValidationError("Scope path entries must be non-empty strings.")

        norm_path = path_str.strip().replace("\\", "/")

        if norm_path.startswith("/"):
            raise ScopeValidationError(
                f"Scope violation: Absolute paths are forbidden: '{path_str}'."
            )

        if ".." in norm_path.split("/"):
            raise ScopeValidationError(
                f"Scope violation: Directory traversal sequences forbidden: '{path_str}'."
            )

    # 2. Ensure allowed and read-only paths do not target protected root files
    for path_str in declared_scope_data.get("allowed_paths", []) + declared_scope_data.get("read_only_paths", []):
        norm_path = path_str.strip().replace("\\", "/")
        for forbidden in FORBIDDEN_SCOPE_PREFIXES:
            if norm_path == forbidden or norm_path.startswith(forbidden):
                raise ScopeValidationError(
                    f"Scope violation: Path '{path_str}' targets protected governance area '{forbidden}'."
                )

    # 2. Check that allowed paths reside strictly under target repositories in repos/
    for allowed in declared_scope_data.get("allowed_paths", []):
        norm_allowed = allowed.strip().replace("\\", "/")
        if not norm_allowed.startswith("repos/"):
            raise ScopeValidationError(
                f"Scope violation: Allowed path '{allowed}' must reside under 'repos/<repo-name>/'."
            )

        parts = norm_allowed.split("/")
        if len(parts) < 2 or not parts[1]:
            raise ScopeValidationError(
                f"Scope violation: Allowed path '{allowed}' must specify a target repository under repos/."
            )

        repo_name = parts[1]
        if target_repositories and repo_name not in target_repositories:
            raise ScopeValidationError(
                f"Scope violation: Repository '{repo_name}' is not in approved target repositories: {target_repositories}."
            )


def verify_prompt_blueprint(prompt_path: Path) -> str:
    """Verify that prompt.md exists, is non-empty, and return its SHA-256 digest.

    Args:
        prompt_path: Path to prompt.md.

    Returns:
        Hex-encoded SHA-256 digest of the prompt file.

    Raises:
        PromptMissingError: If prompt.md is missing.
        PromptGateError: If prompt.md is empty.
    """
    if not prompt_path.is_file():
        raise PromptMissingError(f"Prompt blueprint file not found: '{prompt_path}'.")

    content = prompt_path.read_text(encoding="utf-8").strip()
    if len(content) < 10:
        raise PromptGateError(
            f"Prompt blueprint '{prompt_path}' is empty or trivial (<10 characters)."
        )

    return sha256_file(prompt_path)


def freeze_prompt_and_scope(
    workspace_root: Union[str, Path],
    task_id: str,
    attempt: int = 1,
    target_repositories: Optional[List[str]] = None,
) -> Path:
    """Validate prompt.md and declared_scope.json, and generate prompt_verified.json record.

    Freezes the prompt by calculating digests and locking file permissions to 0444.

    Args:
        workspace_root: Root workspace path.
        task_id: Task identifier (e.g. task-101).
        attempt: Attempt number.
        target_repositories: Optional approved repos list.

    Returns:
        Path to generated prompt_verified.json.
    """
    root = Path(workspace_root).resolve()
    attempt_dir = resolve_task_attempt_dir(root, task_id, attempt, ensure_exists=True)
    phase1_dir = attempt_dir / "Phase-1"
    phase1_dir.mkdir(parents=True, exist_ok=True)

    prompt_path = phase1_dir / "prompt.md"
    scope_path = phase1_dir / "declared_scope.json"
    verified_record_path = phase1_dir / "prompt_verified.json"

    if not prompt_path.is_file():
        raise PromptMissingError(
            f"Missing required blueprint '{prompt_path}'. Cannot verify prompt."
        )

    if not scope_path.is_file():
        raise PromptMissingError(
            f"Missing required scope declaration '{scope_path}'. Cannot verify prompt."
        )

    # 1. Validate prompt
    prompt_sha256 = verify_prompt_blueprint(prompt_path)

    # 2. Validate declared scope
    try:
        scope_data = json.loads(scope_path.read_text(encoding="utf-8"))
    except Exception as err:
        raise ScopeValidationError(f"declared_scope.json is not valid JSON: {err}") from err

    validate_declared_scope(root, scope_data, target_repositories=target_repositories)
    scope_sha256 = sha256_file(scope_path)

    # 3. Create prompt_verified.json
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    record_data: Dict[str, Any] = {
        "schema_version": "2.0",
        "task_id": task_id,
        "attempt": attempt,
        "prompt_sha256": prompt_sha256,
        "scope_sha256": scope_sha256,
        "verified_at": now_iso,
        "status": "VERIFIED",
    }

    # Validate against schema
    schema_path = get_schema_path("prompt_verified.schema.json")
    with schema_path.open("r", encoding="utf-8") as f:
        rec_schema = json.load(f)
    validate_schema(record_data, rec_schema)

    # Write atomically
    tmp_path = phase1_dir / f".prompt_verified.tmp.{os.getpid()}"
    tmp_path.write_text(pretty_json_dumps(record_data), encoding="utf-8")
    os.replace(tmp_path, verified_record_path)

    # Apply read-only mode to frozen Phase-1 files (defense-in-depth)
    for p in [prompt_path, scope_path, verified_record_path]:
        try:
            os.chmod(str(p), 0o444)
        except OSError:
            pass

    return verified_record_path


def assert_prompt_invariance(
    workspace_root: Union[str, Path],
    task_id: str,
    attempt: int = 1,
) -> Dict[str, Any]:
    """Assert that prompt.md and declared_scope.json match the frozen prompt_verified.json.

    Args:
        workspace_root: Root workspace path.
        task_id: Task identifier.
        attempt: Attempt number.

    Returns:
        Verified record data if matches.

    Raises:
        PromptNotVerifiedError: If prompt_verified.json is absent.
        PromptTamperedError: If prompt.md or declared_scope.json was modified.
    """
    root = Path(workspace_root).resolve()
    attempt_dir = resolve_task_attempt_dir(root, task_id, attempt)
    phase1_dir = attempt_dir / "Phase-1"

    prompt_path = phase1_dir / "prompt.md"
    scope_path = phase1_dir / "declared_scope.json"
    verified_record_path = phase1_dir / "prompt_verified.json"

    if not verified_record_path.is_file():
        raise PromptNotVerifiedError(
            f"Gate failure: Prompt blueprint has not been verified for task '{task_id}', "
            f"attempt {attempt}. Run 'stagecheck verify-prompt --task {task_id}' first."
        )

    try:
        record_data = json.loads(verified_record_path.read_text(encoding="utf-8"))
    except Exception as err:
        raise PromptTamperedError(
            f"Prompt verification record '{verified_record_path}' is corrupted: {err}"
        ) from err

    if not prompt_path.is_file():
        raise PromptTamperedError(
            f"Preflight defect [preflight.prompt_tampered_post_verification]: "
            f"Verified prompt '{prompt_path}' was deleted post-verification."
        )

    current_prompt_sha256 = sha256_file(prompt_path)
    if current_prompt_sha256 != record_data.get("prompt_sha256"):
        raise PromptTamperedError(
            f"Preflight defect [preflight.prompt_tampered_post_verification]: "
            f"prompt.md SHA-256 '{current_prompt_sha256}' does not match frozen digest "
            f"'{record_data.get('prompt_sha256')}'."
        )

    if not scope_path.is_file():
        raise PromptTamperedError(
            f"Preflight defect [preflight.prompt_tampered_post_verification]: "
            f"Verified declared_scope.json '{scope_path}' was deleted post-verification."
        )

    current_scope_sha256 = sha256_file(scope_path)
    if current_scope_sha256 != record_data.get("scope_sha256"):
        raise PromptTamperedError(
            f"Preflight defect [preflight.prompt_tampered_post_verification]: "
            f"declared_scope.json SHA-256 '{current_scope_sha256}' does not match frozen digest "
            f"'{record_data.get('scope_sha256')}'."
        )

    return record_data


def is_path_in_scope(
    rel_path: str,
    declared_scope: Dict[str, Any],
) -> bool:
    """Check if a working-tree relative path is permitted by the declared scope.

    Args:
        rel_path: POSIX relative path from workspace root (e.g. 'repos/app/src/main.py').
        declared_scope: Decoded declared_scope.json dictionary.

    Returns:
        True if path is allowed; False if forbidden or not covered by allowed_paths.
    """
    norm = rel_path.strip().replace("\\", "/")

    # 1. Check forbidden paths first
    forbidden_list = declared_scope.get("forbidden_paths", [])
    for forb in forbidden_list:
        forb_norm = forb.strip().replace("\\", "/")
        prefix = forb_norm.rstrip("/*")
        if (
            norm == forb_norm
            or (prefix and (norm == prefix or norm.startswith(prefix + "/")))
            or fnmatch(norm, forb_norm)
        ):
            return False

    # 2. Check allowed paths
    allowed_list = declared_scope.get("allowed_paths", [])
    for allow in allowed_list:
        allow_norm = allow.strip().replace("\\", "/")
        prefix = allow_norm.rstrip("/*")
        if (
            norm == allow_norm
            or (prefix and (norm == prefix or norm.startswith(prefix + "/")))
            or fnmatch(norm, allow_norm)
        ):
            return True

    return False
