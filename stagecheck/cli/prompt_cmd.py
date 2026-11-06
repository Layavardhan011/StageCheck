"""Prompt Verification CLI Command Handler: 'stagecheck verify-prompt' (P3-T2).

Verifies Phase 1 prompt blueprint, validates declared_scope.json containment,
freezes cryptographic digests into prompt_verified.json, and locks file modes.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

from stagecheck.core.prompt_gate import (
    PromptGateError,
    assert_prompt_invariance,
    freeze_prompt_and_scope,
)


def run_verify_prompt(
    task: str,
    attempt: int = 1,
    workspace: Optional[str] = None,
    freeze_reason: str = "INOTIFY_SILENCE_30S",
) -> int:
    """Execute the prompt verification workflow.

    Args:
        task: Task identifier string.
        attempt: Attempt index (defaults to 1).
        workspace: Optional workspace root path.

    Returns:
        0 on success, non-zero on verification error.
    """
    workspace_root = Path(workspace).resolve() if workspace else Path.cwd().resolve()

    try:
        print(f"Freezing and verifying Phase 1 prompt for task '{task}', attempt {attempt}...")
        record_path = freeze_prompt_and_scope(
            workspace_root=workspace_root,
            task_id=task,
            attempt=attempt,
            freeze_reason=freeze_reason,
        )
        # Assert invariance immediately as self-check
        record = assert_prompt_invariance(workspace_root=workspace_root, task_id=task, attempt=attempt)
        print(
            f"SUCCESS: Prompt blueprint verified and frozen.\n"
            f"  Record: {record_path}\n"
            f"  Prompt SHA-256: {record['prompt_sha256']}\n"
            f"  Scope SHA-256:  {record['scope_sha256']}\n"
            f"  Status:         {record['status']}"
        )
        return 0

    except PromptGateError as err:
        print(f"ERROR: [prompt_verification_failed] {err}", file=sys.stderr)
        return 1
    except Exception as err:
        print(f"ERROR: [unexpected_prompt_error] {err}", file=sys.stderr)
        return 1

