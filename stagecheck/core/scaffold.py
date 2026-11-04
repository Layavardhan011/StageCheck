"""Atomic Generation and Transactional Scaffolding for the 8 Workspace Controls (P2-T3).

Ensures all 8 mandatory control files are generated, schema-validated,
and committed atomically with automatic rollback upon any failure.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from stagecheck.core.git import RepoBaseline
from stagecheck.core.utils import (
    canonical_json_dumps,
    sha256_canonical,
    sha256_digest,
)
from stagecheck.schemas.validator import validate_control_descriptor


class ScaffoldingError(Exception):
    """Raised when atomic scaffolding of controls fails."""


class ScaffoldingRollbackError(ScaffoldingError):
    """Raised when a fault causes scaffolding to roll back cleanly."""


# Default content for Markdown control files
DEFAULT_OWNER_GRANTS_MD = """# Human Owner Authorization Grants & Privileged Commands

This document records explicit, human-authorized exemptions, privileged commands,
and security waivers. AI agents have strictly zero authority to modify this file.

## Authorized Commands Whitelist
* Tests, linters, and typecheckers declared in repository configurations.
* Direct remote push commands (git push) are strictly forbidden for AI agents.

## Privileged Operator Identities
* Authorized owner: `owner@stagecheck.local`
"""

DEFAULT_FAILURE_PREVENTION_MD = """# Failure Prevention, Historical Defect Patterns & Anti-Regressions

This document catalogs prohibited development patterns, known defects, and
anti-regression invariants that all AI agents must follow during implementation.

## Anti-Regression Rules
1. Never bypass test execution or weaken assertion criteria.
2. Never hardcode absolute developer machine paths.
3. Preserve multi-repository branch containment on task branches.
4. Never introduce unencrypted API credentials or secret tokens.
"""


def build_control_descriptors(
    baselines: Dict[str, RepoBaseline],
    manifest_sha256: str = "0" * 64,
    stagecheck_root: str = "@package",
    evidence_root: str = "evidence",
    qualification_root: str = "evals",
) -> Dict[str, str]:
    """Generate the formatted string content for all 8 mandatory control files.

    Returns:
        Mapping of filename -> file content string.
    """
    repo_registry_content: Dict[str, Any] = {
        "schema_version": "2.0",
        "repositories": {
            name: {
                "path": baseline.rel_path,
                "default_branch": baseline.branch or "main",
                "baseline_head": baseline.head_commit or ("0" * 40),
            }
            for name, baseline in baselines.items()
        },
    }

    active_state_content: Dict[str, Any] = {
        "schema_version": "2.0",
        "task_id": "task-init",
        "phase": "NOT_STARTED",
        "attempt_index": 1,
        "repair_index": 0,
        "max_total_attempts": 3,
        "max_repairs": 2,
        "circuit_breaker_tripped": False,
        "target_repositories": list(baselines.keys()) if baselines else ["default"],
    }

    stagecheck_root_content = {
        "stagecheck_root": stagecheck_root,
        "manifest_sha256": manifest_sha256,
    }

    evidence_root_content = {
        "evidence_root": evidence_root,
    }

    qualification_root_content = {
        "qualification_root": qualification_root,
    }

    dispositions_content = {
        "schema_version": "2.0",
        "dispositions": [],
    }

    return {
        "STAGECHECK_ROOT.json": canonical_json_dumps(stagecheck_root_content),
        "EVIDENCE_ROOT.json": canonical_json_dumps(evidence_root_content),
        "PRODUCT_REPOSITORIES.json": canonical_json_dumps(repo_registry_content),
        "QUALIFICATION_ROOT.json": canonical_json_dumps(qualification_root_content),
        "ACTIVE_STATE.json": canonical_json_dumps(active_state_content),
        "OWNER_GRANTS.md": DEFAULT_OWNER_GRANTS_MD,
        "FAILURE_PREVENTION.md": DEFAULT_FAILURE_PREVENTION_MD,
        "DISPOSITIONS.json": canonical_json_dumps(dispositions_content),
    }


def scaffold_controls_atomic(
    workspace_root: Path,
    baselines: Dict[str, RepoBaseline],
    manifest_sha256: str = "0" * 64,
    stagecheck_root: str = "@package",
    fault_injector: Optional[Callable[[str], None]] = None,
) -> Dict[str, Path]:
    """Atomically generate all 8 control descriptors under controls/ directory.

    If any descriptor fails generation or validation, or if fault_injector raises
    an exception, all staged files are deleted and controls/ is cleanly rolled back.

    Args:
        workspace_root: Canonical workspace root directory.
        baselines: Discovered multi-repository baselines.
        manifest_sha256: 64-char SHA-256 digest of MANIFEST.sha256.
        stagecheck_root: Package root reference ('@package' or relative path).
        fault_injector: Optional test hook to inject faults during staging.

    Returns:
        Mapping of descriptor filename -> final Path in controls/.

    Raises:
        ScaffoldingError: If generation, validation, or atomic commit fails.
    """
    root = Path(workspace_root).resolve()
    controls_dir = root / "controls"

    # Build descriptor string contents
    descriptors = build_control_descriptors(
        baselines=baselines,
        manifest_sha256=manifest_sha256,
        stagecheck_root=stagecheck_root,
    )

    # Staging directory for atomic transaction
    staging_dir = Path(tempfile.mkdtemp(prefix=".stagecheck_scaffold_", dir=str(root)))
    created_in_controls = False

    try:
        # 1. Write and validate each descriptor in staging
        for filename, content in descriptors.items():
            staged_file = staging_dir / filename
            staged_file.write_text(content, encoding="utf-8")

            # Validate JSON descriptors against their schemas
            if filename.endswith(".json"):
                import json
                data = json.loads(content)
                validate_control_descriptor(filename, data)

            # Fault injection hook for fault-injection unit tests
            if fault_injector:
                fault_injector(filename)

        # 2. Commit transaction: move staged files into controls/
        controls_dir.mkdir(parents=True, exist_ok=True)
        created_in_controls = True

        final_paths: Dict[str, Path] = {}
        for filename in descriptors.keys():
            staged_file = staging_dir / filename
            dest_file = controls_dir / filename
            # Atomic file replace
            os.replace(str(staged_file), str(dest_file))
            final_paths[filename] = dest_file

        return final_paths

    except Exception as err:
        # Rollback: Clean up staging and remove any files written to controls/
        if controls_dir.exists() and created_in_controls:
            for filename in descriptors.keys():
                dest_file = controls_dir / filename
                if dest_file.exists():
                    dest_file.unlink()
            # If controls directory is empty, remove it
            try:
                controls_dir.rmdir()
            except OSError:
                pass

        raise ScaffoldingRollbackError(
            f"Atomic scaffolding transaction rolled back due to error: {err}"
        ) from err

    finally:
        # Clean up staging directory
        if staging_dir.exists():
            shutil.rmtree(staging_dir, ignore_errors=True)
