"""Atomic Generation and Transactional Scaffolding for the 8 Workspace Controls (P2-T3).

Ensures all 8 mandatory control files are generated, schema-validated,
and committed atomically with automatic rollback upon any failure.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from stagecheck.core.git import RepoBaseline
from stagecheck.core.utils import (
    canonical_json_dumps,
    pretty_json_dumps,
    sha256_canonical,
    sha256_digest,
    sha256_file,
    validate_agent_slug,
)
from stagecheck.schemas.validator import validate_control_descriptor

deterministic_json_dumps = pretty_json_dumps


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

DEFAULT_AGENT1_INSTRUCTIONS_MD = """# Agent 1 Instructions: Prompt Architecture & Governance Auditor

Role: `prompt_and_audit`.

## Purpose
Decompose product requirements, generate Phase 1 prompts (`prompt.md`), define declared scope (`declared_scope.json`), perform Phase 2A pre-commit cooperative differential reviews, and conduct Phase 3 independent audit reviews.

## Inputs
- `specs/TASK_PLAN.json`
- `specs/ARCHITECTURE.md`
- `controls/ACTIVE_STATE.json`
- `evidence/tasks/<task_id>/attempt_<N>/`

## Checks
- Verify task decomposition against architectural contracts.
- Review uncommitted diffs for scope compliance and secret exposure.
- Record defect history in `TASK_<ID>_ISSUE_HISTORY.md`.

## Must Not
- MUST NOT execute mutating Git commands (`git commit`, `git push`, `git merge`, `git rebase`).
- MUST NOT write product code in `repos/*`.
- MUST NOT alter control descriptors in `controls/*` or edit `.stagecheck.lock`.
- Permitted Git commands are strictly read-only: `git status`, `git log`, `git diff`, `git show`, `git blame`, `git branch`.
"""

DEFAULT_AGENT2_INSTRUCTIONS_MD = """# Agent 2 Instructions: Code Implementation & Test Authoring

Role: `code_implementation`.

## Purpose
Implement source code, unit tests, and regression coverage for approved tasks on permitted sprint branches.

## Inputs
- `evidence/tasks/<task_id>/attempt_<N>/Phase-1/prompt.md`
- `evidence/tasks/<task_id>/attempt_<N>/Phase-1/declared_scope.json`
- `controls/ACTIVE_STATE.json`

## Checks
- Ensure code satisfies declared scope without modifying forbidden paths.
- Ensure all unit tests pass locally before submitting for Phase 2A review.
- Run local Gitleaks secret check (`gitleaks protect --staged`) prior to commit.

## Must Not
- MUST NOT execute remote push operations (`git push` is strictly forbidden).
- MUST NOT commit directly to `main` or `master` branch.
- MUST NOT modify control descriptors in `controls/*`.
- MUST NOT alter Gitleaks configuration or create `.gitleaksignore` override files.
"""


def scaffold_agent_instructions(
    workspace_root: Path,
    agent1_name: str = "agent1",
    agent2_name: str = "agent2",
) -> Dict[str, Path]:
    """Scaffold instructions/ directory and role instruction markdown files (Specs 03, 08)."""
    root = Path(workspace_root).resolve()
    instructions_dir = root / "instructions"
    instructions_dir.mkdir(parents=True, exist_ok=True)

    norm_a1 = validate_agent_slug(agent1_name.strip().lower())
    norm_a2 = validate_agent_slug(agent2_name.strip().lower())

    paths: Dict[str, Path] = {}
    if norm_a1 == norm_a2:
        # Single-agent unified dual role
        single_path = instructions_dir / f"{norm_a1}_dual_role.md"
        if not single_path.exists():
            single_content = (
                f"# {agent1_name.strip()} Unified Instructions: Dual-Role Operating Protocol\n\n"
                f"Role: `dual_role`.\n\n"
                f"This workspace operates in **Single-Agent Mode** where `{agent1_name.strip()}` executes both "
                f"prompt architecture/auditing and code implementation.\n"
                f"To preserve governance separation of concerns, the agent must strictly alternate between "
                f"planning/auditing and implementation phases.\n\n"
                f"---\n\n"
                f"## Part 1: Planning & Auditing Responsibilities (Phase 1, Phase 2A Review, Phase 3 Audit)\n\n"
                f"### Purpose\n"
                f"Decompose product requirements, generate Phase 1 prompts (`prompt.md`), define declared scope (`declared_scope.json`), "
                f"perform Phase 2A pre-commit cooperative differential reviews, and inspect Phase 3 independent audit verifications.\n\n"
                f"### Inputs\n"
                f"- `specs/TASK_PLAN.json`\n"
                f"- `specs/ARCHITECTURE.md`\n"
                f"- `controls/ACTIVE_STATE.json`\n"
                f"- `evidence/tasks/<task_id>/attempt_<N>/`\n\n"
                f"### Checks & Invariants\n"
                f"- Verify task decomposition against architectural contracts.\n"
                f"- Review uncommitted diffs for scope compliance and secret exposure.\n"
                f"- Record defect history in `TASK_<ID>_ISSUE_HISTORY.md`.\n\n"
                f"### Phase Restrictions\n"
                f"- In planning/review phases, DO NOT write implementation code in `repos/*`.\n"
                f"- NEVER execute remote push commands (`git push`).\n"
                f"- Permitted Git commands during review are read-only: `git status`, `git log`, `git diff`, `git show`, `git blame`, `git branch`.\n\n"
                f"---\n\n"
                f"## Part 2: Code Implementation Responsibilities (Phase 2A Implementation & Delivery)\n\n"
                f"### Purpose\n"
                f"Implement source code, unit tests, and regression coverage for approved tasks on permitted task branches.\n\n"
                f"### Inputs\n"
                f"- `evidence/tasks/<task_id>/attempt_<N>/Phase-1/prompt.md`\n"
                f"- `evidence/tasks/<task_id>/attempt_<N>/Phase-1/declared_scope.json`\n"
                f"- `controls/ACTIVE_STATE.json`\n\n"
                f"### Checks & Invariants\n"
                f"- Ensure code satisfies declared scope without modifying forbidden paths.\n"
                f"- Ensure all unit tests pass locally before submitting for Phase 2A review.\n"
                f"- Run local secret check (`gitleaks protect --staged`) prior to local commit.\n\n"
                f"### Security Invariants & Negative Prohibitions\n"
                f"- MUST NOT execute remote push operations (`git push` is strictly forbidden).\n"
                f"- MUST NOT commit directly to `main` or `master` branch.\n"
                f"- MUST NOT modify control descriptors in `controls/*` or edit `.stagecheck.lock`.\n"
                f"- MUST NOT alter Gitleaks configuration or create `.gitleaksignore` override files.\n"
            )
            single_path.write_text(single_content, encoding="utf-8")
        paths[single_path.name] = single_path
    else:
        # Dual-agent separate instructions
        a1_path = instructions_dir / f"{norm_a1}_prompt_and_audit.md"
        if not a1_path.exists():
            a1_content = (
                f"# {agent1_name.strip()} Instructions: Prompt Architecture & Governance Auditor\n\n"
                f"Role: `prompt_and_audit`.\n\n"
                + DEFAULT_AGENT1_INSTRUCTIONS_MD[DEFAULT_AGENT1_INSTRUCTIONS_MD.find("## Purpose"):]
            )
            a1_path.write_text(a1_content, encoding="utf-8")
        paths[a1_path.name] = a1_path

        a2_path = instructions_dir / f"{norm_a2}_code_implementation.md"
        if not a2_path.exists():
            a2_content = (
                f"# {agent2_name.strip()} Instructions: Code Implementation & Test Authoring\n\n"
                f"Role: `code_implementation`.\n\n"
                + DEFAULT_AGENT2_INSTRUCTIONS_MD[DEFAULT_AGENT2_INSTRUCTIONS_MD.find("## Purpose"):]
            )
            a2_path.write_text(a2_content, encoding="utf-8")
        paths[a2_path.name] = a2_path

    return paths


def scaffold_task_plan(
    workspace_root: Path,
    target_repos: Optional[List[str]] = None,
    project_name: str = "stagecheck-workspace",
) -> Path:
    """Scaffold initial specs/TASK_PLAN.json roadmap (Specs 04, 10 / GAP-05)."""
    root = Path(workspace_root).resolve()
    specs_dir = root / "specs"
    specs_dir.mkdir(parents=True, exist_ok=True)

    plan_file = specs_dir / "TASK_PLAN.json"
    if not plan_file.exists():
        repos = target_repos if target_repos else ["default"]
        initial_plan = {
            "schema_version": 1,
            "project_name": project_name,
            "created_at": "2026-11-04T00:00:00Z",
            "updated_at": "2026-11-04T00:00:00Z",
            "tasks": [
                {
                    "task_id": "TASK-01",
                    "title": "Initial workspace bootstrap and baseline verification",
                    "description": "Establish baseline repository structure and execute initial preflight validation.",
                    "status": "planned",
                    "priority": "HIGH",
                    "dependencies": [],
                    "target_repositories": repos,
                }
            ],
        }
        plan_file.write_text(deterministic_json_dumps(initial_plan), encoding="utf-8")

    return plan_file


def reconcile_specs_directory(
    workspace_root: Path,
    target_repos: Optional[List[str]] = None,
    project_name: str = "stagecheck-workspace",
) -> Dict[str, Path]:
    """Ensure all required files exist in specs/ without destroying existing files (Spec 05 / FR-08).

    1. Checks specs/TASK_PLAN.json -> creates default if missing, preserves if present.
    2. Checks specs/ARCHITECTURE.md -> creates default template if missing, preserves if present.
    3. Checks specs/START_MANIFEST.md -> calculates SHA-256 of all specs files and generates manifest if missing.
    """
    root = Path(workspace_root).resolve()
    specs_dir = root / "specs"
    specs_dir.mkdir(parents=True, exist_ok=True)

    reconciled_paths: Dict[str, Path] = {}

    # 1. Ensure TASK_PLAN.json
    plan_file = specs_dir / "TASK_PLAN.json"
    if not plan_file.exists():
        scaffold_task_plan(root, target_repos=target_repos, project_name=project_name)
    reconciled_paths["TASK_PLAN.json"] = plan_file

    # 2. Ensure ARCHITECTURE.md
    arch_file = specs_dir / "ARCHITECTURE.md"
    if not arch_file.exists():
        arch_content = (
            f"# {project_name} Architectural Specifications\n\n"
            "## 1. System Overview\nDocument core system modules and execution boundaries.\n\n"
            "## 2. Protocol Invariants\nDefine non-negotiable blockchain and security invariants.\n"
        )
        arch_file.write_text(arch_content, encoding="utf-8")
    reconciled_paths["ARCHITECTURE.md"] = arch_file

    # 3. Ensure START_MANIFEST.md (Always hashes current files in specs/)
    manifest_file = specs_dir / "START_MANIFEST.md"
    if not manifest_file.exists():
        manifest_lines = [
            "# Project Specification Baseline Manifest (`START_MANIFEST.md`)\n\n",
            "**Generated by:** StageCheck Scaffolding Engine (v2.0.0)\n\n",
            "| Specification File | Relative Path | SHA-256 Digest |\n",
            "|---|---|---|\n",
        ]
        for f in sorted(specs_dir.glob("*")):
            if f.name == "START_MANIFEST.md" or f.is_dir():
                continue
            f_hash = sha256_file(f)
            manifest_lines.append(f"| `{f.name}` | `specs/{f.name}` | `{f_hash}` |\n")

        manifest_file.write_text("".join(manifest_lines), encoding="utf-8")
    reconciled_paths["START_MANIFEST.md"] = manifest_file

    return reconciled_paths


def build_control_descriptors(
    baselines: Dict[str, RepoBaseline],
    manifest_sha256: str = "0" * 64,
    stagecheck_root: str = "@package",
    evidence_root: str = "evidence",
    qualification_root: str = "evals",
    agent1_name: str = "agent1",
    agent2_name: str = "agent2",
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

    norm_a1 = validate_agent_slug(agent1_name.strip().lower())
    norm_a2 = validate_agent_slug(agent2_name.strip().lower())
    single_agent_mode = (norm_a1 == norm_a2)

    if single_agent_mode:
        registered_agents = [
            {
                "name": norm_a1,
                "role": "dual_role",
                "instruction": f"instructions/{norm_a1}_dual_role.md",
                "comment": f"{agent1_name.strip()} unified dual-role agent",
                "enabled": True,
            }
        ]
    else:
        registered_agents = [
            {
                "name": norm_a1,
                "role": "prompt_and_audit",
                "instruction": f"instructions/{norm_a1}_prompt_and_audit.md",
                "comment": f"{agent1_name.strip()} prompt architect and auditor",
                "enabled": True,
            },
            {
                "name": norm_a2,
                "role": "code_implementation",
                "instruction": f"instructions/{norm_a2}_code_implementation.md",
                "comment": f"{agent2_name.strip()} code implementer",
                "enabled": True,
            },
        ]

    active_state_content: Dict[str, Any] = {
        "schema_version": "2.0",
        "task_id": "task-init",
        "phase": "NOT_STARTED",
        "attempt_index": 1,
        "repair_index": 0,
        "max_total_attempts": 3,
        "max_repairs": 2,
        "circuit_breaker_tripped": False,
        "single_agent_mode": single_agent_mode,
        "target_repositories": list(baselines.keys()) if baselines else ["default"],
        "registered_agents": registered_agents,
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
        "STAGECHECK_ROOT.json": deterministic_json_dumps(stagecheck_root_content),
        "EVIDENCE_ROOT.json": deterministic_json_dumps(evidence_root_content),
        "PRODUCT_REPOSITORIES.json": deterministic_json_dumps(repo_registry_content),
        "QUALIFICATION_ROOT.json": deterministic_json_dumps(qualification_root_content),
        "ACTIVE_STATE.json": deterministic_json_dumps(active_state_content),
        "OWNER_GRANTS.md": DEFAULT_OWNER_GRANTS_MD,
        "FAILURE_PREVENTION.md": DEFAULT_FAILURE_PREVENTION_MD,
        "DISPOSITIONS.json": deterministic_json_dumps(dispositions_content),
    }


def reconcile_controls(
    workspace_root: Path,
    baselines: Dict[str, RepoBaseline],
    manifest_sha256: str = "0" * 64,
    stagecheck_root: str = "@package",
    agent1_name: str = "agent1",
    agent2_name: str = "agent2",
) -> Dict[str, Path]:
    """Reconcile the 8 mandatory control files in controls/ without destroying existing files.

    For each of the 8 mandatory control files:
    - If it already exists: preserves developer customizations verbatim.
    - If it is missing: generates compliant template and validates it against its schema.
    """
    root = Path(workspace_root).resolve()
    controls_dir = root / "controls"
    controls_dir.mkdir(parents=True, exist_ok=True)

    descriptors = build_control_descriptors(
        baselines=baselines,
        manifest_sha256=manifest_sha256,
        stagecheck_root=stagecheck_root,
        agent1_name=agent1_name,
        agent2_name=agent2_name,
    )

    reconciled_paths: Dict[str, Path] = {}
    for filename, content in descriptors.items():
        file_path = controls_dir / filename
        if not file_path.exists():
            file_path.write_text(content, encoding="utf-8")
            if filename.endswith(".json"):
                data = json.loads(content)
                validate_control_descriptor(filename, data)
        reconciled_paths[filename] = file_path

    return reconciled_paths


def scaffold_controls_atomic(
    workspace_root: Path,
    baselines: Dict[str, RepoBaseline],
    manifest_sha256: str = "0" * 64,
    stagecheck_root: str = "@package",
    agent1_name: str = "agent1",
    agent2_name: str = "agent2",
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
        agent1_name: Agent 1 identifier slug or name.
        agent2_name: Agent 2 identifier slug or name.
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
        agent1_name=agent1_name,
        agent2_name=agent2_name,
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

