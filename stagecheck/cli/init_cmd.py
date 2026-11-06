"""Workspace Initialization Command Handler: 'stagecheck init' (P2-T5).

Executes safe workspace scaffolding under bootstrap lock, multi-repo baseline
discovery, atomic control generation, AGENTS.md contract rendering, and POSIX permissions.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path
from typing import Dict, List, Optional, Union

from stagecheck.core.agents_md import write_agents_contract
from stagecheck.core.git import GitError, RepoBaseline, discover_multi_repositories, discover_repository
from stagecheck.core.locking import LockCollisionError, acquire_bootstrap_lock
from stagecheck.core.permissions import apply_at_rest_permissions, elevate_permissions_for_teardown
from stagecheck.core.scaffold import (
    ScaffoldingError,
    reconcile_controls,
    reconcile_specs_directory,
    scaffold_agent_instructions,
    scaffold_controls_atomic,
    scaffold_task_plan,
)
from stagecheck.core.utils import AgentSlugError, pretty_json_dumps, validate_agent_slug


def _prompt_for_agent(prompt_text: str) -> Optional[str]:
    """Interactively prompt for an agent name with validation and retry.

    Returns:
        The validated raw agent name, or None on user abort (EOF / Ctrl+C).
    """
    while True:
        try:
            val = input(prompt_text).strip()
        except (EOFError, KeyboardInterrupt):
            print("\nInitialization aborted by user.", file=sys.stderr)
            return None

        if not val:
            print("Error: Agent name cannot be empty. Please enter a valid name.", file=sys.stderr)
            continue

        try:
            validate_agent_slug(val.lower().strip())
            return val
        except AgentSlugError as err:
            print(f"Error: Invalid agent name '{val}'. {err}", file=sys.stderr)
            continue


def run_init(
    workspace: Optional[str] = None,
    repos: Optional[Union[str, List[str]]] = None,
    force: bool = False,
    manifest_sha256: str = "0" * 64,
    agent1: Optional[str] = None,
    agent2: Optional[str] = None,
) -> int:
    """Execute the governed workspace initialization workflow.

    Args:
        workspace: Optional workspace root directory path (defaults to cwd).
        repos: Comma-separated list of target repository names.
        force: Whether to reinitialize an existing workspace.
        manifest_sha256: 64-char SHA-256 digest of MANIFEST.sha256.
        agent1: Optional Agent 1 identifier (Prompt Architect & Auditor).
        agent2: Optional Agent 2 identifier (Code Implementer).

    Returns:
        0 on success, non-zero on failure.
    """
    workspace_root = Path(workspace).resolve() if workspace else Path.cwd().resolve()
    controls_dir = workspace_root / "controls"

    # Pre-validate explicit CLI arguments if passed
    if agent1 is not None:
        if not agent1.strip():
            print("ERROR: [init.invalid_agent] Agent 1 name cannot be empty.", file=sys.stderr)
            return 1
        try:
            validate_agent_slug(agent1.lower().strip())
        except AgentSlugError as err:
            print(f"ERROR: [init.invalid_agent] Invalid --agent1 value '{agent1}': {err}", file=sys.stderr)
            return 1

    if agent2 is not None:
        if not agent2.strip():
            print("ERROR: [init.invalid_agent] Agent 2 name cannot be empty.", file=sys.stderr)
            return 1
        try:
            validate_agent_slug(agent2.lower().strip())
        except AgentSlugError as err:
            print(f"ERROR: [init.invalid_agent] Invalid --agent2 value '{agent2}': {err}", file=sys.stderr)
            return 1

    try:
        # Step 1: Acquire exclusive bootstrap lock before touching controls/
        with acquire_bootstrap_lock(workspace_root):
            # Step 2: Check for pre-existing initialization and reconcile
            existing_dispositions = None
            is_reconcile = controls_dir.is_dir()

            if is_reconcile:
                elevate_permissions_for_teardown(workspace_root)
                if force:
                    print("Re-initializing existing workspace (--force). Preserving prior dispositions...")
                    disp_file = controls_dir / "DISPOSITIONS.json"
                    if disp_file.is_file():
                        try:
                            existing_dispositions = json.loads(disp_file.read_text(encoding="utf-8"))
                        except Exception:
                            pass
                else:
                    print("Reconciling existing workspace (self-healing mode)...")

            # Step 2b: Interactive or flag-based agent selection (Spec 04)
            resolved_a1 = agent1
            resolved_a2 = agent2
            is_interactive = sys.stdin.isatty()

            if not resolved_a1 or not resolved_a2:
                if not is_interactive:
                    print(
                        "ERROR: [init.missing_agent] In non-interactive mode, both --agent1 and --agent2 flags are required.",
                        file=sys.stderr,
                    )
                    return 1

                # Interactive prompt
                print("================================================================")
                print("          STAGECHECK PROGRAMME WORKSPACE SETUP")
                print("================================================================\n")

                if not resolved_a1:
                    resolved_a1 = _prompt_for_agent(
                        "Enter Agent 1 name (Prompt Architect & Auditor)\n[e.g. Claude, Gemini, Cursor]: "
                    )
                    if resolved_a1 is None:
                        return 1

                if not resolved_a2:
                    prompt_prefix = "\n" if not agent1 else ""
                    resolved_a2 = _prompt_for_agent(
                        f"{prompt_prefix}Enter Agent 2 name (Code Implementer)\n[e.g. Codex, Cursor, Gemini]: "
                    )
                    if resolved_a2 is None:
                        return 1

            norm_a1 = resolved_a1.lower().strip()
            norm_a2 = resolved_a2.lower().strip()
            is_single_agent = (norm_a1 == norm_a2)

            print("\n[INFO] Comparing agent identities:")
            if is_single_agent:
                print(f"  - Agent 1: {resolved_a1.strip()}")
                print(f"  - Agent 2: {resolved_a2.strip()}")
                print("[INFO] Single-Agent Mode detected (Both roles assigned to same agent).")
                print("       -> Generating unified dual-role instructions:")
                print(f"          - instructions/{norm_a1}_dual_role.md")
            else:
                print(f"  - Agent 1: {resolved_a1.strip()} (Prompt & Audit)")
                print(f"  - Agent 2: {resolved_a2.strip()} (Code Implementation)")
                print("[INFO] Dual-Agent Mode detected (Different agents).")
                print("       -> Generating separate role instructions:")
                print(f"          - instructions/{norm_a1}_prompt_and_audit.md")
                print(f"          - instructions/{norm_a2}_code_implementation.md")

            # Step 3: Parse and discover target repositories
            repo_list: List[str] = []
            if isinstance(repos, list):
                repo_list = [str(r).strip() for r in repos if str(r).strip()]
            elif repos:
                repo_list = [r.strip() for r in repos.split(",") if r.strip()]
            else:
                # Autodiscover subdirectories under repos/
                repos_parent = workspace_root / "repos"
                if repos_parent.is_dir():
                    repo_list = [d.name for d in repos_parent.iterdir() if d.is_dir() and not d.name.startswith(".")]

            baselines: Dict[str, RepoBaseline] = {}
            if repo_list:
                print(f"Discovering target repositories under repos/: {', '.join(repo_list)}")
                baselines = discover_multi_repositories(
                    workspace_root=workspace_root,
                    declared_repos=repo_list,
                    allow_unborn=False,
                    require_clean=False,
                )
            else:
                print("Notice: No repositories declared or found under repos/. Initializing base workspace controls.")

            # Step 4: Scaffold or reconcile controls
            if not is_reconcile or force:
                print("Atomically scaffolding the 8 mandatory control files...")
                scaffold_controls_atomic(
                    workspace_root=workspace_root,
                    baselines=baselines,
                    manifest_sha256=manifest_sha256,
                    agent1_name=resolved_a1,
                    agent2_name=resolved_a2,
                )
            else:
                print("Reconciling mandatory control files in controls/...")
                reconcile_controls(
                    workspace_root=workspace_root,
                    baselines=baselines,
                    manifest_sha256=manifest_sha256,
                    agent1_name=resolved_a1,
                    agent2_name=resolved_a2,
                )

            # Step 4b: Scaffold agent instructions & role definitions (Specs 03, 08)
            print("Reconciling agent instructions under instructions/...")
            scaffold_agent_instructions(
                workspace_root=workspace_root,
                agent1_name=resolved_a1,
                agent2_name=resolved_a2,
            )

            # Step 4c: Scaffold specs/ and reconcile specification files (Spec 05 / FR-08)
            print("Reconciling specifications under specs/ (TASK_PLAN.json, ARCHITECTURE.md, START_MANIFEST.md)...")
            reconcile_specs_directory(
                workspace_root=workspace_root,
                target_repos=list(baselines.keys()) if baselines else ["default"],
            )

            # Preserve previous dispositions if force reinit
            if existing_dispositions:
                disp_file = controls_dir / "DISPOSITIONS.json"
                disp_file.write_text(pretty_json_dumps(existing_dispositions), encoding="utf-8")

            # Step 5: Render and write AGENTS.md binding contract
            print("Rendering root AGENTS.md contract with initial SHA-256 table...")
            write_agents_contract(workspace_root)

            # Step 6: Pre-scaffold evidence directory
            evidence_dir = workspace_root / "evidence"
            tasks_dir = evidence_dir / "tasks"
            tasks_dir.mkdir(parents=True, exist_ok=True)
            (evidence_dir / "sentinel.log").touch(mode=0o644, exist_ok=True)
            (evidence_dir / "sentinel_daemon.log").touch(mode=0o644, exist_ok=True)

            # Step 7: Create runtime lock file at workspace root (SR-06 / SEC-05) and controls/
            (workspace_root / ".stagecheck.lock").touch(mode=0o600, exist_ok=True)
            (controls_dir / ".stagecheck.lock").touch(mode=0o600, exist_ok=True)

            # Step 8: Apply at-rest defense-in-depth POSIX security modes
            print("Enforcing defense-in-depth security modes (controls/ 0555, files 0444)...")
            apply_at_rest_permissions(workspace_root)

            print(f"SUCCESS: Workspace reconciled successfully at '{workspace_root}'. State: READY.")
            return 0

    except LockCollisionError as err:
        print(f"ERROR: [init.lock_collision] {err}", file=sys.stderr)
        return 1
    except GitError as err:
        print(f"ERROR: [init.git_error] {err}", file=sys.stderr)
        return 1
    except ScaffoldingError as err:
        print(f"ERROR: [init.scaffolding_failed] {err}", file=sys.stderr)
        # Clean up any partially scaffolded directories if controls was not created
        instructions_dir = workspace_root / "instructions"
        if instructions_dir.is_dir() and not controls_dir.is_dir():
            shutil.rmtree(instructions_dir, ignore_errors=True)
        specs_dir = workspace_root / "specs"
        if specs_dir.is_dir() and not controls_dir.is_dir():
            shutil.rmtree(specs_dir, ignore_errors=True)
        return 1
    except Exception as err:
        print(f"ERROR: [init.unexpected_error] {err}", file=sys.stderr)
        return 1
