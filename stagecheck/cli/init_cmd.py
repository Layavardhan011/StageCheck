"""Workspace Initialization Command Handler: 'stagecheck init' (P2-T5).

Executes safe workspace scaffolding under bootstrap lock, multi-repo baseline
discovery, atomic control generation, AGENTS.md contract rendering, and POSIX permissions.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional

from stagecheck.core.agents_md import write_agents_contract
from stagecheck.core.git import GitError, RepoBaseline, discover_multi_repositories, discover_repository
from stagecheck.core.locking import LockCollisionError, acquire_bootstrap_lock
from stagecheck.core.permissions import apply_at_rest_permissions, elevate_permissions_for_teardown
from stagecheck.core.scaffold import (
    ScaffoldingError,
    scaffold_agent_instructions,
    scaffold_controls_atomic,
    scaffold_task_plan,
)


def run_init(
    workspace: Optional[str] = None,
    repos: Optional[str] = None,
    force: bool = False,
    manifest_sha256: str = "0" * 64,
) -> int:
    """Execute the governed workspace initialization workflow.

    Args:
        workspace: Optional workspace root directory path (defaults to cwd).
        repos: Comma-separated list of target repository names.
        force: Whether to reinitialize an existing workspace.
        manifest_sha256: 64-char SHA-256 digest of MANIFEST.sha256.

    Returns:
        0 on success, non-zero on failure.
    """
    workspace_root = Path(workspace).resolve() if workspace else Path.cwd().resolve()
    controls_dir = workspace_root / "controls"

    try:
        # Step 1: Acquire exclusive bootstrap lock before touching controls/
        with acquire_bootstrap_lock(workspace_root):
            # Step 2: Check for pre-existing initialization
            existing_dispositions = None
            if controls_dir.is_dir():
                if not force:
                    print(
                        f"ERROR: [init.already_initialized] Workspace already initialized at '{controls_dir}'. "
                        "Use '--force' with human owner authorization to reinitialize.",
                        file=sys.stderr,
                    )
                    return 1

                print("Re-initializing existing workspace (--force). Preserving prior dispositions...")
                elevate_permissions_for_teardown(workspace_root)
                disp_file = controls_dir / "DISPOSITIONS.json"
                if disp_file.is_file():
                    try:
                        existing_dispositions = json.loads(disp_file.read_text(encoding="utf-8"))
                    except Exception:
                        pass

            # Step 3: Parse and discover target repositories
            repo_list: List[str] = []
            if repos:
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

            # Step 4: Atomically scaffold all 8 controls
            print("Atomically scaffolding the 8 mandatory control files...")
            scaffold_controls_atomic(
                workspace_root=workspace_root,
                baselines=baselines,
                manifest_sha256=manifest_sha256,
            )

            # Step 4b: Scaffold agent instructions & role definitions (Specs 03, 08)
            print("Scaffolding agent instructions under instructions/...")
            scaffold_agent_instructions(
                workspace_root=workspace_root,
                agent1_name="agent1",
                agent2_name="agent2",
            )

            # Step 4c: Scaffold specs/ and initial TASK_PLAN.json roadmap (Specs 04, 10 / GAP-05)
            print("Scaffolding initial specs/TASK_PLAN.json roadmap...")
            scaffold_task_plan(
                workspace_root=workspace_root,
                target_repos=list(baselines.keys()) if baselines else ["default"],
            )

            # Preserve previous dispositions if force reinit
            if existing_dispositions:
                disp_file = controls_dir / "DISPOSITIONS.json"
                disp_file.write_text(json.dumps(existing_dispositions, indent=2), encoding="utf-8")

            # Step 5: Render and write AGENTS.md binding contract
            print("Rendering root AGENTS.md contract with initial SHA-256 table...")
            write_agents_contract(workspace_root)

            # Step 6: Pre-scaffold evidence directory
            evidence_dir = workspace_root / "evidence"
            tasks_dir = evidence_dir / "tasks"
            tasks_dir.mkdir(parents=True, exist_ok=True)
            (evidence_dir / "sentinel.log").touch(mode=0o644, exist_ok=True)
            (evidence_dir / "sentinel_daemon.log").touch(mode=0o644, exist_ok=True)

            # Step 7: Create runtime lock file
            runtime_lock = controls_dir / ".stagecheck.lock"
            runtime_lock.touch(mode=0o600, exist_ok=True)

            # Step 8: Apply at-rest defense-in-depth POSIX security modes
            print("Enforcing defense-in-depth security modes (controls/ 0555, files 0444)...")
            apply_at_rest_permissions(workspace_root)

            print(f"SUCCESS: Workspace initialized successfully at '{workspace_root}'. State: READY.")
            return 0

    except LockCollisionError as err:
        print(f"ERROR: [init.lock_collision] {err}", file=sys.stderr)
        return 1
    except GitError as err:
        print(f"ERROR: [init.git_error] {err}", file=sys.stderr)
        return 1
    except ScaffoldingError as err:
        print(f"ERROR: [init.scaffolding_failed] {err}", file=sys.stderr)
        return 1
    except Exception as err:
        print(f"ERROR: [init.unexpected_error] {err}", file=sys.stderr)
        return 1

