"""Task Plan Roadmap CLI Command Handler: 'stagecheck plan' (GAP-05, GAP-H4, GAP-L1).

Implements:
- 'stagecheck plan validate': Validates schema, repo whitelisting, and DAG cycles (Kahn's algorithm).
- 'stagecheck plan next [--activate]': Determines next eligible task and optionally activates it.
- 'stagecheck plan show': Visualizes roadmap in terminal.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

from stagecheck.core.paths import find_workspace_root
from stagecheck.core.task_plan import (
    CircularDependencyError,
    TaskPlanError,
    UnauthorizedRepositoryError,
    UnknownDependencyError,
    get_next_eligible_task,
    validate_task_plan,
)
from stagecheck.core.utils import load_json_file


def run_plan(
    action: str,
    workspace: Optional[str] = None,
    task_id: Optional[str] = None,
    activate: bool = False,
) -> int:
    """Execute 'stagecheck plan' roadmap commands."""
    try:
        workspace_root = Path(workspace).resolve() if workspace else find_workspace_root()
    except Exception as err:
        print(f"ERROR: [plan.workspace_error] {err}", file=sys.stderr)
        return 1

    plan_path = workspace_root / "specs" / "TASK_PLAN.json"
    if not plan_path.is_file():
        print(f"ERROR: [plan.missing_plan] Roadmap file not found at '{plan_path}'.", file=sys.stderr)
        return 1

    try:
        plan_data = load_json_file(plan_path)
    except Exception as err:
        print(f"ERROR: [plan.invalid_json] Failed to parse roadmap JSON: {err}", file=sys.stderr)
        return 1

    # Load declared product repositories
    product_repos_file = workspace_root / "controls" / "PRODUCT_REPOSITORIES.json"
    registered_repos = None
    if product_repos_file.is_file():
        try:
            repos_data = load_json_file(product_repos_file)
            registered_repos = list(repos_data.get("repositories", {}).keys())
        except Exception:
            pass

    if action == "validate":
        try:
            topo = validate_task_plan(plan_data, registered_repos=registered_repos)
            print(f"SUCCESS: Task plan roadmap is valid. Topological order: {' -> '.join(topo)}")
            return 0
        except CircularDependencyError as err:
            print(f"ERROR: [plan.circular_dependency] {err}", file=sys.stderr)
            return 1
        except UnknownDependencyError as err:
            print(f"ERROR: [plan.unknown_dependency] {err}", file=sys.stderr)
            return 1
        except UnauthorizedRepositoryError as err:
            print(f"ERROR: [plan.unauthorized_repo] {err}", file=sys.stderr)
            return 1
        except Exception as err:
            print(f"ERROR: [plan.validation_error] {err}", file=sys.stderr)
            return 1

    elif action == "next":
        # Load completed tasks from ACTIVE_STATE.json if present
        completed_tasks = set()
        active_state_file = workspace_root / "controls" / "ACTIVE_STATE.json"
        if active_state_file.is_file():
            try:
                state_data = load_json_file(active_state_file)
                completed_tasks = set(state_data.get("completed_tasks", []))
            except Exception:
                pass

        next_task = get_next_eligible_task(plan_data, completed_tasks=completed_tasks)
        if not next_task:
            print("Notice: No pending eligible tasks found in roadmap. All tasks completed or blocked.")
            return 0

        print(f"Next eligible task: {next_task['task_id']} - {next_task['title']} (Priority: {next_task['priority']})")
        if activate:
            print(f"Activating task '{next_task['task_id']}'...")
            from stagecheck.cli.start_cmd import run_start
            return run_start(task=next_task["task_id"], workspace=str(workspace_root))
        return 0

    elif action == "show":
        tasks = plan_data.get("tasks", [])
        print(f"Project: {plan_data.get('project_name', 'StageCheck Workspace')} (Roadmap)")
        print("-" * 60)
        for t in tasks:
            deps = ", ".join(t.get("dependencies", [])) or "None"
            repos = ", ".join(t.get("target_repositories", []))
            print(f"[{t.get('status', 'planned').upper()}] {t['task_id']}: {t['title']}")
            print(f"  Priority: {t.get('priority')} | Repos: {repos} | Depends on: {deps}")
        return 0

    print(f"ERROR: Unknown action '{action}'. Use validate, next, or show.", file=sys.stderr)
    return 1

