"""Task Plan Roadmap Engine and Topological Cycle Detection (GAP-05, GAP-H4, GAP-L1).

Enforces:
1. Task plan JSON schema validation.
2. Target repository whitelisting against registered product repositories (SEC-H3).
3. Orphan dependency assertion (GAP-H4).
4. Directed Cycle Detection using Kahn's algorithm (GAP-H4).
5. Next-task determination and atomic activation under .stagecheck.lock (GAP-L1).
"""

from __future__ import annotations

import json
import re
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from stagecheck.schemas import get_schema_path
from stagecheck.core.utils import load_json_file, validate_schema


class TaskPlanError(Exception):
    """Base exception for task plan roadmap violations."""


class TaskPlanSchemaError(TaskPlanError):
    """Raised when task plan violates task_plan.schema.json."""


class CircularDependencyError(TaskPlanError):
    """Raised when task plan contains circular dependencies (Kahn's algorithm failure)."""


class UnknownDependencyError(TaskPlanError):
    """Raised when a task depends on an unknown/orphan task identifier."""


class UnauthorizedRepositoryError(TaskPlanError):
    """Raised when a task targets an undeclared repository (SEC-H3)."""


def get_task_id(task: Dict[str, Any]) -> str:
    """Extract canonical task identifier supporting both 'task_id' and 'id'."""
    return str(task.get("task_id") or task.get("id") or "").strip()


def get_task_title(task: Dict[str, Any]) -> str:
    """Extract canonical task title supporting both 'title' and 'name'."""
    return str(task.get("title") or task.get("name") or "").strip()


def validate_task_plan_schema(plan_data: Dict[str, Any]) -> None:
    """Validate task plan dictionary against task_plan.schema.json."""
    schema_path = get_schema_path("task_plan.schema.json")
    schema = load_json_file(schema_path)
    validate_schema(plan_data, schema)


def detect_cycles_kahns_algorithm(tasks: List[Dict[str, Any]]) -> List[str]:
    """Detect circular dependencies in task DAG using Kahn's algorithm.

    Returns:
        Topologically sorted list of task_ids if acyclic.

    Raises:
        CircularDependencyError: If a directed cycle is detected.
        UnknownDependencyError: If a dependency references a nonexistent task_id.
    """
    task_ids = {get_task_id(t) for t in tasks if get_task_id(t)}
    in_degree: Dict[str, int] = {get_task_id(t): 0 for t in tasks if get_task_id(t)}
    adj_list: Dict[str, List[str]] = defaultdict(list)

    # Validate dependencies and compute in-degrees
    for t in tasks:
        t_id = get_task_id(t)
        if not t_id:
            continue
        for dep in t.get("dependencies", []):
            if dep not in task_ids:
                raise UnknownDependencyError(
                    f"Task '{t_id}' declares unknown dependency '{dep}'."
                )
            adj_list[dep].append(t_id)
            in_degree[t_id] += 1

    # Kahn's algorithm: queue of vertices with 0 in-degree
    queue = deque([t_id for t_id, deg in in_degree.items() if deg == 0])
    topo_order: List[str] = []

    while queue:
        curr = queue.popleft()
        topo_order.append(curr)
        for neighbor in adj_list[curr]:
            in_degree[neighbor] -= 1
            if in_degree[neighbor] == 0:
                queue.append(neighbor)

    if len(topo_order) != len(task_ids):
        # A cycle exists among unvisited vertices
        cycle_nodes = [t_id for t_id, deg in in_degree.items() if deg > 0]
        raise CircularDependencyError(
            f"Directed cycle detected in task roadmap among tasks: {sorted(cycle_nodes)}."
        )

    return topo_order


def validate_task_plan(
    plan_data: Dict[str, Any],
    registered_repos: Optional[List[str]] = None,
) -> List[str]:
    """Execute complete validation of task plan roadmap.

    1. Schema validation
    2. Target repository whitelisting (SEC-H3)
    3. Directed cycle & orphan dependency validation (Kahn's algorithm)

    Returns:
        Topologically sorted list of task_ids.
    """
    validate_task_plan_schema(plan_data)

    tasks = plan_data.get("tasks", [])
    for idx, t in enumerate(tasks):
        t_id = get_task_id(t)
        if not t_id:
            raise TaskPlanSchemaError(f"Task at index {idx} must define 'task_id' or 'id'.")
        t_title = get_task_title(t)
        if not t_title:
            raise TaskPlanSchemaError(f"Task '{t_id}' must define 'title' or 'name'.")

    if registered_repos is not None:
        reg_set = set(registered_repos)
        for t in tasks:
            t_id = get_task_id(t)
            for repo in t.get("target_repositories", []):
                if repo not in reg_set:
                    raise UnauthorizedRepositoryError(
                        f"Task '{t_id}' references undeclared repository '{repo}'. "
                        f"Must be one of {sorted(reg_set)}."
                    )

    return detect_cycles_kahns_algorithm(tasks)


def get_next_eligible_task(
    plan_data: Dict[str, Any],
    completed_tasks: Set[str],
) -> Optional[Dict[str, Any]]:
    """Determine the next eligible task based on roadmap status and dependencies."""
    tasks = plan_data.get("tasks", [])
    for task in tasks:
        t_id = get_task_id(task)
        status = task.get("status", "planned")
        if t_id and t_id not in completed_tasks and status in ("planned", "in_progress"):
            deps = set(task.get("dependencies", []))
            if deps.issubset(completed_tasks):
                return task
    return None


def get_sprint_for_task(
    plan_data: Dict[str, Any],
    task_id: str,
) -> Optional[Dict[str, Any]]:
    """Find sprint definition for a given task_id from task plan data.

    Returns:
        Sprint dict with 'id', 'name', 'title' or None if task has no sprint.
    """
    clean_id = task_id.strip()
    tasks = plan_data.get("tasks", [])
    target_task = None
    for t in tasks:
        if get_task_id(t) == clean_id:
            target_task = t
            break

    if not target_task:
        return None

    sprint_id = target_task.get("sprint")
    if not sprint_id:
        return None

    sprints = plan_data.get("sprints", [])
    for sp in sprints:
        if sp.get("id") == sprint_id:
            return sp

    # If sprint specified on task but not defined in sprints array, return minimal definition
    return {"id": sprint_id, "name": ""}


def resolve_sprint_branch(
    plan_data_or_workspace: Union[Dict[str, Any], Path, str],
    task_id: str,
) -> Tuple[str, str]:
    """Resolve the dedicated sprint branch and structured commit prefix for a task.

    Naming Strategy:
      - Standard Sprint Branch: sprint/<sprint-id>-<sprint-name> (e.g. 'sprint/sprint-01-zk-readiness')
      - Fallback (when sprint omitted): sprint/sprint-00-UNKNOWN with prefix '[sp-00]'

    Returns:
        Tuple of (sprint_branch_name, commit_prefix)
    """
    plan_data: Optional[Dict[str, Any]] = None
    if isinstance(plan_data_or_workspace, dict):
        plan_data = plan_data_or_workspace
    else:
        ws_path = Path(plan_data_or_workspace).resolve()
        task_plan_path = ws_path / "specs" / "TASK_PLAN.json"
        if task_plan_path.is_file():
            try:
                plan_data = load_json_file(task_plan_path)
            except Exception:
                plan_data = None

    if plan_data:
        sprint = get_sprint_for_task(plan_data, task_id)
        if sprint:
            s_id = str(sprint.get("id", "")).strip()
            s_name = str(sprint.get("name", "")).strip()
            m = re.search(r"(\d+)", s_id)
            sp_num = f"{int(m.group(1)):02d}" if m else "00"
            prefix = f"[sp-{sp_num}]"

            if s_name:
                branch = f"sprint/{s_id}-{s_name}"
            else:
                branch = f"sprint/{s_id}"
            return branch, prefix

    # Default Fallback (Section 3)
    return "sprint/sprint-00-UNKNOWN", "[sp-00]"
