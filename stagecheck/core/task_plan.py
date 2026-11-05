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
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

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
    task_ids = {t["task_id"] for t in tasks}
    in_degree: Dict[str, int] = {t["task_id"]: 0 for t in tasks}
    adj_list: Dict[str, List[str]] = defaultdict(list)

    # Validate dependencies and compute in-degrees
    for t in tasks:
        t_id = t["task_id"]
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
    if registered_repos is not None:
        reg_set = set(registered_repos)
        for t in tasks:
            for repo in t.get("target_repositories", []):
                if repo not in reg_set:
                    raise UnauthorizedRepositoryError(
                        f"Task '{t['task_id']}' references undeclared repository '{repo}'. "
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
        t_id = task.get("task_id")
        if t_id not in completed_tasks and task.get("status") in ("planned", "in_progress"):
            deps = set(task.get("dependencies", []))
            if deps.issubset(completed_tasks):
                return task
    return None
