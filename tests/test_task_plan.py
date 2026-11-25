"""Unit tests for Task Plan Roadmap Engine and Directed Cycle Detection (GAP-05, GAP-H4)."""

import unittest

from governance.core.task_plan import (
    CircularDependencyError,
    TaskPlanError,
    UnauthorizedRepositoryError,
    UnknownDependencyError,
    get_next_eligible_task,
    get_sprint_for_task,
    resolve_sprint_branch,
    validate_task_plan,
)
from governance.core.utils import SchemaValidationError


class TestTaskPlanValidation(unittest.TestCase):
    """Test task plan schema, DAG cycle detection, and repository whitelisting."""

    def setUp(self):
        self.valid_plan = {
            "schema_version": 1,
            "project_name": "stagecheck-core",
            "created_at": "2026-11-04T10:00:00Z",
            "updated_at": "2026-11-04T10:00:00Z",
            "tasks": [
                {
                    "task_id": "TASK-01",
                    "title": "Bootstrap workspace",
                    "status": "completed",
                    "priority": "HIGH",
                    "dependencies": [],
                    "target_repositories": ["backend"],
                },
                {
                    "task_id": "TASK-02",
                    "title": "Implement core API",
                    "status": "planned",
                    "priority": "CRITICAL",
                    "dependencies": ["TASK-01"],
                    "target_repositories": ["backend"],
                },
                {
                    "task_id": "TASK-03",
                    "title": "Add frontend dashboard",
                    "status": "planned",
                    "priority": "MEDIUM",
                    "dependencies": ["TASK-02"],
                    "target_repositories": ["frontend"],
                },
            ],
        }

    def test_valid_task_plan_topological_sort(self):
        """Verify valid plan passes and returns topological order."""
        topo = validate_task_plan(self.valid_plan, registered_repos=["backend", "frontend"])
        self.assertEqual(topo, ["TASK-01", "TASK-02", "TASK-03"])

    def test_schema_validation_rejects_invalid_enum(self):
        """Verify invalid priority enum fails schema validation."""
        bad_plan = dict(self.valid_plan)
        bad_plan["tasks"] = [
            dict(self.valid_plan["tasks"][0], priority="INVALID_PRIORITY")
        ]
        with self.assertRaises(SchemaValidationError):
            validate_task_plan(bad_plan, registered_repos=["backend"])

    def test_unknown_dependency_fails(self):
        """Verify dependency referencing nonexistent task fails."""
        bad_plan = dict(self.valid_plan)
        bad_plan["tasks"] = [
            {
                "task_id": "TASK-01",
                "title": "Task 1",
                "status": "planned",
                "priority": "HIGH",
                "dependencies": ["NONEXISTENT-TASK"],
                "target_repositories": ["backend"],
            }
        ]
        with self.assertRaises(UnknownDependencyError):
            validate_task_plan(bad_plan, registered_repos=["backend"])

    def test_circular_dependency_detected_kahns_algorithm(self):
        """Verify direct cycle (TASK-01 -> TASK-02 -> TASK-01) triggers CircularDependencyError."""
        cyclic_plan = {
            "schema_version": 1,
            "project_name": "cycle-test",
            "created_at": "2026-11-04T10:00:00Z",
            "updated_at": "2026-11-04T10:00:00Z",
            "tasks": [
                {
                    "task_id": "TASK-01",
                    "title": "Task 1",
                    "status": "planned",
                    "priority": "HIGH",
                    "dependencies": ["TASK-02"],
                    "target_repositories": ["backend"],
                },
                {
                    "task_id": "TASK-02",
                    "title": "Task 2",
                    "status": "planned",
                    "priority": "HIGH",
                    "dependencies": ["TASK-01"],
                    "target_repositories": ["backend"],
                },
            ],
        }
        with self.assertRaises(CircularDependencyError):
            validate_task_plan(cyclic_plan, registered_repos=["backend"])

    def test_target_repository_whitelist_rejection(self):
        """Verify referencing undeclared repository fails (SEC-H3)."""
        with self.assertRaises(UnauthorizedRepositoryError):
            # plan references 'frontend', but registered_repos only has 'backend'
            validate_task_plan(self.valid_plan, registered_repos=["backend"])

    def test_get_next_eligible_task_resolution(self):
        """Verify next eligible task determination based on completed prerequisites."""
        # When TASK-01 is completed, TASK-02 becomes next eligible
        next_task = get_next_eligible_task(self.valid_plan, completed_tasks={"TASK-01"})
        self.assertIsNotNone(next_task)
        self.assertEqual(next_task["task_id"], "TASK-02")

        # When TASK-01 and TASK-02 are completed, TASK-03 becomes next eligible
        next_task_2 = get_next_eligible_task(self.valid_plan, completed_tasks={"TASK-01", "TASK-02"})
        self.assertIsNotNone(next_task_2)
        self.assertEqual(next_task_2["task_id"], "TASK-03")

    def test_task_plan_v2_schema_and_sprint_branch_resolution(self):
        """Verify Task Plan v2.0 schema and sprint branch/prefix resolution."""
        plan_v2 = {
            "schema_version": "2.0",
            "project_name": "sprint-governed-project",
            "created_at": "2026-11-04T10:00:00Z",
            "updated_at": "2026-11-04T10:00:00Z",
            "sprints": [
                {
                    "id": "sprint-01",
                    "name": "zk-readiness",
                    "title": "Zero Knowledge Readiness",
                }
            ],
            "tasks": [
                {
                    "task_id": "task-01",
                    "sprint": "sprint-01",
                    "title": "ZK Canonical Encoder",
                    "status": "planned",
                    "priority": "HIGH",
                    "dependencies": [],
                    "target_repositories": ["backend"],
                },
                {
                    "id": "task-02",
                    "title": "Unassigned Sprint Task",
                    "name": "Unassigned Sprint Task",
                    "status": "planned",
                    "priority": "MEDIUM",
                    "dependencies": [],
                    "target_repositories": ["backend"],
                },
            ],
        }

        # Validate v2 schema passes
        topo = validate_task_plan(plan_v2, registered_repos=["backend"])
        self.assertEqual(len(topo), 2)

        # Resolve sprint branch for task-01
        branch, prefix = resolve_sprint_branch(plan_v2, "task-01")
        self.assertEqual(branch, "sprint/sprint-01-zk-readiness")
        self.assertEqual(prefix, "[sp-01]")

        # Resolve fallback sprint branch for task-02 (no sprint declared)
        fb_branch, fb_prefix = resolve_sprint_branch(plan_v2, "task-02")
        self.assertEqual(fb_branch, "sprint/sprint-00-UNKNOWN")
        self.assertEqual(fb_prefix, "[sp-00]")

    def test_minimal_v2_schema_validation(self):
        """Verify minimal v2 plan without project_name or optional task fields passes validation."""
        minimal_plan = {
            "schema_version": "2.0",
            "sprints": [
                {
                    "id": "sprint-01",
                    "name": "zk-readiness",
                    "title": "Zero Knowledge Public Input and Commitment Hardening",
                },
                {
                    "id": "sprint-02",
                    "name": "batch-verification",
                    "title": "Batch Signature and Proof Aggregation",
                },
            ],
            "tasks": [
                {
                    "id": "task-01",
                    "sprint": "sprint-01",
                    "name": "Local workspace alignment and baseline verification",
                    "target_repositories": ["core", "logger", "Crypto"],
                },
                {
                    "id": "task-02",
                    "sprint": "sprint-01",
                    "name": "Core repository ZK public-input contract and canonical encoder",
                    "target_repositories": ["core"],
                },
                {
                    "id": "task-03",
                    "sprint": "sprint-01",
                    "name": "Domain-separated commitment adapter",
                    "target_repositories": ["core"],
                },
                {
                    "id": "task-04",
                    "sprint": "sprint-01",
                    "name": "Crypto repository ZK readiness compatibility tests",
                    "target_repositories": ["Crypto"],
                },
            ],
        }
        topo = validate_task_plan(minimal_plan, registered_repos=["core", "logger", "Crypto"])
        self.assertEqual(topo, ["task-01", "task-02", "task-03", "task-04"])


if __name__ == "__main__":
    unittest.main()

