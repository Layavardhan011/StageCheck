"""Unit tests for Task Plan Roadmap Engine and Directed Cycle Detection (GAP-05, GAP-H4)."""

import unittest

from stagecheck.core.task_plan import (
    CircularDependencyError,
    TaskPlanError,
    UnauthorizedRepositoryError,
    UnknownDependencyError,
    get_next_eligible_task,
    validate_task_plan,
)
from stagecheck.core.utils import SchemaValidationError


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


if __name__ == "__main__":
    unittest.main()

