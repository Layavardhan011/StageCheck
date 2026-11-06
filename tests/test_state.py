"""Unit Tests for Active State Governance Schema and Persistence (SEC-04 / SR-05 / DEC-018)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from stagecheck.core.state import load_active_state, save_active_state
from stagecheck.core.utils import SchemaValidationError
from stagecheck.schemas.validator import validate_active_state


class TestActiveStateGovernance(unittest.TestCase):
    """Test suite verifying active state schema alignment and fail-closed persistence."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp_dir.name).resolve()
        self.controls_dir = self.workspace / "controls"
        self.controls_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_state_schema_alignment(self) -> None:
        """Verify ACTIVE_STATE schema enforces attempt_index, nullable halt_reason, and flexible task_id (DEC-018)."""
        valid_state = {
            "schema_version": "2.0",
            "task_id": "TASK-101",
            "phase": "PHASE_1_PLANNING",
            "attempt_index": 1,
            "repair_index": 0,
            "max_total_attempts": 3,
            "max_repairs": 2,
            "circuit_breaker_tripped": False,
            "halt_reason": None,
            "target_repositories": ["payment-service"],
        }
        # 1. Nullable halt_reason passes
        validate_active_state(valid_state)

        # 2. String halt_reason passes
        valid_state["halt_reason"] = "Watchdog timeout in Phase 2A"
        validate_active_state(valid_state)

        # 3. Case-insensitive / pattern task_id variants pass
        valid_state["task_id"] = "task-alpha_01"
        validate_active_state(valid_state)

        # 4. Legacy 'attempt' key instead of 'attempt_index' is rejected
        legacy_state = dict(valid_state)
        del legacy_state["attempt_index"]
        legacy_state["attempt"] = 1
        with self.assertRaises(SchemaValidationError):
            validate_active_state(legacy_state)

        # 5. Missing attempt_index is rejected
        missing_index = dict(valid_state)
        del missing_index["attempt_index"]
        with self.assertRaises(SchemaValidationError):
            validate_active_state(missing_index)

    def test_fail_closed_state_persistence(self) -> None:
        """Verify save_active_state raises SchemaValidationError on invalid state without writing (SEC-04)."""
        invalid_state = {
            "schema_version": "2.0",
            "task_id": "task-101",
            "phase": "PHASE_1_PLANNING",
            # missing attempt_index, repair_index, etc.
        }

        # Must raise SchemaValidationError (not swallowed)
        with self.assertRaises(SchemaValidationError):
            save_active_state(
                self.workspace,
                invalid_state,
                update_manifest=False,
                update_contract=False,
            )

        # Active state file must NOT exist
        state_file = self.controls_dir / "ACTIVE_STATE.json"
        self.assertFalse(state_file.exists())

        # Valid state persists with mode 0444
        valid_state = {
            "schema_version": "2.0",
            "task_id": "task-101",
            "phase": "PHASE_1_PLANNING",
            "attempt_index": 1,
            "repair_index": 0,
            "max_total_attempts": 3,
            "max_repairs": 2,
            "circuit_breaker_tripped": False,
            "halt_reason": None,
            "target_repositories": ["payment-service"],
        }
        save_active_state(
            self.workspace,
            valid_state,
            update_manifest=False,
            update_contract=False,
        )
        self.assertTrue(state_file.is_file())
        loaded = load_active_state(self.workspace)
        self.assertEqual(loaded["attempt_index"], 1)
        self.assertEqual(loaded["task_id"], "task-101")


if __name__ == "__main__":
    unittest.main()
