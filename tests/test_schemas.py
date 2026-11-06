"""Unit Tests for Control Schemas and Schema v2 Registry (P2-T2)."""

from __future__ import annotations

import unittest

from stagecheck.core.utils import SchemaValidationError
from stagecheck.schemas.validator import (
    validate_active_state,
    validate_control_descriptor,
    validate_gate_receipt,
    validate_product_repositories,
)


class TestControlSchemas(unittest.TestCase):
    """Test suite verifying validation rules for all control descriptors."""

    # ==========================================
    # PRODUCT_REPOSITORIES Schema v2 Tests
    # ==========================================

    def test_valid_product_repositories_schema_v2(self) -> None:
        valid_registry = {
            "schema_version": "2.0",
            "repositories": {
                "payment-service": {
                    "path": "repos/payment-service",
                    "default_branch": "main",
                    "baseline_head": "a" * 40,
                },
                "ledger-api": {
                    "path": "repos/ledger-api",
                    "default_branch": "release/v1.0",
                    "baseline_head": "b" * 40,
                },
            },
        }
        # Should not raise
        validate_product_repositories(valid_registry)

    def test_product_repositories_rejects_malformed_path(self) -> None:
        invalid_registry = {
            "schema_version": "2.0",
            "repositories": {
                "payment-service": {
                    "path": "external/payment-service",  # Must start with repos/
                    "default_branch": "main",
                    "baseline_head": "a" * 40,
                }
            },
        }
        with self.assertRaises(SchemaValidationError) as ctx:
            validate_product_repositories(invalid_registry)
        self.assertIn("does not match pattern", str(ctx.exception))

    def test_product_repositories_rejects_invalid_commit_head(self) -> None:
        invalid_registry = {
            "schema_version": "2.0",
            "repositories": {
                "payment-service": {
                    "path": "repos/payment-service",
                    "default_branch": "main",
                    "baseline_head": "invalid-sha",  # Must be 40-char hex
                }
            },
        }
        with self.assertRaises(SchemaValidationError):
            validate_product_repositories(invalid_registry)

    # ==========================================
    # ACTIVE_STATE Schema Tests
    # ==========================================

    def test_valid_active_state_descriptor(self) -> None:
        valid_state = {
            "schema_version": "2.0",
            "task_id": "task-101",
            "phase": "PHASE_1_PLANNING",
            "attempt_index": 1,
            "repair_index": 0,
            "max_total_attempts": 3,
            "max_repairs": 2,
            "circuit_breaker_tripped": False,
            "target_repositories": ["payment-service", "ledger-api"],
        }
        validate_active_state(valid_state)

    def test_active_state_rejects_invalid_phase(self) -> None:
        invalid_state = {
            "schema_version": "2.0",
            "task_id": "task-101",
            "phase": "INVALID_PHASE_NAME",
            "attempt_index": 1,
            "repair_index": 0,
            "max_total_attempts": 3,
            "max_repairs": 2,
            "circuit_breaker_tripped": False,
            "target_repositories": ["payment-service"],
        }
        with self.assertRaises(SchemaValidationError) as ctx:
            validate_active_state(invalid_state)
        self.assertIn("not in allowed enum", str(ctx.exception))

    def test_active_state_rejects_missing_required_field(self) -> None:
        incomplete_state = {
            "schema_version": "2.0",
            "task_id": "task-101",
            "phase": "PHASE_1_PLANNING",
            # missing attempt_index
            "repair_index": 0,
            "max_total_attempts": 3,
            "max_repairs": 2,
            "circuit_breaker_tripped": False,
            "target_repositories": ["payment-service"],
        }
        with self.assertRaises(SchemaValidationError) as ctx:
            validate_active_state(incomplete_state)
        self.assertIn("Missing required property", str(ctx.exception))

    # ==========================================
    # STAGECHECK_ROOT, EVIDENCE_ROOT & DISPOSITIONS Tests
    # ==========================================

    def test_valid_stagecheck_root_descriptor(self) -> None:
        valid_root = {
            "stagecheck_root": "@package",
            "manifest_sha256": "c" * 64,
        }
        validate_control_descriptor("STAGECHECK_ROOT.json", valid_root)

    def test_stagecheck_root_rejects_short_hash(self) -> None:
        invalid_root = {
            "stagecheck_root": "@package",
            "manifest_sha256": "short",
        }
        with self.assertRaises(SchemaValidationError):
            validate_control_descriptor("STAGECHECK_ROOT.json", invalid_root)

    def test_valid_dispositions_descriptor(self) -> None:
        valid_disp = {
            "schema_version": "2.0",
            "dispositions": [
                {
                    "task_id": "task-101",
                    "defect_id": "SEC-01",
                    "rationale": "Accepted risk approved by security officer",
                    "authorized_by": "owner@fincore.local",
                    "timestamp": "2026-11-04T10:00:00Z",
                }
            ],
        }
        validate_control_descriptor("DISPOSITIONS.json", valid_disp)


    # ==========================================
    # GATE_RECEIPT Schema Tests
    # ==========================================

    def test_valid_gate_receipt_schema(self) -> None:
        valid_receipt = {
            "schema_version": "2.0.0",
            "gate_id": "GATE_1",
            "task_id": "task-101",
            "attempt": 1,
            "from_phase": "PHASE_1_PLANNING",
            "to_phase": "PHASE_2A_CODING",
            "status": "PASSED",
            "verified_at": "2026-11-06T10:00:00Z",
            "verified_by": "stagecheck-core",
            "deliverables": [
                {
                    "path": "evidence/tasks/task-101/attempt_1/Phase-1/prompt.md",
                    "sha256": "a" * 64,
                    "status": "VALID",
                }
            ],
            "checks_evaluated": ["gate1.prompt_valid"],
            "receipt_sha256": "b" * 64,
        }
        validate_gate_receipt(valid_receipt)

    def test_gate_receipt_rejects_missing_required_field(self) -> None:
        invalid_receipt = {
            "schema_version": "2.0.0",
            "gate_id": "GATE_1",
            "task_id": "task-101",
            # missing attempt
            "from_phase": "PHASE_1_PLANNING",
            "to_phase": "PHASE_2A_CODING",
            "status": "PASSED",
            "verified_at": "2026-11-06T10:00:00Z",
            "verified_by": "stagecheck-core",
            "deliverables": [],
            "receipt_sha256": "b" * 64,
        }
        with self.assertRaises(SchemaValidationError):
            validate_gate_receipt(invalid_receipt)


if __name__ == "__main__":
    unittest.main()

