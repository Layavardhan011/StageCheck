"""Unit and CLI Integration Tests for Prompt Verification & Declared Scope Gate (P3-T2)."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from stagecheck.cli.main import main
from stagecheck.core.agents import resolve_task_attempt_dir
from stagecheck.core.prompt_gate import (
    PromptGateError,
    PromptMissingError,
    PromptNotVerifiedError,
    PromptTamperedError,
    ScopeValidationError,
    assert_prompt_invariance,
    freeze_prompt_and_scope,
    is_path_in_scope,
    validate_declared_scope,
)


class TestPromptGate(unittest.TestCase):
    """Test suite for Phase 1 prompt verification, scope validation, and tamper detection."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp_dir.name).resolve()

        # Create basic directory structure
        (self.workspace / "repos" / "order-service").mkdir(parents=True, exist_ok=True)
        (self.workspace / "evidence" / "tasks").mkdir(parents=True, exist_ok=True)

        # Create task-101 Phase-1 directory
        self.task_id = "task-101"
        self.attempt = 1
        self.phase1_dir = (
            self.workspace / "evidence" / "tasks" / self.task_id / f"attempt_{self.attempt}" / "Phase-1"
        )
        self.phase1_dir.mkdir(parents=True, exist_ok=True)

        self.prompt_file = self.phase1_dir / "prompt.md"
        self.scope_file = self.phase1_dir / "declared_scope.json"

        # Populate valid sample prompt and declared scope
        self.prompt_file.write_text(
            "# Task 101: Order Processing Endpoint\n\nImplement resilient order submission.\n",
            encoding="utf-8",
        )
        self.valid_scope = {
            "schema_version": "2.0",
            "task_id": self.task_id,
            "allowed_paths": [
                "repos/order-service/src/order.py",
                "repos/order-service/tests/test_order.py",
            ],
            "read_only_paths": [
                "repos/order-service/README.md",
            ],
            "forbidden_paths": [
                "controls/",
                "repos/order-service/.git/",
            ],
        }
        self.scope_file.write_text(json.dumps(self.valid_scope, indent=2), encoding="utf-8")

    def tearDown(self) -> None:
        # Restore permissions if needed before cleanup
        for p in self.phase1_dir.glob("*"):
            try:
                os.chmod(str(p), 0o644)
            except OSError:
                pass
        self.temp_dir.cleanup()

    def test_freeze_prompt_and_scope_success(self) -> None:
        """Verify successful freezing of prompt.md and declared_scope.json."""
        verified_path = freeze_prompt_and_scope(
            workspace_root=self.workspace,
            task_id=self.task_id,
            attempt=self.attempt,
            target_repositories=["order-service"],
        )
        self.assertTrue(verified_path.is_file())

        # Check content of prompt_verified.json
        record = json.loads(verified_path.read_text(encoding="utf-8"))
        self.assertEqual(record["task_id"], self.task_id)
        self.assertEqual(record["attempt"], self.attempt)
        self.assertEqual(record["status"], "VERIFIED")
        self.assertEqual(len(record["prompt_sha256"]), 64)
        self.assertEqual(len(record["scope_sha256"]), 64)

        # Invariance assertion must succeed
        assert_record = assert_prompt_invariance(self.workspace, self.task_id, self.attempt)
        self.assertEqual(assert_record["prompt_sha256"], record["prompt_sha256"])

        # Check permissions locked to 0444
        self.assertEqual(oct(self.prompt_file.stat().st_mode)[-3:], "444")
        self.assertEqual(oct(self.scope_file.stat().st_mode)[-3:], "444")
        self.assertEqual(oct(verified_path.stat().st_mode)[-3:], "444")

    def test_missing_prompt_blocks_verification(self) -> None:
        """Verify missing prompt.md raises PromptMissingError."""
        self.prompt_file.unlink()
        with self.assertRaises(PromptMissingError):
            freeze_prompt_and_scope(self.workspace, self.task_id, self.attempt)

    def test_missing_scope_blocks_verification(self) -> None:
        """Verify missing declared_scope.json raises PromptMissingError."""
        self.scope_file.unlink()
        with self.assertRaises(PromptMissingError):
            freeze_prompt_and_scope(self.workspace, self.task_id, self.attempt)

    def test_unverified_prompt_blocks_invariance_assertion(self) -> None:
        """Verify assert_prompt_invariance fails when prompt_verified.json is absent."""
        with self.assertRaises(PromptNotVerifiedError):
            assert_prompt_invariance(self.workspace, self.task_id, self.attempt)

    def test_scope_validation_rejects_absolute_path(self) -> None:
        """Verify rejection of absolute paths in declared_scope.json."""
        bad_scope = dict(self.valid_scope)
        bad_scope["allowed_paths"] = ["/etc/passwd"]
        with self.assertRaises(ScopeValidationError):
            validate_declared_scope(self.workspace, bad_scope)

    def test_scope_validation_rejects_path_traversal(self) -> None:
        """Verify rejection of directory traversal sequences in scope."""
        bad_scope = dict(self.valid_scope)
        bad_scope["allowed_paths"] = ["repos/order-service/../../../etc/shadow"]
        with self.assertRaises(ScopeValidationError):
            validate_declared_scope(self.workspace, bad_scope)

    def test_scope_validation_rejects_protected_controls_path(self) -> None:
        """Verify rejection when scope targets protected governance files."""
        bad_scope = dict(self.valid_scope)
        bad_scope["allowed_paths"] = ["controls/ACTIVE_STATE.json"]
        with self.assertRaises(ScopeValidationError):
            validate_declared_scope(self.workspace, bad_scope)

    def test_scope_validation_rejects_undeclared_repo(self) -> None:
        """Verify rejection when allowed path specifies repository outside approved targets."""
        bad_scope = dict(self.valid_scope)
        bad_scope["allowed_paths"] = ["repos/unauthorized-service/src/code.py"]
        with self.assertRaises(ScopeValidationError):
            validate_declared_scope(
                self.workspace,
                bad_scope,
                target_repositories=["order-service"],
            )

    def test_tampered_prompt_detected_post_verification(self) -> None:
        """Verify modifying prompt.md triggers PromptTamperedError."""
        freeze_prompt_and_scope(self.workspace, self.task_id, self.attempt)

        # Tamper with prompt.md
        os.chmod(str(self.prompt_file), 0o644)
        self.prompt_file.write_text("# Malicious prompt injection\n", encoding="utf-8")

        with self.assertRaises(PromptTamperedError):
            assert_prompt_invariance(self.workspace, self.task_id, self.attempt)

    def test_tampered_scope_detected_post_verification(self) -> None:
        """Verify modifying declared_scope.json triggers PromptTamperedError."""
        freeze_prompt_and_scope(self.workspace, self.task_id, self.attempt)

        # Tamper with declared_scope.json
        os.chmod(str(self.scope_file), 0o644)
        tampered_scope = dict(self.valid_scope)
        tampered_scope["allowed_paths"].append("repos/order-service/extra.py")
        self.scope_file.write_text(json.dumps(tampered_scope), encoding="utf-8")

        with self.assertRaises(PromptTamperedError):
            assert_prompt_invariance(self.workspace, self.task_id, self.attempt)

    def test_is_path_in_scope_predicate(self) -> None:
        """Verify path containment queries against declared scope."""
        self.assertTrue(
            is_path_in_scope("repos/order-service/src/order.py", self.valid_scope)
        )
        self.assertTrue(
            is_path_in_scope("repos/order-service/tests/test_order.py", self.valid_scope)
        )
        self.assertFalse(
            is_path_in_scope("repos/order-service/.git/config", self.valid_scope)
        )
        self.assertFalse(
            is_path_in_scope("repos/order-service/other.py", self.valid_scope)
        )

    def test_cli_verify_prompt_subcommand(self) -> None:
        """Verify CLI 'stagecheck verify-prompt' execution."""
        ret = main([
            "verify-prompt",
            "--task", self.task_id,
            "--attempt", str(self.attempt),
            "--workspace", str(self.workspace),
        ])
        self.assertEqual(ret, 0)


if __name__ == "__main__":
    unittest.main()
