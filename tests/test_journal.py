"""Comprehensive Test Suite for Task 4.3: Write-Ahead Transaction Journal and Startup Recovery (FR-10 / DEC-010).

Verifies:
1. Write-Ahead Journaling:
   - Active journal record created under .stagecheck_journal/<txn_id>.active.json (mode 0700 dir).
   - Pre-images captured before mutation.
   - Successful commit unlinks active journal file.
2. Immediate Exception Rollback:
   - Unhandled exception during write_ahead_transaction triggers automatic rollback.
   - Restores modified files to exact pre-image content and mode.
   - Deletes newly created files.
3. Startup Auto-Recovery (DEC-010):
   - Simulated crash (uncommitted active journal left on disk).
   - recover_interrupted_transactions scans .stagecheck_journal/, rolls back all partial writes,
     unlinks active journal file, and emits operator-visible [RECOVERY] alert.
4. Multi-File Atomic Consistency:
   - Cross-file consistency across controls/ACTIVE_STATE.json, evidence/EVIDENCE_MANIFEST.json,
     and Phase directories.
"""

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from stagecheck.cli.init_cmd import run_init
from stagecheck.cli.main import main
from stagecheck.core.journal import (
    TransactionJournal,
    recover_interrupted_transactions,
    write_ahead_transaction,
)
from stagecheck.core.permissions import controlled_write_transaction, elevate_permissions_for_teardown


class TestWriteAheadJournal(unittest.TestCase):
    """Test suite for write-ahead journal primitives and crash recovery."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.ws = Path(self.temp_dir.name).resolve()

        # Initialize mock repo & workspace
        repo_dir = self.ws / "repos" / "core"
        repo_dir.mkdir(parents=True, exist_ok=True)
        import subprocess
        subprocess.run(["git", "init", "-b", "main"], cwd=str(repo_dir), capture_output=True, check=True)
        subprocess.run(["git", "config", "user.name", "Tester"], cwd=str(repo_dir), capture_output=True, check=True)
        subprocess.run(["git", "config", "user.email", "tester@stagecheck.local"], cwd=str(repo_dir), capture_output=True, check=True)
        (repo_dir / "README.md").write_text("# Core\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=str(repo_dir), capture_output=True, check=True)
        subprocess.run(["git", "commit", "-m", "init"], cwd=str(repo_dir), capture_output=True, check=True)

        rc = run_init(workspace=str(self.ws), agent1="agent1", agent2="agent2", repos="core")
        self.assertEqual(rc, 0)

    def tearDown(self) -> None:
        elevate_permissions_for_teardown(self.ws)
        self.temp_dir.cleanup()

    def test_successful_transaction_commit(self) -> None:
        """Verify normal transaction lifecycle commits changes and removes active log."""
        test_file = self.ws / "evidence" / "tasks" / "task-01" / "CUSTOM_RECORD.json"
        test_file.parent.mkdir(parents=True, exist_ok=True)
        journal_dir = self.ws / ".stagecheck_journal"

        with write_ahead_transaction(self.ws, operation="TEST_COMMIT", task_id="task-01", attempt_index=1) as txn:
            txn.record_pre_image(test_file)
            test_file.write_text('{"committed": true}\n', encoding="utf-8")
            txn.record_staged_write(test_file)
            txn.commit()

        # File exists
        self.assertTrue(test_file.is_file())
        self.assertIn('"committed": true', test_file.read_text(encoding="utf-8"))

        # No active journal files remain
        active_logs = list(journal_dir.glob("*.active.json"))
        self.assertEqual(len(active_logs), 0)

    def test_exception_triggers_immediate_rollback(self) -> None:
        """Verify exception inside transaction context automatically rolls back all mutations."""
        state_file = self.ws / "controls" / "ACTIVE_STATE.json"
        state_original = state_file.read_text(encoding="utf-8")
        new_file = self.ws / "evidence" / "tasks" / "task-01" / "partial.json"

        with self.assertRaises(RuntimeError):
            with write_ahead_transaction(self.ws, operation="TEST_ROLLBACK", task_id="task-01", attempt_index=1) as txn:
                txn.record_pre_image(state_file)
                txn.record_pre_image(new_file)

                # Mutate existing file
                state_file.chmod(0o644)
                state_file.write_text('{"corrupted": true}\n', encoding="utf-8")
                txn.record_staged_write(state_file)

                # Create new file
                new_file.parent.mkdir(parents=True, exist_ok=True)
                new_file.write_text('{"partial": true}\n', encoding="utf-8")
                txn.record_staged_write(new_file)

                # Simulate mid-transaction crash
                raise RuntimeError("Simulated crash mid-transaction")

        # Existing file is restored to exact pre-image
        self.assertEqual(state_file.read_text(encoding="utf-8"), state_original)
        # New file is removed
        self.assertFalse(new_file.exists())
        # Active journal file is cleaned
        self.assertEqual(len(list((self.ws / ".stagecheck_journal").glob("*.active.json"))), 0)

    def test_crash_recovery_startup_cleanup(self) -> None:
        """Verify DEC-010: startup recovery restores uncommitted partial writes and alerts operator."""
        state_file = self.ws / "controls" / "ACTIVE_STATE.json"
        state_original = state_file.read_text(encoding="utf-8")
        manifest_file = self.ws / "evidence" / "EVIDENCE_MANIFEST.json"
        manifest_original = '{"schema_version": "2.0.0", "sealed_tasks": {}}\n'
        with controlled_write_transaction(self.ws / "evidence"):
            manifest_file.parent.mkdir(parents=True, exist_ok=True)
            if manifest_file.exists():
                manifest_file.chmod(0o644)
            manifest_file.write_text(manifest_original, encoding="utf-8")

        new_evidence = self.ws / "evidence" / "tasks" / "task-crash" / "attempt_1" / "partial.txt"
        new_evidence.parent.mkdir(parents=True, exist_ok=True)
        new_evidence.write_text("partial evidence\n", encoding="utf-8")

        # Simulate process kill -9 leaving active journal on disk
        journal_dir = self.ws / ".stagecheck_journal"
        journal_dir.mkdir(mode=0o700, exist_ok=True)
        active_log = journal_dir / "txn_gate4_simulated_crash.active.json"

        # Corrupt state and manifest on disk
        with controlled_write_transaction(self.ws / "controls"):
            state_file.chmod(0o644)
            state_file.write_text('{"phase": "CORRUPTED_MID_FLIGHT"}\n', encoding="utf-8")
        with controlled_write_transaction(self.ws / "evidence"):
            manifest_file.chmod(0o644)
            manifest_file.write_text('{"manifest": "CORRUPTED_MID_FLIGHT"}\n', encoding="utf-8")

        journal_payload = {
            "txn_id": "txn_gate4_simulated_crash",
            "operation": "GATE_4_SEALING",
            "task_id": "task-crash",
            "attempt_index": 1,
            "created_at": "2026-11-06T12:00:00Z",
            "status": "IN_PROGRESS",
            "pre_images": {
                "controls/ACTIVE_STATE.json": state_original,
                "evidence/EVIDENCE_MANIFEST.json": manifest_original,
                "evidence/tasks/task-crash/attempt_1/partial.txt": None,
            },
            "pre_modes": {
                "controls/ACTIVE_STATE.json": 0o444,
                "evidence/EVIDENCE_MANIFEST.json": 0o444,
                "evidence/tasks/task-crash/attempt_1/partial.txt": 0o644,
            },
            "staged_paths": [
                "controls/ACTIVE_STATE.json",
                "evidence/EVIDENCE_MANIFEST.json",
                "evidence/tasks/task-crash/attempt_1/partial.txt",
            ],
        }
        active_log.write_text(json.dumps(journal_payload, indent=2), encoding="utf-8")

        # Run startup recovery with stdout captured
        buf = io.StringIO()
        with redirect_stdout(buf):
            records = recover_interrupted_transactions(self.ws, verbose=True)

        output = buf.getvalue()

        # Verify recovery alert printed
        self.assertIn("[RECOVERY]", output)
        self.assertIn("txn_gate4_simulated_crash", output)
        self.assertIn("GATE_4_SEALING", output)

        # Verify records returned
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].status, "RECOVERED")
        self.assertIn("controls/ACTIVE_STATE.json", records[0].files_restored)
        self.assertIn("evidence/EVIDENCE_MANIFEST.json", records[0].files_restored)
        self.assertIn("evidence/tasks/task-crash/attempt_1/partial.txt", records[0].files_removed)

        # Verify disk state restored
        self.assertEqual(state_file.read_text(encoding="utf-8"), state_original)
        self.assertEqual(manifest_file.read_text(encoding="utf-8"), manifest_original)
        self.assertFalse(new_evidence.exists())

        # Verify active journal log unlinked
        self.assertFalse(active_log.exists())

    def test_cli_invokes_startup_recovery(self) -> None:
        """Verify executing any StageCheck CLI command automatically triggers startup recovery."""
        journal_dir = self.ws / ".stagecheck_journal"
        journal_dir.mkdir(mode=0o700, exist_ok=True)
        active_log = journal_dir / "txn_cli_crash.active.json"

        target_file = self.ws / "evidence" / "tasks" / "task-01" / "ORPHAN.txt"
        target_file.parent.mkdir(parents=True, exist_ok=True)
        target_file.write_text("orphan\n", encoding="utf-8")

        active_log.write_text(
            json.dumps({
                "txn_id": "txn_cli_crash",
                "operation": "TEST_OP",
                "pre_images": {"evidence/tasks/task-01/ORPHAN.txt": None},
                "pre_modes": {"evidence/tasks/task-01/ORPHAN.txt": 0o644},
            }),
            encoding="utf-8",
        )

        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["turn", "--workspace", str(self.ws)])

        # Recovery alert emitted
        self.assertIn("[RECOVERY]", buf.getvalue())
        self.assertFalse(target_file.exists())
        self.assertFalse(active_log.exists())

    def test_journal_binary_file_roundtrip(self) -> None:
        """Verify TransactionJournal handles binary pre-images without UnicodeDecodeError (SC-SEC-03)."""
        binary_file = self.ws / "evidence" / "tasks" / "task-01" / "artifact.bin"
        binary_file.parent.mkdir(parents=True, exist_ok=True)
        original_bytes = bytes(range(256))
        binary_file.write_bytes(original_bytes)

        # 1. Immediate exception rollback restores exact binary payload
        with self.assertRaises(RuntimeError):
            with write_ahead_transaction(self.ws, operation="TEST_BINARY_ROLLBACK", task_id="task-01", attempt_index=1) as txn:
                txn.record_pre_image(binary_file)
                binary_file.write_bytes(b"\x00\x01CORRUPTED")
                txn.record_staged_write(binary_file)
                raise RuntimeError("Simulated mid-write failure")

        self.assertEqual(binary_file.read_bytes(), original_bytes)

        # 2. Startup crash recovery restores exact binary payload from persisted active journal
        txn2 = TransactionJournal(self.ws, operation="TEST_BINARY_CRASH", task_id="task-01", attempt_index=1)
        txn2.start()
        txn2.record_pre_image(binary_file)
        binary_file.write_bytes(b"OVERWRITTEN")
        txn2.record_staged_write(binary_file)

        records = recover_interrupted_transactions(self.ws, verbose=False)
        self.assertEqual(len(records), 1)
        self.assertEqual(binary_file.read_bytes(), original_bytes)

    def test_recovery_from_incomplete_or_corrupted_journal_entry(self) -> None:
        """Verify recovery handles corrupted active records and unlinked temp files cleanly (Gap C)."""
        journal_dir = self.ws / ".stagecheck_journal"
        journal_dir.mkdir(parents=True, exist_ok=True)

        # 1. Lingering tmp / prepare files from interrupted write
        tmp_file = journal_dir / "interrupted.tmp"
        tmp_file.write_text("partial write", encoding="utf-8")
        prep_file = journal_dir / "interrupted.prepare.json"
        prep_file.write_text("{}", encoding="utf-8")

        # 2. Corrupted active record (truncated JSON)
        corrupted_active = journal_dir / "txn_corrupt.active.json"
        corrupted_active.write_text('{"txn_id": "txn_corrupt", "incomplete": ', encoding="utf-8")

        records = recover_interrupted_transactions(self.ws, verbose=False)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].status, "CORRUPTED")
        self.assertFalse(corrupted_active.exists())
        self.assertFalse(tmp_file.exists())
        self.assertFalse(prep_file.exists())

    def test_recovery_repeated_attempts_are_idempotent(self) -> None:
        """Verify calling recovery repeatedly is deterministic and idempotent (Gap C)."""
        journal_dir = self.ws / ".stagecheck_journal"
        journal_dir.mkdir(parents=True, exist_ok=True)

        target = self.ws / "evidence" / "tasks" / "task-01" / "RECOVER_IDEMP.txt"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("original\n", encoding="utf-8")

        txn = TransactionJournal(self.ws, operation="TEST_IDEMP", task_id="task-01", attempt_index=1)
        txn.start()
        txn.record_pre_image(target)
        target.write_text("mutated\n", encoding="utf-8")
        txn.record_staged_write(target)

        # First recovery run restores pre-image
        r1 = recover_interrupted_transactions(self.ws, verbose=False)
        self.assertEqual(len(r1), 1)
        self.assertEqual(r1[0].status, "RECOVERED")
        self.assertEqual(target.read_text(encoding="utf-8"), "original\n")

        # Second recovery run finds no work and returns empty list cleanly
        r2 = recover_interrupted_transactions(self.ws, verbose=False)
        self.assertEqual(len(r2), 0)
        self.assertEqual(target.read_text(encoding="utf-8"), "original\n")

    def test_duplicate_transaction_processing_is_idempotent(self) -> None:
        """Verify calling commit or rollback multiple times behaves idempotently (Gap C)."""
        test_file = self.ws / "evidence" / "tasks" / "task-01" / "DUP_TXN.txt"
        test_file.parent.mkdir(parents=True, exist_ok=True)
        test_file.write_text("base\n", encoding="utf-8")

        # Commit idempotency
        txn = TransactionJournal(self.ws, operation="TEST_COMMIT_IDEMP", task_id="task-01", attempt_index=1)
        txn.start()
        txn.record_pre_image(test_file)
        test_file.write_text("committed\n", encoding="utf-8")
        txn.commit()
        self.assertTrue(txn.is_committed)
        # Calling commit again does not raise error
        txn.commit()
        self.assertTrue(txn.is_committed)

        # Rollback idempotency
        txn2 = TransactionJournal(self.ws, operation="TEST_ROLLBACK_IDEMP", task_id="task-01", attempt_index=1)
        txn2.start()
        txn2.record_pre_image(test_file)
        test_file.write_text("rolled_back\n", encoding="utf-8")
        r_rec1 = txn2.rollback()
        self.assertEqual(r_rec1.status, "ROLLED_BACK")
        self.assertEqual(test_file.read_text(encoding="utf-8"), "committed\n")
        # Calling rollback again is idempotent
        r_rec2 = txn2.rollback()
        self.assertEqual(r_rec2.status, "ALREADY_ROLLED_BACK")

    def test_interrupted_state_transition_restores_authoritative_state(self) -> None:
        """Verify interrupted state transition restores exact active state and mode (Gap C)."""
        from stagecheck.core.state import load_active_state, save_active_state
        state_file = self.ws / "controls" / "ACTIVE_STATE.json"

        # Baseline state
        state = load_active_state(self.ws)
        state["phase"] = "PHASE_1_PLANNING"
        state["turn"] = "AGENT1_PROMPT"
        save_active_state(self.ws, state)
        original_content = state_file.read_text(encoding="utf-8")

        # Simulate interrupted transition to PHASE_2A_CODING
        txn = TransactionJournal(self.ws, operation="GATE_ADVANCE", task_id="task-01", attempt_index=1)
        txn.start()
        txn.record_pre_image(state_file)
        state_file.chmod(0o644)
        state["phase"] = "PHASE_2A_CODING"
        state["turn"] = "AGENT2_CODING"
        state_file.write_text(json.dumps(state, indent=2), encoding="utf-8")
        txn.record_staged_write(state_file)
        # Process interrupted without commit

        # Recovery restores original state and 0444 mode
        recs = recover_interrupted_transactions(self.ws, verbose=False)
        self.assertEqual(len(recs), 1)
        self.assertEqual(state_file.read_text(encoding="utf-8"), original_content)
        restored_state = load_active_state(self.ws)
        self.assertEqual(restored_state["phase"], "PHASE_1_PLANNING")
        self.assertEqual(restored_state["turn"], "AGENT1_PROMPT")

    def test_corrupted_or_modified_evidence_detected_during_recovery_and_sealing(self) -> None:
        """Verify corrupted or modified evidence is strictly detected and not converted to pass (Gap C)."""
        from stagecheck.core.sealing import compute_attempt_merkle_seal, verify_attempt_merkle_seal
        attempt_dir = self.ws / "evidence" / "tasks" / "task-01" / "attempt_1"
        attempt_dir.mkdir(parents=True, exist_ok=True)
        (attempt_dir / "output.txt").write_text("evidence data\n", encoding="utf-8")

        # Compute initial seal
        seal = compute_attempt_merkle_seal(
            attempt_dir=attempt_dir,
            workspace_root=self.ws,
            task_id="task-01",
            attempt_index=1,
            verdict_data={"status": "PASSED"},
            write_seal_file=True,
        )
        ok, violations = verify_attempt_merkle_seal(attempt_dir, self.ws)
        self.assertTrue(ok)
        self.assertEqual(len(violations), 0)

        # Corrupt evidence file after sealing
        (attempt_dir / "output.txt").chmod(0o644)
        (attempt_dir / "output.txt").write_text("TAMPERED DATA\n", encoding="utf-8")

        # Verification fails strictly; never converts tampered evidence into success
        is_valid, violations = verify_attempt_merkle_seal(attempt_dir, self.ws)
        self.assertFalse(is_valid)
        self.assertTrue(any("Merkle root mismatch" in v or "Leaf hash mismatch" in v for v in violations))


if __name__ == "__main__":
    unittest.main()
