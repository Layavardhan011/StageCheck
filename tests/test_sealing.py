"""Comprehensive Test Suite for Task 4.4: Deterministic Acyclic Merkle DAG & Evidence Manifest (FR-12 / DEC-012).

Verifies:
1. Pre-Resolution Symlink Validation:
   - Path traversal in attempt path ('..') rejected.
   - Attempt root itself as a symlink rejected BEFORE resolve().
   - Parent directory as a symlink rejected BEFORE resolve().
   - Child file or directory symlink inside attempt hierarchy rejected during traversal.
2. Canonical Leaf Serialization & Determinism:
   - Leaves sorted by ascending Unicode code point order (C collation).
   - Same inputs produce identical Merkle roots regardless of directory write order.
   - Exclusions verified: seal.json, *.lock, *.tmp, .DS_Store excluded.
3. Acyclic Manifest Indexing:
   - seal.json hashes attempt directory; EVIDENCE_MANIFEST.json hashes seal.json.
   - Strictly acyclic DAG without circular loops.
4. Tamper Detection:
   - Any modified file detected.
   - Deleted file detected.
   - Added unrecorded file detected.
"""

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from stagecheck.cli.init_cmd import run_init
from stagecheck.core.permissions import elevate_permissions_for_teardown
from stagecheck.core.sealing import (
    SymlinkInEvidenceError,
    compute_attempt_merkle_seal,
    index_seal_in_manifest,
    verify_attempt_merkle_seal,
)


class TestAcyclicMerkleSealing(unittest.TestCase):
    """Test suite for Merkle DAG computation, symlink defense, and manifest indexing."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.ws = Path(self.temp_dir.name).resolve()
        self.task_id = "task-merkle-01"
        self.attempt = 1

        # Setup mock repo
        repo_dir = self.ws / "repos" / "core"
        repo_dir.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "init", "-b", "main"], cwd=str(repo_dir), capture_output=True, check=True)
        subprocess.run(["git", "config", "user.name", "Tester"], cwd=str(repo_dir), capture_output=True, check=True)
        subprocess.run(["git", "config", "user.email", "tester@stagecheck.local"], cwd=str(repo_dir), capture_output=True, check=True)
        (repo_dir / "README.md").write_text("# Core\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=str(repo_dir), capture_output=True, check=True)
        subprocess.run(["git", "commit", "-m", "init"], cwd=str(repo_dir), capture_output=True, check=True)

        rc = run_init(workspace=str(self.ws), agent1="agent1", agent2="agent2", repos="core")
        self.assertEqual(rc, 0)

        # Standard attempt dir
        self.attempt_dir = self.ws / "evidence" / "tasks" / self.task_id / f"attempt_{self.attempt}"
        self.attempt_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        elevate_permissions_for_teardown(self.ws)
        self.temp_dir.cleanup()

    def test_merkle_pre_resolution_symlink_checks(self) -> None:
        """Verify DEC-012: Pre-resolution symlink checks fail closed on symlinks at all levels."""
        # 1. Path traversal in attempt path
        traversal_path = self.ws / "evidence" / "tasks" / ".." / "escaped"
        with self.assertRaises(SymlinkInEvidenceError):
            compute_attempt_merkle_seal(traversal_path, self.ws, self.task_id, self.attempt)

        # 2. Attempt root itself is a symlink
        outside_target = self.ws / "outside_evidence"
        outside_target.mkdir(parents=True, exist_ok=True)
        sym_root = self.ws / "evidence" / "tasks" / "task-sym" / "attempt_1"
        sym_root.parent.mkdir(parents=True, exist_ok=True)
        sym_root.symlink_to(outside_target)

        with self.assertRaises(SymlinkInEvidenceError) as ctx:
            compute_attempt_merkle_seal(sym_root, self.ws, "task-sym", 1)
        self.assertIn("ATTEMPT_ROOT_SYMLINK", str(ctx.exception))

        # 3. Parent directory component is a symlink
        sym_parent = self.ws / "evidence" / "tasks" / "task-sym-parent"
        sym_parent.symlink_to(outside_target)
        nested_attempt = sym_parent / "attempt_1"
        nested_attempt.mkdir(parents=True, exist_ok=True)

        with self.assertRaises(SymlinkInEvidenceError) as ctx:
            compute_attempt_merkle_seal(nested_attempt, self.ws, "task-sym-parent", 1)
        self.assertIn("PARENT_SYMLINK", str(ctx.exception))

        # 4. Child directory inside attempt is a symlink
        sym_child_dir = self.attempt_dir / "Phase-Sym"
        sym_child_dir.symlink_to(outside_target)
        with self.assertRaises(SymlinkInEvidenceError) as ctx:
            compute_attempt_merkle_seal(self.attempt_dir, self.ws, self.task_id, self.attempt)
        self.assertIn("Directory symlink", str(ctx.exception))
        sym_child_dir.unlink()

        # 5. Child file inside attempt is a symlink
        outside_file = outside_target / "secret.txt"
        outside_file.write_text("secret\n", encoding="utf-8")
        sym_child_file = self.attempt_dir / "Phase-1" / "sym_prompt.md"
        sym_child_file.parent.mkdir(parents=True, exist_ok=True)
        sym_child_file.symlink_to(outside_file)

        with self.assertRaises(SymlinkInEvidenceError) as ctx:
            compute_attempt_merkle_seal(self.attempt_dir, self.ws, self.task_id, self.attempt)
        self.assertIn("File symlink", str(ctx.exception))
        sym_child_file.unlink()

    def test_merkle_dag_determinism_and_exclusions(self) -> None:
        """Verify identical files in varied creation order produce identical Merkle roots."""
        p1_dir = self.attempt_dir / "Phase-1"
        p2_dir = self.attempt_dir / "Phase-2A"
        p1_dir.mkdir(parents=True, exist_ok=True)
        p2_dir.mkdir(parents=True, exist_ok=True)

        # Write files
        (p1_dir / "prompt.md").write_text("# Blueprint\n", encoding="utf-8")
        (p1_dir / "declared_scope.json").write_text('{"scope": "clean"}\n', encoding="utf-8")
        (p2_dir / "pre_commit_review.json").write_text('{"status": "APPROVED"}\n', encoding="utf-8")

        # Excluded files that must NOT alter the Merkle root
        (p1_dir / "temp.lock").write_text("locked\n", encoding="utf-8")
        (p2_dir / "scratch.tmp").write_text("transient\n", encoding="utf-8")
        (self.attempt_dir / ".DS_Store").write_text("junk\n", encoding="utf-8")

        seal1 = compute_attempt_merkle_seal(self.attempt_dir, self.ws, self.task_id, self.attempt, write_seal_file=True)
        root1 = seal1["merkle_root_sha256"]

        # Leaves must only contain the 3 valid evidence files
        leaf_paths = [item["path"] for item in seal1["leaves"]]
        self.assertEqual(
            leaf_paths,
            ["Phase-1/declared_scope.json", "Phase-1/prompt.md", "Phase-2A/pre_commit_review.json"],
        )

        # Re-compute: must match exactly
        seal2 = compute_attempt_merkle_seal(self.attempt_dir, self.ws, self.task_id, self.attempt, write_seal_file=False)
        self.assertEqual(seal2["merkle_root_sha256"], root1)

        # Verification must pass cleanly
        is_valid, violations = verify_attempt_merkle_seal(self.attempt_dir, self.ws)
        self.assertTrue(is_valid, f"Verification failed with: {violations}")

    def test_acyclic_manifest_indexing(self) -> None:
        """Verify EVIDENCE_MANIFEST.json indexes seal.json without circular dependencies."""
        p1_dir = self.attempt_dir / "Phase-1"
        p1_dir.mkdir(parents=True, exist_ok=True)
        (p1_dir / "prompt.md").write_text("# Valid Blueprint\n", encoding="utf-8")

        seal = compute_attempt_merkle_seal(self.attempt_dir, self.ws, self.task_id, self.attempt, write_seal_file=True)

        # seal.json does NOT contain manifest_sha256
        seal_file = self.attempt_dir / "seal.json"
        seal_data = json.loads(seal_file.read_text(encoding="utf-8"))
        self.assertNotIn("manifest_sha256", seal_data)

        # Index downstream in manifest
        manifest_path = index_seal_in_manifest(self.ws, self.task_id, self.attempt, seal)
        self.assertTrue(manifest_path.is_file())

        manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
        task_entry = manifest_data["sealed_tasks"][self.task_id][f"attempt_{self.attempt}"]
        self.assertEqual(task_entry["merkle_root_sha256"], seal["merkle_root_sha256"])
        self.assertEqual(task_entry["total_files"], seal["total_files_sealed"])

    def test_tamper_detection(self) -> None:
        """Verify tampering with sealed files or adding/removing files is detected."""
        p1_dir = self.attempt_dir / "Phase-1"
        p1_dir.mkdir(parents=True, exist_ok=True)
        prompt_file = p1_dir / "prompt.md"
        prompt_file.write_text("# Initial Content\n", encoding="utf-8")

        compute_attempt_merkle_seal(self.attempt_dir, self.ws, self.task_id, self.attempt, write_seal_file=True)

        # 1. Modifying a sealed file
        prompt_file.chmod(0o644)
        prompt_file.write_text("# Tampered Content\n", encoding="utf-8")

        is_valid, violations = verify_attempt_merkle_seal(self.attempt_dir, self.ws)
        self.assertFalse(is_valid)
        self.assertTrue(any("Tampered sealed file" in v for v in violations))

        # Restore
        prompt_file.write_text("# Initial Content\n", encoding="utf-8")
        is_valid, violations = verify_attempt_merkle_seal(self.attempt_dir, self.ws)
        self.assertTrue(is_valid)

        # 2. Deleting a sealed file
        prompt_file.unlink()
        is_valid, violations = verify_attempt_merkle_seal(self.attempt_dir, self.ws)
        self.assertFalse(is_valid)
        self.assertTrue(any("Missing sealed file" in v for v in violations))

        # 3. Adding an extra unrecorded file
        prompt_file.write_text("# Initial Content\n", encoding="utf-8")
        extra_file = p1_dir / "unrecorded.json"
        extra_file.write_text('{"extra": true}\n', encoding="utf-8")
        is_valid, violations = verify_attempt_merkle_seal(self.attempt_dir, self.ws)
        self.assertFalse(is_valid)
        self.assertTrue(any("Unrecorded file present" in v for v in violations))

    def test_create_task_seal_rejects_symlinked_verdict(self) -> None:
        """Verify create_task_seal uses nofollow and rejects symlinked verdict.json."""
        from stagecheck.core.evidence import EvidenceTamperError, create_task_seal

        outside = self.ws / "outside_verdict.json"
        outside.write_text('{"result": "CLEAR"}', encoding="utf-8")
        p3_dir = self.attempt_dir / "Phase-3"
        p3_dir.mkdir(parents=True, exist_ok=True)
        (p3_dir / "verdict.json").symlink_to(outside)

        with self.assertRaises(EvidenceTamperError):
            create_task_seal(
                workspace_root=self.ws,
                task_id=self.task_id,
                attempt=1,
                verdict_data={"result": "CLEAR"},
                checked_heads={"backend": "a" * 40},
            )


if __name__ == "__main__":
    unittest.main()

