"""Unit and Integration Tests for Evidence Manifest, Task Seals, and Chaining (P4-T3)."""

import json
import os
import shutil
import stat
import tempfile
import unittest
from pathlib import Path

from stagecheck.core.evidence import (
    EvidenceTamperError,
    SealChainBrokenError,
    append_issue_history,
    create_task_seal,
    get_manifest_path,
    get_task_seal_path,
    load_evidence_manifest,
    update_evidence_manifest,
    verify_evidence_manifest,
    verify_seal_chain,
)
from stagecheck.core.utils import canonical_json_dumps, sha256_file


class TestEvidenceEngine(unittest.TestCase):
    """Test suite for evidence manifest integrity, seal Merkle chains, and commit binding."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="stagecheck_ev_test_")
        self.workspace_root = Path(self.temp_dir)
        self.task_id = "task-202"

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_manifest_initialization_and_update(self):
        """Verify updating EVIDENCE_MANIFEST.json records accurate SHA-256 digests and sizes."""
        # Create dummy evidence files
        f1 = self.workspace_root / "evidence" / "test1.txt"
        f1.parent.mkdir(parents=True, exist_ok=True)
        f1.write_text("Evidence Content 1", encoding="utf-8")

        f2 = self.workspace_root / "evidence" / "test2.json"
        f2.write_text('{"status": "OK"}', encoding="utf-8")

        manifest_path = update_evidence_manifest(self.workspace_root, [f1, f2])
        self.assertTrue(manifest_path.is_file())

        manifest = load_evidence_manifest(self.workspace_root)
        self.assertEqual(manifest["schema_version"], "2.0")
        self.assertIn("evidence/test1.txt", manifest["entries"])
        self.assertIn("evidence/test2.json", manifest["entries"])

        self.assertEqual(manifest["entries"]["evidence/test1.txt"]["sha256"], sha256_file(f1))
        self.assertEqual(manifest["entries"]["evidence/test1.txt"]["size_bytes"], f1.stat().st_size)

    def test_manifest_digest_stability(self):
        """Verify that recalculating manifest on unchanged files produces stable entries."""
        f1 = self.workspace_root / "evidence" / "stable.txt"
        f1.parent.mkdir(parents=True, exist_ok=True)
        f1.write_text("Consistent Evidence Data", encoding="utf-8")

        update_evidence_manifest(self.workspace_root, [f1])
        m1 = load_evidence_manifest(self.workspace_root)
        hash1 = m1["entries"]["evidence/stable.txt"]["sha256"]

        # Second update
        update_evidence_manifest(self.workspace_root, [f1])
        m2 = load_evidence_manifest(self.workspace_root)
        hash2 = m2["entries"]["evidence/stable.txt"]["sha256"]

        self.assertEqual(hash1, hash2)

    def test_manifest_tamper_detection_modified_file(self):
        """Verify verify_evidence_manifest detects post-audit file tampering."""
        f1 = self.workspace_root / "evidence" / "guarded.txt"
        f1.parent.mkdir(parents=True, exist_ok=True)
        f1.write_text("Original Valid Content", encoding="utf-8")

        update_evidence_manifest(self.workspace_root, [f1])
        valid, violations = verify_evidence_manifest(self.workspace_root)
        self.assertTrue(valid)
        self.assertEqual(len(violations), 0)

        # Adversarial tamper
        f1.write_text("Adversarially Modified Content", encoding="utf-8")
        tampered_valid, tampered_violations = verify_evidence_manifest(self.workspace_root)
        self.assertFalse(tampered_valid)
        self.assertTrue(any("mismatch" in msg for msg in tampered_violations))

    def test_manifest_tamper_detection_missing_file(self):
        """Verify verify_evidence_manifest detects deleted evidence files."""
        f1 = self.workspace_root / "evidence" / "delete_me.txt"
        f1.parent.mkdir(parents=True, exist_ok=True)
        f1.write_text("Temporary file", encoding="utf-8")

        update_evidence_manifest(self.workspace_root, [f1])
        f1.unlink()

        valid, violations = verify_evidence_manifest(self.workspace_root)
        self.assertFalse(valid)
        self.assertTrue(any("missing" in msg for msg in violations))

    def test_seal_creation_attempt_1_properties(self):
        """Verify attempt 1 seal creation, mode 0444, zeroed prior hash, and manifest registration."""
        checked_heads = {
            "payment-service": "a" * 40,
            "ledger-api": "b" * 40,
        }
        verdict_data = {"type": "verdict", "result": "CLEAR"}

        seal_path = create_task_seal(
            workspace_root=self.workspace_root,
            task_id=self.task_id,
            attempt=1,
            verdict_data=verdict_data,
            checked_heads=checked_heads,
            outcome="PASSED",
        )

        self.assertTrue(seal_path.is_file())
        with open(seal_path, "r", encoding="utf-8") as f:
            seal_data = json.load(f)

        self.assertEqual(seal_data["task_id"], self.task_id)
        self.assertEqual(seal_data["attempt"], 1)
        self.assertEqual(seal_data["outcome"], "PASSED")
        self.assertEqual(seal_data["prior_seal_sha256"], "0" * 64)
        self.assertEqual(seal_data["checked_heads"], checked_heads)
        self.assertIn("manifest_sha256", seal_data)
        self.assertIn("payload_sha256", seal_data)

        # Assert read-only file permissions (0444)
        mode = seal_path.stat().st_mode & 0o777
        self.assertEqual(mode, 0o444)

        # Assert master seal also generated for PASSED
        master_seal = self.workspace_root / "evidence" / "tasks" / self.task_id / "seal.json"
        self.assertTrue(master_seal.is_file())

    def test_seal_chain_linkage_multi_attempt(self):
        """Verify cryptographic Merkle hash chaining across attempts 1, 2, and 3."""
        checked_heads_1 = {"payment-service": "1" * 40}
        checked_heads_2 = {"payment-service": "2" * 40}
        checked_heads_3 = {"payment-service": "3" * 40}

        # Attempt 1
        s1 = create_task_seal(
            self.workspace_root,
            self.task_id,
            1,
            {"result": "BLOCKED"},
            checked_heads_1,
            outcome="FAILED",
        )

        # Attempt 2
        s2 = create_task_seal(
            self.workspace_root,
            self.task_id,
            2,
            {"result": "BLOCKED"},
            checked_heads_2,
            outcome="FAILED",
        )

        # Attempt 3
        s3 = create_task_seal(
            self.workspace_root,
            self.task_id,
            3,
            {"result": "CLEAR"},
            checked_heads_3,
            outcome="PASSED",
        )

        # Verify s2 links to s1
        with open(s2, "r", encoding="utf-8") as f:
            data2 = json.load(f)
        self.assertEqual(data2["prior_seal_sha256"], sha256_file(s1))

        # Verify s3 links to s2
        with open(s3, "r", encoding="utf-8") as f:
            data3 = json.load(f)
        self.assertEqual(data3["prior_seal_sha256"], sha256_file(s2))

        # Verify unbroken chain validation
        valid, violations = verify_seal_chain(self.workspace_root, self.task_id, max_attempt=3)
        self.assertTrue(valid)
        self.assertEqual(len(violations), 0)

    def test_seal_chain_tamper_detection(self):
        """Verify tampering with attempt 1 seal breaks the chain verification at attempt 2."""
        checked_heads = {"app": "a" * 40}
        s1 = create_task_seal(self.workspace_root, self.task_id, 1, {}, checked_heads, "FAILED")
        s2 = create_task_seal(self.workspace_root, self.task_id, 2, {}, checked_heads, "PASSED")

        # Unlock s1 and tamper
        os.chmod(s1, stat.S_IWUSR | stat.S_IRUSR)
        with open(s1, "w", encoding="utf-8") as f:
            f.write(canonical_json_dumps({"task_id": self.task_id, "tampered": True}))

        valid, violations = verify_seal_chain(self.workspace_root, self.task_id, max_attempt=2)
        self.assertFalse(valid)
        self.assertTrue(any("Cryptographic chain broken" in msg for msg in violations))

    def test_multi_repo_commit_vector_binding_determinism(self):
        """Verify multi-repo commit vectors are sorted deterministically in payload hash."""
        heads_a = {"repo-z": "3" * 40, "repo-a": "1" * 40, "repo-m": "2" * 40}
        heads_b = {"repo-a": "1" * 40, "repo-m": "2" * 40, "repo-z": "3" * 40}

        seal1 = create_task_seal(self.workspace_root, "task-a", 1, {}, heads_a, "PASSED")
        seal2 = create_task_seal(self.workspace_root, "task-b", 1, {}, heads_b, "PASSED")

        with open(seal1) as f1, open(seal2) as f2:
            d1, d2 = json.load(f1), json.load(f2)

        self.assertEqual(list(d1["checked_heads"].keys()), ["repo-a", "repo-m", "repo-z"])
        self.assertEqual(list(d2["checked_heads"].keys()), ["repo-a", "repo-m", "repo-z"])

    def test_append_only_issue_history_ledger(self):
        """Verify appending defects to TASK_<ID>_ISSUE_HISTORY.md maintains append-only history."""
        defects_att1 = [
            {"defect_id": "scope.unauthorized_dir", "check_id": "scope_paths", "severity": "CRITICAL", "mode": "blocking"}
        ]
        history_path = append_issue_history(
            self.workspace_root,
            self.task_id,
            attempt=1,
            outcome="FAILED",
            defects=defects_att1,
        )
        self.assertTrue(history_path.is_file())
        content1 = history_path.read_text(encoding="utf-8")
        self.assertIn("Attempt 1 Verification Record", content1)
        self.assertIn("scope.unauthorized_dir", content1)

        # Append Attempt 2
        defects_att2 = [
            {"defect_id": "rerun.mismatch", "check_id": "rerun", "severity": "HIGH", "mode": "blocking"}
        ]
        append_issue_history(
            self.workspace_root,
            self.task_id,
            attempt=2,
            outcome="FAILED",
            defects=defects_att2,
        )
        content2 = history_path.read_text(encoding="utf-8")

        # Assert attempt 1 record is preserved intact (append-only)
        self.assertTrue(content2.startswith(content1))
        self.assertIn("Attempt 2 Verification Record", content2)
        self.assertIn("rerun.mismatch", content2)

        # Assert indexed in manifest
        manifest = load_evidence_manifest(self.workspace_root)
        rel_posix = str(history_path.relative_to(self.workspace_root)).replace("\\", "/")
        self.assertIn(rel_posix, manifest["entries"])


if __name__ == "__main__":
    unittest.main()

