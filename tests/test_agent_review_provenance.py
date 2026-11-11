"""Adversarial & Acceptance Tests for Agent-Assisted Review Provenance (GAP-04)."""

from __future__ import annotations

import datetime
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from stagecheck.core.agents_md import write_agents_contract
from stagecheck.core.cooperative_review import record_pre_commit_review
from stagecheck.core.git import discover_repository
from stagecheck.core.permissions import controlled_write_transaction, elevate_permissions_for_teardown
from stagecheck.core.rubric_engine import (
    build_agent_reviews_artifact,
    compute_uncommitted_state_digest,
    validate_agent_review_provenance,
)
from stagecheck.core.scaffold import scaffold_controls_atomic
from stagecheck.core.state import load_active_state, save_active_state
from stagecheck.core.utils import canonical_json_dumps


class TestAgentReviewProvenance(unittest.TestCase):
    """Verify all 9 GAP-04 agent-assisted review provenance and independence requirements."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.ws = Path(self.temp_dir.name).resolve()
        self.task_id = "task-review-04"
        self.attempt = 1

        self.repo_dir = self.ws / "repos" / "app"
        self.repo_dir.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "init", str(self.repo_dir)], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(self.repo_dir), "config", "user.name", "Tester"], check=True)
        subprocess.run(["git", "-C", str(self.repo_dir), "config", "user.email", "t@test.local"], check=True)
        (self.repo_dir / "app.py").write_text("x = 1\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.repo_dir), "add", "."], check=True)
        subprocess.run(["git", "-C", str(self.repo_dir), "commit", "-m", "init"], check=True)
        subprocess.run(["git", "-C", str(self.repo_dir), "switch", "-c", f"task/{self.task_id}"], check=True, capture_output=True)

        self.base_commit = subprocess.run(
            ["git", "-C", str(self.repo_dir), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
        ).stdout.strip()

        baseline = discover_repository(self.repo_dir, name="app", workspace_root=self.ws)
        scaffold_controls_atomic(self.ws, {"app": baseline}, agent1_name="auditor1", agent2_name="coder2")
        state = load_active_state(self.ws)
        state["task_id"] = self.task_id
        state["attempt_index"] = self.attempt
        state["phase"] = "PHASE_2A_CODING"
        state["cleared_gates"] = {"GATE_1": "a" * 64}
        save_active_state(self.ws, state)
        write_agents_contract(self.ws)

        self.p2a_dir = self.ws / "evidence" / "tasks" / self.task_id / f"attempt_{self.attempt}" / "Phase-2A"
        self.p2a_dir.mkdir(parents=True, exist_ok=True)
        self.status_doc = {
            "schema_version": "2.0",
            "task_id": self.task_id,
            "attempt": self.attempt,
            "cycle": 1,
            "status": "AWAITING_REVIEW",
            "submitted_by": "coder2",
            "touched_repositories": ["app"],
            "base_commits": {"app": self.base_commit},
        }
        (self.p2a_dir / "pre_commit_status.json").write_text(canonical_json_dumps(self.status_doc), encoding="utf-8")

        # Stage uncommitted code diff ready for Phase-2A review
        (self.repo_dir / "app.py").write_text("x = 2\n", encoding="utf-8")

    def tearDown(self) -> None:
        elevate_permissions_for_teardown(self.ws)
        self.temp_dir.cleanup()

    def _write_reviews(self, **kwargs) -> dict:
        reviews = kwargs.pop("reviews", {"COMMON-011": {"status": "PASS", "rationale": "Verified semantics."}})
        doc = build_agent_reviews_artifact(
            workspace_root=self.ws,
            task_id=self.task_id,
            attempt=self.attempt,
            reviews=reviews,
            reviewer=kwargs.pop("reviewer", "auditor1"),
            reviewer_role=kwargs.pop("reviewer_role", "prompt_and_audit"),
            producer=kwargs.pop("producer", "coder2"),
            **kwargs,
        )
        (self.p2a_dir / "agent_reviews.json").write_text(canonical_json_dumps(doc), encoding="utf-8")
        return doc

    def _validate(self, doc: dict, entry: dict | None = None, state_override: dict | None = None):
        state = state_override if state_override is not None else load_active_state(self.ws)
        heads, snap = compute_uncommitted_state_digest(self.ws)
        entry_val = entry if entry is not None else doc["agent_assisted_reviews"]["COMMON-011"]
        return validate_agent_review_provenance(
            workspace_root=self.ws,
            src_doc=doc,
            src_rel_path="Phase-2A/agent_reviews.json",
            task_id=self.task_id,
            attempt=self.attempt,
            active_state=state,
            pre_commit_status=self.status_doc,
            repo_heads=heads,
            diff_snapshot_sha256=snap,
            entry=entry_val,
        )

    def test_valid_independent_agent_review_passes(self) -> None:
        doc = self._write_reviews()
        ok, status, msg = self._validate(doc)
        self.assertTrue(ok, msg)
        self.assertEqual(status, "PASS")

    def test_rejects_generic_evaluator_and_missing_identity(self) -> None:
        for generic in ("generic", "generic_evaluator", "auto", "system", "rubric_engine"):
            doc = self._write_reviews(reviewer=generic)
            ok, status, msg = self._validate(doc)
            self.assertFalse(ok)
            self.assertEqual(status, "FAIL")
            self.assertIn("generic", msg.lower())

        doc_empty = self._write_reviews(reviewer="")
        ok_e, st_e, _ = self._validate(doc_empty)
        self.assertFalse(ok_e)
        self.assertEqual(st_e, "NOT_EVALUATED")

    def test_rejects_unregistered_disabled_wrong_role_and_coder_self_review(self) -> None:
        # Unregistered reviewer
        ok_unreg, st_unreg, _ = self._validate(self._write_reviews(reviewer="rogue-ai"))
        self.assertFalse(ok_unreg)
        self.assertEqual(st_unreg, "FAIL")

        # Code implementation agent attempting to review own changes in dual-agent mode
        ok_coder, st_coder, _ = self._validate(self._write_reviews(reviewer="coder2", reviewer_role="code_implementation"))
        self.assertFalse(ok_coder)
        self.assertEqual(st_coder, "FAIL")

        # Reviewer matches producer despite claiming prompt_and_audit role
        status_spoof = dict(self.status_doc, submitted_by="auditor1")
        heads, snap = compute_uncommitted_state_digest(self.ws)
        doc_self = self._write_reviews(reviewer="auditor1", producer="auditor1")
        ok_self, st_self, msg_self = validate_agent_review_provenance(
            workspace_root=self.ws,
            src_doc=doc_self,
            src_rel_path="Phase-2A/agent_reviews.json",
            task_id=self.task_id,
            attempt=self.attempt,
            active_state=load_active_state(self.ws),
            pre_commit_status=status_spoof,
            repo_heads=heads,
            diff_snapshot_sha256=snap,
            entry=doc_self["agent_assisted_reviews"]["COMMON-011"],
        )
        self.assertFalse(ok_self)
        self.assertEqual(st_self, "FAIL")
        self.assertIn("independence", msg_self.lower())

        # Disabled registered agent must fail
        state_disabled = load_active_state(self.ws)
        state_disabled["registered_agents"] = [
            {"name": "auditor1", "role": "prompt_and_audit", "enabled": False},
            {"name": "coder2", "role": "code_implementation", "enabled": True},
        ]
        ok_dis, st_dis, _ = self._validate(self._write_reviews(), state_override=state_disabled)
        self.assertFalse(ok_dis)
        self.assertEqual(st_dis, "FAIL")

    def test_rejects_tampered_digest_artifact_sha_and_mismatched_binding(self) -> None:
        doc = self._write_reviews()

        # Tamper review content without recomputing review_digest
        tampered = json.loads(json.dumps(doc))
        tampered["agent_assisted_reviews"]["COMMON-011"]["rationale"] = "Post-hoc forged rationale"
        ok_t, st_t, msg_t = self._validate(tampered)
        self.assertFalse(ok_t)
        self.assertEqual(st_t, "FAIL")
        self.assertIn("review_digest", msg_t)

        # Modify pre_commit_status.json so artifact_sha256 mismatches
        (self.p2a_dir / "pre_commit_status.json").write_text(
            canonical_json_dumps(dict(self.status_doc, summary="Changed after review")), encoding="utf-8"
        )
        ok_art, st_art, msg_art = self._validate(doc)
        self.assertFalse(ok_art)
        self.assertEqual(st_art, "FAIL")
        self.assertIn("artifact_sha256", msg_art)

        # Wrong task/attempt binding
        ok_task, st_task, _ = self._validate(self._write_reviews(reviews={
            "COMMON-011": {"status": "PASS", "rationale": "ok", "task_id": "other-task"}
        }))
        self.assertFalse(ok_task)
        self.assertEqual(st_task, "FAIL")

    def test_rejects_stale_timestamp_dirty_edit_and_unapproved_commit(self) -> None:
        # Expired reviewed_at
        old_ts = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=2)).isoformat()
        ok_old, st_old, msg_old = self._validate(self._write_reviews(reviewed_at=old_ts))
        self.assertFalse(ok_old)
        self.assertEqual(st_old, "NOT_EVALUATED")
        self.assertIn("expired", msg_old.lower())

        # Fresh review, then code modified in working tree -> stale diff_snapshot_sha256
        fresh_doc = self._write_reviews()
        (self.repo_dir / "app.py").write_text("x = 999  # unreviewed edit\n", encoding="utf-8")
        ok_dirty, st_dirty, _ = self._validate(fresh_doc)
        self.assertFalse(ok_dirty)
        self.assertEqual(st_dirty, "NOT_EVALUATED")

    def test_post_gate2a_clean_approved_commit_remains_valid_until_diverged(self) -> None:
        """Frozen Phase-2A agent_reviews remains valid in Phase-3 IFF committed diff matches approved review."""
        fresh_doc = self._write_reviews()
        record_pre_commit_review(
            workspace_root=self.ws,
            task_id=self.task_id,
            attempt=self.attempt,
            cycle=1,
            status="APPROVED",
            summary="Approved Phase-2A changes",
            base_commits={"app": self.base_commit},
        )
        subprocess.run(["git", "-C", str(self.repo_dir), "add", "app.py"], check=True)
        subprocess.run(["git", "-C", str(self.repo_dir), "commit", "-m", "Approved change"], check=True)

        state = load_active_state(self.ws)
        state["phase"] = "PHASE_3_AUDIT"
        state["cleared_gates"]["GATE_2A"] = "b" * 64
        save_active_state(self.ws, state)

        ok_post, st_post, msg_post = self._validate(fresh_doc, state_override=state)
        self.assertTrue(ok_post, msg_post)
        self.assertEqual(st_post, "PASS")

        # An extra unapproved commit in Phase-3 diverges from approved_diff_hashes -> rejected
        (self.repo_dir / "sneaky.py").write_text("backdoor = True\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.repo_dir), "add", "sneaky.py"], check=True)
        subprocess.run(["git", "-C", str(self.repo_dir), "commit", "-m", "Sneaky extra commit"], check=True)
        ok_div, st_div, _ = self._validate(fresh_doc, state_override=state)
        self.assertFalse(ok_div)
        self.assertEqual(st_div, "NOT_EVALUATED")


if __name__ == "__main__":
    unittest.main()

