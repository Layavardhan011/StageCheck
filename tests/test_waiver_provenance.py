"""Adversarial & Acceptance Tests for Human-Waiver Provenance (GAP-03)."""

from __future__ import annotations

import datetime
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from stagecheck.cli.main import main
from stagecheck.core.agents_md import write_agents_contract
from stagecheck.core.dispositions import (
    DispositionError,
    UnauthorizedDispositionError,
    add_disposition,
    build_waiver_entry,
    compute_waiver_digest,
    load_dispositions,
    mark_waivers_finalized,
    record_waiver_in_replay_ledger,
    revoke_disposition,
    validate_waiver_provenance,
)
from stagecheck.core.git import discover_repository
from stagecheck.core.permissions import controlled_write_transaction, elevate_permissions_for_teardown
from stagecheck.core.rubric_engine import _evaluate_human_waiver, load_270_rule_catalog
from stagecheck.core.scaffold import scaffold_controls_atomic
from stagecheck.core.state import load_active_state, save_active_state
from stagecheck.core.utils import canonical_json_dumps


class TestHumanWaiverProvenance(unittest.TestCase):
    """Verify all 8 GAP-03 human-waiver provenance invariants fail closed."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.ws = Path(self.temp_dir.name).resolve()
        self.task_id = "task-waiver-03"
        self.attempt = 1

        self.repo_dir = self.ws / "repos" / "app"
        self.repo_dir.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "init", str(self.repo_dir)], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(self.repo_dir), "config", "user.name", "Tester"], check=True)
        subprocess.run(["git", "-C", str(self.repo_dir), "config", "user.email", "t@test.local"], check=True)
        (self.repo_dir / "app.py").write_text("x = 1\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.repo_dir), "add", "."], check=True)
        subprocess.run(["git", "-C", str(self.repo_dir), "commit", "-m", "init"], check=True)

        baseline = discover_repository(self.repo_dir, name="app", workspace_root=self.ws)
        scaffold_controls_atomic(self.ws, {"app": baseline}, agent1_name="agent1", agent2_name="agent2")
        state = load_active_state(self.ws)
        state["task_id"] = self.task_id
        state["attempt_index"] = self.attempt
        save_active_state(self.ws, state)
        write_agents_contract(self.ws)

        self.evidence_rel = "evidence/waiver_proof.txt"
        ev_file = self.ws / self.evidence_rel
        ev_file.parent.mkdir(parents=True, exist_ok=True)
        ev_file.write_text("Approved security risk acceptance artifact.\n", encoding="utf-8")

    def tearDown(self) -> None:
        elevate_permissions_for_teardown(self.ws)
        self.temp_dir.cleanup()

    def _valid_entry(self, **overrides) -> dict:
        entry = build_waiver_entry(
            workspace_root=self.ws,
            task_id=self.task_id,
            defect_id="COMMON-001",
            rationale="Verified temporary exception with compensating network filter",
            authorized_by="owner@stagecheck.local",
            attempt=self.attempt,
            evidence_path=self.evidence_rel,
            rule_id="COMMON-001",
            waived_rules=["COMMON-001"],
        )
        entry.update(overrides)
        return entry

    def test_rejects_non_human_agent_and_bot_identities(self) -> None:
        """Agents, bots, and wildcards must never be accepted as human waiver approvers."""
        for bad_actor in ("agent1", "agent2", "claude", "codex", "ci-bot", "automation", "*"):
            with self.subTest(actor=bad_actor):
                with self.assertRaises(UnauthorizedDispositionError):
                    add_disposition(
                        workspace_root=self.ws,
                        task_id=self.task_id,
                        defect_id="COMMON-001",
                        rationale="Attempted agent self-waiver justification",
                        authorized_by=bad_actor,
                        evidence_path=self.evidence_rel,
                        require_tty=False,
                        confirmed=True,
                    )

                forged = self._valid_entry(authorized_by=bad_actor)
                ok, reason = validate_waiver_provenance(self.ws, forged, self.task_id, self.attempt)
                self.assertFalse(ok)
                self.assertIn("human", reason.lower())

    def test_rejects_unauthorized_human_and_insufficient_owner_grants(self) -> None:
        """Operators absent from OWNER_GRANTS.md or lacking WAIVER_APPROVE must fail closed."""
        with self.assertRaises(UnauthorizedDispositionError):
            add_disposition(
                workspace_root=self.ws,
                task_id=self.task_id,
                defect_id="COMMON-001",
                rationale="Unlisted operator attempting waiver",
                authorized_by="stranger@company.com",
                evidence_path=self.evidence_rel,
                require_tty=False,
                confirmed=True,
            )

        # Grant operator with only WAIVER_REVOKE (no WAIVER_APPROVE)
        grants_path = self.ws / "controls" / "OWNER_GRANTS.md"
        with controlled_write_transaction(self.ws / "controls"):
            existing = grants_path.read_text(encoding="utf-8")
            grants_path.write_text(
                existing + "\n* Authorized operator: `reviewer@stagecheck.local` (roles: AUDITOR; permissions: WAIVER_REVOKE)\n",
                encoding="utf-8",
            )
        write_agents_contract(self.ws)

        with self.assertRaises(UnauthorizedDispositionError):
            add_disposition(
                workspace_root=self.ws,
                task_id=self.task_id,
                defect_id="COMMON-001",
                rationale="Insufficient grant attempting approval",
                authorized_by="reviewer@stagecheck.local",
                evidence_path=self.evidence_rel,
                require_tty=False,
                confirmed=True,
            )

    def test_rejects_missing_trivial_rationale_or_tampered_evidence(self) -> None:
        """Missing/trivial rationale, missing evidence, symlinked evidence, or SHA tampering must fail."""
        for bad_rationale in ("", "ok", "lgtm", "n/a", "short"):
            with self.assertRaises(DispositionError):
                add_disposition(
                    workspace_root=self.ws,
                    task_id=self.task_id,
                    defect_id="COMMON-001",
                    rationale=bad_rationale,
                    authorized_by="owner@stagecheck.local",
                    evidence_path=self.evidence_rel,
                    require_tty=False,
                    confirmed=True,
                )

        # Missing evidence file
        with self.assertRaises(DispositionError):
            add_disposition(
                workspace_root=self.ws,
                task_id=self.task_id,
                defect_id="COMMON-001",
                rationale="Valid rationale but missing supporting evidence",
                authorized_by="owner@stagecheck.local",
                evidence_path="evidence/nonexistent.txt",
                require_tty=False,
                confirmed=True,
            )

        # Tampered evidence file after waiver creation breaks evidence_sha256 check
        entry = self._valid_entry()
        (self.ws / self.evidence_rel).write_text("Tampered contents!\n", encoding="utf-8")
        ok, reason = validate_waiver_provenance(self.ws, entry, self.task_id, self.attempt)
        self.assertFalse(ok)
        self.assertIn("evidence_sha256", reason)

    def test_rejects_wrong_attempt_wildcard_target_and_expired_waivers(self) -> None:
        """Attempt mismatches, wildcard '*' targets, unapproved flags, and expired timestamps must fail."""
        entry = self._valid_entry()
        # Wrong attempt binding
        ok_att, msg_att = validate_waiver_provenance(self.ws, entry, self.task_id, self.attempt + 1)
        self.assertFalse(ok_att)
        self.assertIn("attempt", msg_att.lower())

        # Missing explicit_approval
        ok_exp_app, _ = validate_waiver_provenance(
            self.ws, self._valid_entry(explicit_approval=False), self.task_id, self.attempt
        )
        self.assertFalse(ok_exp_app)

        # Expired timestamp
        past_auth = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=2)).isoformat()
        past_exp = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)).isoformat()
        expired = build_waiver_entry(
            workspace_root=self.ws,
            task_id=self.task_id,
            defect_id="COMMON-001",
            rationale="Expired waiver acceptance test case",
            authorized_by="owner@stagecheck.local",
            attempt=self.attempt,
            evidence_path=self.evidence_rel,
            expires_at=past_exp,
            rule_id="COMMON-001",
            waived_rules=["COMMON-001"],
        )
        expired["authorized_at"] = past_auth
        expired["waiver_digest"] = compute_waiver_digest(expired)
        ok_exp, msg_exp = validate_waiver_provenance(self.ws, expired, self.task_id, self.attempt)
        self.assertFalse(ok_exp)
        self.assertIn("expired", msg_exp.lower())

        # Wildcard '*' rule target rejected by HUMAN_WAIVER rubric rule
        rule = next(r for r in load_270_rule_catalog() if r.rule_id == "COMMON-001")
        wildcard_entry = build_waiver_entry(
            workspace_root=self.ws,
            task_id=self.task_id,
            defect_id="*",
            rationale="Wildcard blanket waiver attempt",
            authorized_by="owner@stagecheck.local",
            attempt=self.attempt,
            evidence_path=self.evidence_rel,
            rule_id="*",
            waived_rules=["*"],
        )
        ev_res = _evaluate_human_waiver(
            rule,
            {"human_waivers": {"*": wildcard_entry}, "task_id": self.task_id, "attempt": self.attempt},
        )
        self.assertNotEqual(ev_res.status, "PASS")

    def test_revocation_and_replay_prevention_ledger(self) -> None:
        """Verify disposition revocation via CLI and replay rejection across attempts/nonces."""
        added = add_disposition(
            workspace_root=self.ws,
            task_id=self.task_id,
            defect_id="COMMON-001",
            rationale="Initial valid human waiver with full provenance",
            authorized_by="owner@stagecheck.local",
            attempt=self.attempt,
            evidence_path=self.evidence_rel,
            rule_id="COMMON-001",
            waived_rules=["COMMON-001"],
            require_tty=False,
            confirmed=True,
        )

        # Valid in attempt 1
        ok1, msg1 = validate_waiver_provenance(self.ws, added, self.task_id, self.attempt, required_rule_id="COMMON-001")
        self.assertTrue(ok1, msg1)

        # Duplicate nonce across entries rejected
        ok_dup, msg_dup = validate_waiver_provenance(
            self.ws, added, self.task_id, self.attempt, all_entries=[added, dict(added)]
        )
        self.assertFalse(ok_dup)
        self.assertIn("nonce", msg_dup.lower())

        # CLI revoke marks REVOKED and fails provenance checks permanently
        rc_rev = main([
            "disposition", "revoke",
            "--task", self.task_id,
            "--disposition-id", added["disposition_id"],
            "--authorized-by", "owner@stagecheck.local",
            "--rationale", "Compensating control removed",
            "--yes",
            "--workspace", str(self.ws),
        ])
        self.assertEqual(rc_rev, 0)

        doc_after = load_dispositions(self.ws)
        revoked_entry = doc_after["dispositions"][0]
        self.assertEqual(revoked_entry["status"], "REVOKED")
        ok_rev, msg_rev = validate_waiver_provenance(self.ws, revoked_entry, self.task_id, self.attempt)
        self.assertFalse(ok_rev)
        self.assertIn("revoked", msg_rev.lower())

        # Finalizing attempt prevents replaying previously issued nonces even if entry is copied forward
        added2 = add_disposition(
            workspace_root=self.ws,
            task_id=self.task_id,
            defect_id="COMMON-002",
            rationale="Second valid waiver prior to attempt finalization",
            authorized_by="owner@stagecheck.local",
            attempt=self.attempt,
            evidence_path=self.evidence_rel,
            rule_id="COMMON-002",
            waived_rules=["COMMON-002"],
            require_tty=False,
            confirmed=True,
        )
        mark_waivers_finalized(self.ws, self.task_id, self.attempt)
        ok_fin, msg_fin = validate_waiver_provenance(self.ws, added2, self.task_id, self.attempt)
        self.assertFalse(ok_fin)
        self.assertIn("finalized", msg_fin.lower())


if __name__ == "__main__":
    unittest.main()
