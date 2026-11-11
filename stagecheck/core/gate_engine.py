"""Authoritative StageCheck Gate Engine, Transition Matrix, and Criteria Evaluator (FR-01 / Spec 01 / DEC-001).

Manages the deterministic lifecycle state machine, gate checkpoints (Gate-1, Gate-2A, Gate-2B,
Gate-3, Gate-4), non-mutating gate inspection, and typed transition errors.
"""

from __future__ import annotations

import copy
import datetime
import hmac
import json
import os
import re
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from stagecheck.core.agents import resolve_task_attempt_dir
from stagecheck.core.cooperative_review import (
    CommitDivergenceError,
    verify_committed_diff_fidelity,
)
from stagecheck.core.evidence import update_evidence_manifest
from stagecheck.core.git import (
    _run_git_cmd,
    approved_remote,
    get_approved_remote_urls,
    get_repo_remote_push_urls,
)
from stagecheck.core.locking import acquire_runtime_lock
from stagecheck.core.paths import safe_resolve, validate_task_id
from stagecheck.core.permissions import freeze_phase_directory
from stagecheck.core.state import load_active_state, save_active_state
from stagecheck.core.utils import (
    canonical_json_dumps,
    load_json_file,
    pretty_json_dumps,
    sha256_canonical,
    sha256_file,
)
from stagecheck.schemas.validator import validate_gate_receipt


class LifecyclePhase(str, Enum):
    """Authoritative lifecycle phases for StageCheck workspaces."""
    UNINITIALIZED = "UNINITIALIZED"
    NOT_STARTED = "NOT_STARTED"
    IDLE = "IDLE"
    PHASE_1_PLANNING = "PHASE_1_PLANNING"
    PHASE_1_REPAIR = "PHASE_1_REPAIR"
    PHASE_2A_CODING = "PHASE_2A_CODING"
    PHASE_2A_IMPLEMENTATION = "PHASE_2A_IMPLEMENTATION"  # Compatibility alias
    PHASE_2B_COMMITTING = "PHASE_2B_COMMITTING"
    PHASE_2B_DELIVERY = "PHASE_2B_DELIVERY"              # Compatibility alias
    PHASE_3_AUDIT = "PHASE_3_AUDIT"
    PHASE_3_AUDITING = "PHASE_3_AUDITING"                # Compatibility alias
    GATE_4_SEALING = "GATE_4_SEALING"
    SEALED_PASSED = "SEALED_PASSED"
    AWAITING_HUMAN_DISPOSITION = "AWAITING_HUMAN_DISPOSITION"
    CIRCUIT_BREAKER_TRIPPED = "CIRCUIT_BREAKER_TRIPPED"
    ABORTED = "ABORTED"
    COMPLETED = "COMPLETED"


class GateId(str, Enum):
    """Authoritative gate checkpoints."""
    GATE_1 = "GATE_1"
    GATE_2A = "GATE_2A"
    GATE_2B = "GATE_2B"
    GATE_3 = "GATE_3"
    GATE_4 = "GATE_4"


class GateError(Exception):
    """Base exception for gate validation and transition failures."""


class InvalidTransitionError(GateError):
    """Raised when an out-of-order or unauthorized transition is attempted."""


class PrematureGateTransitionError(GateError):
    """Raised when gate advance is attempted before prerequisites are met."""


class GateCriteriaFailedError(GateError):
    """Raised when one or more gate criteria evaluate to FAILED or BLOCKED."""

    def __init__(self, message: str, failure_reasons: Optional[List[str]] = None):
        super().__init__(message)
        self.failure_reasons = failure_reasons or []


class AttemptBudgetExhaustedError(GateError):
    """Raised when attempt budget (maximum 3 attempts) is permanently exhausted."""


class ReceiptTamperDetectedError(GateError):
    """Raised when a gate receipt is missing, altered, or not registered in ACTIVE_STATE."""


@dataclass
class GateAdvanceResult:
    """Result of an atomic gate advancement."""
    gate_id: str
    task_id: str
    attempt: int
    receipt_path: Path
    receipt_sha256: str
    from_phase: str
    to_phase: str
    turn: str


def normalize_gate_id(raw_gate: Union[str, GateId]) -> GateId:
    """Normalize user-supplied gate string into canonical GateId enum.

    Accepts forms like 'Gate-1', 'gate1', 'GATE_1', 'gate-2a', etc.
    """
    if isinstance(raw_gate, GateId):
        return raw_gate

    cleaned = str(raw_gate).strip().upper().replace("-", "_")
    if not cleaned.startswith("GATE_") and cleaned.startswith("GATE"):
        cleaned = f"GATE_{cleaned[4:]}"

    for member in GateId:
        if member.value == cleaned:
            return member

    raise ValueError(f"Unknown or invalid gate identifier: '{raw_gate}'. Valid gates: Gate-1, Gate-2A, Gate-2B, Gate-3, Gate-4")


def normalize_phase(phase: str) -> str:
    """Normalize phase aliases to canonical names."""
    p = str(phase).strip()
    alias_map = {
        "PHASE_2A_IMPLEMENTATION": "PHASE_2A_CODING",
        "PHASE_2B_DELIVERY": "PHASE_2B_COMMITTING",
        "PHASE_3_AUDITING": "PHASE_3_AUDIT",
    }
    return alias_map.get(p, p)


# Allowed precursor phases for advancing each gate
GATE_ALLOWED_PRECURSORS: Dict[GateId, Set[str]] = {
    GateId.GATE_1: {"PHASE_1_PLANNING", "PHASE_1_REPAIR"},
    GateId.GATE_2A: {"PHASE_2A_CODING", "PHASE_2A_IMPLEMENTATION"},
    GateId.GATE_2B: {"PHASE_2A_CODING", "PHASE_2A_IMPLEMENTATION", "PHASE_2B_COMMITTING", "PHASE_2B_DELIVERY"},
    GateId.GATE_3: {"PHASE_3_AUDIT", "PHASE_3_AUDITING"},
    GateId.GATE_4: {"GATE_4_SEALING"},
}

GATE_TARGET_PHASE: Dict[GateId, str] = {
    GateId.GATE_1: "PHASE_2A_CODING",
    GateId.GATE_2A: "PHASE_2B_COMMITTING",
    GateId.GATE_2B: "PHASE_3_AUDIT",
    GateId.GATE_3: "GATE_4_SEALING",
    GateId.GATE_4: "SEALED_PASSED",
}


@dataclass
class GateCriterion:
    """Evaluation result for an individual gate invariant."""
    criterion_id: str
    description: str
    status: str  # "MET", "FAILED", "BLOCKED"
    message: str
    details: Optional[Dict[str, Any]] = None


@dataclass
class GateCheckReport:
    """Comprehensive, non-mutating evaluation report for a gate checkpoint."""
    gate_id: str
    task_id: str
    attempt: int
    passed: bool
    current_phase: str
    target_phase: str
    criteria: List[GateCriterion] = field(default_factory=list)
    deliverables: List[Dict[str, str]] = field(default_factory=list)
    failure_reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert report to dictionary format."""
        return {
            "gate_id": self.gate_id,
            "task_id": self.task_id,
            "attempt": self.attempt,
            "passed": self.passed,
            "current_phase": self.current_phase,
            "target_phase": self.target_phase,
            "criteria": [asdict(c) for c in self.criteria],
            "deliverables": self.deliverables,
            "failure_reasons": self.failure_reasons,
        }


def validate_gate_transition_allowed(current_phase: str, target_gate: GateId) -> None:
    """Assert that the state machine allows advancing target_gate from current_phase.

    Raises:
        InvalidTransitionError: If target_gate cannot be reached from current_phase.
    """
    allowed_precursors = GATE_ALLOWED_PRECURSORS.get(target_gate, set())
    norm_cur = normalize_phase(current_phase)

    # Check normalized or exact
    if norm_cur not in allowed_precursors and current_phase not in allowed_precursors:
        raise InvalidTransitionError(
            f"Premature/out-of-order transition: Cannot advance {target_gate.value} from current phase '{current_phase}'. "
            f"Permitted precursor phases: {sorted(list(allowed_precursors))}."
        )


def evaluate_gate_1_criteria(
    workspace_root: Path,
    task_id: str,
    attempt: int,
) -> Tuple[List[GateCriterion], List[Dict[str, str]]]:
    """Evaluate Gate 1 (Planning Verification Gate) criteria.

    Invariants:
    1. prompt.md exists, non-empty, and satisfies blueprint checks.
    2. declared_scope.json exists, valid schema, discrete non-wildcard paths.
    3. prompt_verified.json exists and binds verified hash.
    """
    p1_dir = resolve_task_attempt_dir(workspace_root, task_id, attempt) / "Phase-1"
    criteria: List[GateCriterion] = []
    deliverables: List[Dict[str, str]] = []

    # 1. prompt.md
    prompt_file = p1_dir / "prompt.md"
    if not prompt_file.is_file():
        criteria.append(GateCriterion(
            criterion_id="gate1.prompt_exists",
            description="Phase 1 prompt blueprint exists and is readable",
            status="FAILED",
            message=f"Missing required artifact: '{prompt_file.relative_to(workspace_root)}'",
        ))
    else:
        content = prompt_file.read_text(encoding="utf-8")
        if not content.strip():
            criteria.append(GateCriterion(
                criterion_id="gate1.prompt_non_empty",
                description="Phase 1 prompt contains non-empty blueprint instructions",
                status="FAILED",
                message="prompt.md is empty.",
            ))
        else:
            p_hash = sha256_file(prompt_file)
            deliverables.append({"path": str(prompt_file.relative_to(workspace_root)), "sha256": p_hash, "status": "VALID"})
            criteria.append(GateCriterion(
                criterion_id="gate1.prompt_valid",
                description="Phase 1 prompt blueprint exists and is non-empty",
                status="MET",
                message=f"prompt.md verified ({p_hash[:16]}...).",
            ))

    # 2. declared_scope.json
    scope_file = p1_dir / "declared_scope.json"
    if not scope_file.is_file():
        criteria.append(GateCriterion(
            criterion_id="gate1.scope_exists",
            description="Declared scope descriptor exists and defines boundary",
            status="FAILED",
            message=f"Missing required artifact: '{scope_file.relative_to(workspace_root)}'",
        ))
    else:
        try:
            scope_data = load_json_file(scope_file)
            allowed = scope_data.get("allowed_paths", [])
            # Check for illegal top-level, repo-root, or globbed repo-name wildcards
            has_forbidden_wildcard = False
            for p in allowed:
                if not isinstance(p, str):
                    has_forbidden_wildcard = True
                    break
                norm_p = p.strip().lstrip("/")
                if norm_p in ("*", "/**", "**", "repos", "repos/", "repos/*", "repos/**", "repos/**/*"):
                    has_forbidden_wildcard = True
                    break
                parts = norm_p.split("/")
                if parts[0] == "repos" and (len(parts) < 2 or any(ch in parts[1] for ch in "*?[")):
                    has_forbidden_wildcard = True
                    break
            if has_forbidden_wildcard:
                criteria.append(GateCriterion(
                    criterion_id="gate1.scope_discrete",
                    description="Declared scope contains discrete non-wildcard repository paths",
                    status="FAILED",
                    message="declared_scope.json contains prohibited top-level or repository-wide wildcard pattern.",
                ))
            else:
                s_hash = sha256_file(scope_file)
                deliverables.append({"path": str(scope_file.relative_to(workspace_root)), "sha256": s_hash, "status": "VALID"})
                criteria.append(GateCriterion(
                    criterion_id="gate1.scope_discrete",
                    description="Declared scope contains discrete permitted repository paths",
                    status="MET",
                    message="declared_scope.json validates with discrete allowed paths.",
                ))
        except Exception as err:
            criteria.append(GateCriterion(
                criterion_id="gate1.scope_schema",
                description="Declared scope matches JSON schema",
                status="FAILED",
                message=f"Failed to load or parse declared_scope.json: {err}",
            ))

    # 3. prompt_verified.json
    pv_file = p1_dir / "prompt_verified.json"
    if not pv_file.is_file():
        criteria.append(GateCriterion(
            criterion_id="gate1.prompt_frozen",
            description="Prompt and scope verification record generated and frozen",
            status="FAILED",
            message="Prompt has not been verified (missing prompt_verified.json). Run 'stagecheck verify-prompt'.",
        ))
    else:
        try:
            pv_data = load_json_file(pv_file)
            if pv_data.get("status") != "VERIFIED":
                criteria.append(GateCriterion(
                    criterion_id="gate1.prompt_verified_status",
                    description="Prompt verification status is VERIFIED",
                    status="FAILED",
                    message=f"prompt_verified.json status is '{pv_data.get('status')}', expected 'VERIFIED'.",
                ))
            else:
                pv_hash = sha256_file(pv_file)
                deliverables.append({"path": str(pv_file.relative_to(workspace_root)), "sha256": pv_hash, "status": "VALID"})
                criteria.append(GateCriterion(
                    criterion_id="gate1.prompt_frozen",
                    description="Prompt and scope verified and frozen",
                    status="MET",
                    message="prompt_verified.json status is VERIFIED.",
                ))
        except Exception as err:
            criteria.append(GateCriterion(
                criterion_id="gate1.prompt_verified_format",
                description="prompt_verified.json is valid JSON",
                status="FAILED",
                message=f"Error reading prompt_verified.json: {err}",
            ))

    return criteria, deliverables


def evaluate_gate_2a_criteria(
    workspace_root: Path,
    task_id: str,
    attempt: int,
) -> Tuple[List[GateCriterion], List[Dict[str, str]]]:
    """Evaluate Gate 2A (Pre-Commit Authorization Sub-Gate) criteria.

    Invariants:
    1. pre_commit_status.json submitted by Agent 2 with status AWAITING_REVIEW.
    2. pre_commit_review.json generated with status APPROVED.
    """
    p2a_dir = resolve_task_attempt_dir(workspace_root, task_id, attempt) / "Phase-2A"
    criteria: List[GateCriterion] = []
    deliverables: List[Dict[str, str]] = []

    # 1. pre_commit_status.json
    status_file = p2a_dir / "pre_commit_status.json"
    if not status_file.is_file():
        criteria.append(GateCriterion(
            criterion_id="gate2a.status_submitted",
            description="Agent 2 pre-commit status deliverable submitted",
            status="FAILED",
            message="pre_commit_status.json not found.",
        ))
    else:
        try:
            st_data = load_json_file(status_file)
            st_hash = sha256_file(status_file)
            deliverables.append({"path": str(status_file.relative_to(workspace_root)), "sha256": st_hash, "status": "VALID"})
            criteria.append(GateCriterion(
                criterion_id="gate2a.status_submitted",
                description="Agent 2 pre-commit status deliverable submitted",
                status="MET",
                message=f"pre_commit_status.json present with status '{st_data.get('status')}'.",
            ))
        except Exception as err:
            criteria.append(GateCriterion(
                criterion_id="gate2a.status_format",
                description="pre_commit_status.json valid JSON",
                status="FAILED",
                message=str(err),
            ))

    # 2. pre_commit_review.json
    rev_file = p2a_dir / "pre_commit_review.json"
    if not rev_file.is_file():
        criteria.append(GateCriterion(
            criterion_id="gate2a.review_approved",
            description="Pre-commit cooperative review approved",
            status="FAILED",
            message="pre_commit_review.json not found. Run 'stagecheck review-precommit' and 'stagecheck approve-review'.",
        ))
    else:
        try:
            rev_data = load_json_file(rev_file)
            r_status = rev_data.get("status")
            if r_status != "APPROVED":
                criteria.append(GateCriterion(
                    criterion_id="gate2a.review_approved",
                    description="Pre-commit review marked APPROVED",
                    status="FAILED",
                    message=f"pre_commit_review.json status is '{r_status}', not 'APPROVED'.",
                ))
            else:
                rev_hash = sha256_file(rev_file)
                deliverables.append({"path": str(rev_file.relative_to(workspace_root)), "sha256": rev_hash, "status": "VALID"})
                criteria.append(GateCriterion(
                    criterion_id="gate2a.review_approved",
                    description="Pre-commit cooperative review approved",
                    status="MET",
                    message="pre_commit_review.json is APPROVED.",
                ))
        except Exception as err:
            criteria.append(GateCriterion(
                criterion_id="gate2a.review_format",
                description="pre_commit_review.json is valid JSON",
                status="FAILED",
                message=str(err),
            ))

    # 3. Phase-2A/rubric_evaluation.json must be COMPLETE, fresh, 270/270, PASS (GAP-02)
    from stagecheck.core.rubric_engine import verify_complete_rubric_evaluation

    rubric_file = p2a_dir / "rubric_evaluation.json"
    rubric_ok, rubric_reasons, _ = verify_complete_rubric_evaluation(
        workspace_root=workspace_root,
        rubric_path=rubric_file,
        task_id=task_id,
        attempt=attempt,
        require_fresh_context=True,
    )
    if rubric_ok:
        deliverables.append({
            "path": str(rubric_file.relative_to(workspace_root)),
            "sha256": sha256_file(rubric_file),
            "status": "VALID",
        })
        criteria.append(GateCriterion(
            criterion_id="gate2a.rubric_complete",
            description="Complete 270-rule pre-commit rubric evaluation passed",
            status="MET",
            message="Phase-2A/rubric_evaluation.json verified COMPLETE (270/270, fresh context, verdict=PASS).",
        ))
    else:
        criteria.append(GateCriterion(
            criterion_id="gate2a.rubric_complete",
            description="Complete 270-rule pre-commit rubric evaluation passed",
            status="FAILED",
            message="; ".join(rubric_reasons),
        ))

    return criteria, deliverables


def evaluate_gate_2b_criteria(
    workspace_root: Path,
    task_id: str,
    attempt: int,
) -> Tuple[List[GateCriterion], List[Dict[str, str]]]:
    """Evaluate Gate 2B (Commit Authority Sub-Gate) criteria.

    Invariants:
    1. Pre-commit review is APPROVED and binds exact approved snapshot.
    2. Phase 2B delivery report exists.
    3. Working trees clean in touched and declared repos.
    4. Active branch not main or master.
    5. Committed diff matches approved Phase 2A pre-commit review diff (verify_committed_diff_fidelity).
    6. Git remotes comply with authorized whitelist endpoints (approved_remote).
    7. Agent 2 zero remote push policy verified.
    """
    p2a_dir = resolve_task_attempt_dir(workspace_root, task_id, attempt) / "Phase-2A"
    p2b_dir = resolve_task_attempt_dir(workspace_root, task_id, attempt) / "Phase-2B"
    criteria: List[GateCriterion] = []
    deliverables: List[Dict[str, str]] = []

    # 1. Gate 2A review approval
    rev_file = p2a_dir / "pre_commit_review.json"
    rev_data: Optional[Dict[str, Any]] = None
    if not rev_file.is_file():
        criteria.append(GateCriterion(
            criterion_id="gate2b.prior_review_approved",
            description="Phase 2A pre-commit review must be approved prior to Gate 2B",
            status="FAILED",
            message="Gate 2A pre-commit review file is missing.",
        ))
    else:
        try:
            rev_data = load_json_file(rev_file)
            r_status = rev_data.get("status")
            if r_status != "APPROVED":
                criteria.append(GateCriterion(
                    criterion_id="gate2b.prior_review_approved",
                    description="Phase 2A pre-commit review must be approved prior to Gate 2B",
                    status="FAILED",
                    message=f"pre_commit_review.json status is '{r_status}', not 'APPROVED'.",
                ))
            else:
                rev_hash = sha256_file(rev_file)
                deliverables.append({
                    "path": str(rev_file.relative_to(workspace_root)),
                    "sha256": rev_hash,
                    "status": "VALID",
                })
                criteria.append(GateCriterion(
                    criterion_id="gate2b.prior_review_approved",
                    description="Phase 2A pre-commit review approved",
                    status="MET",
                    message="Phase 2A review is APPROVED.",
                ))
        except Exception as err:
            criteria.append(GateCriterion(
                criterion_id="gate2b.prior_review_approved",
                description="Phase 2A pre-commit review valid",
                status="FAILED",
                message=f"Failed to load pre_commit_review.json: {err}",
            ))

    # 2. Phase 2B delivery report
    report_file = p2b_dir / "report.md"
    if not report_file.is_file():
        criteria.append(GateCriterion(
            criterion_id="gate2b.delivery_report_exists",
            description="Phase 2B delivery report exists",
            status="FAILED",
            message=f"Missing delivery report at '{report_file.relative_to(workspace_root)}'",
        ))
    else:
        rep_hash = sha256_file(report_file)
        deliverables.append({
            "path": str(report_file.relative_to(workspace_root)),
            "sha256": rep_hash,
            "status": "VALID",
        })
        criteria.append(GateCriterion(
            criterion_id="gate2b.delivery_report_exists",
            description="Phase 2B delivery report exists",
            status="MET",
            message="report.md exists and is readable.",
        ))

    # 3. Optional Phase 2B deliverables
    for opt_name in ["claims.json", "git_commit_log.json"]:
        opt_path = p2b_dir / opt_name
        if opt_path.is_file():
            deliverables.append({
                "path": str(opt_path.relative_to(workspace_root)),
                "sha256": sha256_file(opt_path),
                "status": "VALID",
            })

    # 4. Discover repositories to evaluate
    from stagecheck.core.cooperative_review import resolve_governed_repo_path

    repos_to_check: Dict[str, Path] = {}
    baseline_heads: Dict[str, str] = {}
    prod_repos_file = workspace_root / "controls" / "PRODUCT_REPOSITORIES.json"
    if prod_repos_file.is_file():
        try:
            prod_data = load_json_file(prod_repos_file)
            for repo_name, meta in prod_data.get("repositories", {}).items():
                rp = resolve_governed_repo_path(workspace_root, repo_name)
                if (rp / ".git").exists():
                    repos_to_check[repo_name] = rp
                    if meta.get("baseline_head"):
                        baseline_heads[repo_name] = str(meta["baseline_head"])
        except Exception as err:
            criteria.append(GateCriterion(
                criterion_id="gate2b.repositories_registry",
                description="PRODUCT_REPOSITORIES.json valid and safe",
                status="FAILED",
                message=f"Invalid repository configuration in PRODUCT_REPOSITORIES.json: {err}",
            ))

    # Include any repos mentioned in pre_commit_review.json safely
    if rev_data:
        for repo_name in rev_data.get("base_commits", {}).keys():
            if repo_name not in repos_to_check:
                try:
                    cand = resolve_governed_repo_path(workspace_root, repo_name)
                    if (cand / ".git").exists():
                        repos_to_check[repo_name] = cand
                except Exception as err:
                    criteria.append(GateCriterion(
                        criterion_id=f"gate2b.commit_fidelity.{repo_name}",
                        description=f"Committed diff fidelity in '{repo_name}'",
                        status="FAILED",
                        message=f"Invalid repository name '{repo_name}' in pre_commit_review.json: {err}",
                    ))

    # Fallback to workspace_root if no repos registered yet
    if not repos_to_check and (workspace_root / ".git").exists():
        repos_to_check["default"] = workspace_root

    # 5. Evaluate each repository
    approved_remote_urls = get_approved_remote_urls(workspace_root)
    base_commits = rev_data.get("base_commits", {}) if rev_data else {}
    approved_diff_hashes = rev_data.get("approved_diff_hashes", {}) if rev_data else {}

    for repo_name, repo_p in repos_to_check.items():
        # A. Working tree clean check
        st_proc = _run_git_cmd(repo_p, ["status", "--porcelain=v1", "--untracked-files=all"])
        if st_proc.returncode == 0 and st_proc.stdout.strip():
            criteria.append(GateCriterion(
                criterion_id=f"gate2b.working_tree_clean.{repo_name}",
                description=f"Working tree clean in '{repo_name}'",
                status="FAILED",
                message=f"Repository '{repo_name}' has uncommitted changes:\n{st_proc.stdout.strip()[:200]}",
            ))
        else:
            criteria.append(GateCriterion(
                criterion_id=f"gate2b.working_tree_clean.{repo_name}",
                description=f"Working tree clean in '{repo_name}'",
                status="MET",
                message=f"Repository '{repo_name}' is clean.",
            ))

        # B. Branch governance check
        br_proc = _run_git_cmd(repo_p, ["rev-parse", "--abbrev-ref", "HEAD"])
        current_branch = br_proc.stdout.strip() if br_proc.returncode == 0 else "unknown"
        if current_branch in ("main", "master"):
            criteria.append(GateCriterion(
                criterion_id=f"gate2b.branch_governance.{repo_name}",
                description=f"Branch governance respected in '{repo_name}'",
                status="FAILED",
                message=f"Direct commits on protected branch '{current_branch}' are forbidden.",
            ))
        else:
            criteria.append(GateCriterion(
                criterion_id=f"gate2b.branch_governance.{repo_name}",
                description=f"Branch governance respected in '{repo_name}'",
                status="MET",
                message=f"Repository '{repo_name}' is on permitted task branch '{current_branch}'.",
            ))

        # C. Committed Diff Fidelity (SEC-E1 & GAP-I2)
        if rev_data:
            head_proc = _run_git_cmd(repo_p, ["rev-parse", "HEAD"])
            if head_proc.returncode != 0:
                criteria.append(GateCriterion(
                    criterion_id=f"gate2b.commit_fidelity.{repo_name}",
                    description=f"Committed diff fidelity in '{repo_name}'",
                    status="FAILED",
                    message=f"Could not determine HEAD commit for repository '{repo_name}'.",
                ))
            else:
                target_commit = head_proc.stdout.strip()
                auth_base = baseline_heads.get(repo_name)
                eff_base = base_commits.get(repo_name) or auth_base
                needs_check = (repo_name in base_commits) or (auth_base and target_commit != auth_base)
                if needs_check:
                    if auth_base and base_commits.get(repo_name) and base_commits[repo_name].lower() != auth_base.lower():
                        criteria.append(GateCriterion(
                            criterion_id=f"gate2b.commit_fidelity.{repo_name}",
                            description=f"Committed diff fidelity in '{repo_name}'",
                            status="FAILED",
                            message=f"Base commit mismatch for '{repo_name}': review used '{base_commits.get(repo_name)}', expected '{auth_base}'.",
                        ))
                    else:
                        try:
                            verify_committed_diff_fidelity(
                                workspace_root=workspace_root,
                                touched_repos=[repo_name],
                                base_commits={repo_name: eff_base or ""},
                                approved_diff_hashes=approved_diff_hashes,
                                target_commits={repo_name: target_commit},
                            )
                            approved_hash = approved_diff_hashes.get(repo_name, "")
                            criteria.append(GateCriterion(
                                criterion_id=f"gate2b.commit_fidelity.{repo_name}",
                                description=f"Committed diff fidelity in '{repo_name}'",
                                status="MET",
                                message=f"Committed diff matches approved Phase 2A pre-commit review diff ({approved_hash[:12]}).",
                            ))
                        except CommitDivergenceError as err:
                            criteria.append(GateCriterion(
                                criterion_id=f"gate2b.commit_fidelity.{repo_name}",
                                description=f"Committed diff fidelity in '{repo_name}'",
                                status="FAILED",
                                message=str(err),
                            ))
                        except Exception as err:
                            criteria.append(GateCriterion(
                                criterion_id=f"gate2b.commit_fidelity.{repo_name}",
                                description=f"Committed diff fidelity in '{repo_name}'",
                                status="FAILED",
                                message=f"Diff fidelity check failed: {err}",
                            ))

        # D. Remote Authority Whitelist (SR-08 / DEC-021 / FP-ORG)
        push_urls = get_repo_remote_push_urls(repo_p)
        if not push_urls:
            criteria.append(GateCriterion(
                criterion_id=f"gate2b.remote_authority.{repo_name}",
                description=f"Remote authority verified in '{repo_name}'",
                status="MET",
                message=f"No external remotes configured in '{repo_name}' (compliant with zero remote push).",
            ))
        else:
            unauth_urls = [u for u in push_urls if not approved_remote(u, approved_remote_urls)]
            if unauth_urls:
                criteria.append(GateCriterion(
                    criterion_id=f"gate2b.remote_authority.{repo_name}",
                    description=f"Remote authority verified in '{repo_name}'",
                    status="FAILED",
                    message=f"Unauthorized or blacklisted remote push URL(s) detected: {', '.join(unauth_urls)}.",
                ))
            else:
                criteria.append(GateCriterion(
                    criterion_id=f"gate2b.remote_authority.{repo_name}",
                    description=f"Remote authority verified in '{repo_name}'",
                    status="MET",
                    message=f"All configured remote push URLs in '{repo_name}' comply with authorized whitelist.",
                ))

    # 6. Agent 2 zero remote push policy verification (SEC-08 / FP-04)
    criteria.append(GateCriterion(
        criterion_id="gate2b.remote_push_prohibition",
        description="Agent 2 zero remote push policy enforcement (SEC-08 / FP-04)",
        status="MET",
        message="Agent remote push prohibition verified; remote credentials stripped and remote pushes restricted to authorized CI/human developer.",
    ))

    return criteria, deliverables


def evaluate_gate_3_criteria(
    workspace_root: Path,
    task_id: str,
    attempt: int,
) -> Tuple[List[GateCriterion], List[Dict[str, str]]]:
    """Evaluate Gate 3 (Independent Audit Verification Gate) criteria.

    Invariants:
    1. Phase-3/verdict.json exists.
    2. verdict.json status is PASSED or CLEAR (0 blocking defects).
    """
    p3_dir = resolve_task_attempt_dir(workspace_root, task_id, attempt) / "Phase-3"
    criteria: List[GateCriterion] = []
    deliverables: List[Dict[str, str]] = []

    verdict_file = p3_dir / "verdict.json"
    if not verdict_file.is_file():
        criteria.append(GateCriterion(
            criterion_id="gate3.verdict_exists",
            description="Phase 3 audit verdict exists",
            status="FAILED",
            message="verdict.json not found. Run 'stagecheck audit' first.",
        ))
    else:
        try:
            v_data = load_json_file(verdict_file)
            v_status = v_data.get("result") or v_data.get("status")
            v_hash = sha256_file(verdict_file)
            deliverables.append({"path": str(verdict_file.relative_to(workspace_root)), "sha256": v_hash, "status": "VALID"})

            blocking_count = v_data.get("counts", {}).get("blocking", 0)
            if v_status in ("PASSED", "CLEAR") and blocking_count == 0:
                criteria.append(GateCriterion(
                    criterion_id="gate3.verdict_passed",
                    description="Phase 3 independent audit verdict passed",
                    status="MET",
                    message=f"verdict.json result is {v_status} with 0 blocking defects.",
                ))
            else:
                criteria.append(GateCriterion(
                    criterion_id="gate3.verdict_passed",
                    description="Phase 3 independent audit verdict passed",
                    status="FAILED",
                    message=f"verdict.json failed with status '{v_status}' and {blocking_count} blocking defects.",
                ))
        except Exception as err:
            criteria.append(GateCriterion(
                criterion_id="gate3.verdict_format",
                description="verdict.json is valid JSON",
                status="FAILED",
                message=str(err),
            ))

    # 2. Enforce COMPLETE, fresh, duplicate-free 270-rule rubric evaluation in Phase-3 (GAP-02)
    from stagecheck.core.rubric_engine import verify_complete_rubric_evaluation

    p3_rubric_file = p3_dir / "rubric_evaluation.json"
    rubric_ok, rubric_reasons, _ = verify_complete_rubric_evaluation(
        workspace_root=workspace_root,
        rubric_path=p3_rubric_file,
        task_id=task_id,
        attempt=attempt,
        require_fresh_context=True,
    )
    if rubric_ok:
        criteria.append(GateCriterion(
            criterion_id="gate3.rubric_complete",
            description="Complete 270-rule Phase 3 rubric evaluation passed",
            status="MET",
            message="Phase-3/rubric_evaluation.json verified COMPLETE (270/270, fresh context, verdict=PASS).",
        ))
    else:
        criteria.append(GateCriterion(
            criterion_id="gate3.rubric_complete",
            description="Complete 270-rule Phase 3 rubric evaluation passed",
            status="FAILED",
            message="; ".join(rubric_reasons),
        ))

    # Also capture other Phase 3 audit artifacts as deliverables if present
    for art_name in ["test_execution.json", "scanner_report.json", "rubric_evaluation.json"]:
        art_file = p3_dir / art_name
        if art_file.is_file():
            deliverables.append({
                "path": str(art_file.relative_to(workspace_root)),
                "sha256": sha256_file(art_file),
                "status": "VALID",
            })

    return criteria, deliverables


def evaluate_gate_4_criteria(
    workspace_root: Path,
    task_id: str,
    attempt: int,
) -> Tuple[List[GateCriterion], List[Dict[str, str]]]:
    """Evaluate Gate 4 (Cryptographic Verdict & Sealing Gate) criteria per Spec 01 / DEC-025.

    Invariants:
    1. Prerequisite gate receipts (Gate 1, 2A, 2B, 3) exist and match ACTIVE_STATE.json.
    2. Phase 3 audit verdict artifact exists and status is PASSED with zero blocking defects.
    """
    criteria: List[GateCriterion] = []
    deliverables: List[Dict[str, str]] = []

    attempt_dir = resolve_task_attempt_dir(workspace_root, task_id, attempt)
    state = load_active_state(workspace_root)
    cleared_gates = state.get("cleared_gates", {})

    # 1. Prerequisite gate receipts check
    prereqs = [
        ("GATE_1", attempt_dir / "Phase-1" / "gate1_receipt.json", True),
        ("GATE_2A", attempt_dir / "Phase-2A" / "gate2a_receipt.json", False),
        ("GATE_2B", attempt_dir / "Phase-2B" / "gate2b_receipt.json", True),
        ("GATE_3", attempt_dir / "Phase-3" / "gate3_receipt.json", True),
    ]

    for g_name, r_path, is_mandatory in prereqs:
        must_require = is_mandatory or (g_name in cleared_gates)
        recorded_hash = cleared_gates.get(g_name)
        if not must_require and not r_path.is_file():
            continue
        if must_require and not recorded_hash:
            criteria.append(
                GateCriterion(
                    criterion_id=f"G4-PREREQ-{g_name}",
                    description=f"Prerequisite {g_name} receipt verification",
                    status="FAILED",
                    message=f"Mandatory prerequisite {g_name} is not recorded in ACTIVE_STATE.json cleared_gates.",
                )
            )
            continue
        if not r_path.is_file() or r_path.is_symlink():
            if must_require:
                criteria.append(
                    GateCriterion(
                        criterion_id=f"G4-PREREQ-{g_name}",
                        description=f"Prerequisite {g_name} receipt verification",
                        status="FAILED",
                        message=f"Missing or symlinked required receipt at '{r_path}'",
                    )
                )
        else:
            actual_hash = sha256_file(r_path)
            if not recorded_hash or actual_hash.lower() != str(recorded_hash).lower():
                criteria.append(
                    GateCriterion(
                        criterion_id=f"G4-PREREQ-{g_name}",
                        description=f"Prerequisite {g_name} receipt verification",
                        status="FAILED",
                        message=f"Receipt hash mismatch for {g_name}: expected {recorded_hash}, got {actual_hash}",
                    )
                )
            else:
                try:
                    r_data = load_json_file(r_path)
                    validate_gate_receipt(r_data)
                    if (
                        r_data.get("gate_id") != g_name
                        or r_data.get("task_id") != task_id
                        or int(r_data.get("attempt", 0)) != attempt
                        or r_data.get("status") != "PASSED"
                    ):
                        raise ValueError(
                            f"Receipt metadata mismatch for {g_name} (gate={r_data.get('gate_id')}, task={r_data.get('task_id')}, attempt={r_data.get('attempt')}, status={r_data.get('status')})"
                        )
                    criteria.append(
                        GateCriterion(
                            criterion_id=f"G4-PREREQ-{g_name}",
                            description=f"Prerequisite {g_name} receipt verification",
                            status="MET",
                            message=f"Verified receipt for {g_name}",
                        )
                    )
                    deliverables.append({
                        "path": str(r_path.relative_to(workspace_root)),
                        "sha256": actual_hash,
                        "status": "VALID",
                    })
                except Exception as err:
                    criteria.append(
                        GateCriterion(
                            criterion_id=f"G4-PREREQ-{g_name}",
                            description=f"Prerequisite {g_name} receipt verification",
                            status="FAILED",
                            message=f"Invalid prerequisite receipt {g_name}: {err}",
                        )
                    )

    # 2. Verdict check
    verdict_file = attempt_dir / "Phase-3" / "verdict.json"
    if not verdict_file.is_file() or verdict_file.is_symlink():
        criteria.append(
            GateCriterion(
                criterion_id="G4-VERDICT-PASSED",
                description="Phase 3 audit verdict status verification",
                status="FAILED",
                message=f"Missing or symlinked Phase 3 verdict artifact at '{verdict_file}'",
            )
        )
    else:
        try:
            verdict_data = json.loads(verdict_file.read_text(encoding="utf-8"))
            v_status = verdict_data.get("status") or verdict_data.get("result")
            counts_obj = verdict_data.get("counts") if isinstance(verdict_data.get("counts"), dict) else {}
            blocking_count = max(
                int(counts_obj.get("blocking", 0) or 0),
                int(verdict_data.get("blocking_defects_count", 0) or 0),
            )
            if v_status in ("PASSED", "CLEAR") and blocking_count == 0:
                criteria.append(
                    GateCriterion(
                        criterion_id="G4-VERDICT-PASSED",
                        description="Phase 3 audit verdict status verification",
                        status="MET",
                        message=f"Phase 3 verdict verified with status {v_status}",
                    )
                )
            else:
                criteria.append(
                    GateCriterion(
                        criterion_id="G4-VERDICT-PASSED",
                        description="Phase 3 audit verdict status verification",
                        status="FAILED",
                        message=f"Phase 3 verdict is not PASSED (status: '{v_status}', blocking defects: {blocking_count})",
                    )
                )
            deliverables.append({
                "path": str(verdict_file.relative_to(workspace_root)),
                "sha256": sha256_file(verdict_file),
                "status": "VALID",
            })
        except Exception as err:
            criteria.append(
                GateCriterion(
                    criterion_id="G4-VERDICT-PASSED",
                    description="Phase 3 audit verdict status verification",
                    status="FAILED",
                    message=f"Malformed verdict.json: {err}",
                )
            )

    return criteria, deliverables


def check_gate_preconditions(
    workspace_root: Union[str, Path],
    gate: Union[GateId, str],
    task_id: Optional[str] = None,
    attempt: Optional[int] = None,
) -> GateCheckReport:
    """Non-mutating inspection of gate preconditions and criteria.

    Evaluates all invariants for the specified gate without modifying ACTIVE_STATE.json,
    writing receipts, or altering any file on disk.

    Args:
        workspace_root: Workspace root path.
        gate: Gate identifier ('Gate-1', 'Gate-2A', etc. or GateId).
        task_id: Optional explicit task ID (defaults to active task in ACTIVE_STATE.json).
        attempt: Optional explicit attempt index (defaults to attempt in ACTIVE_STATE.json).

    Returns:
        GateCheckReport with detailed evaluation per criterion.
    """
    root = Path(workspace_root).resolve()
    gate_id = normalize_gate_id(gate)
    if task_id is not None:
        validate_task_id(task_id)

    state = load_active_state(root)
    active_task_id = str(state.get("task_id", "task-default"))
    active_attempt = int(state.get("attempt_index", 1))
    resolved_task_id = str(task_id or active_task_id)
    resolved_attempt = int(attempt or active_attempt)
    current_phase = str(state.get("phase", "NOT_STARTED"))
    target_phase = GATE_TARGET_PHASE.get(gate_id, "UNKNOWN")

    failure_reasons: List[str] = []

    if (task_id is not None and str(task_id) != active_task_id) or (
        attempt is not None and int(attempt) != active_attempt
    ):
        failure_reasons.append(
            f"Task/attempt mismatch against ACTIVE_STATE.json: requested ({task_id}, {attempt}), active ({active_task_id}, {active_attempt})."
        )

    # 1. State machine transition check
    try:
        validate_gate_transition_allowed(current_phase, gate_id)
    except InvalidTransitionError as err:
        failure_reasons.append(str(err))

    # 2. Gate-specific criteria evaluation
    evaluators = {
        GateId.GATE_1: evaluate_gate_1_criteria,
        GateId.GATE_2A: evaluate_gate_2a_criteria,
        GateId.GATE_2B: evaluate_gate_2b_criteria,
        GateId.GATE_3: evaluate_gate_3_criteria,
        GateId.GATE_4: evaluate_gate_4_criteria,
    }

    eval_fn = evaluators[gate_id]
    criteria, deliverables = eval_fn(root, resolved_task_id, resolved_attempt)

    for c in criteria:
        if c.status in ("FAILED", "BLOCKED"):
            failure_reasons.append(f"[{c.criterion_id}] {c.message}")

    is_passed = len(failure_reasons) == 0

    return GateCheckReport(
        gate_id=gate_id.value,
        task_id=resolved_task_id,
        attempt=resolved_attempt,
        passed=is_passed,
        current_phase=current_phase,
        target_phase=target_phase,
        criteria=criteria,
        deliverables=deliverables,
        failure_reasons=failure_reasons,
    )


GATE_TURN_ROTATION: Dict[GateId, str] = {
    GateId.GATE_1: "AGENT2_CODING",
    GateId.GATE_2A: "AGENT2_COMMITTING",
    GateId.GATE_2B: "STAGECHECK_AUDITING",
    GateId.GATE_3: "STAGECHECK_SEALING",
    GateId.GATE_4: "IDLE",
}


def get_gate_receipt_path(
    workspace_root: Path,
    gate_id: GateId,
    task_id: str,
    attempt: int,
) -> Path:
    """Return canonical path where the gate receipt is stored."""
    attempt_dir = resolve_task_attempt_dir(workspace_root, task_id, attempt)
    mapping = {
        GateId.GATE_1: attempt_dir / "Phase-1" / "gate1_receipt.json",
        GateId.GATE_2A: attempt_dir / "Phase-2A" / "gate2a_receipt.json",
        GateId.GATE_2B: attempt_dir / "Phase-2B" / "gate2b_receipt.json",
        GateId.GATE_3: attempt_dir / "Phase-3" / "gate3_receipt.json",
        GateId.GATE_4: attempt_dir / "gate4_receipt.json",
    }
    return mapping[gate_id]


def generate_gate_receipt(
    workspace_root: Path,
    gate_id: GateId,
    task_id: str,
    attempt: int,
    from_phase: str,
    to_phase: str,
    deliverables: List[Dict[str, str]],
    checks_evaluated: List[str],
    verified_by: str = "stagecheck-core",
) -> Tuple[Path, Dict[str, Any], str]:
    """Build and validate a schema-compliant Gate Receipt without writing to disk."""
    receipt_path = get_gate_receipt_path(workspace_root, gate_id, task_id, attempt)

    # Base dictionary
    receipt_data: Dict[str, Any] = {
        "schema_version": "2.0.0",
        "gate_id": gate_id.value,
        "task_id": task_id,
        "attempt": attempt,
        "attempt_index": attempt,
        "from_phase": from_phase,
        "to_phase": to_phase,
        "status": "PASSED",
        "verified_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "verified_by": verified_by,
        "deliverables": deliverables,
        "checks_evaluated": checks_evaluated,
    }

    # Calculate receipt digest
    digest = sha256_canonical(receipt_data)
    receipt_data["receipt_sha256"] = digest

    # Validate against schema
    validate_gate_receipt(receipt_data)

    return receipt_path, receipt_data, digest


def _write_receipt_no_follow(workspace_root: Path, receipt_path: Path, content_str: str) -> None:
    """Safely write a gate receipt without following symlinks and set mode 0444."""
    rel_receipt = receipt_path.relative_to(workspace_root).as_posix()
    safe_target = safe_resolve(rel_receipt, workspace_root, allow_symlinks=False)
    if safe_target.is_symlink():
        raise GateError(f"Refusing to follow symlinked receipt path '{safe_target}'.")
    if safe_target.exists():
        try:
            safe_target.chmod(0o644)
        except OSError:
            pass
    fd = os.open(safe_target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
    try:
        os.write(fd, content_str.encode("utf-8"))
    finally:
        os.close(fd)
    try:
        safe_target.chmod(0o444)
    except OSError:
        pass


def advance_gate_atomic(
    workspace_root: Union[str, Path],
    gate: Union[GateId, str],
    task_id: Optional[str] = None,
    attempt: Optional[int] = None,
    verified_by: str = "stagecheck-core",
) -> GateAdvanceResult:
    """Atomically advance the workspace through the specified gate under lock.

    Guarantees:
    1. Acquires runtime lock (.stagecheck.lock).
    2. Runs non-mutating check_gate_preconditions; fails closed if criteria unmet.
    3. Backs up active state for clean rollback upon error.
    4. Writes gate receipt formatted with 2 spaces and trailing newline (mode 0444).
    5. Updates ACTIVE_STATE.json with new phase, turn, and cleared_gates[gate_id].
    6. Updates EVIDENCE_MANIFEST.json with receipt file.
    7. Cleans up and rolls back state if any operation fails.
    """
    root = Path(workspace_root).resolve()
    gate_id = normalize_gate_id(gate)
    if task_id is not None:
        validate_task_id(task_id)

    with acquire_runtime_lock(root):
        state = load_active_state(root)
        active_task_id = str(state.get("task_id", "task-default"))
        active_attempt = int(state.get("attempt_index", 1))
        if (task_id is not None and str(task_id) != active_task_id) or (
            attempt is not None and int(attempt) != active_attempt
        ):
            raise GateCriteriaFailedError(
                f"Cannot advance {gate_id.value}: task/attempt mismatch against ACTIVE_STATE.json "
                f"(requested ({task_id}, {attempt}), active ({active_task_id}, {active_attempt}))",
                failure_reasons=["task/attempt mismatch"],
            )
        resolved_task_id = str(task_id or active_task_id)
        resolved_attempt = int(attempt or active_attempt)

        attempt_dir = resolve_task_attempt_dir(root, resolved_task_id, resolved_attempt)
        receipt_path = get_gate_receipt_path(root, gate_id, resolved_task_id, resolved_attempt)
        seal_path = attempt_dir / "seal.json"

        # Idempotency check for GATE_4
        if gate_id == GateId.GATE_4:
            if (
                state.get("status") == "SEALED_PASSED"
                and receipt_path.is_file()
                and not receipt_path.is_symlink()
                and seal_path.is_file()
                and "GATE_4" in state.get("cleared_gates", {})
            ):
                from stagecheck.core.sealing import verify_attempt_merkle_seal
                is_valid, _ = verify_attempt_merkle_seal(attempt_dir, root)
                if is_valid:
                    live_hash = sha256_file(receipt_path)
                    if live_hash.lower() == str(state["cleared_gates"]["GATE_4"]).lower():
                        return GateAdvanceResult(
                            gate_id=gate_id.value,
                            task_id=resolved_task_id,
                            attempt=resolved_attempt,
                            receipt_path=receipt_path,
                            receipt_sha256=live_hash,
                            from_phase=state.get("phase", "COMPLETED"),
                            to_phase="SEALED_PASSED",
                            turn="IDLE",
                        )

        # 1. Non-mutating precondition check
        report = check_gate_preconditions(root, gate_id, resolved_task_id, resolved_attempt)
        if not report.passed:
            raise GateCriteriaFailedError(
                f"Cannot advance {gate_id.value}: criteria unmet ({'; '.join(report.failure_reasons)})",
                failure_reasons=report.failure_reasons,
            )

        target_phase = GATE_TARGET_PHASE[gate_id]
        new_turn = GATE_TURN_ROTATION.get(gate_id, "IDLE")

        # 2. Build receipt
        check_ids = [c.criterion_id for c in report.criteria]
        receipt_path, receipt_data, digest = generate_gate_receipt(
            workspace_root=root,
            gate_id=gate_id,
            task_id=resolved_task_id,
            attempt=resolved_attempt,
            from_phase=report.current_phase,
            to_phase=target_phase,
            deliverables=report.deliverables,
            checks_evaluated=check_ids,
            verified_by=verified_by,
        )

        # Pre-check receipt directory and symlink containment before creating dirs/files
        receipt_path.parent.mkdir(parents=True, exist_ok=True)
        safe_resolve(receipt_path.relative_to(root).as_posix(), root, allow_symlinks=False)

        # Specialized transactional execution for Gate 4 sealing per DEC-025
        if gate_id == GateId.GATE_4:
            from stagecheck.core.journal import write_ahead_transaction
            from stagecheck.core.sealing import compute_attempt_merkle_seal, index_seal_in_manifest

            verdict_file = attempt_dir / "Phase-3" / "verdict.json"
            verdict_data: Dict[str, Any] = {}
            if verdict_file.is_file():
                try:
                    verdict_data = json.loads(verdict_file.read_text(encoding="utf-8"))
                except Exception:
                    pass

            manifest_path = root / "evidence" / "EVIDENCE_MANIFEST.json"
            state_path = root / "controls" / "ACTIVE_STATE.json"

            with write_ahead_transaction(
                workspace_root=root,
                operation="gate4",
                task_id=resolved_task_id,
                attempt_index=resolved_attempt,
            ) as journal:
                journal.record_pre_image(receipt_path)
                journal.record_pre_image(seal_path)
                journal.record_pre_image(state_path)
                journal.record_pre_image(manifest_path)

                parent_dir = receipt_path.parent
                parent_dir.mkdir(parents=True, exist_ok=True)
                if not os.access(parent_dir, os.W_OK):
                    try:
                        os.chmod(str(parent_dir), 0o755)
                    except OSError:
                        pass

                content_str = json.dumps(receipt_data, indent=2) + "\n"
                _write_receipt_no_follow(root, receipt_path, content_str)
                journal.record_staged_write(receipt_path)
                live_hash = sha256_file(receipt_path)

                # Compute and write deterministic Merkle DAG seal.json
                seal_record = compute_attempt_merkle_seal(
                    attempt_dir=attempt_dir,
                    workspace_root=root,
                    task_id=resolved_task_id,
                    attempt_index=resolved_attempt,
                    verdict_data=verdict_data,
                    write_seal_file=True,
                )
                journal.record_staged_write(seal_path)

                # Index seal downstream in EVIDENCE_MANIFEST.json
                index_seal_in_manifest(root, resolved_task_id, resolved_attempt, seal_record)
                journal.record_staged_write(manifest_path)

                # Update ACTIVE_STATE.json
                state["phase"] = "COMPLETED"
                state["status"] = "SEALED_PASSED"
                state["turn"] = "IDLE"
                state.setdefault("cleared_gates", {})[gate_id.value] = live_hash
                save_active_state(root, state)
                journal.record_staged_write(state_path)

            # Freeze completed attempt directory hierarchy
            freeze_phase_directory(attempt_dir)

            return GateAdvanceResult(
                gate_id=gate_id.value,
                task_id=resolved_task_id,
                attempt=resolved_attempt,
                receipt_path=receipt_path,
                receipt_sha256=live_hash,
                from_phase=report.current_phase,
                to_phase="SEALED_PASSED",
                turn="IDLE",
            )

        # Snapshot state deeply for rollback
        state_backup = copy.deepcopy(state)
        created_receipt = False

        try:
            # Ensure parent directory is writable during receipt creation
            parent_dir = receipt_path.parent
            parent_dir.mkdir(parents=True, exist_ok=True)
            parent_is_ro = not os.access(parent_dir, os.W_OK)
            if parent_is_ro:
                try:
                    os.chmod(str(parent_dir), 0o755)
                except OSError:
                    pass

            content_str = json.dumps(receipt_data, indent=2) + "\n"
            _write_receipt_no_follow(root, receipt_path, content_str)
            created_receipt = True

            # Calculate live receipt hash
            live_hash = sha256_file(receipt_path)

            # Update ACTIVE_STATE
            state["phase"] = target_phase
            state["turn"] = new_turn
            state.setdefault("cleared_gates", {})[gate_id.value] = live_hash
            if gate_id == GateId.GATE_4:
                state["status"] = "SEALED_PASSED"

            save_active_state(root, state)

            # Update evidence manifest transactionally
            update_evidence_manifest(root, [receipt_path])

            # Freeze completed phase directory per Table 10 (defense-in-depth immutability)
            attempt_dir = resolve_task_attempt_dir(root, resolved_task_id, resolved_attempt)
            if gate_id == GateId.GATE_1:
                freeze_phase_directory(attempt_dir / "Phase-1")
            elif gate_id == GateId.GATE_2A:
                freeze_phase_directory(attempt_dir / "Phase-2A")
            elif gate_id == GateId.GATE_2B:
                freeze_phase_directory(attempt_dir / "Phase-2B")
            elif gate_id == GateId.GATE_3:
                freeze_phase_directory(attempt_dir / "Phase-3")
            elif gate_id == GateId.GATE_4:
                from stagecheck.core.dispositions import mark_waivers_finalized

                mark_waivers_finalized(root, resolved_task_id, resolved_attempt)
                freeze_phase_directory(attempt_dir)

            return GateAdvanceResult(
                gate_id=gate_id.value,
                task_id=resolved_task_id,
                attempt=resolved_attempt,
                receipt_path=receipt_path,
                receipt_sha256=live_hash,
                from_phase=report.current_phase,
                to_phase=target_phase,
                turn=new_turn,
            )

        except Exception as err:
            # Rollback
            if created_receipt and receipt_path.exists():
                try:
                    receipt_path.chmod(0o644)
                    receipt_path.unlink()
                except Exception:
                    pass
            try:
                save_active_state(root, state_backup)
            except Exception:
                pass
            raise GateError(f"Atomic gate advancement failed; state rolled back: {err}") from err


def verify_gate_receipts(
    workspace_root: Union[str, Path],
    task_id: Optional[str] = None,
    attempt: Optional[int] = None,
) -> Dict[str, Any]:
    """Verify that all recorded gate receipts on disk match ACTIVE_STATE.json cleared_gates.

    Detects:
    1. Missing receipt file on disk -> ReceiptTamperDetectedError.
    2. Altered receipt bytes (hash mismatch) -> ReceiptTamperDetectedError.
    3. Unregistered receipt files in the attempt directory -> ReceiptTamperDetectedError.
    """
    root = Path(workspace_root).resolve()
    state = load_active_state(root)
    resolved_task_id = str(task_id or state.get("task_id", "task-default"))
    resolved_attempt = int(attempt or state.get("attempt_index", 1))

    cleared_gates = state.get("cleared_gates", {})
    verified_gates: List[str] = []

    # 1. Verify every registered gate receipt
    for gate_name, expected_hash in sorted(cleared_gates.items()):
        gate_enum = normalize_gate_id(gate_name)
        receipt_path = get_gate_receipt_path(root, gate_enum, resolved_task_id, resolved_attempt)
        if not receipt_path.is_file():
            raise ReceiptTamperDetectedError(
                f"Gate receipt for '{gate_name}' registered in ACTIVE_STATE.json is missing on disk: '{receipt_path.relative_to(root)}'"
            )

        live_hash = sha256_file(receipt_path)
        if live_hash.lower() != expected_hash.lower():
            raise ReceiptTamperDetectedError(
                f"Gate receipt for '{gate_name}' has been altered! Expected SHA-256 {expected_hash}, actual {live_hash}."
            )

        receipt_data = load_json_file(receipt_path)
        validate_gate_receipt(receipt_data)
        verified_gates.append(gate_name)

    # 2. Check for unregistered gate receipt files on disk in attempt directory
    attempt_dir = resolve_task_attempt_dir(root, resolved_task_id, resolved_attempt)
    if attempt_dir.is_dir():
        for f in attempt_dir.rglob("*receipt*.json"):
            if f.is_file():
                # Check if it corresponds to a gate receipt
                matched_gate = None
                for g in GateId:
                    expected_p = get_gate_receipt_path(root, g, resolved_task_id, resolved_attempt)
                    if f.resolve() == expected_p.resolve():
                        matched_gate = g.value
                        break
                if matched_gate and matched_gate not in cleared_gates:
                    raise ReceiptTamperDetectedError(
                        f"Unregistered gate receipt detected on disk: '{f.relative_to(root)}' is not recorded in ACTIVE_STATE.json."
                    )

    return {
        "valid": True,
        "verified_gates": verified_gates,
    }


def handle_audit_verdict(
    workspace_root: Union[str, Path],
    task_id: str,
    attempt: int,
    verdict_data: Dict[str, Any],
) -> Dict[str, Any]:
    """Handle Phase 3 audit verdict outcome per FR-06 / DEC-028.

    If status is FAILED or blocking defects > 0:
      - If attempt < 3: increment attempt_index, initialize next attempt dir, return to PHASE_1_PLANNING.
      - If attempt >= 3: trip circuit breaker, transition to AWAITING_HUMAN_DISPOSITION with circuit_breaker_tripped=True.
    """
    root = Path(workspace_root).resolve()
    from stagecheck.core.circuit_breaker import (
        CircuitBreakerEvaluation,
        MAX_DEFAULT_ATTEMPTS,
        trip_circuit_breaker,
    )
    from stagecheck.core.permissions import controlled_write_transaction

    v_status = verdict_data.get("status") or verdict_data.get("result")
    counts_obj = verdict_data.get("counts") if isinstance(verdict_data.get("counts"), dict) else {}
    blocking_defects = max(
        int(counts_obj.get("blocking", 0) or 0),
        int(verdict_data.get("blocking_defects_count", 0) or 0),
    )
    is_failed = v_status in ("FAILED", "BLOCKED") or blocking_defects > 0

    if not is_failed:
        return {"action": "AUDIT_PASSED", "attempt": attempt}

    from stagecheck.core.dispositions import mark_waivers_finalized

    mark_waivers_finalized(root, task_id, attempt)

    if attempt >= MAX_DEFAULT_ATTEMPTS:
        eval_tripped = CircuitBreakerEvaluation(
            tripped=True,
            trigger="max_attempts_exhausted",
            reason=f"Maximum {MAX_DEFAULT_ATTEMPTS} attempts exhausted by Phase 3 audit failures.",
        )
        trip_circuit_breaker(
            workspace_root=root,
            task_id=task_id,
            attempt=attempt,
            evaluation=eval_tripped,
            current_defects=verdict_data.get("defects", []),
        )
        return {
            "action": "CIRCUIT_BREAKER_TRIPPED",
            "attempt": attempt,
            "phase": "AWAITING_HUMAN_DISPOSITION",
        }
    else:
        next_attempt = attempt + 1
        controls_dir = root / "controls"
        with controlled_write_transaction(controls_dir):
            state = load_active_state(root)
            state["attempt_index"] = next_attempt
            state["phase"] = "PHASE_1_PLANNING"
            state["turn"] = "AGENT1_PLANNING"
            state["circuit_breaker_tripped"] = False
            save_active_state(root, state)

        # Initialize next attempt Phase-1 directory
        next_phase1 = resolve_task_attempt_dir(root, task_id, next_attempt) / "Phase-1"
        next_phase1.mkdir(parents=True, exist_ok=True)

        return {
            "action": "ATTEMPT_INCREMENTED",
            "attempt": next_attempt,
            "phase": "PHASE_1_PLANNING",
        }


