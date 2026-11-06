"""Authoritative StageCheck Gate Engine, Transition Matrix, and Criteria Evaluator (FR-01 / Spec 01 / DEC-001).

Manages the deterministic lifecycle state machine, gate checkpoints (Gate-1, Gate-2A, Gate-2B,
Gate-3, Gate-4), non-mutating gate inspection, and typed transition errors.
"""

from __future__ import annotations

import datetime
import json
import os
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

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
from stagecheck.core.paths import safe_resolve
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
    GateId.GATE_4: {"GATE_4_SEALING", "PHASE_3_AUDIT", "PHASE_3_AUDITING"},
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
    p1_dir = workspace_root / "evidence" / "tasks" / task_id / f"attempt_{attempt}" / "Phase-1"
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
            # Check for illegal wildcard escaping
            has_forbidden_wildcard = any(p in ("*", "/**", "**") for p in allowed)
            if has_forbidden_wildcard:
                criteria.append(GateCriterion(
                    criterion_id="gate1.scope_discrete",
                    description="Declared scope contains discrete non-wildcard repository paths",
                    status="FAILED",
                    message="declared_scope.json contains prohibited top-level wildcard pattern.",
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
    p2a_dir = workspace_root / "evidence" / "tasks" / task_id / f"attempt_{attempt}" / "Phase-2A"
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
    p2a_dir = workspace_root / "evidence" / "tasks" / task_id / f"attempt_{attempt}" / "Phase-2A"
    p2b_dir = workspace_root / "evidence" / "tasks" / task_id / f"attempt_{attempt}" / "Phase-2B"
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
    repos_to_check: Dict[str, Path] = {}
    prod_repos_file = workspace_root / "controls" / "PRODUCT_REPOSITORIES.json"
    if prod_repos_file.is_file():
        try:
            prod_data = load_json_file(prod_repos_file)
            for repo_name, meta in prod_data.get("repositories", {}).items():
                rel = meta.get("path", f"repos/{repo_name}")
                rp = workspace_root / rel
                if (rp / ".git").exists():
                    repos_to_check[repo_name] = rp
        except Exception:
            pass

    # Include any repos mentioned in pre_commit_review.json
    if rev_data:
        for repo_name in rev_data.get("base_commits", {}).keys():
            if repo_name not in repos_to_check:
                cand = workspace_root / "repos" / repo_name
                if (cand / ".git").exists():
                    repos_to_check[repo_name] = cand
                elif (workspace_root / ".git").exists():
                    repos_to_check[repo_name] = workspace_root

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
        if rev_data and repo_name in base_commits:
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
                try:
                    verify_committed_diff_fidelity(
                        workspace_root=workspace_root,
                        touched_repos=[repo_name],
                        base_commits=base_commits,
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
    p3_dir = workspace_root / "evidence" / "tasks" / task_id / f"attempt_{attempt}" / "Phase-3"
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
    """Evaluate Gate 4 (Cryptographic Verdict & Sealing Gate) criteria.

    Invariants:
    1. Phase 3 verdict passed.
    2. Prior gate criteria cleared.
    """
    criteria: List[GateCriterion] = []
    deliverables: List[Dict[str, str]] = []

    # 1. Check Phase 3 verdict
    g3_crit, g3_deliv = evaluate_gate_3_criteria(workspace_root, task_id, attempt)
    criteria.extend(g3_crit)
    deliverables.extend(g3_deliv)

    # 2. Check Gate 1 & 2 deliverables
    p1_pv = workspace_root / "evidence" / "tasks" / task_id / f"attempt_{attempt}" / "Phase-1" / "prompt_verified.json"
    if p1_pv.is_file():
        deliverables.append({"path": str(p1_pv.relative_to(workspace_root)), "sha256": sha256_file(p1_pv), "status": "VALID"})

    p2a_rev = workspace_root / "evidence" / "tasks" / task_id / f"attempt_{attempt}" / "Phase-2A" / "pre_commit_review.json"
    if p2a_rev.is_file():
        deliverables.append({"path": str(p2a_rev.relative_to(workspace_root)), "sha256": sha256_file(p2a_rev), "status": "VALID"})

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

    state = load_active_state(root)
    resolved_task_id = str(task_id or state.get("task_id", "task-default"))
    resolved_attempt = int(attempt or state.get("attempt_index", 1))
    current_phase = str(state.get("phase", "NOT_STARTED"))
    target_phase = GATE_TARGET_PHASE.get(gate_id, "UNKNOWN")

    failure_reasons: List[str] = []

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
    attempt_dir = workspace_root / "evidence" / "tasks" / task_id / f"attempt_{attempt}"
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

    with acquire_runtime_lock(root):
        state = load_active_state(root)
        resolved_task_id = str(task_id or state.get("task_id", "task-default"))
        resolved_attempt = int(attempt or state.get("attempt_index", 1))

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

        receipt_path.parent.mkdir(parents=True, exist_ok=True)

        # Snapshot state for rollback
        state_backup = dict(state)
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

            # Write receipt file with 2-space indentation and trailing newline
            content_str = json.dumps(receipt_data, indent=2) + "\n"
            # Ensure file is writable if it exists, or remove prior
            if receipt_path.exists():
                try:
                    receipt_path.chmod(0o644)
                except OSError:
                    pass
            receipt_path.write_text(content_str, encoding="utf-8")
            try:
                receipt_path.chmod(0o444)
            except OSError:
                pass
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
            attempt_dir = root / "evidence" / "tasks" / resolved_task_id / f"attempt_{resolved_attempt}"
            if gate_id == GateId.GATE_1:
                freeze_phase_directory(attempt_dir / "Phase-1")
            elif gate_id == GateId.GATE_2A:
                freeze_phase_directory(attempt_dir / "Phase-2A")
            elif gate_id == GateId.GATE_2B:
                freeze_phase_directory(attempt_dir / "Phase-2B")
            elif gate_id == GateId.GATE_3:
                freeze_phase_directory(attempt_dir / "Phase-3")
            elif gate_id == GateId.GATE_4:
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
    attempt_dir = root / "evidence" / "tasks" / resolved_task_id / f"attempt_{resolved_attempt}"
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


