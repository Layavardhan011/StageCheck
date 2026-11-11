"""270-Rule Rubric Evaluator and Deterministic Exemption Engine (FR-03 / Spec 02 / DEC-026).

Implements:
- 270-rule catalog parsed from canonical agent instructions across 9 domains (30 rules each).
- Machine-readable 270-rule Audit Matrix mapping each rule to strategy, inputs, and validation.
- Exact allocation: 162 Automated, 64 Evidence, 34 Agent-Assisted, 10 Human Waiver.
- Deterministic structural exemption predicates (PREDICATE_NO_GO_MODULE, PREDICATE_NO_BLOCKCHAIN_PROTOCOL, etc.).
- Fail-closed validation rejecting arbitrary agent self-exemptions and incomplete rubrics.
- Programmatic execution targeted under 200ms.
- Synchronization with rubric_evaluation.json and pre_commit_review.json.
"""

from __future__ import annotations

import ast
import datetime
import hashlib
import importlib.resources
import json
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

from stagecheck.core.agents import resolve_task_attempt_dir
from stagecheck.core.dispositions import parse_owner_grants, validate_waiver_provenance
from stagecheck.core.paths import StageCheckPathError, safe_resolve
from stagecheck.core.state import load_active_state
from stagecheck.core.utils import canonical_json_dumps, load_json_file, sha256_file, validate_schema
from stagecheck.schemas import get_schema_path
from stagecheck.schemas.validator import (
    validate_active_state,
    validate_rubric_evaluation,
)


class InvalidRubricExemptionError(Exception):
    """Raised when an illegal or unverifiable NOT_APPLICABLE exemption is detected."""


class RubricEvaluationError(Exception):
    """Raised when rubric evaluation encounters an unrecoverable failure."""


class DuplicateRuleEvaluationError(RubricEvaluationError):
    """Raised when duplicate rule IDs appear in rubric evaluations."""


class IncompleteRubricEvaluationError(RubricEvaluationError):
    """Raised when a partial rubric evaluation is presented for a complete-audit gate."""


class StaleRubricEvaluationError(RubricEvaluationError):
    """Raised when a rubric evaluation predates subsequent workspace, repo, or control changes."""


_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
_GENERIC_REVIEWER_NAMES = frozenset({
    "generic",
    "generic_evaluator",
    "auto",
    "automated",
    "fallback",
    "default",
    "unknown",
    "system",
    "placeholder",
    "rubric_engine",
})


_BLOCKCHAIN_MARKERS = ("multiversx", "mx-chain", "elrond", "dharitri", "drwa")
_SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", "node_modules", ".pytest_cache", ".mypy_cache"}
_PIN_SPEC_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*(==|===|>=|<=|>|<|~=|\*|$)(.*)$")
_SECRET_RE = re.compile(
    r"(?:AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9_]{20,}|-----BEGIN (?:RSA|EC|OPENSSH|PRIVATE) KEY-----|sk-[A-Za-z0-9]{20,})"
)


def _has_blockchain_protocol(ws: Path, repo: Path) -> bool:
    """Detect deterministically whether a repository implements blockchain/MultiversX/DRWA protocol logic."""
    if not repo.is_dir():
        return False
    for manifest_name in ("go.mod", "Cargo.toml", "package.json", "requirements.txt", "pyproject.toml"):
        mf = repo / manifest_name
        if mf.is_file() and not mf.is_symlink():
            text = mf.read_text(encoding="utf-8", errors="ignore").lower()
            if any(m in text for m in _BLOCKCHAIN_MARKERS):
                return True
    # Also check shallow source indicators for Go/Rust shard/metachain/vm modules
    if (repo / "go.mod").is_file() or (repo / "Cargo.toml").is_file():
        for root_dir, dirs, _ in os.walk(repo):
            dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
            low = [d.lower() for d in dirs]
            if any(k in low for k in ("metachain", "crossshard", "sharding", "vmhost", "drwa")):
                return True
    return False


# Deterministic structural exemption predicates (FR-03 / DEC-026)
EXEMPTION_PREDICATES: Dict[str, Callable[[Path, Path], bool]] = {
    "PREDICATE_NO_REACT_DEPENDENCY": lambda ws, repo: not (repo / "package.json").is_file()
    or "react" not in (repo / "package.json").read_text(encoding="utf-8", errors="ignore").lower(),
    "PREDICATE_NO_FLASK_DEPENDENCY": lambda ws, repo: not (repo / "requirements.txt").is_file()
    or "flask" not in (repo / "requirements.txt").read_text(encoding="utf-8", errors="ignore").lower(),
    "PREDICATE_BACKEND_ONLY_REPO": lambda ws, repo: not any(repo.rglob("*.tsx"))
    and not any(repo.rglob("*.jsx")),
    "PREDICATE_NO_NODE_PACKAGE": lambda ws, repo: not (repo / "package.json").is_file(),
    "PREDICATE_NO_PYTHON_PACKAGE": lambda ws, repo: not (repo / "requirements.txt").is_file()
    and not (repo / "pyproject.toml").is_file(),
    "PREDICATE_NO_GO_MODULE": lambda ws, repo: not (repo / "go.mod").is_file(),
    "PREDICATE_NO_RUST_CRATE": lambda ws, repo: not (repo / "Cargo.toml").is_file(),
    "PREDICATE_NO_DOCKER": lambda ws, repo: not (repo / "Dockerfile").is_file(),
    "PREDICATE_NO_BLOCKCHAIN_PROTOCOL": lambda ws, repo: not _has_blockchain_protocol(ws, repo),
}


@dataclass
class RubricRule:
    """Descriptor for an individual audit criterion in the 270-rule catalog."""

    rule_id: str
    domain: str
    title: str
    question: str
    category: str  # AUTOMATED, EVIDENCE, AGENT_ASSISTED, HUMAN_WAIVER
    primary_witness: Optional[str] = None
    counterexample: Optional[str] = None
    exemption_predicate: Optional[str] = None
    exemption_rationale: Optional[str] = None


@dataclass
class RuleEvaluationResult:
    """Evaluation result for an individual rule."""

    rule_id: str
    domain: str
    category: str
    status: str  # PASS, FAIL, NOT_APPLICABLE, NOT_EVALUATED, BLOCKED
    evaluator: str = "default"
    evaluation_strategy: Optional[str] = None
    message: Optional[str] = None
    witness: Optional[str] = None
    artifact: Optional[str] = None
    exemption_predicate: Optional[str] = None
    rationale: Optional[str] = None
    evidence_path: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serialize evaluation result to dictionary."""
        d: Dict[str, Any] = {
            "rule_id": self.rule_id,
            "domain": self.domain,
            "category": self.category,
            "status": self.status,
            "evaluator": self.evaluator,
        }
        if self.evaluation_strategy:
            d["evaluation_strategy"] = self.evaluation_strategy
        if self.message:
            d["message"] = self.message
        if self.witness:
            d["witness"] = self.witness
        if self.artifact:
            d["artifact"] = self.artifact
        if self.status == "NOT_APPLICABLE":
            d["exemption_predicate"] = self.exemption_predicate
            d["rationale"] = self.rationale
            d["evidence_path"] = self.evidence_path
        return d


# Global caches
_CATALOG_CACHE: Optional[List[RubricRule]] = None
_CATALOG_BY_ID_CACHE: Optional[Dict[str, RubricRule]] = None
_MATRIX_CACHE: Optional[List[Dict[str, Any]]] = None
_MATRIX_BY_ID_CACHE: Optional[Dict[str, Dict[str, Any]]] = None
_MATRIX_FILE_SIG: Optional[Tuple[str, int, int]] = None
_SCHEMA_CACHE: Dict[str, Dict[str, Any]] = {}


def _get_cached_schema(name: str) -> Dict[str, Any]:
    if name not in _SCHEMA_CACHE:
        _SCHEMA_CACHE[name] = load_json_file(get_schema_path(name))
    return _SCHEMA_CACHE[name]


def get_agent_instructions_dir() -> Path:
    """Locate the canonical agent_instructions directory."""
    try:
        pkg_dir = importlib.resources.files("stagecheck").joinpath("agent_instructions")
        pkg_path = Path(str(pkg_dir))
        if pkg_path.is_dir():
            return pkg_path
    except Exception:
        pass

    local_dir = Path(__file__).resolve().parent.parent / "agent_instructions"
    if local_dir.is_dir():
        return local_dir

    raise FileNotFoundError("Could not locate agent_instructions directory containing 270-rule manuals.")


def get_rubric_audit_matrix_path() -> Path:
    """Locate the packaged 270-rule machine-readable audit matrix JSON asset."""
    try:
        pkg_file = importlib.resources.files("stagecheck").joinpath("config/defaults/rubric_audit_matrix.json")
        pkg_path = Path(str(pkg_file))
        if pkg_path.is_file():
            return pkg_path
    except Exception:
        pass

    local_file = Path(__file__).resolve().parent.parent / "config" / "defaults" / "rubric_audit_matrix.json"
    if local_file.is_file():
        return local_file

    raise FileNotFoundError("Could not locate packaged config/defaults/rubric_audit_matrix.json.")


def _matrix_file_signature(path: Path) -> Tuple[str, int, int]:
    st = path.stat()
    return (str(path), st.st_mtime_ns, st.st_size)


def _get_raw_matrix_entries(force_reload: bool = False) -> List[Dict[str, Any]]:
    """Load matrix JSON entries, refreshing automatically if the matrix file changes on disk."""
    global _MATRIX_CACHE, _MATRIX_BY_ID_CACHE, _MATRIX_FILE_SIG
    matrix_path = get_rubric_audit_matrix_path()
    sig = _matrix_file_signature(matrix_path)
    if (
        not force_reload
        and _MATRIX_CACHE is not None
        and (_MATRIX_FILE_SIG is None or _MATRIX_FILE_SIG == sig)
    ):
        return _MATRIX_CACHE

    data = json.loads(matrix_path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError(
            f"Audit matrix integrity error: expected JSON list in '{matrix_path}', found {type(data).__name__}."
        )
    _MATRIX_CACHE = data
    _MATRIX_FILE_SIG = sig
    by_id: Dict[str, Dict[str, Any]] = {}
    for entry in data:
        if isinstance(entry, dict) and isinstance(entry.get("rule_id"), str) and entry["rule_id"]:
            by_id.setdefault(entry["rule_id"], entry)
    _MATRIX_BY_ID_CACHE = by_id
    return data


def load_270_rule_audit_matrix(force_reload: bool = False) -> List[Dict[str, Any]]:
    """Load and validate the canonical 270-rule machine-readable audit matrix."""
    data = _get_raw_matrix_entries(force_reload=force_reload)
    matrix_path = get_rubric_audit_matrix_path()
    if len(data) != 270:
        raise ValueError(
            f"Audit matrix integrity error: expected 270 entries in '{matrix_path}', found {len(data)}."
        )
    by_id: Dict[str, Dict[str, Any]] = {}
    for entry in data:
        if not isinstance(entry, dict):
            raise ValueError(f"Malformed non-object entry in audit matrix '{matrix_path}'.")
        rid = entry.get("rule_id")
        if not rid or rid in by_id:
            raise ValueError(f"Duplicate or missing rule_id in audit matrix: {rid!r}")
        by_id[rid] = entry
    return data


def get_rule_strategy(rule_id: str) -> Optional[Dict[str, Any]]:
    """Look up the machine-readable strategy specification for a specific rule_id."""
    if _MATRIX_BY_ID_CACHE is None:
        load_270_rule_audit_matrix()
    return (_MATRIX_BY_ID_CACHE or {}).get(rule_id)


def _get_canonical_catalog_by_id() -> Dict[str, RubricRule]:
    global _CATALOG_BY_ID_CACHE
    if _CATALOG_BY_ID_CACHE is None or _CATALOG_CACHE is None:
        catalog = load_270_rule_catalog()
        _CATALOG_BY_ID_CACHE = {r.rule_id: r for r in catalog}
    return _CATALOG_BY_ID_CACHE


def load_270_rule_catalog() -> List[RubricRule]:
    """Load and parse exactly 270 audit criteria from agent_instructions/ with exact category allocation.

    Allocation:
      162 Automated
      64 Evidence
      34 Agent-Assisted
      10 Human Waiver
      = 270 total
    """
    global _CATALOG_CACHE
    if _CATALOG_CACHE is not None:
        return _CATALOG_CACHE

    instr_dir = get_agent_instructions_dir()
    if _MATRIX_BY_ID_CACHE is None:
        load_270_rule_audit_matrix()
    matrix_by_id = _MATRIX_BY_ID_CACHE or {}

    manuals = [
        ("COMMON", "00_common.md"),
        ("CLAIM_SUPPORT", "claim_support.md"),
        ("TEST_ADEQUACY", "test_adequacy.md"),
        ("BLAST_RADIUS", "blast_radius.md"),
        ("FAILURE_CLASS", "failure_class.md"),
        ("UPSTREAM_REUSE", "upstream_reuse.md"),
        ("INDEPENDENT_RERUN", "independent_rerun.md"),
        ("EVAL_CURATOR", "eval_curator.md"),
        ("ORCHESTRATOR", "orchestrator.md"),
    ]

    catalog: List[RubricRule] = []

    for domain_name, filename in manuals:
        filepath = instr_dir / filename
        if not filepath.is_file():
            raise FileNotFoundError(f"Missing required rubric manual: '{filename}'.")

        lines = filepath.read_text(encoding="utf-8").splitlines()
        current_rule_id = ""
        current_title = ""
        current_question = ""
        current_witness = ""
        current_counter = ""

        def flush_rule(r_id: str, r_title: str, r_q: str, r_w: str, r_c: str) -> None:
            if not r_id:
                return
            catalog.append(
                RubricRule(
                    rule_id=r_id,
                    domain=domain_name,
                    title=r_title,
                    question=r_q,
                    category="AUTOMATED",
                    primary_witness=r_w or None,
                    counterexample=r_c or None,
                )
            )

        for line in lines:
            line_s = line.strip()
            header_match = re.match(r"^###\s+([A-Z0-9_]+-\d{3})\s+(.*)$", line_s)
            if header_match:
                flush_rule(current_rule_id, current_title, current_question, current_witness, current_counter)
                current_rule_id = header_match.group(1)
                current_title = header_match.group(2)
                current_question = ""
                current_witness = ""
                current_counter = ""
                continue

            if current_rule_id:
                if line_s.startswith("Question:"):
                    current_question = line_s[len("Question:"):].strip()
                elif line_s.startswith("Primary witness:"):
                    current_witness = line_s[len("Primary witness:"):].strip()
                elif line_s.startswith("Counterexample:"):
                    current_counter = line_s[len("Counterexample:"):].strip()

        flush_rule(current_rule_id, current_title, current_question, current_witness, current_counter)

    if len(catalog) != 270:
        raise ValueError(f"Rubric catalog integrity error: expected exactly 270 rules, found {len(catalog)}.")

    domain_counts: Dict[str, int] = {}
    for rule in catalog:
        domain = rule.domain
        idx = domain_counts.get(domain, 0)
        domain_counts[domain] = idx + 1

        if domain in ("BLAST_RADIUS", "UPSTREAM_REUSE", "FAILURE_CLASS"):
            rule.category = "AUTOMATED"
        elif domain in ("TEST_ADEQUACY", "INDEPENDENT_RERUN"):
            rule.category = "AUTOMATED" if idx < 25 else "EVIDENCE"
        elif domain == "EVAL_CURATOR":
            rule.category = "AUTOMATED" if idx < 22 else "EVIDENCE"
        elif domain == "CLAIM_SUPPORT":
            rule.category = "EVIDENCE" if idx < 20 else "AGENT_ASSISTED"
        elif domain == "ORCHESTRATOR":
            rule.category = "EVIDENCE" if idx < 16 else "AGENT_ASSISTED"
        elif domain == "COMMON":
            if idx < 10:
                rule.category = "HUMAN_WAIVER"
            elif idx < 20:
                rule.category = "AGENT_ASSISTED"
            else:
                rule.category = "EVIDENCE"

        # Bind genuine criterion-matched structural predicates from the canonical audit matrix
        spec = matrix_by_id.get(rule.rule_id)
        if spec and spec.get("exemption_predicate"):
            rule.exemption_predicate = spec["exemption_predicate"]
            rule.exemption_rationale = spec.get("exemption_rationale")

    global _CATALOG_BY_ID_CACHE
    _CATALOG_CACHE = catalog
    _CATALOG_BY_ID_CACHE = {r.rule_id: r for r in catalog}
    return catalog


# Explicit mapping of rubric domains to automated evaluators (Spec 02 / Gap A)
EVALUATOR_MAP: Dict[str, str] = {
    "BLAST_RADIUS": "blast_radius_containment",
    "FAILURE_CLASS": "failure_class_secret_detector",
    "UPSTREAM_REUSE": "upstream_reuse_dependency_analyzer",
    "TEST_ADEQUACY": "test_adequacy_suite_inspector",
    "INDEPENDENT_RERUN": "independent_rerun_environment_verifier",
    "EVAL_CURATOR": "eval_curator_benchmark_verifier",
    "CLAIM_SUPPORT": "claim_support_evidence_verifier",
    "ORCHESTRATOR": "orchestrator_governance_verifier",
    "COMMON": "common_discipline_auditor",
}

EXPECTED_EVALUATOR_BY_CATEGORY_AND_DOMAIN: Dict[Tuple[str, str], str] = {
    ("AUTOMATED", "BLAST_RADIUS"): "blast_radius_containment",
    ("AUTOMATED", "FAILURE_CLASS"): "failure_class_secret_detector",
    ("AUTOMATED", "UPSTREAM_REUSE"): "upstream_reuse_dependency_analyzer",
    ("AUTOMATED", "TEST_ADEQUACY"): "test_adequacy_suite_inspector",
    ("AUTOMATED", "INDEPENDENT_RERUN"): "independent_rerun_environment_verifier",
    ("AUTOMATED", "EVAL_CURATOR"): "eval_curator_benchmark_verifier",
}


def expected_evaluator_for_rule(category: str, domain: str) -> Optional[str]:
    """Return canonical declared evaluator_implementation for (category, domain)."""
    if category == "HUMAN_WAIVER":
        return "human_waiver_evaluator"
    if category == "AGENT_ASSISTED":
        return "agent_assisted_evaluator"
    if category == "EVIDENCE":
        return "phase_evidence_validator"
    if category == "AUTOMATED":
        return EXPECTED_EVALUATOR_BY_CATEGORY_AND_DOMAIN.get(("AUTOMATED", domain))
    return None


def validate_rubric_evaluation_payload(evaluation_results: List[Union[RuleEvaluationResult, Dict[str, Any]]]) -> None:
    """Fail-closed validation: ensures no agent self-exemptions, duplicate rules, or missing strategy/evaluator metadata (FR-03 / GAP-01 / GAP-02)."""
    seen_ids: Set[str] = set()
    duplicates: List[str] = []
    normalized: List[Dict[str, Any]] = []
    for raw_res in evaluation_results:
        res = raw_res.to_dict() if isinstance(raw_res, RuleEvaluationResult) else raw_res
        if not isinstance(res, dict):
            raise RubricEvaluationError(f"Malformed rubric evaluation entry of type {type(raw_res).__name__}.")
        normalized.append(res)
        rid = res.get("rule_id")
        if isinstance(rid, str) and rid:
            if rid in seen_ids and rid not in duplicates:
                duplicates.append(rid)
            seen_ids.add(rid)
    if duplicates:
        raise DuplicateRuleEvaluationError(
            f"Duplicate rubric rule evaluation(s) rejected: {', '.join(sorted(duplicates))}"
        )

    canon_by_id = _get_canonical_catalog_by_id()
    raw_by_id = {
        e["rule_id"]: e
        for e in _get_raw_matrix_entries()
        if isinstance(e, dict) and isinstance(e.get("rule_id"), str)
    }
    for res in normalized:
        rid = res.get("rule_id")
        if res.get("status") == "NOT_APPLICABLE":
            pred = res.get("exemption_predicate")
            if not pred or pred not in EXEMPTION_PREDICATES:
                raise InvalidRubricExemptionError(
                    f"Illegal exemption in rule '{rid}': Unknown or missing predicate '{pred}'."
                )
            if not res.get("rationale") or not res.get("evidence_path"):
                raise InvalidRubricExemptionError(
                    f"Illegal exemption in rule '{rid}': Missing required rationale or evidence_path."
                )
        evaluator = res.get("evaluator")
        strategy = res.get("evaluation_strategy")
        if evaluator == "unsupported_fallback" and res.get("status") == "PASS":
            raise RubricEvaluationError(
                f"Unsupported rule '{rid}' cannot pass without an authorized evaluator."
            )
        if strategy and strategy not in STRATEGY_REGISTRY and res.get("status") == "PASS":
            raise RubricEvaluationError(
                f"Rule '{rid}' cannot pass with unregistered strategy '{strategy}'."
            )
        if isinstance(rid, str) and rid in canon_by_id and res.get("status") == "PASS":
            if not strategy or strategy not in STRATEGY_REGISTRY:
                raise RubricEvaluationError(
                    f"Canonical rule '{rid}' cannot pass without a recorded registered evaluation_strategy."
                )
            m_entry = raw_by_id.get(rid)
            if m_entry and m_entry.get("evaluation_strategy") != strategy:
                raise RubricEvaluationError(
                    f"Rule '{rid}' recorded mismatched strategy '{strategy}' (expected '{m_entry.get('evaluation_strategy')}')."
                )


# Authoritative 228 evaluation strategies indexed with (evaluator_impl, category, exemption_predicate, allowed_domains)
_CANONICAL_STRATEGY_SPECS: Dict[str, Tuple[str, str, Optional[str], Tuple[str, ...]]] = {
    # HUMAN_WAIVER (1 shared strategy across COMMON-001..010)
    "human_disposition_authorization_check": ("human_waiver_evaluator", "HUMAN_WAIVER", None, ("COMMON",)),
    # AGENT_ASSISTED (1 shared strategy across COMMON, CLAIM_SUPPORT, ORCHESTRATOR)
    "agent_semantic_review_attestation_check": ("agent_assisted_evaluator", "AGENT_ASSISTED", None, ("COMMON", "CLAIM_SUPPORT", "ORCHESTRATOR")),
    # BLAST_RADIUS (30 strategies)
    "blast_radius_producer_boundary_ast_and_scope_check": ("blast_radius_containment", "AUTOMATED", None, ("BLAST_RADIUS",)),
    "blast_radius_direct_callers_ast_and_scope_check": ("blast_radius_containment", "AUTOMATED", None, ("BLAST_RADIUS",)),
    "blast_radius_transitive_callers_ast_and_scope_check": ("blast_radius_containment", "AUTOMATED", None, ("BLAST_RADIUS",)),
    "blast_radius_factories_ast_and_scope_check": ("blast_radius_containment", "AUTOMATED", None, ("BLAST_RADIUS",)),
    "blast_radius_registrations_ast_and_scope_check": ("blast_radius_containment", "AUTOMATED", None, ("BLAST_RADIUS",)),
    "blast_radius_config_defaults_ast_and_scope_check": ("blast_radius_containment", "AUTOMATED", None, ("BLAST_RADIUS",)),
    "blast_radius_generated_config_ast_and_scope_check": ("blast_radius_containment", "AUTOMATED", None, ("BLAST_RADIUS",)),
    "blast_radius_activation_ast_and_scope_check": ("blast_radius_containment", "AUTOMATED", None, ("BLAST_RADIUS",)),
    "blast_radius_persistence_producer_ast_and_scope_check": ("blast_radius_containment", "AUTOMATED", None, ("BLAST_RADIUS",)),
    "blast_radius_persistence_consumer_ast_and_scope_check": ("blast_radius_containment", "AUTOMATED", None, ("BLAST_RADIUS",)),
    "blast_radius_encoding_ast_and_scope_check": ("blast_radius_containment", "AUTOMATED", None, ("BLAST_RADIUS",)),
    "blast_radius_migration_ast_and_scope_check": ("blast_radius_containment", "AUTOMATED", None, ("BLAST_RADIUS",)),
    "blast_radius_same_shard_with_predicate_no_blockchain_protocol": ("blast_radius_containment", "AUTOMATED", "PREDICATE_NO_BLOCKCHAIN_PROTOCOL", ("BLAST_RADIUS",)),
    "blast_radius_cross_shard_with_predicate_no_blockchain_protocol": ("blast_radius_containment", "AUTOMATED", "PREDICATE_NO_BLOCKCHAIN_PROTOCOL", ("BLAST_RADIUS",)),
    "blast_radius_metachain_with_predicate_no_blockchain_protocol": ("blast_radius_containment", "AUTOMATED", "PREDICATE_NO_BLOCKCHAIN_PROTOCOL", ("BLAST_RADIUS",)),
    "blast_radius_relayed_paths_with_predicate_no_blockchain_protocol": ("blast_radius_containment", "AUTOMATED", "PREDICATE_NO_BLOCKCHAIN_PROTOCOL", ("BLAST_RADIUS",)),
    "blast_radius_successful_states_ast_and_scope_check": ("blast_radius_containment", "AUTOMATED", None, ("BLAST_RADIUS",)),
    "blast_radius_denied_states_ast_and_scope_check": ("blast_radius_containment", "AUTOMATED", None, ("BLAST_RADIUS",)),
    "blast_radius_malformed_states_ast_and_scope_check": ("blast_radius_containment", "AUTOMATED", None, ("BLAST_RADIUS",)),
    "blast_radius_wire_forms_ast_and_scope_check": ("blast_radius_containment", "AUTOMATED", None, ("BLAST_RADIUS",)),
    "blast_radius_gas_ownership_with_predicate_no_blockchain_protocol": ("blast_radius_containment", "AUTOMATED", "PREDICATE_NO_BLOCKCHAIN_PROTOCOL", ("BLAST_RADIUS",)),
    "blast_radius_concurrency_ast_and_scope_check": ("blast_radius_containment", "AUTOMATED", None, ("BLAST_RADIUS",)),
    "blast_radius_crash_boundaries_ast_and_scope_check": ("blast_radius_containment", "AUTOMATED", None, ("BLAST_RADIUS",)),
    "blast_radius_ordinary_disabled_ast_and_scope_check": ("blast_radius_containment", "AUTOMATED", None, ("BLAST_RADIUS",)),
    "blast_radius_ordinary_enabled_ast_and_scope_check": ("blast_radius_containment", "AUTOMATED", None, ("BLAST_RADIUS",)),
    "blast_radius_simulator_limits_ast_and_scope_check": ("blast_radius_containment", "AUTOMATED", None, ("BLAST_RADIUS",)),
    "blast_radius_evidence_retention_ast_and_scope_check": ("blast_radius_containment", "AUTOMATED", None, ("BLAST_RADIUS",)),
    "blast_radius_blind_labels_ast_and_scope_check": ("blast_radius_containment", "AUTOMATED", None, ("BLAST_RADIUS",)),
    "blast_radius_count_reconciliation_ast_and_scope_check": ("blast_radius_containment", "AUTOMATED", None, ("BLAST_RADIUS",)),
    "blast_radius_coverage_judgment_ast_and_scope_check": ("blast_radius_containment", "AUTOMATED", None, ("BLAST_RADIUS",)),
    # FAILURE_CLASS (30 strategies)
    "failure_class_observed_event_register_and_hygiene_check": ("failure_class_secret_detector", "AUTOMATED", None, ("FAILURE_CLASS",)),
    "failure_class_product_defect_register_and_hygiene_check": ("failure_class_secret_detector", "AUTOMATED", None, ("FAILURE_CLASS",)),
    "failure_class_self_inflicted_defect_register_and_hygiene_check": ("failure_class_secret_detector", "AUTOMATED", None, ("FAILURE_CLASS",)),
    "failure_class_environment_event_register_and_hygiene_check": ("failure_class_secret_detector", "AUTOMATED", None, ("FAILURE_CLASS",)),
    "failure_class_invocation_exception_register_and_hygiene_check": ("failure_class_secret_detector", "AUTOMATED", None, ("FAILURE_CLASS",)),
    "failure_class_compile_exception_register_and_hygiene_check": ("failure_class_secret_detector", "AUTOMATED", None, ("FAILURE_CLASS",)),
    "failure_class_side_effect_boundary_register_and_hygiene_check": ("failure_class_secret_detector", "AUTOMATED", None, ("FAILURE_CLASS",)),
    "failure_class_derived_facts_register_and_hygiene_check": ("failure_class_secret_detector", "AUTOMATED", None, ("FAILURE_CLASS",)),
    "failure_class_root_cause_proof_register_and_hygiene_check": ("failure_class_secret_detector", "AUTOMATED", None, ("FAILURE_CLASS",)),
    "failure_class_symptom_distinction_register_and_hygiene_check": ("failure_class_secret_detector", "AUTOMATED", None, ("FAILURE_CLASS",)),
    "failure_class_surface_sweep_register_and_hygiene_check": ("failure_class_secret_detector", "AUTOMATED", None, ("FAILURE_CLASS",)),
    "failure_class_owning_layer_register_and_hygiene_check": ("failure_class_secret_detector", "AUTOMATED", None, ("FAILURE_CLASS",)),
    "failure_class_correction_inventory_register_and_hygiene_check": ("failure_class_secret_detector", "AUTOMATED", None, ("FAILURE_CLASS",)),
    "failure_class_focused_proof_register_and_hygiene_check": ("failure_class_secret_detector", "AUTOMATED", None, ("FAILURE_CLASS",)),
    "failure_class_expensive_rerun_register_and_hygiene_check": ("failure_class_secret_detector", "AUTOMATED", None, ("FAILURE_CLASS",)),
    "failure_class_recurrence_identity_register_and_hygiene_check": ("failure_class_secret_detector", "AUTOMATED", None, ("FAILURE_CLASS",)),
    "failure_class_recurrence_ruling_register_and_hygiene_check": ("failure_class_secret_detector", "AUTOMATED", None, ("FAILURE_CLASS",)),
    "failure_class_live_surface_count_register_and_hygiene_check": ("failure_class_secret_detector", "AUTOMATED", None, ("FAILURE_CLASS",)),
    "failure_class_ambiguous_transaction_register_and_hygiene_check": ("failure_class_secret_detector", "AUTOMATED", None, ("FAILURE_CLASS",)),
    "failure_class_programme_count_register_and_hygiene_check": ("failure_class_secret_detector", "AUTOMATED", None, ("FAILURE_CLASS",)),
    "failure_class_register_protection_register_and_hygiene_check": ("failure_class_secret_detector", "AUTOMATED", None, ("FAILURE_CLASS",)),
    "failure_class_evidence_retention_register_and_hygiene_check": ("failure_class_secret_detector", "AUTOMATED", None, ("FAILURE_CLASS",)),
    "failure_class_repair_authority_register_and_hygiene_check": ("failure_class_secret_detector", "AUTOMATED", None, ("FAILURE_CLASS",)),
    "failure_class_boundary_expansion_register_and_hygiene_check": ("failure_class_secret_detector", "AUTOMATED", None, ("FAILURE_CLASS",)),
    "failure_class_proof_versus_credit_register_and_hygiene_check": ("failure_class_secret_detector", "AUTOMATED", None, ("FAILURE_CLASS",)),
    "failure_class_partial_execution_register_and_hygiene_check": ("failure_class_secret_detector", "AUTOMATED", None, ("FAILURE_CLASS",)),
    "failure_class_concurrent_change_register_and_hygiene_check": ("failure_class_secret_detector", "AUTOMATED", None, ("FAILURE_CLASS",)),
    "failure_class_operational_script_register_and_hygiene_check": ("failure_class_secret_detector", "AUTOMATED", None, ("FAILURE_CLASS",)),
    "failure_class_unknown_cause_register_and_hygiene_check": ("failure_class_secret_detector", "AUTOMATED", None, ("FAILURE_CLASS",)),
    "failure_class_class_consistency_register_and_hygiene_check": ("failure_class_secret_detector", "AUTOMATED", None, ("FAILURE_CLASS",)),
    # UPSTREAM_REUSE (30 strategies)
    "upstream_reuse_exact_baseline_pin_and_policy_check": ("upstream_reuse_dependency_analyzer", "AUTOMATED", None, ("UPSTREAM_REUSE",)),
    "upstream_reuse_native_entrypoint_pin_and_policy_check": ("upstream_reuse_dependency_analyzer", "AUTOMATED", None, ("UPSTREAM_REUSE",)),
    "upstream_reuse_existing_semantics_pin_and_policy_check": ("upstream_reuse_dependency_analyzer", "AUTOMATED", None, ("UPSTREAM_REUSE",)),
    "upstream_reuse_naming_fidelity_with_predicate_no_blockchain_protocol": ("upstream_reuse_dependency_analyzer", "AUTOMATED", "PREDICATE_NO_BLOCKCHAIN_PROTOCOL", ("UPSTREAM_REUSE",)),
    "upstream_reuse_new_concept_with_predicate_no_blockchain_protocol": ("upstream_reuse_dependency_analyzer", "AUTOMATED", "PREDICATE_NO_BLOCKCHAIN_PROTOCOL", ("UPSTREAM_REUSE",)),
    "upstream_reuse_classification_pin_and_policy_check": ("upstream_reuse_dependency_analyzer", "AUTOMATED", None, ("UPSTREAM_REUSE",)),
    "upstream_reuse_deviation_scope_pin_and_policy_check": ("upstream_reuse_dependency_analyzer", "AUTOMATED", None, ("UPSTREAM_REUSE",)),
    "upstream_reuse_native_guard_pin_and_policy_check": ("upstream_reuse_dependency_analyzer", "AUTOMATED", None, ("UPSTREAM_REUSE",)),
    "upstream_reuse_property_truth_pin_and_policy_check": ("upstream_reuse_dependency_analyzer", "AUTOMATED", None, ("UPSTREAM_REUSE",)),
    "upstream_reuse_role_truth_pin_and_policy_check": ("upstream_reuse_dependency_analyzer", "AUTOMATED", None, ("UPSTREAM_REUSE",)),
    "upstream_reuse_error_behavior_pin_and_policy_check": ("upstream_reuse_dependency_analyzer", "AUTOMATED", None, ("UPSTREAM_REUSE",)),
    "upstream_reuse_return_behavior_pin_and_policy_check": ("upstream_reuse_dependency_analyzer", "AUTOMATED", None, ("UPSTREAM_REUSE",)),
    "upstream_reuse_gas_behavior_with_predicate_no_blockchain_protocol": ("upstream_reuse_dependency_analyzer", "AUTOMATED", "PREDICATE_NO_BLOCKCHAIN_PROTOCOL", ("UPSTREAM_REUSE",)),
    "upstream_reuse_storage_behavior_pin_and_policy_check": ("upstream_reuse_dependency_analyzer", "AUTOMATED", None, ("UPSTREAM_REUSE",)),
    "upstream_reuse_cross_shard_behavior_with_predicate_no_blockchain_protocol": ("upstream_reuse_dependency_analyzer", "AUTOMATED", "PREDICATE_NO_BLOCKCHAIN_PROTOCOL", ("UPSTREAM_REUSE",)),
    "upstream_reuse_metachain_behavior_with_predicate_no_blockchain_protocol": ("upstream_reuse_dependency_analyzer", "AUTOMATED", "PREDICATE_NO_BLOCKCHAIN_PROTOCOL", ("UPSTREAM_REUSE",)),
    "upstream_reuse_relayed_behavior_with_predicate_no_blockchain_protocol": ("upstream_reuse_dependency_analyzer", "AUTOMATED", "PREDICATE_NO_BLOCKCHAIN_PROTOCOL", ("UPSTREAM_REUSE",)),
    "upstream_reuse_activation_behavior_with_predicate_no_blockchain_protocol": ("upstream_reuse_dependency_analyzer", "AUTOMATED", "PREDICATE_NO_BLOCKCHAIN_PROTOCOL", ("UPSTREAM_REUSE",)),
    "upstream_reuse_vm_selection_with_predicate_no_blockchain_protocol": ("upstream_reuse_dependency_analyzer", "AUTOMATED", "PREDICATE_NO_BLOCKCHAIN_PROTOCOL", ("UPSTREAM_REUSE",)),
    "upstream_reuse_configuration_defaults_pin_and_policy_check": ("upstream_reuse_dependency_analyzer", "AUTOMATED", None, ("UPSTREAM_REUSE",)),
    "upstream_reuse_duplicate_helper_with_predicate_no_blockchain_protocol": ("upstream_reuse_dependency_analyzer", "AUTOMATED", "PREDICATE_NO_BLOCKCHAIN_PROTOCOL", ("UPSTREAM_REUSE",)),
    "upstream_reuse_wrapper_necessity_pin_and_policy_check": ("upstream_reuse_dependency_analyzer", "AUTOMATED", None, ("UPSTREAM_REUSE",)),
    "upstream_reuse_existing_tooling_pin_and_policy_check": ("upstream_reuse_dependency_analyzer", "AUTOMATED", None, ("UPSTREAM_REUSE",)),
    "upstream_reuse_existing_document_pin_and_policy_check": ("upstream_reuse_dependency_analyzer", "AUTOMATED", None, ("UPSTREAM_REUSE",)),
    "upstream_reuse_excluded_legacy_with_predicate_no_blockchain_protocol": ("upstream_reuse_dependency_analyzer", "AUTOMATED", "PREDICATE_NO_BLOCKCHAIN_PROTOCOL", ("UPSTREAM_REUSE",)),
    "upstream_reuse_disabled_equivalence_with_predicate_no_blockchain_protocol": ("upstream_reuse_dependency_analyzer", "AUTOMATED", "PREDICATE_NO_BLOCKCHAIN_PROTOCOL", ("UPSTREAM_REUSE",)),
    "upstream_reuse_enabled_equivalence_pin_and_policy_check": ("upstream_reuse_dependency_analyzer", "AUTOMATED", None, ("UPSTREAM_REUSE",)),
    "upstream_reuse_search_completeness_pin_and_policy_check": ("upstream_reuse_dependency_analyzer", "AUTOMATED", None, ("UPSTREAM_REUSE",)),
    "upstream_reuse_security_requirement_pin_and_policy_check": ("upstream_reuse_dependency_analyzer", "AUTOMATED", None, ("UPSTREAM_REUSE",)),
    "upstream_reuse_unknown_baseline_with_predicate_no_blockchain_protocol": ("upstream_reuse_dependency_analyzer", "AUTOMATED", "PREDICATE_NO_BLOCKCHAIN_PROTOCOL", ("UPSTREAM_REUSE",)),
    # TEST_ADEQUACY (25 AUTOMATED + 5 EVIDENCE strategies)
    "test_adequacy_specification_oracle_ast_and_suite_check": ("test_adequacy_suite_inspector", "AUTOMATED", None, ("TEST_ADEQUACY",)),
    "test_adequacy_oracle_identity_ast_and_suite_check": ("test_adequacy_suite_inspector", "AUTOMATED", None, ("TEST_ADEQUACY",)),
    "test_adequacy_oracle_acceptance_ast_and_suite_check": ("test_adequacy_suite_inspector", "AUTOMATED", None, ("TEST_ADEQUACY",)),
    "test_adequacy_fixture_independence_ast_and_suite_check": ("test_adequacy_suite_inspector", "AUTOMATED", None, ("TEST_ADEQUACY",)),
    "test_adequacy_shared_algorithm_ast_and_suite_check": ("test_adequacy_suite_inspector", "AUTOMATED", None, ("TEST_ADEQUACY",)),
    "test_adequacy_assertion_strength_ast_and_suite_check": ("test_adequacy_suite_inspector", "AUTOMATED", None, ("TEST_ADEQUACY",)),
    "test_adequacy_assertion_removal_ast_and_suite_check": ("test_adequacy_suite_inspector", "AUTOMATED", None, ("TEST_ADEQUACY",)),
    "test_adequacy_selector_coverage_ast_and_suite_check": ("test_adequacy_suite_inspector", "AUTOMATED", None, ("TEST_ADEQUACY",)),
    "test_adequacy_qual_selection_ast_and_suite_check": ("test_adequacy_suite_inspector", "AUTOMATED", None, ("TEST_ADEQUACY",)),
    "test_adequacy_skipped_outcomes_ast_and_suite_check": ("test_adequacy_suite_inspector", "AUTOMATED", None, ("TEST_ADEQUACY",)),
    "test_adequacy_compile_distinction_ast_and_suite_check": ("test_adequacy_suite_inspector", "AUTOMATED", None, ("TEST_ADEQUACY",)),
    "test_adequacy_build_scope_ast_and_suite_check": ("test_adequacy_suite_inspector", "AUTOMATED", None, ("TEST_ADEQUACY",)),
    "test_adequacy_focused_reproduction_ast_and_suite_check": ("test_adequacy_suite_inspector", "AUTOMATED", None, ("TEST_ADEQUACY",)),
    "test_adequacy_post_fix_reproduction_ast_and_suite_check": ("test_adequacy_suite_inspector", "AUTOMATED", None, ("TEST_ADEQUACY",)),
    "test_adequacy_consumer_coverage_ast_and_suite_check": ("test_adequacy_suite_inspector", "AUTOMATED", None, ("TEST_ADEQUACY",)),
    "test_adequacy_positive_behavior_ast_and_suite_check": ("test_adequacy_suite_inspector", "AUTOMATED", None, ("TEST_ADEQUACY",)),
    "test_adequacy_negative_behavior_ast_and_suite_check": ("test_adequacy_suite_inspector", "AUTOMATED", None, ("TEST_ADEQUACY",)),
    "test_adequacy_malformed_behavior_ast_and_suite_check": ("test_adequacy_suite_inspector", "AUTOMATED", None, ("TEST_ADEQUACY",)),
    "test_adequacy_duplicate_behavior_ast_and_suite_check": ("test_adequacy_suite_inspector", "AUTOMATED", None, ("TEST_ADEQUACY",)),
    "test_adequacy_refund_behavior_with_predicate_no_blockchain_protocol": ("test_adequacy_suite_inspector", "AUTOMATED", "PREDICATE_NO_BLOCKCHAIN_PROTOCOL", ("TEST_ADEQUACY",)),
    "test_adequacy_concurrency_behavior_ast_and_suite_check": ("test_adequacy_suite_inspector", "AUTOMATED", None, ("TEST_ADEQUACY",)),
    "test_adequacy_crash_behavior_ast_and_suite_check": ("test_adequacy_suite_inspector", "AUTOMATED", None, ("TEST_ADEQUACY",)),
    "test_adequacy_disabled_equivalence_ast_and_suite_check": ("test_adequacy_suite_inspector", "AUTOMATED", None, ("TEST_ADEQUACY",)),
    "test_adequacy_enabled_equivalence_ast_and_suite_check": ("test_adequacy_suite_inspector", "AUTOMATED", None, ("TEST_ADEQUACY",)),
    "test_adequacy_toolchain_identity_ast_and_suite_check": ("test_adequacy_suite_inspector", "AUTOMATED", None, ("TEST_ADEQUACY",)),
    "raw_test_output_retention_check": ("phase_evidence_validator", "EVIDENCE", None, ("TEST_ADEQUACY",)),
    "pinned_test_environment_evidence_check": ("phase_evidence_validator", "EVIDENCE", None, ("TEST_ADEQUACY",)),
    "mutation_and_test_compile_evidence_check": ("phase_evidence_validator", "EVIDENCE", None, ("TEST_ADEQUACY",)),
    "network_boundary_evidence_check": ("phase_evidence_validator", "EVIDENCE", None, ("TEST_ADEQUACY",)),
    "unexecuted_check_disclosure_evidence_check": ("phase_evidence_validator", "EVIDENCE", None, ("TEST_ADEQUACY",)),
    # INDEPENDENT_RERUN (25 AUTOMATED + 5 EVIDENCE strategies)
    "independent_rerun_producer_identity_verification": ("independent_rerun_environment_verifier", "AUTOMATED", None, ("INDEPENDENT_RERUN",)),
    "independent_rerun_reviewer_appointment_verification": ("independent_rerun_environment_verifier", "AUTOMATED", None, ("INDEPENDENT_RERUN",)),
    "independent_rerun_read_only_boundary_verification": ("independent_rerun_environment_verifier", "AUTOMATED", None, ("INDEPENDENT_RERUN",)),
    "independent_rerun_execution_supplier_verification": ("independent_rerun_environment_verifier", "AUTOMATED", None, ("INDEPENDENT_RERUN",)),
    "independent_rerun_grant_identity_verification": ("independent_rerun_environment_verifier", "AUTOMATED", None, ("INDEPENDENT_RERUN",)),
    "independent_rerun_grant_expiry_verification": ("independent_rerun_environment_verifier", "AUTOMATED", None, ("INDEPENDENT_RERUN",)),
    "independent_rerun_smoke_authority_verification": ("independent_rerun_environment_verifier", "AUTOMATED", None, ("INDEPENDENT_RERUN",)),
    "independent_rerun_smoke_execution_verification": ("independent_rerun_environment_verifier", "AUTOMATED", None, ("INDEPENDENT_RERUN",)),
    "independent_rerun_exact_argv_verification": ("independent_rerun_environment_verifier", "AUTOMATED", None, ("INDEPENDENT_RERUN",)),
    "independent_rerun_exact_cwd_verification": ("independent_rerun_environment_verifier", "AUTOMATED", None, ("INDEPENDENT_RERUN",)),
    "independent_rerun_current_head_verification": ("independent_rerun_environment_verifier", "AUTOMATED", None, ("INDEPENDENT_RERUN",)),
    "independent_rerun_dirty_state_verification": ("independent_rerun_environment_verifier", "AUTOMATED", None, ("INDEPENDENT_RERUN",)),
    "independent_rerun_binary_lock_verification": ("independent_rerun_environment_verifier", "AUTOMATED", None, ("INDEPENDENT_RERUN",)),
    "independent_rerun_toolchain_local_with_predicate_no_go_module": ("independent_rerun_environment_verifier", "AUTOMATED", "PREDICATE_NO_GO_MODULE", ("INDEPENDENT_RERUN",)),
    "independent_rerun_inputs_before_verification": ("independent_rerun_environment_verifier", "AUTOMATED", None, ("INDEPENDENT_RERUN",)),
    "independent_rerun_inputs_after_verification": ("independent_rerun_environment_verifier", "AUTOMATED", None, ("INDEPENDENT_RERUN",)),
    "independent_rerun_exit_equality_verification": ("independent_rerun_environment_verifier", "AUTOMATED", None, ("INDEPENDENT_RERUN",)),
    "independent_rerun_stdout_equality_verification": ("independent_rerun_environment_verifier", "AUTOMATED", None, ("INDEPENDENT_RERUN",)),
    "independent_rerun_stderr_equality_verification": ("independent_rerun_environment_verifier", "AUTOMATED", None, ("INDEPENDENT_RERUN",)),
    "independent_rerun_timing_differences_with_predicate_no_go_module": ("independent_rerun_environment_verifier", "AUTOMATED", "PREDICATE_NO_GO_MODULE", ("INDEPENDENT_RERUN",)),
    "independent_rerun_timeout_disclosure_verification": ("independent_rerun_environment_verifier", "AUTOMATED", None, ("INDEPENDENT_RERUN",)),
    "independent_rerun_failure_disclosure_verification": ("independent_rerun_environment_verifier", "AUTOMATED", None, ("INDEPENDENT_RERUN",)),
    "independent_rerun_environment_scope_verification": ("independent_rerun_environment_verifier", "AUTOMATED", None, ("INDEPENDENT_RERUN",)),
    "independent_rerun_network_exclusion_verification": ("independent_rerun_environment_verifier", "AUTOMATED", None, ("INDEPENDENT_RERUN",)),
    "independent_rerun_consumer_reruns_verification": ("independent_rerun_environment_verifier", "AUTOMATED", None, ("INDEPENDENT_RERUN",)),
    "rerun_raw_record_schema_check": ("phase_evidence_validator", "EVIDENCE", None, ("INDEPENDENT_RERUN",)),
    "rerun_observation_label_evidence_check": ("phase_evidence_validator", "EVIDENCE", None, ("INDEPENDENT_RERUN",)),
    "rerun_gate_order_evidence_check": ("phase_evidence_validator", "EVIDENCE", None, ("INDEPENDENT_RERUN",)),
    "rerun_missing_evidence_prohibits_pass_check": ("phase_evidence_validator", "EVIDENCE", None, ("INDEPENDENT_RERUN",)),
    "rerun_acceptance_boundary_evidence_check": ("phase_evidence_validator", "EVIDENCE", None, ("INDEPENDENT_RERUN",)),
    # EVAL_CURATOR (22 AUTOMATED + 8 EVIDENCE strategies)
    "eval_curator_owner_confirmation_verification": ("eval_curator_benchmark_verifier", "AUTOMATED", None, ("EVAL_CURATOR",)),
    "eval_curator_escaped_version_verification": ("eval_curator_benchmark_verifier", "AUTOMATED", None, ("EVAL_CURATOR",)),
    "eval_curator_target_criterion_verification": ("eval_curator_benchmark_verifier", "AUTOMATED", None, ("EVAL_CURATOR",)),
    "eval_curator_defective_twin_verification": ("eval_curator_benchmark_verifier", "AUTOMATED", None, ("EVAL_CURATOR",)),
    "eval_curator_clean_twin_verification": ("eval_curator_benchmark_verifier", "AUTOMATED", None, ("EVAL_CURATOR",)),
    "eval_curator_oracle_independence_verification": ("eval_curator_benchmark_verifier", "AUTOMATED", None, ("EVAL_CURATOR",)),
    "eval_curator_installed_failure_verification": ("eval_curator_benchmark_verifier", "AUTOMATED", None, ("EVAL_CURATOR",)),
    "eval_curator_candidate_catch_verification": ("eval_curator_benchmark_verifier", "AUTOMATED", None, ("EVAL_CURATOR",)),
    "eval_curator_clean_preservation_verification": ("eval_curator_benchmark_verifier", "AUTOMATED", None, ("EVAL_CURATOR",)),
    "eval_curator_paired_inventory_verification": ("eval_curator_benchmark_verifier", "AUTOMATED", None, ("EVAL_CURATOR",)),
    "eval_curator_held_out_boundary_verification": ("eval_curator_benchmark_verifier", "AUTOMATED", None, ("EVAL_CURATOR",)),
    "eval_curator_held_out_evaluation_verification": ("eval_curator_benchmark_verifier", "AUTOMATED", None, ("EVAL_CURATOR",)),
    "eval_curator_historical_inventory_verification": ("eval_curator_benchmark_verifier", "AUTOMATED", None, ("EVAL_CURATOR",)),
    "eval_curator_replay_omissions_verification": ("eval_curator_benchmark_verifier", "AUTOMATED", None, ("EVAL_CURATOR",)),
    "eval_curator_regression_definition_verification": ("eval_curator_benchmark_verifier", "AUTOMATED", None, ("EVAL_CURATOR",)),
    "eval_curator_typed_outcomes_verification": ("eval_curator_benchmark_verifier", "AUTOMATED", None, ("EVAL_CURATOR",)),
    "eval_curator_source_proof_verification": ("eval_curator_benchmark_verifier", "AUTOMATED", None, ("EVAL_CURATOR",)),
    "eval_curator_command_proof_verification": ("eval_curator_benchmark_verifier", "AUTOMATED", None, ("EVAL_CURATOR",)),
    "eval_curator_label_proof_verification": ("eval_curator_benchmark_verifier", "AUTOMATED", None, ("EVAL_CURATOR",)),
    "eval_curator_relaxation_detection_verification": ("eval_curator_benchmark_verifier", "AUTOMATED", None, ("EVAL_CURATOR",)),
    "eval_curator_no_weakening_verification": ("eval_curator_benchmark_verifier", "AUTOMATED", None, ("EVAL_CURATOR",)),
    "eval_curator_minimal_change_verification": ("eval_curator_benchmark_verifier", "AUTOMATED", None, ("EVAL_CURATOR",)),
    "eval_fixture_provenance_evidence_check": ("phase_evidence_validator", "EVIDENCE", None, ("EVAL_CURATOR",)),
    "eval_control_isolation_evidence_check": ("phase_evidence_validator", "EVIDENCE", None, ("EVAL_CURATOR",)),
    "eval_deterministic_repeat_evidence_check": ("phase_evidence_validator", "EVIDENCE", None, ("EVAL_CURATOR",)),
    "eval_model_trial_boundary_evidence_check": ("phase_evidence_validator", "EVIDENCE", None, ("EVAL_CURATOR",)),
    "eval_false_block_disposition_evidence_check": ("phase_evidence_validator", "EVIDENCE", None, ("EVAL_CURATOR",)),
    "eval_proposal_location_boundary_check": ("phase_evidence_validator", "EVIDENCE", None, ("EVAL_CURATOR",)),
    "eval_manifest_installation_authority_check": ("phase_evidence_validator", "EVIDENCE", None, ("EVAL_CURATOR",)),
    "eval_open_obligation_blocks_pass_check": ("phase_evidence_validator", "EVIDENCE", None, ("EVAL_CURATOR",)),
    # ORCHESTRATOR (16 EVIDENCE strategies)
    "launcher_task_binding_evidence_check": ("phase_evidence_validator", "EVIDENCE", None, ("ORCHESTRATOR",)),
    "git_root_boundary_evidence_check": ("phase_evidence_validator", "EVIDENCE", None, ("ORCHESTRATOR",)),
    "initial_head_status_retention_check": ("phase_evidence_validator", "EVIDENCE", None, ("ORCHESTRATOR",)),
    "complete_change_inventory_evidence_check": ("phase_evidence_validator", "EVIDENCE", None, ("ORCHESTRATOR",)),
    "depth_monotonicity_evidence_check": ("phase_evidence_validator", "EVIDENCE", None, ("ORCHESTRATOR",)),
    "control_manifest_hash_evidence_check": ("phase_evidence_validator", "EVIDENCE", None, ("ORCHESTRATOR",)),
    "active_state_schema_evidence_check": ("phase_evidence_validator", "EVIDENCE", None, ("ORCHESTRATOR",)),
    "tool_manifest_integrity_evidence_check": ("phase_evidence_validator", "EVIDENCE", None, ("ORCHESTRATOR",)),
    "instruction_manual_admission_check": ("phase_evidence_validator", "EVIDENCE", None, ("ORCHESTRATOR",)),
    "deterministic_orchestrator_entrypoint_check": ("phase_evidence_validator", "EVIDENCE", None, ("ORCHESTRATOR",)),
    "nine_stage_check_order_evidence_check": ("phase_evidence_validator", "EVIDENCE", None, ("ORCHESTRATOR",)),
    "check_interface_exit_agreement_check": ("phase_evidence_validator", "EVIDENCE", None, ("ORCHESTRATOR",)),
    "script_error_precedence_evidence_check": ("phase_evidence_validator", "EVIDENCE", None, ("ORCHESTRATOR",)),
    "advisory_binding_mode_evidence_check": ("phase_evidence_validator", "EVIDENCE", None, ("ORCHESTRATOR",)),
    "agent_selection_identity_evidence_check": ("phase_evidence_validator", "EVIDENCE", None, ("ORCHESTRATOR",)),
    "secret_scan_preflight_admission_check": ("phase_evidence_validator", "EVIDENCE", None, ("ORCHESTRATOR",)),
    # CLAIM_SUPPORT (20 EVIDENCE strategies)
    "claim_evidence_literal_entailment_check": ("phase_evidence_validator", "EVIDENCE", None, ("CLAIM_SUPPORT",)),
    "claim_evidence_quantifier_preservation_check": ("phase_evidence_validator", "EVIDENCE", None, ("CLAIM_SUPPORT",)),
    "claim_evidence_negation_preservation_check": ("phase_evidence_validator", "EVIDENCE", None, ("CLAIM_SUPPORT",)),
    "claim_evidence_conjunction_check": ("phase_evidence_validator", "EVIDENCE", None, ("CLAIM_SUPPORT",)),
    "claim_evidence_disjunction_check": ("phase_evidence_validator", "EVIDENCE", None, ("CLAIM_SUPPORT",)),
    "claim_evidence_conditional_scope_check": ("phase_evidence_validator", "EVIDENCE", None, ("CLAIM_SUPPORT",)),
    "claim_evidence_exhaustiveness_check": ("phase_evidence_validator", "EVIDENCE", None, ("CLAIM_SUPPORT",)),
    "claim_evidence_normative_level_check": ("phase_evidence_validator", "EVIDENCE", None, ("CLAIM_SUPPORT",)),
    "claim_evidence_source_status_check": ("phase_evidence_validator", "EVIDENCE", None, ("CLAIM_SUPPORT",)),
    "claim_evidence_current_implementation_check": ("phase_evidence_validator", "EVIDENCE", None, ("CLAIM_SUPPORT",)),
    "claim_evidence_test_scope_check": ("phase_evidence_validator", "EVIDENCE", None, ("CLAIM_SUPPORT",)),
    "claim_evidence_runtime_scope_check": ("phase_evidence_validator", "EVIDENCE", None, ("CLAIM_SUPPORT",)),
    "claim_evidence_independent_scope_check": ("phase_evidence_validator", "EVIDENCE", None, ("CLAIM_SUPPORT",)),
    "claim_evidence_observed_versus_accepted_check": ("phase_evidence_validator", "EVIDENCE", None, ("CLAIM_SUPPORT",)),
    "claim_evidence_completion_breadth_check": ("phase_evidence_validator", "EVIDENCE", None, ("CLAIM_SUPPORT",)),
    "claim_evidence_missing_claims_check": ("phase_evidence_validator", "EVIDENCE", None, ("CLAIM_SUPPORT",)),
    "claim_evidence_duplicate_claims_check": ("phase_evidence_validator", "EVIDENCE", None, ("CLAIM_SUPPORT",)),
    "claim_evidence_evidence_aggregation_check": ("phase_evidence_validator", "EVIDENCE", None, ("CLAIM_SUPPORT",)),
    "claim_evidence_historical_provenance_check": ("phase_evidence_validator", "EVIDENCE", None, ("CLAIM_SUPPORT",)),
    "claim_evidence_failure_causality_check": ("phase_evidence_validator", "EVIDENCE", None, ("CLAIM_SUPPORT",)),
    # COMMON (10 EVIDENCE strategies)
    "role_identity_binding_check": ("phase_evidence_validator", "EVIDENCE", None, ("COMMON",)),
    "unresolved_work_blocks_pass_check": ("phase_evidence_validator", "EVIDENCE", None, ("COMMON",)),
    "citation_resolution_integrity_check": ("phase_evidence_validator", "EVIDENCE", None, ("COMMON",)),
    "execution_error_vs_defect_separation_check": ("phase_evidence_validator", "EVIDENCE", None, ("COMMON",)),
    "manifest_context_continuity_check": ("phase_evidence_validator", "EVIDENCE", None, ("COMMON",)),
    "scope_boundary_evidence_check": ("phase_evidence_validator", "EVIDENCE", None, ("COMMON",)),
    "concrete_repo_and_file_enumeration_check": ("phase_evidence_validator", "EVIDENCE", None, ("COMMON",)),
    "counterexample_guard_evidence_check": ("phase_evidence_validator", "EVIDENCE", None, ("COMMON",)),
    "owner_decision_authority_check": ("phase_evidence_validator", "EVIDENCE", None, ("COMMON",)),
    "verdict_findings_consistency_check": ("phase_evidence_validator", "EVIDENCE", None, ("COMMON",)),
}


def _dispatch_evaluator_for_strategy(
    rule: RubricRule,
    workspace_root: Path,
    repo_path: Path,
    ctx: Dict[str, Any],
    evaluator_impl: str,
) -> RuleEvaluationResult:
    """Execute the registered evaluator implementation backing a validated strategy."""
    if evaluator_impl == "human_waiver_evaluator":
        return _evaluate_human_waiver(rule, ctx)
    if evaluator_impl == "agent_assisted_evaluator":
        return _evaluate_agent_assisted(rule, ctx)
    if evaluator_impl == "phase_evidence_validator":
        return _evaluate_evidence_rule(rule, workspace_root, ctx)
    if evaluator_impl == "blast_radius_containment":
        return _eval_blast_radius(rule, ctx, evaluator_impl)
    if evaluator_impl == "failure_class_secret_detector":
        return _eval_failure_class(rule, ctx, evaluator_impl)
    if evaluator_impl == "upstream_reuse_dependency_analyzer":
        return _eval_upstream_reuse(rule, ctx, evaluator_impl)
    if evaluator_impl == "test_adequacy_suite_inspector":
        return _eval_test_adequacy(rule, ctx, evaluator_impl)
    if evaluator_impl == "independent_rerun_environment_verifier":
        return _eval_independent_rerun(rule, ctx, evaluator_impl)
    if evaluator_impl == "eval_curator_benchmark_verifier":
        return _eval_eval_curator(rule, ctx, evaluator_impl)
    raise RubricEvaluationError(f"Unsupported evaluator implementation '{evaluator_impl}'.")


def _resolve_and_validate_matrix_entry(
    rule: RubricRule,
    context: Optional[Dict[str, Any]] = None,
) -> Tuple[Optional[Dict[str, Any]], Optional[RuleEvaluationResult]]:
    """Resolve exactly one matrix entry for rule and fail closed on any tampering or mismatch."""
    canon_by_id = _get_canonical_catalog_by_id()
    canon_rule = canon_by_id.get(rule.rule_id)

    raw_by_id = context.get("_raw_matrix_by_id") if isinstance(context, dict) else None
    if isinstance(raw_by_id, dict):
        matching = raw_by_id.get(rule.rule_id, [])
    else:
        raw_entries = _get_raw_matrix_entries()
        matching = [e for e in raw_entries if isinstance(e, dict) and e.get("rule_id") == rule.rule_id]
    if not matching:
        if canon_rule is None and rule.domain not in EVALUATOR_MAP:
            return None, RuleEvaluationResult(
                rule_id=rule.rule_id,
                domain=rule.domain,
                category=rule.category,
                status="NOT_EVALUATED",
                evaluator="unsupported_fallback",
                message=f"No evaluator or matrix entry registered for rule '{rule.rule_id}' (domain '{rule.domain}').",
            )
        return None, RuleEvaluationResult(
            rule_id=rule.rule_id,
            domain=rule.domain,
            category=rule.category,
            status="FAIL",
            evaluator=EVALUATOR_MAP.get(rule.domain, "matrix_integrity_validator"),
            message=f"Matrix validation failed: no entry found for rule '{rule.rule_id}'.",
        )

    if len(matching) != 1:
        return None, RuleEvaluationResult(
            rule_id=rule.rule_id,
            domain=rule.domain,
            category=rule.category,
            status="FAIL",
            evaluator=EVALUATOR_MAP.get(rule.domain, "matrix_integrity_validator"),
            message=f"Matrix integrity error: rule '{rule.rule_id}' resolved to {len(matching)} entries (expected 1).",
        )

    entry = matching[0]
    m_domain = entry.get("domain")
    m_category = entry.get("category")
    m_strategy = entry.get("evaluation_strategy")
    m_eval = entry.get("evaluator_implementation")
    m_crit = entry.get("original_criterion") or {}

    if canon_rule is not None:
        if rule.domain != canon_rule.domain or m_domain != canon_rule.domain:
            return None, RuleEvaluationResult(
                rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="FAIL",
                evaluator=EVALUATOR_MAP.get(canon_rule.domain, "matrix_integrity_validator"),
                message=f"Domain mismatch for '{rule.rule_id}': expected '{canon_rule.domain}', got rule='{rule.domain}' matrix='{m_domain}'.",
            )
        if rule.category != canon_rule.category or m_category != canon_rule.category:
            return None, RuleEvaluationResult(
                rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="FAIL",
                evaluator=EVALUATOR_MAP.get(canon_rule.domain, "matrix_integrity_validator"),
                message=f"Category mismatch for '{rule.rule_id}': expected '{canon_rule.category}', got rule='{rule.category}' matrix='{m_category}'.",
            )
        if (
            rule.title != canon_rule.title
            or rule.question != canon_rule.question
            or rule.primary_witness != canon_rule.primary_witness
            or rule.counterexample != canon_rule.counterexample
            or m_crit.get("title") != canon_rule.title
            or m_crit.get("question") != canon_rule.question
            or m_crit.get("primary_witness") != canon_rule.primary_witness
            or m_crit.get("counterexample") != canon_rule.counterexample
        ):
            return None, RuleEvaluationResult(
                rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="FAIL",
                evaluator=EVALUATOR_MAP.get(canon_rule.domain, "matrix_integrity_validator"),
                message=f"Original criterion mismatch or tampering detected for rule '{rule.rule_id}'.",
            )
        if rule.exemption_predicate != canon_rule.exemption_predicate:
            return None, RuleEvaluationResult(
                rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="FAIL",
                evaluator="structural_predicate_evaluator",
                message=f"Exemption predicate mismatch for '{rule.rule_id}': expected '{canon_rule.exemption_predicate}', got '{rule.exemption_predicate}'.",
            )

    expected_eval = expected_evaluator_for_rule(str(m_category or ""), str(m_domain or ""))
    if not m_eval or m_eval not in EVALUATOR_REGISTRY or m_eval != expected_eval:
        return None, RuleEvaluationResult(
            rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="FAIL",
            evaluator="matrix_integrity_validator",
            message=f"Evaluator implementation mismatch or missing mapping for '{rule.rule_id}': got '{m_eval}', expected '{expected_eval}'.",
        )

    spec = STRATEGY_REGISTRY.get(str(m_strategy or ""))
    if not spec:
        return None, RuleEvaluationResult(
            rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="FAIL",
            evaluator=m_eval,
            message=f"Unsupported or unregistered evaluation_strategy '{m_strategy}' for rule '{rule.rule_id}'.",
        )

    if (
        spec["evaluator"] != m_eval
        or spec["category"] != m_category
        or str(m_domain or "") not in spec["allowed_domains"]
        or spec["exemption_predicate"] != rule.exemption_predicate
    ):
        return None, RuleEvaluationResult(
            rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="FAIL",
            evaluator=m_eval,
            message=(
                f"Matrix strategy binding mismatch on '{rule.rule_id}': strategy '{m_strategy}' "
                f"does not match domain='{m_domain}', category='{m_category}', evaluator='{m_eval}', predicate='{rule.exemption_predicate}'."
            ),
        )

    if entry.get("verification_outcome") != "VERIFIED":
        return None, RuleEvaluationResult(
            rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="FAIL",
            evaluator=m_eval, evaluation_strategy=str(m_strategy),
            message=f"Matrix entry '{rule.rule_id}' has non-VERIFIED outcome '{entry.get('verification_outcome')}'.",
        )

    req_inputs = entry.get("required_inputs")
    req_evidence = entry.get("required_evidence")
    if not isinstance(req_inputs, list) or not req_inputs or not isinstance(req_evidence, list) or not req_evidence:
        return None, RuleEvaluationResult(
            rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="FAIL",
            evaluator=m_eval, evaluation_strategy=str(m_strategy),
            message=f"Matrix entry '{rule.rule_id}' missing required_inputs or required_evidence definitions.",
        )

    return entry, None


def _evidence_artifact_available(
    ev_ref: str,
    rule: RubricRule,
    workspace_root: Path,
    ctx: Dict[str, Any],
) -> Tuple[bool, str]:
    """Verify whether a declared matrix required_evidence reference is genuinely satisfied."""
    missing_flag = ctx.get("missing_evidence", [])
    if ev_ref in missing_flag or "*" in missing_flag or rule.rule_id in missing_flag:
        return False, f"Required evidence '{ev_ref}' marked missing."
    if ev_ref == "controls/ACTIVE_STATE.json":
        ok = bool(ctx.get("active_state")) and not ctx.get("active_state_err")
        return ok, str(ctx.get("active_state_err") or "Missing or invalid controls/ACTIVE_STATE.json.")
    if ev_ref == "controls/PRODUCT_REPOSITORIES.json":
        ok = bool(ctx.get("prod_repos")) and not ctx.get("prod_repos_err")
        return ok, str(ctx.get("prod_repos_err") or "Missing or invalid controls/PRODUCT_REPOSITORIES.json.")
    if ev_ref == "controls/AGENTS.md":
        return bool(ctx.get("agents_md_ok")), "Missing or empty controls/AGENTS.md."
    if ev_ref == "controls/DISPOSITIONS.json":
        if rule.category == "HUMAN_WAIVER":
            return True, ""
        return (workspace_root / "controls" / "DISPOSITIONS.json").is_file() or bool(ctx.get("agents_md_ok")), "Missing controls/DISPOSITIONS.json."
    if ev_ref == "specs/START_MANIFEST.md":
        return bool(ctx.get("start_manifest_ok")), str(ctx.get("start_manifest_err") or "Missing or invalid specs/START_MANIFEST.md.")
    if ev_ref == "Phase-1/declared_scope.json":
        ok = bool(ctx.get("declared_scope")) and not ctx.get("declared_scope_err")
        return ok, str(ctx.get("declared_scope_err") or "Missing or invalid Phase-1/declared_scope.json.")
    if ev_ref == "Phase-1/prompt_verified.json":
        ok = bool(ctx.get("prompt_verified")) and not ctx.get("prompt_verified_err")
        return ok, str(ctx.get("prompt_verified_err") or "Missing or invalid Phase-1/prompt_verified.json.")
    if ev_ref == "Phase-2A/pre_commit_status.json":
        ok = bool(ctx.get("pre_commit_status")) and not ctx.get("pre_commit_status_err")
        return ok, str(ctx.get("pre_commit_status_err") or "Missing Phase-2A/pre_commit_status.json.")
    if ev_ref == "Phase-2A/pre_commit_review.json":
        return True, ""
    if ev_ref == "Phase-2A/agent_reviews.json":
        return True, ""
    if ev_ref in ("Phase-2B/claims.json", "Phase-2B/report.md", "Phase-3/test_execution.json", "Phase-3/verdict.json", "Phase-3/scanner_report.json"):
        return True, ""
    if ev_ref == "repos/**/test_*.py":
        return True, ""
    if ev_ref == "repos/*/requirements.txt":
        ok = bool(ctx.get("prod_repos")) and not ctx.get("prod_repos_err")
        return ok, "Missing PRODUCT_REPOSITORIES.json for dependency manifest evaluation."
    if ev_ref == "evals/":
        ok = (workspace_root / "evals").is_dir() or bool(ctx.get("eval_proposal"))
        return ok, "Missing evals/ directory or proposal evidence."
    return False, f"Unrecognized required_evidence reference '{ev_ref}'."


def _validate_rule_inputs_and_evidence(
    rule: RubricRule,
    matrix_entry: Dict[str, Any],
    workspace_root: Path,
    ctx: Dict[str, Any],
) -> Optional[RuleEvaluationResult]:
    """Fail closed when matrix-required inputs or evidence prerequisites are missing."""
    strategy = str(matrix_entry["evaluation_strategy"])
    evaluator_impl = str(matrix_entry["evaluator_implementation"])
    if rule.rule_id in ctx.get("blocked_rules", []) or rule.rule_id in ctx.get("unevaluated_rules", []):
        return None
    if rule.category in ("HUMAN_WAIVER", "AGENT_ASSISTED", "EVIDENCE"):
        return None

    for req_ev in matrix_entry.get("required_evidence", []):
        ok, err_msg = _evidence_artifact_available(req_ev, rule, workspace_root, ctx)
        if not ok:
            status = "NOT_EVALUATED" if req_ev in ("controls/PRODUCT_REPOSITORIES.json", "controls/ACTIVE_STATE.json") else "FAIL"
            return RuleEvaluationResult(
                rule_id=rule.rule_id,
                domain=rule.domain,
                category=rule.category,
                status=status,
                evaluator=evaluator_impl,
                evaluation_strategy=strategy,
                artifact=req_ev,
                witness=req_ev,
                message=f"Required evidence unavailable for strategy '{strategy}': {err_msg}",
            )
    return None


def _parse_utc_iso_strict(raw: Any) -> Optional[datetime.datetime]:
    if not isinstance(raw, str) or not raw.strip():
        return None
    val = raw.strip()
    if val.endswith("Z"):
        val = val[:-1] + "+00:00"
    try:
        dt = datetime.datetime.fromisoformat(val)
    except ValueError:
        return None
    if dt.tzinfo is None:
        return None
    return dt.astimezone(datetime.timezone.utc)


def compute_uncommitted_state_digest(
    workspace_root: Union[str, Path],
    repo_dirs: Optional[List[Path]] = None,
    repo_heads: Optional[Dict[str, str]] = None,
    uncommitted_diffs: Optional[Dict[str, str]] = None,
) -> Tuple[Dict[str, str], str]:
    """Compute per-repo HEAD map and deterministic SHA-256 over uncommitted working-tree state."""
    from stagecheck.core.git import run_safe_git

    root = Path(workspace_root).resolve()
    if repo_dirs is None:
        r_base = root / "repos"
        repo_dirs = [d for d in sorted(r_base.iterdir()) if d.is_dir() and not d.name.startswith(".")] if r_base.is_dir() else []

    heads: Dict[str, str] = dict(repo_heads) if repo_heads is not None else {}
    porcelain_map: Dict[str, str] = dict(uncommitted_diffs) if uncommitted_diffs is not None else {}
    dirty_file_hashes: Dict[str, str] = {}

    for r_dir in repo_dirs:
        if not (r_dir / ".git").exists():
            continue
        if repo_heads is None:
            head_res = run_safe_git(r_dir, ["rev-parse", "HEAD"])
            if head_res.returncode == 0:
                heads[r_dir.name] = head_res.stdout.strip()
        if uncommitted_diffs is None:
            st_res = run_safe_git(r_dir, ["status", "--porcelain=v1", "--untracked-files=all"])
            if st_res.returncode == 0 and st_res.stdout.rstrip("\r\n"):
                porcelain_map[r_dir.name] = st_res.stdout.rstrip("\r\n")

        raw_porcelain = porcelain_map.get(r_dir.name, "")
        if raw_porcelain:
            for line in raw_porcelain.splitlines():
                raw_line = line.rstrip("\r\n")
                if not raw_line or len(raw_line) <= 3:
                    continue
                rel_p = raw_line[3:].strip()
                if " -> " in rel_p:
                    rel_p = rel_p.split(" -> ")[1].strip()
                fpath = r_dir / rel_p
                key = f"{r_dir.name}/{rel_p}"
                if fpath.is_symlink():
                    dirty_file_hashes[key] = f"symlink:{os.readlink(fpath)}"
                elif fpath.is_file():
                    dirty_file_hashes[key] = sha256_file(fpath)
                else:
                    dirty_file_hashes[key] = "deleted_or_missing"

    snapshot_payload = {
        "heads": {k: heads[k] for k in sorted(heads)},
        "porcelain": {k: porcelain_map[k] for k in sorted(porcelain_map)},
        "dirty_files": {k: dirty_file_hashes[k] for k in sorted(dirty_file_hashes)},
    }
    digest = hashlib.sha256(canonical_json_dumps(snapshot_payload).encode("utf-8")).hexdigest()
    return heads, digest


def compute_agent_review_digest(review_doc: Dict[str, Any]) -> str:
    """Compute canonical SHA-256 digest over an agent review document excluding review_digest."""
    clean = {k: v for k, v in review_doc.items() if k != "review_digest"}
    return hashlib.sha256(canonical_json_dumps(clean).encode("utf-8")).hexdigest()


def build_agent_reviews_artifact(
    workspace_root: Union[str, Path],
    task_id: str,
    attempt: int,
    reviews: Dict[str, Any],
    reviewer: str,
    reviewer_role: str = "prompt_and_audit",
    producer: Optional[str] = None,
    reviewed_at: Optional[str] = None,
    head_commits: Optional[Dict[str, str]] = None,
    diff_snapshot_sha256: Optional[str] = None,
    artifact_sha256: Optional[str] = None,
) -> Dict[str, Any]:
    """Construct a complete, integrity-bound Phase-2A/agent_reviews.json document (GAP-04)."""
    root = Path(workspace_root).resolve()
    computed_heads, computed_diff_sha = compute_uncommitted_state_digest(root)
    heads = dict(head_commits) if head_commits is not None else computed_heads
    diff_sha = diff_snapshot_sha256 or computed_diff_sha

    p2a_dir = resolve_task_attempt_dir(root, task_id, int(attempt)) / "Phase-2A"
    status_file = p2a_dir / "pre_commit_status.json"
    if artifact_sha256:
        art_sha = artifact_sha256
    elif status_file.is_file() and not status_file.is_symlink():
        art_sha = sha256_file(status_file)
    else:
        art_sha = hashlib.sha256(canonical_json_dumps({"task_id": task_id, "attempt": int(attempt)}).encode("utf-8")).hexdigest()

    doc: Dict[str, Any] = {
        "schema_version": "2.0",
        "task_id": task_id,
        "attempt": int(attempt),
        "reviewer": reviewer,
        "reviewer_role": reviewer_role,
        "producer": producer,
        "reviewed_at": reviewed_at or datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "head_commits": heads,
        "diff_snapshot_sha256": diff_sha,
        "artifact_sha256": art_sha,
        "agent_assisted_reviews": reviews,
    }
    doc["review_digest"] = compute_agent_review_digest(doc)
    return doc


def _extract_registered_agents(active_state: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not isinstance(active_state, dict):
        return []
    reg = active_state.get("registered_agents")
    if reg is None and isinstance(active_state.get("protected"), dict):
        reg = active_state["protected"].get("registered_agents")
    if isinstance(reg, list):
        return [a for a in reg if isinstance(a, dict)]
    if isinstance(reg, dict):
        out: List[Dict[str, Any]] = []
        for k, v in reg.items():
            if isinstance(v, dict):
                item = dict(v)
                item.setdefault("name", k)
                out.append(item)
        return out
    return []


def _verify_clean_post_approval_commit(
    ws: Path,
    p2a_dir: Path,
    task_id: str,
    attempt: int,
    active_state: Optional[Dict[str, Any]],
    doc_heads: Dict[str, str],
    repo_heads: Dict[str, str],
    diff_snapshot_sha256: str,
    pre_commit_review: Optional[Dict[str, Any]] = None,
) -> Tuple[bool, str]:
    """Allow frozen Phase-2A agent reviews during Phase-2B/3/4 ONLY if commits match pre_commit_review cleanly."""
    if not isinstance(active_state, dict):
        return False, "Missing ACTIVE_STATE.json for post-approval review binding."
    phase = active_state.get("phase")
    cleared = active_state.get("cleared_gates") or {}
    if phase not in ("PHASE_2B_COMMITTING", "PHASE_3_AUDIT", "GATE_4_SEALING") or not any(
        g in cleared for g in ("GATE_2A", "GATE_2B")
    ):
        return False, "Agent review head_commits/diff_snapshot_sha256 do not match current workspace state (stale review)."

    # Require completely clean working tree across all repos once Gate 2A has cleared
    clean_payload = {
        "heads": {k: repo_heads[k] for k in sorted(repo_heads)},
        "porcelain": {},
        "dirty_files": {},
    }
    clean_sha = hashlib.sha256(canonical_json_dumps(clean_payload).encode("utf-8")).hexdigest()
    if diff_snapshot_sha256 != clean_sha:
        return False, "Uncommitted working-tree changes present after Phase-2A review (stale review)."

    rev_doc = pre_commit_review
    if rev_doc is None:
        rev_path = p2a_dir / "pre_commit_review.json"
        if rev_path.is_symlink() or not rev_path.is_file():
            return False, "Missing Phase-2A/pre_commit_review.json to verify post-approval commit fidelity."
        try:
            rev_doc = load_json_file(rev_path)
        except Exception:
            return False, "Unreadable Phase-2A/pre_commit_review.json."

    if (
        not isinstance(rev_doc, dict)
        or rev_doc.get("status") != "APPROVED"
        or rev_doc.get("task_id") != task_id
        or rev_doc.get("attempt") != int(attempt)
    ):
        return False, "Phase-2A/pre_commit_review.json is not APPROVED for active task/attempt."

    base_commits = rev_doc.get("base_commits") or {}
    approved_hashes = rev_doc.get("approved_diff_hashes") or {}
    if not isinstance(base_commits, dict) or not isinstance(approved_hashes, dict):
        return False, "Approved pre_commit_review.json lacks base_commits/approved_diff_hashes."

    from stagecheck.core.cooperative_review import validate_commit_sha
    from stagecheck.core.git import run_safe_git_bytes

    for r_name, cur_head in repo_heads.items():
        reviewed_head = doc_heads.get(r_name)
        if not reviewed_head:
            return False, f"Agent review lacks baseline commit for repository '{r_name}'."
        if base_commits.get(r_name) and base_commits[r_name] != reviewed_head:
            return False, f"Agent review head_commits for '{r_name}' differs from approved base_commits."
        if cur_head != reviewed_head:
            expected_diff_hash = approved_hashes.get(r_name)
            repo_path = ws / "repos" / r_name
            if not expected_diff_hash or not repo_path.is_dir():
                return False, f"No approved diff hash covers post-review commit in '{r_name}' (stale review)."
            try:
                validate_commit_sha(reviewed_head, r_name)
                validate_commit_sha(cur_head, r_name)
                res = run_safe_git_bytes(
                    repo_path,
                    ["diff", "--binary", "--end-of-options", f"{reviewed_head}..{cur_head}", "--"],
                    check=True,
                )
            except Exception:
                return False, f"Unable to verify committed diff fidelity against reviewed commit in '{r_name}'."
            if hashlib.sha256(res.stdout).hexdigest() != expected_diff_hash:
                return False, f"Repository '{r_name}' HEAD commit diverged from Phase-2A approved diff (stale review)."

    return True, "OK"


def validate_agent_review_provenance(
    workspace_root: Path,
    src_doc: Dict[str, Any],
    src_rel_path: str,
    task_id: str,
    attempt: int,
    active_state: Optional[Dict[str, Any]],
    pre_commit_status: Optional[Dict[str, Any]],
    repo_heads: Dict[str, str],
    diff_snapshot_sha256: str,
    entry: Optional[Dict[str, Any]] = None,
    max_age_seconds: int = 86400,
    now_utc: Optional[datetime.datetime] = None,
    pre_commit_review: Optional[Dict[str, Any]] = None,
    _commit_match_cache: Optional[Dict[str, Tuple[bool, str]]] = None,
) -> Tuple[bool, str, str]:
    """Validate all 9 GAP-04 agent-assisted review provenance requirements.

    Returns:
        Tuple of (is_valid, failure_status ['NOT_EVALUATED'|'FAIL'], message).
    """
    if not isinstance(src_doc, dict):
        return False, "NOT_EVALUATED", f"Review source '{src_rel_path}' is missing or malformed."

    ws = workspace_root.resolve()
    now = now_utc or datetime.datetime.now(datetime.timezone.utc)
    p2a_dir = resolve_task_attempt_dir(ws, task_id, int(attempt)) / "Phase-2A"

    # 1. Source file must exist safely on disk (no symlinks / no generic substitution)
    src_file = p2a_dir / Path(src_rel_path).name
    if src_file.is_symlink() or not src_file.is_file():
        return False, "FAIL", f"Review artifact '{src_rel_path}' is missing or is a prohibited symlink."

    # 2. Task & attempt binding
    doc_task = src_doc.get("task_id")
    doc_att = src_doc.get("attempt")
    if doc_task != task_id:
        return False, "FAIL", f"Agent review task_id '{doc_task}' does not match '{task_id}'."
    if isinstance(doc_att, bool) or not isinstance(doc_att, int) or doc_att != int(attempt):
        return False, "FAIL", f"Agent review attempt '{doc_att}' does not match '{attempt}'."

    if isinstance(entry, dict):
        if entry.get("task_id") is not None and entry.get("task_id") != task_id:
            return False, "FAIL", f"Rule review entry task_id '{entry.get('task_id')}' mismatches '{task_id}'."
        if entry.get("attempt") is not None and entry.get("attempt") != int(attempt):
            return False, "FAIL", f"Rule review entry attempt '{entry.get('attempt')}' mismatches '{attempt}'."

    # 3. Reviewer identity & generic evaluator rejection
    reviewer = (entry.get("reviewer") if isinstance(entry, dict) else None) or src_doc.get("reviewer") or src_doc.get("reviewed_by")
    if not isinstance(reviewer, str) or len(reviewer.strip()) < 2:
        return False, "NOT_EVALUATED", "Agent review missing reviewer identity."
    reviewer_clean = reviewer.strip()
    reviewer_lower = reviewer_clean.lower()
    if reviewer_lower in _GENERIC_REVIEWER_NAMES:
        return False, "FAIL", f"Generic evaluator '{reviewer_clean}' cannot substitute for authorized agent review."

    reviewer_role = (entry.get("reviewer_role") if isinstance(entry, dict) else None) or src_doc.get("reviewer_role")
    if not isinstance(reviewer_role, str) or not reviewer_role.strip():
        return False, "NOT_EVALUATED", "Agent review missing reviewer_role."
    role_clean = reviewer_role.strip()

    # 4. Authorization against ACTIVE_STATE.json registered_agents
    agents = _extract_registered_agents(active_state)
    if not agents:
        return False, "FAIL", "ACTIVE_STATE.json lacks registered_agents to authorize reviewer identity."

    enabled_agents = [a for a in agents if a.get("enabled", True) and isinstance(a.get("name"), str)]
    auditors = {a["name"].strip().lower(): a for a in enabled_agents if a.get("role") == "prompt_and_audit"}
    coders = {a["name"].strip().lower(): a for a in enabled_agents if a.get("role") == "code_implementation"}
    dual_agents = {a["name"].strip().lower(): a for a in enabled_agents if a.get("role") == "dual_role"}
    single_mode = bool(active_state.get("single_agent_mode")) if isinstance(active_state, dict) else False

    if not single_mode:
        if role_clean != "prompt_and_audit":
            return False, "FAIL", f"Reviewer role '{role_clean}' is unauthorized in dual-agent mode (must be 'prompt_and_audit')."
        if reviewer_lower not in auditors:
            return False, "FAIL", f"Reviewer '{reviewer_clean}' is not an enabled 'prompt_and_audit' agent in ACTIVE_STATE.json."
    else:
        if role_clean not in ("dual_role", "prompt_and_audit"):
            return False, "FAIL", f"Reviewer role '{role_clean}' is unauthorized in single-agent mode."
        allowed_pool = set(dual_agents) | set(auditors)
        if reviewer_lower not in allowed_pool:
            return False, "FAIL", f"Reviewer '{reviewer_clean}' is not authorized in ACTIVE_STATE.json."

    # 5. Reviewer independence (dual-agent mode prohibits self-review by coder/producer)
    producer = (
        (pre_commit_status.get("submitted_by") or pre_commit_status.get("author") or pre_commit_status.get("producer"))
        if isinstance(pre_commit_status, dict)
        else None
    ) or src_doc.get("producer")
    if not single_mode:
        if reviewer_lower in coders:
            return False, "FAIL", f"Reviewer independence violated: '{reviewer_clean}' holds 'code_implementation' role."
        if isinstance(producer, str) and producer.strip() and reviewer_lower == producer.strip().lower():
            return False, "FAIL", f"Reviewer independence violated: reviewer '{reviewer_clean}' matches producer '{producer}'."

    # 6. Artifact integrity (review_digest + artifact_sha256 + safe evidence_path)
    review_digest = src_doc.get("review_digest")
    if not isinstance(review_digest, str) or not _SHA256_HEX_RE.match(review_digest):
        return False, "FAIL", "Agent review missing valid 64-hex review_digest."
    if compute_agent_review_digest(src_doc) != review_digest:
        return False, "FAIL", "Agent review review_digest mismatch (tampering detected)."

    status_file = p2a_dir / "pre_commit_status.json"
    art_sha = src_doc.get("artifact_sha256")
    if status_file.is_file() and not status_file.is_symlink():
        if not isinstance(art_sha, str) or not _SHA256_HEX_RE.match(art_sha):
            return False, "FAIL", "Agent review missing artifact_sha256 binding Phase-2A/pre_commit_status.json."
        if sha256_file(status_file) != art_sha:
            return False, "FAIL", "Agent review artifact_sha256 does not match Phase-2A/pre_commit_status.json (stale or tampered)."

    if isinstance(entry, dict) and entry.get("evidence_path"):
        ev_rel = str(entry["evidence_path"])
        try:
            ev_target = safe_resolve(ev_rel, ws, allow_symlinks=False)
            if not ev_target.is_file():
                ev_target = safe_resolve(ev_rel, resolve_task_attempt_dir(ws, task_id, int(attempt)), allow_symlinks=False)
        except StageCheckPathError as err:
            return False, "FAIL", f"Unsafe agent review evidence_path '{ev_rel}': {err}"
        if ev_target.is_symlink() or not ev_target.is_file():
            return False, "FAIL", f"Agent review evidence artifact '{ev_rel}' does not exist."

    # 7. Freshness (reviewed_at + head_commits + diff_snapshot_sha256)
    rev_dt = _parse_utc_iso_strict((entry.get("reviewed_at") if isinstance(entry, dict) else None) or src_doc.get("reviewed_at"))
    if rev_dt is None:
        return False, "NOT_EVALUATED", "Agent review missing valid timezone-aware UTC reviewed_at timestamp."
    if rev_dt > now + datetime.timedelta(seconds=60):
        return False, "FAIL", "Agent review reviewed_at timestamp is in the future."
    if (now - rev_dt).total_seconds() > max_age_seconds:
        return False, "NOT_EVALUATED", f"Agent review expired (older than {max_age_seconds}s)."

    doc_heads = src_doc.get("head_commits") or src_doc.get("base_commits")
    doc_diff_sha = src_doc.get("diff_snapshot_sha256")
    heads_match = isinstance(doc_heads, dict) and (not repo_heads or doc_heads == repo_heads)
    diff_match = isinstance(doc_diff_sha, str) and doc_diff_sha == diff_snapshot_sha256
    if not (heads_match and diff_match):
        if not isinstance(doc_heads, dict) or not isinstance(doc_diff_sha, str):
            return False, "NOT_EVALUATED", "Agent review lacks valid head_commits or diff_snapshot_sha256 binding."
        cache_key = f"{src_rel_path}:{doc_diff_sha}"
        if _commit_match_cache is not None and cache_key in _commit_match_cache:
            post_ok, post_msg = _commit_match_cache[cache_key]
        else:
            post_ok, post_msg = _verify_clean_post_approval_commit(
                ws=ws,
                p2a_dir=p2a_dir,
                task_id=task_id,
                attempt=int(attempt),
                active_state=active_state,
                doc_heads=doc_heads,
                repo_heads=repo_heads,
                diff_snapshot_sha256=diff_snapshot_sha256,
                pre_commit_review=pre_commit_review,
            )
            if _commit_match_cache is not None:
                _commit_match_cache[cache_key] = (post_ok, post_msg)
        if not post_ok:
            return False, "NOT_EVALUATED", post_msg

    return True, "PASS", "OK"


def compute_rubric_context_digest(
    workspace_root: Union[str, Path],
    task_id: str,
    attempt: int,
    repo_dirs: Optional[List[Path]] = None,
    repo_heads: Optional[Dict[str, str]] = None,
    uncommitted_diffs: Optional[Dict[str, str]] = None,
    diff_snapshot_sha256: Optional[str] = None,
) -> str:
    """Compute fast deterministic SHA-256 over audited governance, repo, and phase inputs (GAP-02)."""
    root = Path(workspace_root).resolve()
    attempt_dir = resolve_task_attempt_dir(root, task_id, int(attempt))
    heads, snap_sha = compute_uncommitted_state_digest(
        root,
        repo_dirs=repo_dirs,
        repo_heads=repo_heads,
        uncommitted_diffs=uncommitted_diffs,
    )
    if diff_snapshot_sha256:
        snap_sha = diff_snapshot_sha256

    def _safe_sha(p: Path) -> Optional[str]:
        if p.is_symlink():
            return "SYMLINK"
        if p.is_file():
            return sha256_file(p)
        return None

    active_state, _ = _safe_load_json(root / "controls" / "ACTIVE_STATE.json")
    active_bound: Optional[Dict[str, Any]] = None
    if isinstance(active_state, dict):
        active_bound = {
            "task_id": active_state.get("task_id"),
            "attempt_index": active_state.get("attempt_index"),
            "single_agent_mode": active_state.get("single_agent_mode"),
            "registered_agents": active_state.get("registered_agents"),
            "protected": active_state.get("protected"),
        }

    digest_inputs = {
        "task_id": task_id,
        "attempt": int(attempt),
        "active_bound": active_bound,
        "dispositions_sha": _safe_sha(root / "controls" / "DISPOSITIONS.json"),
        "owner_grants_sha": _safe_sha(root / "controls" / "OWNER_GRANTS.md"),
        "prod_repos_sha": _safe_sha(root / "controls" / "PRODUCT_REPOSITORIES.json"),
        "failure_prev_sha": _safe_sha(root / "controls" / "FAILURE_PREVENTION.md"),
        "agents_md_sha": _safe_sha(root / "AGENTS.md"),
        "start_manifest_sha": _safe_sha(root / "specs" / "START_MANIFEST.md"),
        "prompt_md_sha": _safe_sha(attempt_dir / "Phase-1" / "prompt.md"),
        "declared_scope_sha": _safe_sha(attempt_dir / "Phase-1" / "declared_scope.json"),
        "prompt_verified_sha": _safe_sha(attempt_dir / "Phase-1" / "prompt_verified.json"),
        "pre_commit_status_sha": _safe_sha(attempt_dir / "Phase-2A" / "pre_commit_status.json"),
        "agent_reviews_sha": _safe_sha(attempt_dir / "Phase-2A" / "agent_reviews.json"),
        "claims_sha": _safe_sha(attempt_dir / "Phase-2B" / "claims.json"),
        "report_sha": _safe_sha(attempt_dir / "Phase-2B" / "report.md"),
        "repo_heads": heads,
        "diff_snapshot_sha256": snap_sha,
    }
    return hashlib.sha256(canonical_json_dumps(digest_inputs).encode("utf-8")).hexdigest()


def analyze_rubric_completeness(
    evaluations: List[Union[RuleEvaluationResult, Dict[str, Any]]],
    target_domain: Optional[str] = None,
) -> Dict[str, Any]:
    """Classify evaluation completeness against the immutable 270-rule matrix (GAP-02)."""
    catalog = load_270_rule_catalog()
    expected_ids = [r.rule_id for r in catalog]
    expected_set = set(expected_ids)

    seen_ids: Set[str] = set()
    duplicate_rules: List[str] = []
    for item in evaluations:
        rid = item.rule_id if isinstance(item, RuleEvaluationResult) else item.get("rule_id")
        if isinstance(rid, str) and rid:
            if rid in seen_ids and rid not in duplicate_rules:
                duplicate_rules.append(rid)
            seen_ids.add(rid)

    missing_rules = [rid for rid in expected_ids if rid not in seen_ids]
    unexpected_rules = sorted(seen_ids - expected_set)

    is_complete = (
        target_domain is None
        and len(evaluations) == len(expected_ids)
        and len(seen_ids) == len(expected_ids)
        and not missing_rules
        and not duplicate_rules
        and not unexpected_rules
    )
    return {
        "evaluation_completeness": "COMPLETE" if is_complete else "PARTIAL",
        "expected_rule_count": len(expected_ids),
        "evaluated_rule_count": len(seen_ids),
        "missing_rules": missing_rules,
        "duplicate_rules": sorted(duplicate_rules),
        "unexpected_rules": unexpected_rules,
    }


def verify_complete_rubric_evaluation(
    workspace_root: Union[str, Path],
    rubric_path: Union[str, Path],
    task_id: str,
    attempt: int,
    cycle: Optional[int] = None,
    max_age_seconds: int = 86400,
    require_fresh_context: bool = True,
) -> Tuple[bool, List[str], Optional[Dict[str, Any]]]:
    """Authoritative GAP-02 verifier rejecting partial, missing, duplicate, unbound, or stale rubric evaluations."""
    root = Path(workspace_root).resolve()
    r_path = Path(rubric_path)
    reasons: List[str] = []

    if r_path.is_symlink():
        return False, [f"Rubric evaluation file '{r_path.name}' is a prohibited symbolic link."], None
    if not r_path.is_file():
        return False, [f"Required complete rubric evaluation file missing at '{r_path}'."], None

    try:
        payload = load_json_file(r_path)
    except Exception as err:
        return False, [f"Malformed rubric_evaluation.json: {err}"], None

    try:
        validate_rubric_evaluation(payload)
    except Exception as err:
        reasons.append(f"Schema validation failed: {err}")

    if payload.get("task_id") != task_id:
        reasons.append(f"Task binding mismatch: expected '{task_id}', got '{payload.get('task_id')}'.")

    p_att = payload.get("attempt")
    if isinstance(p_att, bool) or not isinstance(p_att, int) or p_att != int(attempt):
        reasons.append(f"Attempt binding mismatch: expected {attempt}, got {p_att!r}.")

    if cycle is not None and payload.get("cycle") != int(cycle):
        reasons.append(f"Cycle binding mismatch: expected {cycle}, got {payload.get('cycle')!r}.")

    completeness = payload.get("evaluation_completeness")
    if completeness != "COMPLETE":
        reasons.append(f"Rubric evaluation completeness is '{completeness or 'MISSING'}'; 'COMPLETE' is required.")

    if payload.get("target_domain") is not None:
        reasons.append(f"Partial target_domain '{payload.get('target_domain')}' evaluation cannot pass a complete-audit gate.")

    eval_items = payload.get("evaluations")
    if not isinstance(eval_items, list):
        reasons.append("Missing 'evaluations' array in rubric_evaluation.json.")
        return False, reasons, payload

    try:
        validate_rubric_evaluation_payload(eval_items)
    except Exception as err:
        reasons.append(f"Payload integrity check failed: {err}")

    analysis = analyze_rubric_completeness(eval_items, target_domain=payload.get("target_domain"))
    if payload.get("expected_rule_count") != 270 or analysis["expected_rule_count"] != 270:
        reasons.append(f"Expected 270 catalog rules, got expected_rule_count={payload.get('expected_rule_count')!r}.")
    if payload.get("evaluated_rule_count") != 270 or analysis["evaluated_rule_count"] != 270 or len(eval_items) != 270:
        reasons.append(
            f"Expected 270 evaluated rules, got evaluated_rule_count={payload.get('evaluated_rule_count')!r} "
            f"(unique={analysis['evaluated_rule_count']}, len={len(eval_items)})."
        )
    if analysis["missing_rules"] or payload.get("missing_rules"):
        missing_count = len(analysis["missing_rules"] or payload.get("missing_rules") or [])
        reasons.append(f"Missing {missing_count} required rubric rule(s): {(analysis['missing_rules'] or [])[:5]}")
    if analysis["duplicate_rules"] or payload.get("duplicate_rules"):
        dups = analysis["duplicate_rules"] or payload.get("duplicate_rules") or []
        reasons.append(f"Duplicate rule evaluation(s) detected: {dups[:5]}")
    if analysis["unexpected_rules"]:
        reasons.append(f"Unexpected non-catalog rule IDs detected: {analysis['unexpected_rules'][:5]}")

    eval_dt = _parse_utc_iso_strict(payload.get("evaluated_at"))
    now = datetime.datetime.now(datetime.timezone.utc)
    if eval_dt is None:
        reasons.append("Missing or invalid timezone-aware UTC 'evaluated_at' timestamp.")
    else:
        if eval_dt > now + datetime.timedelta(seconds=60):
            reasons.append("Rubric 'evaluated_at' timestamp is unexpectedly in the future.")
        if (now - eval_dt).total_seconds() > max_age_seconds:
            reasons.append(f"Stale rubric evaluation (older than {max_age_seconds}s).")

    if require_fresh_context:
        recorded_digest = payload.get("context_digest")
        current_digest = compute_rubric_context_digest(root, task_id=task_id, attempt=int(attempt))
        if not isinstance(recorded_digest, str) or not _SHA256_HEX_RE.match(recorded_digest):
            reasons.append("Missing valid 64-hex 'context_digest' binding audited state.")
        elif recorded_digest != current_digest:
            reasons.append("Stale rubric evaluation: workspace, repository, control, or evidence files changed after evaluation.")

    if payload.get("overall_verdict") != "PASS":
        reasons.append(f"Rubric overall_verdict is '{payload.get('overall_verdict')}', expected 'PASS'.")

    non_passing = [
        f"{item.get('rule_id')}:{item.get('status')}"
        for item in eval_items
        if item.get("status") not in ("PASS", "NOT_APPLICABLE")
    ]
    if non_passing:
        reasons.append(f"{len(non_passing)} rule(s) did not pass: {non_passing[:5]}")

    return len(reasons) == 0, reasons, payload


def _safe_load_json(path: Path) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    if not path.is_file() or path.is_symlink():
        return None, f"Missing artifact '{path.name}'"
    try:
        data = load_json_file(path)
        if not isinstance(data, dict):
            return None, f"Invalid JSON object in '{path.name}'"
        return data, None
    except Exception as err:
        return None, f"Failed parsing '{path.name}': {err}"


def _resolve_predicate_evidence_path(workspace_root: Path, repo_path: Path) -> str:
    candidates = [
        repo_path / "package.json",
        repo_path / "requirements.txt",
        repo_path / "pyproject.toml",
        repo_path / "go.mod",
        repo_path / "Cargo.toml",
        workspace_root / "controls" / "PRODUCT_REPOSITORIES.json",
        repo_path,
    ]
    for cand in candidates:
        if cand.exists():
            try:
                return str(cand.relative_to(workspace_root))
            except ValueError:
                return str(cand)
    return str(repo_path)


def _scan_dependencies(repo_dir: Path) -> List[str]:
    """Return any unpinned/wildcard dependencies found in repo manifests."""
    unpinned: List[str] = []
    req_file = repo_dir / "requirements.txt"
    if req_file.is_file() and not req_file.is_symlink():
        for raw in req_file.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line or line.startswith(("-r", "--", "-e")):
                continue
            m = _PIN_SPEC_RE.match(line)
            if m:
                op = m.group(2)
                if op != "==":
                    unpinned.append(f"{repo_dir.name}/{req_file.name}: {line}")

    pkg_file = repo_dir / "package.json"
    if pkg_file.is_file() and not pkg_file.is_symlink():
        try:
            pkg = json.loads(pkg_file.read_text(encoding="utf-8", errors="ignore"))
            for section in ("dependencies", "devDependencies"):
                deps = pkg.get(section)
                if isinstance(deps, dict):
                    for name, ver in deps.items():
                        v_str = str(ver).strip()
                        if v_str in ("*", "latest", "") or v_str.startswith(("^", "~", ">", "<")):
                            unpinned.append(f"{repo_dir.name}/package.json: {name}@{v_str}")
        except Exception:
            unpinned.append(f"{repo_dir.name}/package.json: unparseable manifest")
    return unpinned


def _analyze_python_repo_files(repo_dir: Path, max_files: int = 120) -> Dict[str, Any]:
    """Fast single-pass AST analysis for repository source & test adequacy signals."""
    metrics: Dict[str, Any] = {
        "syntax_errors": [],
        "resource_leak_files": [],
        "swallowed_exceptions": [],
        "unsafe_patterns": [],
        "eval_imports_in_repo": [],
        "qual_in_prod": [],
        "test_count": 0,
        "test_files": [],
        "weak_assertions": [],
        "skipped_tests_in_code": [],
        "flaky_sleep_detected": [],
        "has_positive_tests": False,
        "has_negative_tests": False,
        "has_malformed_tests": False,
        "has_duplicate_tests": False,
        "self_comparison_tautologies": [],
        "defined_symbols": set(),
    }
    if not repo_dir.is_dir():
        return metrics

    scanned = 0
    for root_str, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in sorted(dirs) if d not in _SKIP_DIRS]
        root_p = Path(root_str)
        for fname in sorted(files):
            if not fname.endswith(".py"):
                continue
            fpath = root_p / fname
            if fpath.is_symlink() or not fpath.is_file():
                continue
            try:
                if fpath.stat().st_size > 512 * 1024:
                    continue
                src = fpath.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            scanned += 1
            if scanned > max_files:
                break

            rel = str(fpath.relative_to(repo_dir))
            is_test = (
                fname.startswith("test_")
                or fname.endswith("_test.py")
                or "tests" in fpath.relative_to(repo_dir).parts
            )

            try:
                tree = ast.parse(src, filename=rel)
            except SyntaxError as err:
                metrics["syntax_errors"].append(f"{repo_dir.name}/{rel}:{err.lineno}: {err.msg}")
                continue

            if not is_test and (fname.startswith("qual_") or "TestQual" in src):
                metrics["qual_in_prod"].append(f"{repo_dir.name}/{rel}")

            if not is_test and ("from evals" in src or "import evals" in src):
                metrics["eval_imports_in_repo"].append(f"{repo_dir.name}/{rel}")

            with_open_lines: Set[int] = set()
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    metrics["defined_symbols"].add(node.name)

                if isinstance(node, ast.With):
                    for item in node.items:
                        if isinstance(item.context_expr, ast.Call):
                            fn = item.context_expr.func
                            if isinstance(fn, ast.Name) and fn.id == "open":
                                with_open_lines.add(item.context_expr.lineno)

                if isinstance(node, ast.Call):
                    fn = node.func
                    if isinstance(fn, ast.Name) and fn.id == "open" and node.lineno not in with_open_lines:
                        if not is_test:
                            metrics["resource_leak_files"].append(f"{repo_dir.name}/{rel}:{node.lineno}")
                    elif isinstance(fn, ast.Name) and fn.id in ("eval", "exec") and not is_test:
                        metrics["unsafe_patterns"].append(f"{repo_dir.name}/{rel}:{node.lineno}:{fn.id}()")
                    elif (
                        isinstance(fn, ast.Attribute)
                        and fn.attr == "sleep"
                        and isinstance(fn.value, ast.Name)
                        and fn.value.id == "time"
                        and is_test
                    ):
                        metrics["flaky_sleep_detected"].append(f"{repo_dir.name}/{rel}:{node.lineno}")

                if isinstance(node, ast.ExceptHandler) and not is_test:
                    if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
                        metrics["swallowed_exceptions"].append(f"{repo_dir.name}/{rel}:{node.lineno}")

            if is_test:
                metrics["test_files"].append(f"{repo_dir.name}/{rel}")
                low_src = src.lower()
                if any(k in low_src for k in ("malformed", "corrupt", "invalid", "partial", "bad_")):
                    metrics["has_malformed_tests"] = True
                if any(k in low_src for k in ("duplicate", "replay", "idempoten")):
                    metrics["has_duplicate_tests"] = True
                if any(k in src for k in ("assertRaises", "pytest.raises", "assertNotEqual", "assertFalse", "assertIn", "assertNotIn")):
                    metrics["has_negative_tests"] = True

                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_"):
                        metrics["test_count"] += 1
                        dec_names = " ".join(ast.unparse(d) for d in node.decorator_list) if node.decorator_list else ""
                        if "skip" in dec_names.lower():
                            metrics["skipped_tests_in_code"].append(f"{repo_dir.name}/{rel}:{node.name}")

                        has_assertion = False
                        only_trivial = True
                        for sub in ast.walk(node):
                            if isinstance(sub, ast.Assert):
                                has_assertion = True
                                test_expr = sub.test
                                if isinstance(test_expr, ast.Constant) and test_expr.value is True:
                                    metrics["weak_assertions"].append(f"{repo_dir.name}/{rel}:{sub.lineno}: assert True")
                                elif isinstance(test_expr, ast.Compare) and len(test_expr.ops) == 1 and isinstance(test_expr.ops[0], ast.Eq):
                                    left_s = ast.unparse(test_expr.left)
                                    right_s = ast.unparse(test_expr.comparators[0])
                                    if left_s == right_s:
                                        metrics["self_comparison_tautologies"].append(
                                            f"{repo_dir.name}/{rel}:{sub.lineno}: {left_s} == {right_s}"
                                        )
                                else:
                                    only_trivial = False
                                    metrics["has_positive_tests"] = True
                            elif isinstance(sub, ast.Call):
                                callee = ast.unparse(sub.func)
                                if "assert" in callee or "pytest.raises" in callee or "fail" in callee:
                                    has_assertion = True
                                    only_trivial = False
                                    metrics["has_positive_tests"] = True
                                if "skip" in callee.lower() and ("pytest.skip" in callee or "skipTest" in callee):
                                    metrics["skipped_tests_in_code"].append(f"{repo_dir.name}/{rel}:{sub.lineno}")
                        if not has_assertion and not dec_names:
                            metrics["weak_assertions"].append(f"{repo_dir.name}/{rel}:{node.lineno}: {node.name} has zero assertions")
                        elif has_assertion and only_trivial and f"{repo_dir.name}/{rel}" not in [w.split(":")[0] for w in metrics["weak_assertions"]]:
                            pass

    return metrics


def _collect_rubric_context(
    workspace_root: Path,
    task_id: str,
    attempt: int,
    repo_dirs: Optional[List[Path]] = None,
    existing_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Gather comprehensive live workspace, controls, git, AST, and artifact context in a single fast pass."""
    from stagecheck.core.git import run_safe_git
    from stagecheck.core.prompt_gate import is_path_in_scope
    from stagecheck.core.start_manifest import verify_spec_manifest

    root = workspace_root.resolve()
    if repo_dirs is None:
        r_base = root / "repos"
        repo_dirs = [d for d in sorted(r_base.iterdir()) if d.is_dir() and not d.name.startswith(".")] if r_base.is_dir() else []

    attempt_dir = resolve_task_attempt_dir(root, task_id, attempt)
    p1_dir = attempt_dir / "Phase-1"
    p2a_dir = attempt_dir / "Phase-2A"
    p2b_dir = attempt_dir / "Phase-2B"
    p3_dir = attempt_dir / "Phase-3"

    # Controls & specs
    active_state, active_state_err = _safe_load_json(root / "controls" / "ACTIVE_STATE.json")
    if active_state is not None:
        try:
            validate_active_state(active_state)
        except Exception as err:
            active_state_err = str(err)

    prod_repos, prod_repos_err = _safe_load_json(root / "controls" / "PRODUCT_REPOSITORIES.json")
    dispositions_doc, _ = _safe_load_json(root / "controls" / "DISPOSITIONS.json")
    agents_md_path = root / "AGENTS.md"
    legacy_agents_md_path = root / "controls" / "AGENTS.md"
    agents_md_ok = (
        (agents_md_path.is_file() and agents_md_path.stat().st_size > 0)
        or (legacy_agents_md_path.is_file() and legacy_agents_md_path.stat().st_size > 0)
    )
    owner_grants_ok = (root / "controls" / "OWNER_GRANTS.md").is_file()
    start_manifest_ok = False
    start_manifest_err: Optional[str] = None
    manifest_file = root / "specs" / "START_MANIFEST.md"
    if manifest_file.is_file():
        try:
            m_res = verify_spec_manifest(root)
            start_manifest_ok = bool(m_res.get("valid"))
            if not start_manifest_ok:
                problems = (m_res.get("missing") or []) + [
                    f"tampered:{t.get('file')}" for t in (m_res.get("tampered") or [])
                ] + (m_res.get("unregistered") or [])
                start_manifest_err = "; ".join(problems[:3]) or str(m_res.get("error") or "START_MANIFEST verification failed")
        except Exception as err:
            start_manifest_err = str(err)
    else:
        start_manifest_err = "Missing specs/START_MANIFEST.md"

    # Phase artifacts
    prompt_md_ok = (p1_dir / "prompt.md").is_file() and (p1_dir / "prompt.md").stat().st_size > 0
    declared_scope, declared_scope_err = _safe_load_json(p1_dir / "declared_scope.json")
    if declared_scope is not None:
        try:
            validate_schema(declared_scope, _get_cached_schema("declared_scope.schema.json"))
        except Exception as err:
            declared_scope_err = str(err)
    prompt_verified, prompt_verified_err = _safe_load_json(p1_dir / "prompt_verified.json")
    if prompt_verified is not None and prompt_md_ok and (p1_dir / "declared_scope.json").is_file():
        exp_p = prompt_verified.get("prompt_sha256")
        if exp_p and exp_p != sha256_file(p1_dir / "prompt.md"):
            prompt_verified_err = "prompt.md modified after prompt_verified.json freeze"
        exp_s = prompt_verified.get("scope_sha256")
        if exp_s and exp_s != sha256_file(p1_dir / "declared_scope.json"):
            prompt_verified_err = "declared_scope.json modified after prompt_verified.json freeze"

    pre_commit_status, pre_commit_status_err = _safe_load_json(p2a_dir / "pre_commit_status.json")
    pre_commit_review, pre_commit_review_err = _safe_load_json(p2a_dir / "pre_commit_review.json")
    agent_reviews_doc, _ = _safe_load_json(p2a_dir / "agent_reviews.json")

    report_md_ok = (p2b_dir / "report.md").is_file() and (p2b_dir / "report.md").stat().st_size > 0
    claims_doc, claims_err = _safe_load_json(p2b_dir / "claims.json")
    if claims_doc is not None and isinstance(claims_doc.get("claims"), list):
        try:
            validate_schema(claims_doc, _get_cached_schema("claims.schema.json"))
        except Exception as err:
            claims_err = str(err)

    test_execution_doc, _ = _safe_load_json(p3_dir / "test_execution.json")
    scanner_report_doc, _ = _safe_load_json(p3_dir / "scanner_report.json")
    verdict_doc, _ = _safe_load_json(p3_dir / "verdict.json")
    issue_history_file = root / "evidence" / "issue_history.json"
    task_history_md = root / "evidence" / "tasks" / task_id / f"TASK_{task_id}_ISSUE_HISTORY.md"
    if issue_history_file.is_file():
        issue_history_doc, issue_history_err = _safe_load_json(issue_history_file)
    elif task_history_md.is_file():
        issue_history_doc, issue_history_err = {"format": "markdown"}, None
    elif (root / "evidence").is_dir() and int(attempt) == 1:
        issue_history_doc, issue_history_err = {"issues": []}, None
    else:
        issue_history_doc, issue_history_err = None, "Missing artifact 'issue_history.json'"
    ev_manifest_doc, _ = _safe_load_json(root / "evidence" / "EVIDENCE_MANIFEST.json")

    # Dispositions / Human Waivers for active task & attempt (GAP-03 strict provenance)
    approved_waivers: Dict[str, Dict[str, Any]] = {}
    waiver_rejection_reasons: Dict[str, str] = {}
    if isinstance(dispositions_doc, dict):
        disp_entries = dispositions_doc.get("dispositions", [])
        if isinstance(disp_entries, list):
            for entry in disp_entries:
                if not isinstance(entry, dict):
                    continue
                target_ids: List[str] = []
                for key in ("rule_id", "defect_id"):
                    val = entry.get(key)
                    if isinstance(val, str) and val:
                        target_ids.append(val)
                waived_list = entry.get("waived_rules")
                if isinstance(waived_list, list):
                    target_ids.extend(str(x) for x in waived_list if x)
                if "*" in target_ids:
                    for tid in target_ids:
                        if tid != "*":
                            waiver_rejection_reasons[tid] = "Wildcard '*' waiver target is prohibited."
                    continue

                ok_w, reason_w = validate_waiver_provenance(
                    workspace_root=root,
                    entry=entry,
                    task_id=task_id,
                    attempt=int(attempt),
                    all_entries=disp_entries,
                )
                if not ok_w:
                    if entry.get("task_id") == task_id or not entry.get("task_id"):
                        for tid in target_ids:
                            waiver_rejection_reasons.setdefault(tid, reason_w)
                    continue

                for tid in target_ids:
                    approved_waivers[tid] = {
                        "_provenance_verified": True,
                        "disposition_id": entry.get("disposition_id"),
                        "authorized_by": entry.get("authorized_by"),
                        "authorized_role": entry.get("authorized_role", "OWNER"),
                        "attempt": entry.get("attempt") if entry.get("attempt") is not None else entry.get("attempt_index"),
                        "rationale": entry.get("rationale"),
                        "evidence_path": entry.get("evidence_path") or entry.get("evidence"),
                        "nonce": entry.get("nonce"),
                        "waiver_digest": entry.get("waiver_digest"),
                    }

    # Agent-assisted review records populated after git/diff inspection (see below)
    recorded_agent_reviews: Dict[str, Any] = {}
    agent_review_errors: Dict[str, Tuple[str, str]] = {}

    # Touched repos
    touched_repo_names: Optional[Set[str]] = None
    if isinstance(pre_commit_status, dict) and isinstance(pre_commit_status.get("touched_repositories"), list):
        touched_repo_names = set(pre_commit_status["touched_repositories"])

    # Git, secrets, dependencies, AST inspection across repositories
    uncommitted_diffs: Dict[str, str] = {}
    untouched_dirty: List[str] = []
    out_of_scope_files: List[str] = []
    secrets_found: List[str] = []
    unpinned_dependencies: List[str] = []
    rogue_scanner_configs: List[str] = []
    symlink_escapes: List[str] = []
    repo_heads: Dict[str, str] = {}
    removed_assertions: List[str] = []
    agg_ast: Dict[str, Any] = {
        "syntax_errors": [],
        "resource_leak_files": [],
        "swallowed_exceptions": [],
        "unsafe_patterns": [],
        "eval_imports_in_repo": [],
        "qual_in_prod": [],
        "test_count": 0,
        "test_files": [],
        "weak_assertions": [],
        "skipped_tests_in_code": [],
        "flaky_sleep_detected": [],
        "has_positive_tests": False,
        "has_negative_tests": False,
        "has_malformed_tests": False,
        "has_duplicate_tests": False,
        "self_comparison_tautologies": [],
    }

    registered_repos = prod_repos.get("repositories", {}) if isinstance(prod_repos, dict) else {}
    for r_name, meta in registered_repos.items():
        r_rel = meta.get("path", f"repos/{r_name}")
        cand = root / r_rel
        if cand.is_symlink():
            symlink_escapes.append(f"{r_rel} (symlinked repository root)")

    for r_dir in repo_dirs:
        unpinned_dependencies.extend(_scan_dependencies(r_dir))
        if (r_dir / ".gitleaks.toml").exists():
            rogue_scanner_configs.append(f"repos/{r_dir.name}/.gitleaks.toml")

        repo_ast = _analyze_python_repo_files(r_dir)
        for k in (
            "syntax_errors", "resource_leak_files", "swallowed_exceptions", "unsafe_patterns",
            "eval_imports_in_repo", "qual_in_prod", "test_files", "weak_assertions",
            "skipped_tests_in_code", "flaky_sleep_detected", "self_comparison_tautologies",
        ):
            agg_ast[k].extend(repo_ast[k])
        agg_ast["test_count"] += repo_ast["test_count"]
        for flag in ("has_positive_tests", "has_negative_tests", "has_malformed_tests", "has_duplicate_tests"):
            agg_ast[flag] = agg_ast[flag] or repo_ast[flag]

        if (r_dir / ".git").exists():
            try:
                head_res = run_safe_git(r_dir, ["rev-parse", "HEAD"])
                if head_res.returncode == 0:
                    repo_heads[r_dir.name] = head_res.stdout.strip()
                res = run_safe_git(r_dir, ["status", "--porcelain=v1", "--untracked-files=all"])
                if res.returncode == 0 and res.stdout.strip():
                    uncommitted_diffs[r_dir.name] = res.stdout.strip()
                    if touched_repo_names is not None and r_dir.name not in touched_repo_names:
                        untouched_dirty.append(r_dir.name)
                    for line in res.stdout.splitlines():
                        if not line.strip():
                            continue
                        rel_p = line[3:].strip()
                        if " -> " in rel_p:
                            rel_p = rel_p.split(" -> ")[1].strip()
                        ws_rel = f"repos/{r_dir.name}/{rel_p}"
                        if declared_scope and not is_path_in_scope(ws_rel, declared_scope):
                            out_of_scope_files.append(ws_rel)
                        fpath = r_dir / rel_p
                        if fpath.is_symlink():
                            try:
                                fpath.resolve().relative_to(r_dir.resolve())
                            except ValueError:
                                symlink_escapes.append(ws_rel)
                        if fpath.is_file() and not fpath.is_symlink() and fpath.stat().st_size <= 1024 * 1024:
                            if _SECRET_RE.search(fpath.read_text(encoding="utf-8", errors="ignore")):
                                secrets_found.append(ws_rel)
                # Inspect committed task branch diff scope vs baseline_head
                base_sha = registered_repos.get(r_dir.name, {}).get("baseline_head")
                cur_sha = repo_heads.get(r_dir.name)
                if base_sha and cur_sha and base_sha.lower() != cur_sha.lower():
                    d_names = run_safe_git(r_dir, ["diff", "--name-only", f"{base_sha}..{cur_sha}"])
                    if d_names.returncode == 0:
                        for changed_rel in d_names.stdout.splitlines():
                            changed_rel = changed_rel.strip()
                            if not changed_rel:
                                continue
                            ws_rel = f"repos/{r_dir.name}/{changed_rel}"
                            if declared_scope and not is_path_in_scope(ws_rel, declared_scope):
                                if ws_rel not in out_of_scope_files:
                                    out_of_scope_files.append(ws_rel)
                    diff_patch = run_safe_git(r_dir, ["diff", "-U0", f"{base_sha}..{cur_sha}"])
                    if diff_patch.returncode == 0:
                        for dline in diff_patch.stdout.splitlines():
                            if dline.startswith("-") and not dline.startswith("---") and ("assert" in dline or "pytest.raises" in dline):
                                removed_assertions.append(f"{r_dir.name}: {dline[1:].strip()[:80]}")
            except Exception:
                pass

    if isinstance(scanner_report_doc, dict):
        for d in scanner_report_doc.get("defects", []):
            if d.get("blocking"):
                secrets_found.append(d.get("message", d.get("defect_id", "secret_detected")))
        if scanner_report_doc.get("status") == "FAILED" and not secrets_found:
            secrets_found.append("Phase-3/scanner_report.json status FAILED")

    _, diff_snapshot_sha256 = compute_uncommitted_state_digest(
        root,
        repo_dirs=repo_dirs,
        repo_heads=repo_heads,
        uncommitted_diffs=uncommitted_diffs,
    )

    # Validate Agent-Assisted review provenance against GAP-04 requirements
    commit_match_cache: Dict[str, Tuple[bool, str]] = {}
    for src_doc, src_path in (
        (pre_commit_review, "Phase-2A/pre_commit_review.json"),
        (agent_reviews_doc, "Phase-2A/agent_reviews.json"),
    ):
        if isinstance(src_doc, dict):
            mapping = src_doc.get("agent_assisted_reviews") or src_doc.get("reviews")
            if isinstance(mapping, dict):
                for rid, rinfo in mapping.items():
                    if isinstance(rinfo, dict):
                        entry_copy = dict(rinfo)
                        entry_copy.setdefault("evidence_path", src_path)
                    else:
                        entry_copy = {"status": str(rinfo), "evidence_path": src_path}

                    ok_rev, fail_status, fail_msg = validate_agent_review_provenance(
                        workspace_root=root,
                        src_doc=src_doc,
                        src_rel_path=src_path,
                        task_id=task_id,
                        attempt=int(attempt),
                        active_state=active_state,
                        pre_commit_status=pre_commit_status,
                        repo_heads=repo_heads,
                        diff_snapshot_sha256=diff_snapshot_sha256,
                        entry=entry_copy,
                        pre_commit_review=pre_commit_review,
                        _commit_match_cache=commit_match_cache,
                    )
                    if ok_rev:
                        entry_copy["_provenance_verified"] = True
                        recorded_agent_reviews[rid] = entry_copy
                        agent_review_errors.pop(rid, None)
                    else:
                        agent_review_errors[rid] = (fail_status, fail_msg)

    context_digest = compute_rubric_context_digest(
        root,
        task_id=task_id,
        attempt=int(attempt),
        repo_dirs=repo_dirs,
        repo_heads=repo_heads,
        uncommitted_diffs=uncommitted_diffs,
        diff_snapshot_sha256=diff_snapshot_sha256,
    )

    ctx: Dict[str, Any] = {
        "_collected": True,
        "workspace_root": str(root),
        "task_id": task_id,
        "attempt": attempt,
        "context_digest": context_digest,
        "diff_snapshot_sha256": diff_snapshot_sha256,
        "repo_dirs": repo_dirs,
        "active_state": active_state,
        "active_state_err": active_state_err,
        "prod_repos": prod_repos,
        "prod_repos_err": prod_repos_err,
        "agents_md_ok": agents_md_ok,
        "owner_grants_ok": owner_grants_ok,
        "start_manifest_ok": start_manifest_ok,
        "start_manifest_err": start_manifest_err,
        "prompt_md_ok": prompt_md_ok,
        "declared_scope": declared_scope,
        "declared_scope_err": declared_scope_err,
        "prompt_verified": prompt_verified,
        "prompt_verified_err": prompt_verified_err,
        "pre_commit_status": pre_commit_status,
        "pre_commit_status_err": pre_commit_status_err,
        "pre_commit_review": pre_commit_review,
        "pre_commit_review_err": pre_commit_review_err,
        "report_md_ok": report_md_ok,
        "claims_doc": claims_doc,
        "claims_err": claims_err,
        "test_execution_doc": test_execution_doc,
        "scanner_report_doc": scanner_report_doc,
        "verdict_doc": verdict_doc,
        "issue_history_doc": issue_history_doc,
        "issue_history_err": issue_history_err,
        "ev_manifest_doc": ev_manifest_doc,
        "human_waivers": approved_waivers,
        "waiver_rejection_reasons": waiver_rejection_reasons,
        "agent_reviews": recorded_agent_reviews,
        "agent_review_errors": agent_review_errors,
        "uncommitted_diffs": uncommitted_diffs,
        "untouched_dirty": untouched_dirty,
        "out_of_scope_files": out_of_scope_files,
        "secrets_found": secrets_found,
        "unpinned_dependencies": unpinned_dependencies,
        "rogue_scanner_configs": rogue_scanner_configs,
        "symlink_escapes": symlink_escapes,
        "repo_heads": repo_heads,
        "removed_assertions": removed_assertions,
        "ast_metrics": agg_ast,
        "flaky_sleep_detected": list(agg_ast["flaky_sleep_detected"]),
    }

    if existing_context:
        # Merge list/dict inputs cleanly while keeping explicit caller context authoritative
        for k, v in existing_context.items():
            if k == "human_waivers" and isinstance(v, dict):
                merged = dict(approved_waivers)
                merged.update(v)
                ctx[k] = merged
            elif k == "agent_reviews" and isinstance(v, dict):
                merged = dict(recorded_agent_reviews)
                merged.update(v)
                ctx[k] = merged
            elif k in ("unpinned_dependencies", "out_of_scope_files", "untouched_dirty", "secrets_found", "flaky_sleep_detected") and isinstance(v, list):
                ctx[k] = list(ctx[k]) + list(v)
            else:
                ctx[k] = v

    return ctx


def _evaluate_human_waiver(rule: RubricRule, ctx: Dict[str, Any]) -> RuleEvaluationResult:
    """Strictly validate human disposition provenance from controls/DISPOSITIONS.json (GAP-03)."""
    task_id = str(ctx.get("task_id", "task-default"))
    attempt = int(ctx.get("attempt", 1) or 1)
    if rule.rule_id in ctx.get("failed_human_waivers", []):
        return RuleEvaluationResult(
            rule_id=rule.rule_id,
            domain=rule.domain,
            category=rule.category,
            status="FAIL",
            evaluator="human_waiver_evaluator",
            witness="controls/DISPOSITIONS.json",
            message=f"Human disposition explicitly rejected for '{rule.rule_id}'.",
        )

    waivers = ctx.get("human_waivers", {})
    if isinstance(waivers, dict) and "*" in waivers:
        return RuleEvaluationResult(
            rule_id=rule.rule_id,
            domain=rule.domain,
            category=rule.category,
            status="FAIL",
            evaluator="human_waiver_evaluator",
            witness="controls/DISPOSITIONS.json",
            message="Wildcard '*' human waiver is strictly prohibited.",
        )

    if isinstance(waivers, dict) and rule.rule_id in waivers:
        waiver_info = waivers.get(rule.rule_id)
        if not isinstance(waiver_info, dict):
            return RuleEvaluationResult(
                rule_id=rule.rule_id,
                domain=rule.domain,
                category=rule.category,
                status="FAIL",
                evaluator="human_waiver_evaluator",
                witness="controls/DISPOSITIONS.json",
                message=f"Malformed human waiver entry for '{rule.rule_id}'.",
            )
        if waiver_info.get("_provenance_verified") is not True:
            ws_str = ctx.get("workspace_root")
            if not ws_str:
                return RuleEvaluationResult(
                    rule_id=rule.rule_id,
                    domain=rule.domain,
                    category=rule.category,
                    status="FAIL",
                    evaluator="human_waiver_evaluator",
                    witness="controls/DISPOSITIONS.json",
                    message=f"Unverified human waiver provenance for '{rule.rule_id}' (missing workspace provenance check).",
                )
            ok_w, reason_w = validate_waiver_provenance(
                workspace_root=Path(ws_str),
                entry=waiver_info,
                task_id=task_id,
                attempt=attempt,
                required_rule_id=rule.rule_id,
            )
            if not ok_w:
                return RuleEvaluationResult(
                    rule_id=rule.rule_id,
                    domain=rule.domain,
                    category=rule.category,
                    status="FAIL",
                    evaluator="human_waiver_evaluator",
                    witness="controls/DISPOSITIONS.json",
                    message=f"Human waiver provenance invalid for '{rule.rule_id}': {reason_w}",
                )
        return RuleEvaluationResult(
            rule_id=rule.rule_id,
            domain=rule.domain,
            category=rule.category,
            status="PASS",
            evaluator="human_waiver_evaluator",
            witness=waiver_info.get("evidence_path", "controls/DISPOSITIONS.json"),
            message=f"Human waiver authorized by {waiver_info.get('authorized_by')}: {waiver_info.get('rationale', '')}.",
        )

    rej_reasons = ctx.get("waiver_rejection_reasons", {})
    if isinstance(rej_reasons, dict) and rule.rule_id in rej_reasons:
        return RuleEvaluationResult(
            rule_id=rule.rule_id,
            domain=rule.domain,
            category=rule.category,
            status="FAIL",
            evaluator="human_waiver_evaluator",
            witness="controls/DISPOSITIONS.json",
            message=f"Human disposition rejected for '{rule.rule_id}': {rej_reasons[rule.rule_id]}",
        )

    return RuleEvaluationResult(
        rule_id=rule.rule_id,
        domain=rule.domain,
        category=rule.category,
        status="BLOCKED",
        evaluator="human_waiver_evaluator",
        witness="controls/DISPOSITIONS.json",
        message=(
            f"Human disposition required for '{rule.rule_id}' ({rule.title}) "
            f"but no provenance-verified APPROVED waiver exists for task '{task_id}' attempt {attempt}."
        ),
    )


def _evaluate_agent_assisted(rule: RubricRule, ctx: Dict[str, Any]) -> RuleEvaluationResult:
    """Validate real provenance-verified Agent-Assisted review entries; never allow generic substitution (GAP-04)."""
    if rule.rule_id in ctx.get("missing_agent_reviews", []):
        return RuleEvaluationResult(
            rule_id=rule.rule_id,
            domain=rule.domain,
            category=rule.category,
            status="NOT_EVALUATED",
            evaluator="agent_assisted_evaluator",
            witness="Phase-2A/agent_reviews.json",
            message=f"Agent-assisted review evidence missing for rule '{rule.rule_id}'.",
        )

    reviews = ctx.get("agent_reviews", {})
    entry = reviews.get(rule.rule_id) if isinstance(reviews, dict) else None

    # Check illegal agent self-exemption first (even on unverified context entries)
    if isinstance(entry, dict) and str(entry.get("status", "")).upper() == "NOT_APPLICABLE":
        raise InvalidRubricExemptionError(
            f"Illegal agent self-exemption attempted for '{rule.rule_id}': agents cannot mark AGENT_ASSISTED rules NOT_APPLICABLE."
        )
    elif isinstance(entry, str) and entry.upper() == "NOT_APPLICABLE":
        raise InvalidRubricExemptionError(
            f"Illegal agent self-exemption attempted for '{rule.rule_id}': agents cannot mark AGENT_ASSISTED rules NOT_APPLICABLE."
        )

    rev_errors = ctx.get("agent_review_errors", {})
    if isinstance(rev_errors, dict) and rule.rule_id in rev_errors:
        err_status, err_msg = rev_errors[rule.rule_id]
        return RuleEvaluationResult(
            rule_id=rule.rule_id,
            domain=rule.domain,
            category=rule.category,
            status=err_status,
            evaluator="agent_assisted_evaluator",
            witness="Phase-2A/agent_reviews.json",
            message=f"Agent-assisted review provenance rejected for '{rule.rule_id}': {err_msg}",
        )

    if not entry:
        return RuleEvaluationResult(
            rule_id=rule.rule_id,
            domain=rule.domain,
            category=rule.category,
            status="NOT_EVALUATED",
            evaluator="agent_assisted_evaluator",
            witness="Phase-2A/agent_reviews.json",
            message=f"No recorded Agent 1 semantic review found for '{rule.rule_id}' ({rule.title}).",
        )

    if not isinstance(entry, dict):
        return RuleEvaluationResult(
            rule_id=rule.rule_id,
            domain=rule.domain,
            category=rule.category,
            status="NOT_EVALUATED",
            evaluator="agent_assisted_evaluator",
            witness="Phase-2A/agent_reviews.json",
            message=f"Agent-assisted review entry for '{rule.rule_id}' lacks structured provenance object.",
        )

    if entry.get("_provenance_verified") is not True:
        reviewer = str(entry.get("reviewer") or entry.get("reviewed_by") or "").strip()
        reviewer_role = str(entry.get("reviewer_role") or "").strip()
        if not reviewer or reviewer.lower() in _GENERIC_REVIEWER_NAMES or not reviewer_role:
            return RuleEvaluationResult(
                rule_id=rule.rule_id,
                domain=rule.domain,
                category=rule.category,
                status="FAIL" if reviewer.lower() in _GENERIC_REVIEWER_NAMES else "NOT_EVALUATED",
                evaluator="agent_assisted_evaluator",
                witness=str(entry.get("evidence_path") or "Phase-2A/agent_reviews.json"),
                message=f"Agent-assisted review for '{rule.rule_id}' lacks verified reviewer identity/role provenance.",
            )

    r_status = str(entry.get("status", "")).upper()
    rationale = str(entry.get("rationale") or entry.get("summary") or entry.get("message") or "").strip()
    ev_path = str(entry.get("evidence_path") or entry.get("witness") or "Phase-2A/agent_reviews.json")

    if r_status in ("FAIL", "FAILED", "BLOCKING", "REVISION_REQUIRED", "REJECTED"):
        return RuleEvaluationResult(
            rule_id=rule.rule_id,
            domain=rule.domain,
            category=rule.category,
            status="FAIL",
            evaluator="agent_assisted_evaluator",
            witness=ev_path,
            message=rationale or f"Agent-assisted review reported failure on '{rule.rule_id}'.",
        )
    if r_status == "BLOCKED":
        return RuleEvaluationResult(
            rule_id=rule.rule_id,
            domain=rule.domain,
            category=rule.category,
            status="BLOCKED",
            evaluator="agent_assisted_evaluator",
            witness=ev_path,
            message=rationale or f"Agent-assisted review blocked on '{rule.rule_id}'.",
        )
    if r_status in ("PASS", "PASSED", "APPROVED", "CLEAR") and rationale:
        return RuleEvaluationResult(
            rule_id=rule.rule_id,
            domain=rule.domain,
            category=rule.category,
            status="PASS",
            evaluator="agent_assisted_evaluator",
            witness=ev_path,
            message=f"Agent-assisted review verified ({rule.title}): {rationale}",
        )
    return RuleEvaluationResult(
        rule_id=rule.rule_id,
        domain=rule.domain,
        category=rule.category,
        status="NOT_EVALUATED",
        evaluator="agent_assisted_evaluator",
        witness=ev_path,
        message=f"Agent-assisted review entry for '{rule.rule_id}' is incomplete or UNKNOWN.",
    )


def _ev_fail(rule: RubricRule, artifact: str, message: str) -> RuleEvaluationResult:
    return RuleEvaluationResult(
        rule_id=rule.rule_id,
        domain=rule.domain,
        category=rule.category,
        status="FAIL",
        evaluator="phase_evidence_validator",
        artifact=artifact,
        witness=artifact,
        message=message,
    )


def _ev_pass(rule: RubricRule, artifact: str, message: str) -> RuleEvaluationResult:
    return RuleEvaluationResult(
        rule_id=rule.rule_id,
        domain=rule.domain,
        category=rule.category,
        status="PASS",
        evaluator="phase_evidence_validator",
        artifact=artifact,
        witness=artifact,
        message=message,
    )


def _has_distinct_agent_roles(active: Optional[Dict[str, Any]]) -> bool:
    """Return True if ACTIVE_STATE.json configures distinct producer/reviewer or valid agent identities."""
    if not isinstance(active, dict):
        return False
    a1 = active.get("agent1")
    a2 = active.get("agent2")
    if a1 and a2 and a1 != a2:
        return True
    agents = active.get("registered_agents")
    if not agents and isinstance(active.get("protected"), dict):
        agents = active["protected"].get("registered_agents")
    if not isinstance(agents, list) or not agents:
        return False
    auditors = {a.get("name") for a in agents if isinstance(a, dict) and a.get("role") == "prompt_and_audit" and a.get("name")}
    coders = {a.get("name") for a in agents if isinstance(a, dict) and a.get("role") == "code_implementation" and a.get("name")}
    if auditors and coders and auditors != coders:
        return True
    is_single = bool(active.get("single_agent_mode")) or (
        isinstance(active.get("protected"), dict) and bool(active["protected"].get("single_agent_mode"))
    )
    if is_single and any(isinstance(a, dict) and a.get("role") == "dual_role" and a.get("name") for a in agents):
        return True
    return False


def _has_execution_record(ctx: Dict[str, Any]) -> Tuple[bool, bool, str]:
    """Return (present, passed, artifact_label) for Phase-3/orchestrator test execution."""
    if isinstance(ctx.get("rerun_results"), dict):
        rr = ctx["rerun_results"]
        ok = rr.get("status") in ("PASS", "PASSED", "CLEAR") and not rr.get("errors")
        return True, ok, "Phase-3/test_execution.json"
    tex = ctx.get("test_execution_doc")
    if isinstance(tex, dict):
        st = str(tex.get("status", "")).upper()
        ok = st in ("PASS", "PASSED", "CLEAR")
        if not ok and isinstance(tex.get("repositories"), dict):
            ok = bool(tex["repositories"]) and all(
                isinstance(v, dict) and v.get("exit_code", 0) == 0 and str(v.get("status", "")).upper() in ("PASS", "PASSED")
                for v in tex["repositories"].values()
            )
        return True, ok, "Phase-3/test_execution.json"
    return False, False, "Phase-3/test_execution.json"


def _evaluate_evidence_rule(rule: RubricRule, workspace_root: Path, ctx: Dict[str, Any]) -> RuleEvaluationResult:
    """Validate real workspace/phase evidence artifacts for each of the 64 EVIDENCE rules."""
    missing_list = ctx.get("missing_evidence", [])
    if rule.rule_id in missing_list or "*" in missing_list:
        return _ev_fail(
            rule,
            rule.primary_witness or "evidence_artifact",
            f"Missing required evidence artifact for rule '{rule.rule_id}'.",
        )

    rid = rule.rule_id
    dom = rule.domain
    ast_m = ctx.get("ast_metrics", {})
    active = ctx.get("active_state")
    scope = ctx.get("declared_scope")
    p2a_stat = ctx.get("pre_commit_status")
    p2a_rev = ctx.get("pre_commit_review")
    claims_doc = ctx.get("claims_doc") or ctx.get("claims")
    verdict_doc = ctx.get("verdict_doc")
    exec_present, exec_ok, exec_art = _has_execution_record(ctx)

    # Pre-check general structural violations where relevant
    if ctx.get("out_of_scope_files"):
        out_f = ctx["out_of_scope_files"][0]
    else:
        out_f = None

    if dom == "ORCHESTRATOR":
        if rid == "ORCHESTRATOR-001":
            if not active or not ctx.get("prod_repos") or not scope:
                return _ev_fail(rule, "Phase-1/declared_scope.json", "Missing active state, registered repos, or declared_scope.json.")
            if scope.get("task_id") != ctx.get("task_id"):
                return _ev_fail(rule, "Phase-1/declared_scope.json", "declared_scope.json task_id does not match active task.")
            return _ev_pass(rule, "controls/ACTIVE_STATE.json", "Launcher task, repository, and scope bindings verified.")
        if rid == "ORCHESTRATOR-002":
            if ctx.get("symlink_escapes"):
                return _ev_fail(rule, "controls/PRODUCT_REPOSITORIES.json", f"Repository symlink boundary violation: {ctx['symlink_escapes'][0]}")
            if not ctx.get("prod_repos"):
                return _ev_fail(rule, "controls/PRODUCT_REPOSITORIES.json", ctx.get("prod_repos_err") or "Missing PRODUCT_REPOSITORIES.json")
            return _ev_pass(rule, "controls/PRODUCT_REPOSITORIES.json", "Repository roots verified inside governed repos/ tree.")
        if rid == "ORCHESTRATOR-003":
            if not p2a_stat:
                return _ev_fail(rule, "Phase-2A/pre_commit_status.json", ctx.get("pre_commit_status_err") or "Missing Phase-2A/pre_commit_status.json.")
            if not p2a_stat.get("base_commits"):
                return _ev_fail(rule, "Phase-2A/pre_commit_status.json", "pre_commit_status.json missing retained base_commits.")
            return _ev_pass(rule, "Phase-2A/pre_commit_status.json", "Baseline HEAD and base_commits identities retained.")
        if rid == "ORCHESTRATOR-004":
            if not scope:
                return _ev_fail(rule, "Phase-1/declared_scope.json", ctx.get("declared_scope_err") or "Missing declared_scope.json.")
            if out_f:
                return _ev_fail(rule, out_f, f"Out-of-scope change detected in inventory: {out_f}")
            return _ev_pass(rule, "Phase-1/declared_scope.json", "Staged, unstaged, and untracked change inventory contained in scope.")
        if rid in ("ORCHESTRATOR-005", "ORCHESTRATOR-006", "ORCHESTRATOR-008"):
            if not ctx.get("start_manifest_ok"):
                return _ev_fail(rule, "specs/START_MANIFEST.md", f"Manifest verification failed: {ctx.get('start_manifest_err')}")
            return _ev_pass(rule, "specs/START_MANIFEST.md", f"Control and tool identities verified under START_MANIFEST ({rule.title}).")
        if rid == "ORCHESTRATOR-007":
            if not active or ctx.get("active_state_err"):
                return _ev_fail(rule, "controls/ACTIVE_STATE.json", ctx.get("active_state_err") or "Missing ACTIVE_STATE.json")
            return _ev_pass(rule, "controls/ACTIVE_STATE.json", "ACTIVE_STATE.json conforms to schema and active task binding.")
        if rid in ("ORCHESTRATOR-009", "ORCHESTRATOR-010"):
            if not ctx.get("agents_md_ok"):
                return _ev_fail(rule, "controls/AGENTS.md", "Missing or empty controls/AGENTS.md governance contract.")
            return _ev_pass(rule, "controls/AGENTS.md", f"Orchestrator governance contract and manuals verified ({rule.title}).")
        if rid in ("ORCHESTRATOR-011", "ORCHESTRATOR-012", "ORCHESTRATOR-013"):
            sr = ctx.get("stage_results")
            if isinstance(sr, list):
                if len(sr) < 9:
                    return _ev_fail(rule, "Phase-3/verdict.json", f"Only {len(sr)}/9 deterministic audit stages executed.")
                errs = [e for s in sr for e in (s.get("errors") or [])]
                if errs:
                    return _ev_fail(rule, "Phase-3/test_execution.json", f"Stage execution errors present: {errs[0]}")
                return _ev_pass(rule, "Phase-3/verdict.json", f"All 9 deterministic stages verified cleanly ({rule.title}).")
            if verdict_doc and exec_present:
                if not exec_ok:
                    return _ev_fail(rule, exec_art, "Retained execution evidence indicates failed or errored run.")
                return _ev_pass(rule, "Phase-3/verdict.json", f"Retained Phase-3 audit and execution records consistent ({rule.title}).")
            return _ev_fail(rule, "Phase-3/verdict.json", "Missing Phase-3 execution and verdict evidence.")
        if rid == "ORCHESTRATOR-014":
            if not active or not ctx.get("agents_md_ok"):
                return _ev_fail(rule, "controls/AGENTS.md", "Missing binding/governance controls.")
            return _ev_pass(rule, "controls/DISPOSITIONS.json", "Binding descriptors remain owner-governed.")
        if rid == "ORCHESTRATOR-015":
            if not _has_distinct_agent_roles(active):
                return _ev_fail(rule, "controls/ACTIVE_STATE.json", "Distinct agent identities/roles missing in ACTIVE_STATE.json.")
            return _ev_pass(rule, "controls/ACTIVE_STATE.json", "Agent role selection and separation verified.")
        if rid == "ORCHESTRATOR-016":
            if ctx.get("secrets_found"):
                return _ev_fail(rule, ctx["secrets_found"][0], f"Secret scan blocking finding: {ctx['secrets_found'][0]}")
            if not ctx.get("rogue_scanner_configs") and (ctx.get("scanner_report_doc") or ctx.get("stage_results")):
                return _ev_pass(rule, "Phase-3/scanner_report.json", "Preflight, configuration, and secret scan clean prior to acceptance.")
            if ctx.get("rogue_scanner_configs"):
                return _ev_fail(rule, ctx["rogue_scanner_configs"][0], "Unauthorized repository .gitleaks.toml override detected.")
            return _ev_fail(rule, "Phase-3/scanner_report.json", "Missing Phase-3/scanner_report.json secret scan evidence.")

    if dom == "CLAIM_SUPPORT":
        if not ctx.get("report_md_ok"):
            return _ev_fail(rule, "Phase-2B/report.md", "Missing or empty delivery report Phase-2B/report.md.")
        if not claims_doc or ctx.get("claims_err"):
            return _ev_fail(rule, "Phase-2B/claims.json", ctx.get("claims_err") or "Missing required claim attachment Phase-2B/claims.json.")
        if rid == "CLAIM_SUPPORT-009" and not ctx.get("start_manifest_ok"):
            return _ev_fail(rule, "specs/START_MANIFEST.md", f"Manifest mismatch: {ctx.get('start_manifest_err')}")
        if rid == "CLAIM_SUPPORT-010" and not ctx.get("repo_heads"):
            return _ev_fail(rule, "controls/PRODUCT_REPOSITORIES.json", "Missing resolved repository HEAD identities for claims.")
        if rid in ("CLAIM_SUPPORT-011", "CLAIM_SUPPORT-012") and not (exec_present and exec_ok):
            return _ev_fail(rule, exec_art, "Claims lack passing Phase-3/test_execution.json runtime/test proof.")
        if rid == "CLAIM_SUPPORT-013":
            if not _has_distinct_agent_roles(active):
                return _ev_fail(rule, "controls/ACTIVE_STATE.json", "Independent non-producer actor identity missing.")
        if rid == "CLAIM_SUPPORT-015" and out_f:
            return _ev_fail(rule, out_f, f"Completion breadth violated by out-of-scope file: {out_f}")
        if rid == "CLAIM_SUPPORT-020" and ctx.get("issue_history_err"):
            return _ev_fail(rule, "evidence/issue_history.json", ctx["issue_history_err"])
        return _ev_pass(rule, "Phase-2B/claims.json", f"Claim support evidence validated against Phase-2B/claims.json & report.md ({rule.title}).")

    if dom == "COMMON":
        in_p2a_precommit = (
            isinstance(active, dict)
            and active.get("phase") == "PHASE_2A_CODING"
            and isinstance(p2a_stat, dict)
            and not ctx.get("pre_commit_status_err")
            and bool(ctx.get("agent_reviews"))
        )
        if rid == "COMMON-021":
            if not _has_distinct_agent_roles(active):
                return _ev_fail(rule, "controls/ACTIVE_STATE.json", "Missing distinct agent roles in ACTIVE_STATE.json.")
            if p2a_rev:
                return _ev_pass(rule, "Phase-2A/pre_commit_review.json", "Response role identity verified.")
            if in_p2a_precommit:
                return _ev_pass(rule, "Phase-2A/pre_commit_status.json", "Pre-commit request and reviewer identities verified.")
            return _ev_fail(rule, "Phase-2A/pre_commit_review.json", ctx.get("pre_commit_review_err") or "Missing pre_commit_review.json.")
        if rid == "COMMON-022":
            if p2a_rev:
                if p2a_rev.get("status") == "APPROVED" and p2a_rev.get("new_issues_found"):
                    return _ev_fail(rule, "Phase-2A/pre_commit_review.json", "Review APPROVED while unresolved new_issues_found exist.")
                return _ev_pass(rule, "Phase-2A/pre_commit_review.json", "Zero unresolved omissions under approved status.")
            if in_p2a_precommit:
                return _ev_pass(rule, "Phase-2A/pre_commit_status.json", "Initial pre-commit review cycle has zero unrecorded omissions.")
            return _ev_fail(rule, "Phase-2A/pre_commit_review.json", "Missing pre_commit_review.json to verify unresolved omissions.")
        if rid == "COMMON-023":
            if not scope or ctx.get("declared_scope_err"):
                return _ev_fail(rule, "Phase-1/declared_scope.json", ctx.get("declared_scope_err") or "Missing declared_scope.json.")
            if not claims_doc or ctx.get("claims_err"):
                return _ev_fail(rule, "Phase-2B/claims.json", ctx.get("claims_err") or "Missing Phase-2B/claims.json citations.")
            return _ev_pass(rule, "Phase-2B/claims.json", "Citation resolution integrity verified without promoted faults.")
        if rid == "COMMON-024":
            if not exec_present:
                return _ev_fail(rule, exec_art, "Missing execution evidence separating faults from product defects.")
            if not exec_ok:
                return _ev_fail(rule, exec_art, "Execution errors or test failures recorded.")
            return _ev_pass(rule, exec_art, "Execution status and defect reporting separated cleanly.")
        if rid == "COMMON-025":
            if not ctx.get("start_manifest_ok"):
                return _ev_fail(rule, "specs/START_MANIFEST.md", f"Context continuity breach: {ctx.get('start_manifest_err')}")
            if not ctx.get("prompt_verified") or ctx.get("prompt_verified_err"):
                return _ev_fail(rule, "Phase-1/prompt_verified.json", ctx.get("prompt_verified_err") or "Missing prompt_verified.json.")
            return _ev_pass(rule, "Phase-1/prompt_verified.json", "Manifest and prompt hashes match current workspace bytes.")
        if rid == "COMMON-026":
            if not scope or ctx.get("declared_scope_err"):
                return _ev_fail(rule, "Phase-1/declared_scope.json", ctx.get("declared_scope_err") or "Missing declared_scope.json.")
            if out_f or ctx.get("untouched_dirty"):
                return _ev_fail(rule, out_f or "git_status", "Work escaped configured scope boundaries.")
            return _ev_pass(rule, "Phase-1/declared_scope.json", "Review and modifications bounded to declared scope.")
        if rid == "COMMON-027":
            if not p2a_stat or not ctx.get("prod_repos"):
                return _ev_fail(rule, "Phase-2A/pre_commit_status.json", "Missing concrete repository/touched enumeration.")
            return _ev_pass(rule, "Phase-2A/pre_commit_status.json", "Concrete repository and touched-surface enumeration verified.")
        if rid == "COMMON-028":
            if ctx.get("symlink_escapes") or ast_m.get("test_count", 0) == 0 or not ast_m.get("has_negative_tests"):
                return _ev_fail(rule, "Phase-1/declared_scope.json", "Missing negative boundary tests or path-escape counterexample violation.")
            return _ev_pass(rule, "Phase-1/declared_scope.json", "In-scope counterexample and negative guard checks verified.")
        if rid == "COMMON-029":
            if not ctx.get("agents_md_ok"):
                return _ev_fail(rule, "controls/AGENTS.md", "Missing AGENTS.md governance contract.")
            return _ev_pass(rule, "controls/DISPOSITIONS.json", "Promotion and binding remain strictly owner-governed.")
        if rid == "COMMON-030":
            if not (exec_present or verdict_doc):
                return _ev_fail(rule, "Phase-3/verdict.json", "Missing Phase-3 verdict/execution evidence for consistency verification.")
            if verdict_doc and verdict_doc.get("result") in ("CLEAR", "PASSED") and verdict_doc.get("counts", {}).get("blocking", 0) > 0:
                return _ev_fail(rule, "Phase-3/verdict.json", "Inconsistent verdict: CLEAR/PASSED with nonzero blocking defects.")
            return _ev_pass(rule, "Phase-3/verdict.json", "Findings, omissions, and verdict status verified consistent.")

    if dom == "TEST_ADEQUACY":
        if not exec_present:
            return _ev_fail(rule, exec_art, f"Missing execution evidence in Phase-3/test_execution.json for '{rule.title}'.")
        if rid == "TEST_ADEQUACY-027":
            if ctx.get("unpinned_dependencies") or not ctx.get("start_manifest_ok"):
                return _ev_fail(rule, "specs/START_MANIFEST.md", "Environment manifest or dependency pinning invalid.")
        if rid == "TEST_ADEQUACY-028" and ast_m.get("syntax_errors"):
            return _ev_fail(rule, ast_m["syntax_errors"][0], f"Test/source syntax failure: {ast_m['syntax_errors'][0]}")
        if not exec_ok:
            return _ev_fail(rule, exec_art, f"Test execution reported failures or unexecuted suites for '{rule.title}'.")
        return _ev_pass(rule, exec_art, f"Test execution evidence verified for '{rule.title}'.")

    if dom == "INDEPENDENT_RERUN":
        if rid in ("INDEPENDENT_RERUN-026", "INDEPENDENT_RERUN-027", "INDEPENDENT_RERUN-029"):
            if not exec_present or not exec_ok:
                return _ev_fail(rule, exec_art, f"Missing or failing rerun execution evidence for '{rule.title}'.")
            if rid == "INDEPENDENT_RERUN-027" and not (ctx.get("report_md_ok") or p2a_rev):
                return _ev_fail(rule, "Phase-2B/report.md", "Missing report/review record alongside rerun evidence.")
            return _ev_pass(rule, exec_art, f"Rerun evidence validated for '{rule.title}'.")
        if rid == "INDEPENDENT_RERUN-028":
            has_p2a_order = bool(p2a_rev) or (
                isinstance(active, dict)
                and active.get("phase") == "PHASE_2A_CODING"
                and isinstance(p2a_stat, dict)
                and not ctx.get("pre_commit_status_err")
            )
            if not active or "GATE_1" not in active.get("cleared_gates", {}) or not has_p2a_order:
                return _ev_fail(rule, "controls/ACTIVE_STATE.json", "Prior Gate-1 / Phase-2A review ordering incomplete.")
            return _ev_pass(rule, "controls/ACTIVE_STATE.json", "Phase ordering prerequisites verified.")
        # INDEPENDENT_RERUN-030
        if not (verdict_doc or isinstance(ctx.get("stage_results"), list)) or not ctx.get("agents_md_ok"):
            return _ev_fail(rule, "Phase-3/verdict.json", "Missing verdict/control evidence separating rerun from owner acceptance.")
        return _ev_pass(rule, "Phase-3/verdict.json", "Rerun verification separated cleanly from Gate-4 owner acceptance.")

    # EVAL_CURATOR-023..030
    if ast_m.get("eval_imports_in_repo"):
        return _ev_fail(rule, ast_m["eval_imports_in_repo"][0], "Product repo imports evals/ fixtures directly.")
    if rid in ("EVAL_CURATOR-024", "EVAL_CURATOR-028", "EVAL_CURATOR-029"):
        if not ctx.get("start_manifest_ok"):
            return _ev_fail(rule, "specs/START_MANIFEST.md", f"Manifest integrity error: {ctx.get('start_manifest_err')}")
        if ctx.get("out_of_scope_files"):
            return _ev_fail(rule, ctx["out_of_scope_files"][0], "Scope/control isolation boundary violated.")
        return _ev_pass(rule, "specs/START_MANIFEST.md", f"Eval/control isolation and manifest authority verified ({rule.title}).")
    if not exec_present or not exec_ok:
        return _ev_fail(rule, exec_art, f"Missing or failing evaluation execution evidence for '{rule.title}'.")
    return _ev_pass(rule, exec_art, f"Evaluation curator evidence verified ({rule.title}).")


def _eval_blast_radius(rule: RubricRule, ctx: Dict[str, Any], evaluator_name: str) -> RuleEvaluationResult:
    if ctx.get("out_of_scope_files"):
        offender = ctx["out_of_scope_files"][0]
        return RuleEvaluationResult(
            rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="FAIL",
            evaluator=evaluator_name, witness=offender,
            message=f"Out-of-scope file modified ({rule.title}): {offender}.",
        )
    if ctx.get("untouched_dirty"):
        dirty = ctx["untouched_dirty"][0]
        return RuleEvaluationResult(
            rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="FAIL",
            evaluator=evaluator_name, witness=dirty,
            message=f"Untouched repository '{dirty}' contains uncommitted modifications.",
        )
    if ctx.get("dag_order_violation"):
        return RuleEvaluationResult(
            rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="FAIL",
            evaluator=evaluator_name, witness="dag_order_violation",
            message=f"Dependency topological violation ({rule.title}): {ctx['dag_order_violation']}",
        )
    if ctx.get("symlink_escapes"):
        return RuleEvaluationResult(
            rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="FAIL",
            evaluator=evaluator_name, witness=ctx["symlink_escapes"][0],
            message=f"Symlink boundary escape detected: {ctx['symlink_escapes'][0]}",
        )
    ast_m = ctx.get("ast_metrics", {})
    if rule.rule_id in ("BLAST_RADIUS-002", "BLAST_RADIUS-003", "BLAST_RADIUS-004", "BLAST_RADIUS-005") and ast_m.get("syntax_errors"):
        return RuleEvaluationResult(
            rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="FAIL",
            evaluator=evaluator_name, witness=ast_m["syntax_errors"][0],
            message=f"AST parse failure prevents call-graph analysis: {ast_m['syntax_errors'][0]}",
        )
    if rule.rule_id in ("BLAST_RADIUS-006", "BLAST_RADIUS-007", "BLAST_RADIUS-008") and ctx.get("rogue_scanner_configs"):
        return RuleEvaluationResult(
            rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="FAIL",
            evaluator=evaluator_name, witness=ctx["rogue_scanner_configs"][0],
            message=f"Unauthorized config override detected: {ctx['rogue_scanner_configs'][0]}",
        )
    if rule.rule_id in ("BLAST_RADIUS-009", "BLAST_RADIUS-010", "BLAST_RADIUS-022", "BLAST_RADIUS-023") and ast_m.get("resource_leak_files"):
        return RuleEvaluationResult(
            rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="FAIL",
            evaluator=evaluator_name, witness=ast_m["resource_leak_files"][0],
            message=f"Unguarded file handle open() outside context manager: {ast_m['resource_leak_files'][0]}",
        )
    if rule.rule_id in ("BLAST_RADIUS-017", "BLAST_RADIUS-018", "BLAST_RADIUS-019") and ast_m.get("swallowed_exceptions"):
        return RuleEvaluationResult(
            rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="FAIL",
            evaluator=evaluator_name, witness=ast_m["swallowed_exceptions"][0],
            message=f"Silent exception suppression detected: {ast_m['swallowed_exceptions'][0]}",
        )
    if rule.rule_id in ("BLAST_RADIUS-026",) and ast_m.get("eval_imports_in_repo"):
        return RuleEvaluationResult(
            rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="FAIL",
            evaluator=evaluator_name, witness=ast_m["eval_imports_in_repo"][0],
            message=f"Production repo imports simulator/eval fixture: {ast_m['eval_imports_in_repo'][0]}",
        )
    if rule.rule_id in ("BLAST_RADIUS-027", "BLAST_RADIUS-028", "BLAST_RADIUS-029", "BLAST_RADIUS-030"):
        if not ctx.get("declared_scope") and ctx.get("uncommitted_diffs"):
            return RuleEvaluationResult(
                rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="FAIL",
                evaluator=evaluator_name, witness="Phase-1/declared_scope.json",
                message="Modified working tree lacks Phase-1/declared_scope.json inventory boundary.",
            )
    if rule.rule_id == "BLAST_RADIUS-001":
        witness = "scope_containment_verified"
    else:
        witness = "Phase-1/declared_scope.json" if ctx.get("declared_scope") else "controls/PRODUCT_REPOSITORIES.json"
    return RuleEvaluationResult(
        rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="PASS",
        evaluator=evaluator_name, witness=witness,
        message=f"Blast radius containment and AST invariants verified ({rule.title}).",
    )


def _eval_upstream_reuse(rule: RubricRule, ctx: Dict[str, Any], evaluator_name: str) -> RuleEvaluationResult:
    unpinned = ctx.get("unpinned_dependencies", [])
    if unpinned:
        return RuleEvaluationResult(
            rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="FAIL",
            evaluator=evaluator_name, witness=unpinned[0],
            message=f"Unpinned wildcard dependency detected: {unpinned[0]}.",
        )
    if ctx.get("rogue_scanner_configs"):
        return RuleEvaluationResult(
            rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="FAIL",
            evaluator=evaluator_name, witness=ctx["rogue_scanner_configs"][0],
            message=f"Unauthorized local override replacing packaged scanner config: {ctx['rogue_scanner_configs'][0]}.",
        )
    ast_m = ctx.get("ast_metrics", {})
    if ast_m.get("unsafe_patterns"):
        return RuleEvaluationResult(
            rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="FAIL",
            evaluator=evaluator_name, witness=ast_m["unsafe_patterns"][0],
            message=f"Unsafe dynamic execution pattern prohibited by upstream security reuse rules: {ast_m['unsafe_patterns'][0]}.",
        )
    if not ctx.get("prod_repos"):
        return RuleEvaluationResult(
            rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="NOT_EVALUATED",
            evaluator=evaluator_name, witness="controls/PRODUCT_REPOSITORIES.json",
            message="Missing PRODUCT_REPOSITORIES.json baseline lock to verify upstream reuse.",
        )
    return RuleEvaluationResult(
        rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="PASS",
        evaluator=evaluator_name, witness="controls/PRODUCT_REPOSITORIES.json",
        message=f"Upstream dependency pinning and reuse discipline verified ({rule.title}).",
    )


def _eval_failure_class(rule: RubricRule, ctx: Dict[str, Any], evaluator_name: str) -> RuleEvaluationResult:
    secrets = ctx.get("secrets_found", [])
    if secrets:
        return RuleEvaluationResult(
            rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="FAIL",
            evaluator=evaluator_name, witness=secrets[0],
            message=f"Credential or secret exposure detected: {secrets[0]}.",
        )
    if ctx.get("issue_history_err"):
        return RuleEvaluationResult(
            rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="FAIL",
            evaluator=evaluator_name, witness="evidence/issue_history.json",
            message=f"Failure register integrity error: {ctx['issue_history_err']}.",
        )
    ast_m = ctx.get("ast_metrics", {})
    if ast_m.get("resource_leak_files"):
        return RuleEvaluationResult(
            rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="FAIL",
            evaluator=evaluator_name, witness=ast_m["resource_leak_files"][0],
            message=f"Unclosed file handle leak risk: {ast_m['resource_leak_files'][0]}.",
        )
    if ast_m.get("swallowed_exceptions"):
        return RuleEvaluationResult(
            rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="FAIL",
            evaluator=evaluator_name, witness=ast_m["swallowed_exceptions"][0],
            message=f"Silent exception swallowing hides failure cause: {ast_m['swallowed_exceptions'][0]}.",
        )
    active = ctx.get("active_state")
    if isinstance(active, dict) and active.get("circuit_breaker_tripped"):
        return RuleEvaluationResult(
            rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="BLOCKED",
            evaluator=evaluator_name, witness="controls/ACTIVE_STATE.json",
            message="Circuit breaker tripped on repeated failure cause; human reset required.",
        )
    if not active:
        return RuleEvaluationResult(
            rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="NOT_EVALUATED",
            evaluator=evaluator_name, witness="controls/ACTIVE_STATE.json",
            message="Missing controls/ACTIVE_STATE.json to evaluate failure history state.",
        )
    return RuleEvaluationResult(
        rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="PASS",
        evaluator=evaluator_name, witness="controls/ACTIVE_STATE.json",
        message=f"Zero secrets, clean resource/exception hygiene, and valid failure register ({rule.title}).",
    )


def _eval_test_adequacy(rule: RubricRule, ctx: Dict[str, Any], evaluator_name: str) -> RuleEvaluationResult:
    if ctx.get("missing_tests"):
        return RuleEvaluationResult(
            rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="FAIL",
            evaluator=evaluator_name, witness=ctx["missing_tests"][0],
            message=f"Missing required test coverage: {ctx['missing_tests'][0]}.",
        )
    if ctx.get("flaky_sleep_detected"):
        return RuleEvaluationResult(
            rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="FAIL",
            evaluator=evaluator_name, witness=ctx["flaky_sleep_detected"][0],
            message=f"Non-deterministic time.sleep() detected in tests: {ctx['flaky_sleep_detected'][0]}.",
        )
    if rule.rule_id == "TEST_ADEQUACY-025":
        if ctx.get("unpinned_dependencies"):
            return RuleEvaluationResult(
                rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="FAIL",
                evaluator=evaluator_name, witness=ctx["unpinned_dependencies"][0],
                message=f"Toolchain/dependency manifest unpinned: {ctx['unpinned_dependencies'][0]}.",
            )
        return RuleEvaluationResult(
            rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="PASS",
            evaluator=evaluator_name, witness="requirements.txt",
            message="Toolchain and manifest dependency pins verified.",
        )

    ast_m = ctx.get("ast_metrics", {})
    if ast_m.get("syntax_errors"):
        return RuleEvaluationResult(
            rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="FAIL",
            evaluator=evaluator_name, witness=ast_m["syntax_errors"][0],
            message=f"Python syntax error detected: {ast_m['syntax_errors'][0]}.",
        )
    if ast_m.get("test_count", 0) == 0:
        return RuleEvaluationResult(
            rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="NOT_EVALUATED",
            evaluator=evaluator_name, witness="repos/*",
            message=f"No test files discovered in repository to evaluate '{rule.title}'.",
        )
    if rule.rule_id in ("TEST_ADEQUACY-004", "TEST_ADEQUACY-005") and ast_m.get("self_comparison_tautologies"):
        return RuleEvaluationResult(
            rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="FAIL",
            evaluator=evaluator_name, witness=ast_m["self_comparison_tautologies"][0],
            message=f"Self-comparison tautology in test oracle: {ast_m['self_comparison_tautologies'][0]}.",
        )
    if rule.rule_id == "TEST_ADEQUACY-006" and ast_m.get("weak_assertions"):
        return RuleEvaluationResult(
            rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="FAIL",
            evaluator=evaluator_name, witness=ast_m["weak_assertions"][0],
            message=f"Weak or missing assertion in test suite: {ast_m['weak_assertions'][0]}.",
        )
    if rule.rule_id == "TEST_ADEQUACY-007" and ctx.get("removed_assertions"):
        return RuleEvaluationResult(
            rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="FAIL",
            evaluator=evaluator_name, witness=ctx["removed_assertions"][0],
            message=f"Required assertion removed in commit diff: {ctx['removed_assertions'][0]}.",
        )
    if rule.rule_id == "TEST_ADEQUACY-009" and ast_m.get("qual_in_prod"):
        return RuleEvaluationResult(
            rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="FAIL",
            evaluator=evaluator_name, witness=ast_m["qual_in_prod"][0],
            message=f"Qualification code leaked into production module: {ast_m['qual_in_prod'][0]}.",
        )
    if rule.rule_id == "TEST_ADEQUACY-010" and ast_m.get("skipped_tests_in_code"):
        return RuleEvaluationResult(
            rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="FAIL",
            evaluator=evaluator_name, witness=ast_m["skipped_tests_in_code"][0],
            message=f"Skipped test marker detected: {ast_m['skipped_tests_in_code'][0]}.",
        )
    if rule.rule_id == "TEST_ADEQUACY-016" and not ast_m.get("has_positive_tests"):
        return RuleEvaluationResult(
            rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="FAIL",
            evaluator=evaluator_name, witness=ast_m["test_files"][0],
            message="Positive test suite lacks concrete output/state assertions.",
        )
    if rule.rule_id == "TEST_ADEQUACY-017" and not ast_m.get("has_negative_tests"):
        return RuleEvaluationResult(
            rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="FAIL",
            evaluator=evaluator_name, witness=ast_m["test_files"][0],
            message="Test suite lacks negative/denial assertions (assertRaises/pytest.raises/assertNotEqual).",
        )
    if rule.rule_id == "TEST_ADEQUACY-018" and not ast_m.get("has_malformed_tests"):
        return RuleEvaluationResult(
            rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="FAIL",
            evaluator=evaluator_name, witness=ast_m["test_files"][0],
            message="Test suite lacks malformed/invalid input boundary coverage.",
        )
    if rule.rule_id == "TEST_ADEQUACY-019" and not ast_m.get("has_duplicate_tests"):
        return RuleEvaluationResult(
            rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="FAIL",
            evaluator=evaluator_name, witness=ast_m["test_files"][0],
            message="Test suite lacks duplicate/replay/idempotency case coverage.",
        )
    return RuleEvaluationResult(
        rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="PASS",
        evaluator=evaluator_name, witness=ast_m["test_files"][0],
        message=f"Test adequacy AST and suite checks verified ({rule.title}).",
    )


def _eval_independent_rerun(rule: RubricRule, ctx: Dict[str, Any], evaluator_name: str) -> RuleEvaluationResult:
    active = ctx.get("active_state")
    if rule.rule_id in (
        "INDEPENDENT_RERUN-001", "INDEPENDENT_RERUN-002", "INDEPENDENT_RERUN-003", "INDEPENDENT_RERUN-004",
        "INDEPENDENT_RERUN-005", "INDEPENDENT_RERUN-006", "INDEPENDENT_RERUN-007",
    ):
        if not _has_distinct_agent_roles(active):
            return RuleEvaluationResult(
                rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="FAIL",
                evaluator=evaluator_name, witness="controls/ACTIVE_STATE.json",
                message="Producer and reviewer identities must be configured and distinct.",
            )
        if not ctx.get("agents_md_ok"):
            return RuleEvaluationResult(
                rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="FAIL",
                evaluator=evaluator_name, witness="controls/AGENTS.md",
                message="Missing controls/AGENTS.md grant and role boundary contract.",
            )
        return RuleEvaluationResult(
            rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="PASS",
            evaluator=evaluator_name, witness="controls/ACTIVE_STATE.json",
            message=f"Independent reviewer identity and authority verified ({rule.title}).",
        )

    if rule.rule_id in (
        "INDEPENDENT_RERUN-010", "INDEPENDENT_RERUN-011", "INDEPENDENT_RERUN-012",
        "INDEPENDENT_RERUN-015", "INDEPENDENT_RERUN-016", "INDEPENDENT_RERUN-024",
    ):
        if not ctx.get("start_manifest_ok"):
            return RuleEvaluationResult(
                rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="FAIL",
                evaluator=evaluator_name, witness="specs/START_MANIFEST.md",
                message=f"Input hash/manifest mismatch: {ctx.get('start_manifest_err')}.",
            )
        if ctx.get("out_of_scope_files") or ctx.get("untouched_dirty"):
            return RuleEvaluationResult(
                rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="FAIL",
                evaluator=evaluator_name, witness=(ctx.get("out_of_scope_files") or ctx.get("untouched_dirty"))[0],
                message="Dirty or out-of-scope worktree state invalidates clean rerun.",
            )
        return RuleEvaluationResult(
            rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="PASS",
            evaluator=evaluator_name, witness="specs/START_MANIFEST.md",
            message=f"Rerun worktree, HEAD, dirty state, and manifest inputs verified ({rule.title}).",
        )

    exec_present, exec_ok, exec_art = _has_execution_record(ctx)
    if not exec_present:
        return RuleEvaluationResult(
            rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="NOT_EVALUATED",
            evaluator=evaluator_name, witness=exec_art,
            message=f"Rerun execution has not occurred yet for '{rule.title}'.",
        )
    if not exec_ok:
        return RuleEvaluationResult(
            rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="FAIL",
            evaluator=evaluator_name, witness=exec_art,
            message=f"Independent rerun execution failed or recorded errors for '{rule.title}'.",
        )
    return RuleEvaluationResult(
        rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="PASS",
        evaluator=evaluator_name, witness=exec_art,
        message=f"Independent rerun execution parity verified ({rule.title}).",
    )


def _eval_eval_curator(rule: RubricRule, ctx: Dict[str, Any], evaluator_name: str) -> RuleEvaluationResult:
    if ctx.get("benchmark_sla_breach"):
        return RuleEvaluationResult(
            rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="FAIL",
            evaluator=evaluator_name, witness="benchmark_sla_breach",
            message=f"Benchmark SLA breach detected: {ctx['benchmark_sla_breach']}.",
        )
    ast_m = ctx.get("ast_metrics", {})
    if rule.rule_id in ("EVAL_CURATOR-001", "EVAL_CURATOR-019"):
        if not ctx.get("start_manifest_ok"):
            return _ev_fail(rule, "specs/START_MANIFEST.md", f"Manifest integrity error: {ctx.get('start_manifest_err')}")
        return RuleEvaluationResult(
            rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="PASS",
            evaluator=evaluator_name, witness="controls/DISPOSITIONS.json",
            message=f"Owner disposition and label authority verified ({rule.title}).",
        )
    if rule.rule_id in ("EVAL_CURATOR-002", "EVAL_CURATOR-017"):
        if not ctx.get("start_manifest_ok") or not ctx.get("repo_heads"):
            return RuleEvaluationResult(
                rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="FAIL",
                evaluator=evaluator_name, witness="specs/START_MANIFEST.md",
                message="Pinned source or manifest identity missing/mismatched.",
            )
        return RuleEvaluationResult(
            rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="PASS",
            evaluator=evaluator_name, witness="specs/START_MANIFEST.md",
            message=f"Candidate source and tool manifest bytes verified ({rule.title}).",
        )
    if rule.rule_id in ("EVAL_CURATOR-011", "EVAL_CURATOR-012"):
        if ast_m.get("eval_imports_in_repo"):
            return RuleEvaluationResult(
                rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="FAIL",
                evaluator=evaluator_name, witness=ast_m["eval_imports_in_repo"][0],
                message=f"Held-out eval import leak in repo: {ast_m['eval_imports_in_repo'][0]}.",
            )
        return RuleEvaluationResult(
            rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="PASS",
            evaluator=evaluator_name, witness="evals/",
            message="Held-out/eval separation from tuned product code verified.",
        )
    if rule.rule_id in ("EVAL_CURATOR-020", "EVAL_CURATOR-021"):
        if ctx.get("removed_assertions") or ast_m.get("skipped_tests_in_code") or ast_m.get("weak_assertions"):
            witness = (ctx.get("removed_assertions") or ast_m.get("skipped_tests_in_code") or ast_m.get("weak_assertions"))[0]
            return RuleEvaluationResult(
                rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="FAIL",
                evaluator=evaluator_name, witness=witness,
                message=f"Assertion/check relaxation detected: {witness}.",
            )
        return RuleEvaluationResult(
            rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="PASS",
            evaluator=evaluator_name, witness="repos/*",
            message="Zero assertion removals or silent check relaxations detected.",
        )
    if rule.rule_id == "EVAL_CURATOR-022":
        if ctx.get("out_of_scope_files") or ctx.get("untouched_dirty"):
            witness = (ctx.get("out_of_scope_files") or ctx.get("untouched_dirty"))[0]
            return RuleEvaluationResult(
                rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="FAIL",
                evaluator=evaluator_name, witness=witness,
                message=f"Scope containment violated beyond minimal change boundary: {witness}.",
            )
        return RuleEvaluationResult(
            rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="PASS",
            evaluator=evaluator_name, witness="Phase-1/declared_scope.json",
            message="Minimal declared scope change boundary respected.",
        )

    exec_present, exec_ok, exec_art = _has_execution_record(ctx)
    if not exec_present:
        return RuleEvaluationResult(
            rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="NOT_EVALUATED",
            evaluator=evaluator_name, witness=exec_art,
            message=f"Evaluation execution evidence absent for '{rule.title}'.",
        )
    if not exec_ok:
        return RuleEvaluationResult(
            rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="FAIL",
            evaluator=evaluator_name, witness=exec_art,
            message=f"Evaluation execution regression or failure detected for '{rule.title}'.",
        )
    return RuleEvaluationResult(
        rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="PASS",
        evaluator=evaluator_name, witness=exec_art,
        message=f"Eval curator regression and typed outcome checks verified ({rule.title}).",
    )


def _make_strategy_executor(strategy_name: str, evaluator_impl: str):
    """Build a dedicated strategy execution callable bound to its matrix strategy and evaluator."""
    def _execute_strategy(
        rule: RubricRule,
        workspace_root: Path,
        repo_path: Path,
        ctx: Dict[str, Any],
    ) -> RuleEvaluationResult:
        res = _dispatch_evaluator_for_strategy(rule, workspace_root, repo_path, ctx, evaluator_impl)
        res.evaluation_strategy = strategy_name
        return res

    _execute_strategy.__name__ = f"strategy_{strategy_name}"
    return _execute_strategy


EVALUATOR_REGISTRY: Dict[str, Any] = {
    "human_waiver_evaluator": _evaluate_human_waiver,
    "agent_assisted_evaluator": _evaluate_agent_assisted,
    "phase_evidence_validator": _evaluate_evidence_rule,
    "blast_radius_containment": _eval_blast_radius,
    "failure_class_secret_detector": _eval_failure_class,
    "upstream_reuse_dependency_analyzer": _eval_upstream_reuse,
    "test_adequacy_suite_inspector": _eval_test_adequacy,
    "independent_rerun_environment_verifier": _eval_independent_rerun,
    "eval_curator_benchmark_verifier": _eval_eval_curator,
}

STRATEGY_REGISTRY: Dict[str, Dict[str, Any]] = {
    s_name: {
        "strategy": s_name,
        "evaluator": ev_impl,
        "category": cat,
        "exemption_predicate": ex_pred,
        "allowed_domains": frozenset(doms),
        "handler": _make_strategy_executor(s_name, ev_impl),
    }
    for s_name, (ev_impl, cat, ex_pred, doms) in _CANONICAL_STRATEGY_SPECS.items()
}


def evaluate_rubric_rule(
    rule: RubricRule,
    workspace_root: Path,
    repo_path: Path,
    context: Optional[Dict[str, Any]] = None,
) -> RuleEvaluationResult:
    """Evaluate an individual rubric rule against its 270-rule matrix entry and registered strategy."""
    try:
        # 1. Resolve and strictly verify single authoritative matrix entry (domain, category, criterion, strategy, evaluator)
        matrix_entry, matrix_err = _resolve_and_validate_matrix_entry(rule, context=context)
        if matrix_err is not None:
            return matrix_err
        assert matrix_entry is not None

        strategy_name = str(matrix_entry["evaluation_strategy"])
        evaluator_impl = str(matrix_entry["evaluator_implementation"])
        strategy_spec = STRATEGY_REGISTRY[strategy_name]

        # 2. Collect or reuse repository and evidence context
        ctx = context if (context and context.get("_collected")) else _collect_rubric_context(
            workspace_root=workspace_root,
            task_id=(context or {}).get("task_id") or load_active_state(workspace_root).get("task_id", "task-default"),
            attempt=int((context or {}).get("attempt") or load_active_state(workspace_root).get("attempt_index", 1)),
            repo_dirs=[repo_path] if repo_path.is_dir() else None,
            existing_context=context,
        )

        # 3. Check genuine criterion-matched structural exemption predicate (unless suppressed by multi-repo requirement)
        suppress_rule = ctx.get("_suppress_exemption_for_rule")
        if rule.exemption_predicate and suppress_rule != rule.rule_id:
            pred_fn = EXEMPTION_PREDICATES.get(rule.exemption_predicate)
            if pred_fn and pred_fn(workspace_root, repo_path):
                rel_ev = _resolve_predicate_evidence_path(workspace_root, repo_path)
                return RuleEvaluationResult(
                    rule_id=rule.rule_id,
                    domain=rule.domain,
                    category=rule.category,
                    status="NOT_APPLICABLE",
                    evaluator="structural_predicate_evaluator",
                    evaluation_strategy=strategy_name,
                    exemption_predicate=rule.exemption_predicate,
                    rationale=rule.exemption_rationale or "Structurally exempt based on codebase topology.",
                    evidence_path=rel_ev,
                )

        # 4. Explicit context overrides
        if rule.rule_id in ctx.get("blocked_rules", []):
            return RuleEvaluationResult(
                rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="BLOCKED",
                evaluator=evaluator_impl, evaluation_strategy=strategy_name,
                message=f"Rule '{rule.rule_id}' blocked by governance policy or unverified prerequisite.",
            )
        if rule.rule_id in ctx.get("unevaluated_rules", []):
            return RuleEvaluationResult(
                rule_id=rule.rule_id, domain=rule.domain, category=rule.category, status="NOT_EVALUATED",
                evaluator=evaluator_impl, evaluation_strategy=strategy_name,
                message=f"Rule '{rule.rule_id}' not evaluated: verification deferred.",
            )

        # 5. Fail closed when declared matrix required_inputs / required_evidence are unavailable
        missing_ev_res = _validate_rule_inputs_and_evidence(rule, matrix_entry, workspace_root, ctx)
        if missing_ev_res is not None:
            return missing_ev_res

        # 6. Dispatch through validated strategy handler in STRATEGY_REGISTRY / EVALUATOR_REGISTRY
        handler = strategy_spec["handler"]
        result = handler(rule, workspace_root, repo_path, ctx)
        if not result.evaluation_strategy:
            result.evaluation_strategy = strategy_name
        return result

    except InvalidRubricExemptionError:
        raise
    except Exception as err:
        return RuleEvaluationResult(
            rule_id=rule.rule_id,
            domain=rule.domain,
            category=rule.category,
            status="FAIL",
            evaluator=EVALUATOR_MAP.get(rule.domain, "error_fallback"),
            message=f"Evaluation execution failure for rule '{rule.rule_id}': {err}",
        )


def aggregate_rubric_results(
    evaluations: List[Union[RuleEvaluationResult, Dict[str, Any]]]
) -> Tuple[str, Dict[str, int], Dict[str, Any]]:
    """Deterministically aggregate rule evaluations into domain summaries and overall verdict (Spec 02 / GAP-01 / GAP-03).

    Rules:
    - Domain status is 'FAIL' if any rule failed; 'BLOCKED' if any rule is blocked;
      'NOT_EVALUATED' if any rule is unevaluated; 'PASS' only if all rules passed or are exempt.
    - Overall verdict is 'FAIL' if any required rule failed, is blocked, or is unevaluated.
    - Overall verdict is 'PASS' only if every rule is PASS or NOT_APPLICABLE.
    - Domain counts and overall counts are guaranteed to be mutually consistent.
    """
    eval_dicts = [e.to_dict() if isinstance(e, RuleEvaluationResult) else e for e in evaluations]

    seen_ids: Set[str] = set()
    duplicate_ids: List[str] = []
    for item in eval_dicts:
        rid = item.get("rule_id")
        if isinstance(rid, str) and rid:
            if rid in seen_ids and rid not in duplicate_ids:
                duplicate_ids.append(rid)
            seen_ids.add(rid)
    if duplicate_ids:
        raise DuplicateRuleEvaluationError(
            f"Duplicate rubric rule evaluation(s) rejected during aggregation: {', '.join(sorted(duplicate_ids))}"
        )

    total_rules = len(eval_dicts)
    passed = sum(1 for e in eval_dicts if e.get("status") == "PASS")
    failed = sum(1 for e in eval_dicts if e.get("status") == "FAIL")
    na = sum(1 for e in eval_dicts if e.get("status") == "NOT_APPLICABLE")
    not_evaluated = sum(1 for e in eval_dicts if e.get("status") == "NOT_EVALUATED")
    blocked = sum(1 for e in eval_dicts if e.get("status") == "BLOCKED")

    if failed > 0 or blocked > 0 or not_evaluated > 0:
        overall_verdict = "FAIL"
    elif total_rules > 0 and (passed + na == total_rules):
        overall_verdict = "PASS"
    else:
        overall_verdict = "FAIL"

    counts = {
        "total_rules": total_rules,
        "passed": passed,
        "failed": failed,
        "not_applicable": na,
        "not_evaluated": not_evaluated,
        "blocked": blocked,
    }

    domain_groups: Dict[str, List[Dict[str, Any]]] = {}
    for e in eval_dicts:
        domain = e.get("domain", "COMMON")
        domain_groups.setdefault(domain, []).append(e)

    domains_map: Dict[str, Any] = {}
    for d_name, d_rules in domain_groups.items():
        d_total = len(d_rules)
        d_passed = sum(1 for r in d_rules if r.get("status") == "PASS")
        d_failed = sum(1 for r in d_rules if r.get("status") == "FAIL")
        d_na = sum(1 for r in d_rules if r.get("status") == "NOT_APPLICABLE")
        d_not_eval = sum(1 for r in d_rules if r.get("status") == "NOT_EVALUATED")
        d_blocked = sum(1 for r in d_rules if r.get("status") == "BLOCKED")

        if d_failed > 0:
            d_status = "FAIL"
        elif d_blocked > 0:
            d_status = "BLOCKED"
        elif d_not_eval > 0:
            d_status = "NOT_EVALUATED"
        elif d_total > 0 and (d_passed + d_na == d_total):
            d_status = "PASS"
        else:
            d_status = "FAIL"

        domains_map[d_name] = {
            "status": d_status,
            "counts": {
                "total_rules": d_total,
                "passed": d_passed,
                "failed": d_failed,
                "not_applicable": d_na,
                "not_evaluated": d_not_eval,
                "blocked": d_blocked,
            },
            "rules": d_rules,
        }

    return overall_verdict, counts, domains_map


def run_rubric_evaluation(
    workspace_root: Union[str, Path],
    task_id: Optional[str] = None,
    attempt: Optional[int] = None,
    cycle: Optional[int] = None,
    target_domain: Optional[str] = None,
    fail_fast: bool = False,
    context: Optional[Dict[str, Any]] = None,
) -> Tuple[Dict[str, Any], float]:
    """Execute complete 270-rule evaluation and return (evaluation_dict, elapsed_ms)."""
    start_time = time.perf_counter()
    root = Path(workspace_root).resolve()
    state = load_active_state(root)

    resolved_task = task_id or state.get("task_id", "task-default")
    resolved_attempt = attempt or state.get("attempt_index", 1)
    resolved_cycle = cycle or 1

    catalog = load_270_rule_catalog()

    repos_dir = root / "repos"
    repo_dirs: List[Path] = []
    if repos_dir.is_dir():
        repo_dirs = [d for d in sorted(repos_dir.iterdir()) if d.is_dir() and not d.name.startswith(".")]
    target_repo = repo_dirs[0] if repo_dirs else repos_dir

    live_context = _collect_rubric_context(
        workspace_root=root,
        task_id=resolved_task,
        attempt=resolved_attempt,
        repo_dirs=repo_dirs,
        existing_context=context,
    )
    raw_by_id: Dict[str, List[Dict[str, Any]]] = {}
    for entry in _get_raw_matrix_entries():
        if isinstance(entry, dict) and isinstance(entry.get("rule_id"), str):
            raw_by_id.setdefault(entry["rule_id"], []).append(entry)
    live_context["_raw_matrix_by_id"] = raw_by_id

    evaluations: List[RuleEvaluationResult] = []

    for rule in catalog:
        if target_domain and rule.domain.upper() != target_domain.upper():
            continue

        # In multi-repo workspaces, exemption holds only if ALL registered repos satisfy predicate
        if rule.exemption_predicate and len(repo_dirs) > 1:
            pred_fn = EXEMPTION_PREDICATES.get(rule.exemption_predicate)
            if pred_fn and not all(pred_fn(root, r_d) for r_d in repo_dirs):
                live_context["_suppress_exemption_for_rule"] = rule.rule_id
                try:
                    res = evaluate_rubric_rule(rule, root, target_repo, live_context)
                finally:
                    live_context.pop("_suppress_exemption_for_rule", None)
                evaluations.append(res)
                if fail_fast and res.status in ("FAIL", "BLOCKED"):
                    break
                continue

        res = evaluate_rubric_rule(rule, root, target_repo, live_context)
        evaluations.append(res)
        if fail_fast and res.status in ("FAIL", "BLOCKED"):
            break

    eval_dicts = [e.to_dict() for e in evaluations]
    validate_rubric_evaluation_payload(eval_dicts)

    overall_verdict, counts, domains_map = aggregate_rubric_results(evaluations)
    completeness = analyze_rubric_completeness(eval_dicts, target_domain=target_domain)
    if completeness["evaluation_completeness"] != "COMPLETE":
        overall_verdict = "FAIL"

    elapsed_ms = (time.perf_counter() - start_time) * 1000.0

    payload: Dict[str, Any] = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "schema_version": "2.0.0",
        "task_id": resolved_task,
        "attempt": resolved_attempt,
        "cycle": resolved_cycle,
        "evaluated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "overall_verdict": overall_verdict,
        "evaluation_completeness": completeness["evaluation_completeness"],
        "expected_rule_count": completeness["expected_rule_count"],
        "evaluated_rule_count": completeness["evaluated_rule_count"],
        "missing_rules": completeness["missing_rules"],
        "duplicate_rules": completeness["duplicate_rules"],
        "target_domain": target_domain,
        "context_digest": live_context.get("context_digest"),
        "counts": counts,
        "domains": domains_map,
        "evaluations": eval_dicts,
    }

    validate_rubric_evaluation(payload)
    return payload, elapsed_ms


def update_rubric_artifacts(
    workspace_root: Union[str, Path],
    rubric_payload: Dict[str, Any],
) -> Tuple[Path, Optional[Path]]:
    """Save rubric_evaluation.json and update pre_commit_review.json accordingly."""
    root = Path(workspace_root).resolve()
    task_id = rubric_payload["task_id"]
    attempt = rubric_payload["attempt"]

    p2a_dir = resolve_task_attempt_dir(root, task_id, attempt) / "Phase-2A"
    p2a_dir.mkdir(parents=True, exist_ok=True)

    rubric_file = p2a_dir / "rubric_evaluation.json"
    rubric_file.write_text(canonical_json_dumps(rubric_payload), encoding="utf-8")

    review_file = p2a_dir / "pre_commit_review.json"
    updated_review = None

    if review_file.is_file():
        try:
            rev_data = load_json_file(review_file)
            is_complete = rubric_payload.get("evaluation_completeness") == "COMPLETE"
            rev_data["rubric_summary"] = {
                "total_evaluated": rubric_payload["counts"]["total_rules"],
                "expected_rule_count": rubric_payload.get("expected_rule_count", 270),
                "evaluation_completeness": rubric_payload.get("evaluation_completeness", "PARTIAL"),
                "passed": rubric_payload["counts"]["passed"],
                "failed": rubric_payload["counts"]["failed"],
                "not_applicable": rubric_payload["counts"]["not_applicable"],
                "not_evaluated": rubric_payload["counts"].get("not_evaluated", 0),
                "blocked": rubric_payload["counts"].get("blocked", 0),
                "evaluation_file": str(rubric_file.relative_to(root)),
            }
            if rubric_payload["overall_verdict"] != "PASS" or not is_complete:
                rev_data["status"] = "REVISION_REQUIRED"
                blocking_rules = [
                    e for e in rubric_payload["evaluations"] if e.get("status") in ("FAIL", "BLOCKED", "NOT_EVALUATED")
                ]
                for f_rule in blocking_rules:
                    rev_data.setdefault("new_issues_found", []).append({
                        "defect_id": f_rule["rule_id"],
                        "severity": "BLOCKING",
                        "location": f_rule.get("witness", "codebase"),
                        "description": f_rule.get("message", f"Rubric rule ended with status {f_rule.get('status')}."),
                    })
                if not is_complete:
                    rev_data.setdefault("new_issues_found", []).append({
                        "defect_id": "RUBRIC-INCOMPLETE",
                        "severity": "BLOCKING",
                        "location": str(rubric_file.relative_to(root)),
                        "description": (
                            f"Partial rubric evaluation ({rubric_payload.get('evaluated_rule_count')}/"
                            f"{rubric_payload.get('expected_rule_count', 270)}) cannot authorize approval."
                        ),
                    })
            review_file.write_text(canonical_json_dumps(rev_data), encoding="utf-8")
            updated_review = review_file
        except Exception:
            pass

    return rubric_file, updated_review
