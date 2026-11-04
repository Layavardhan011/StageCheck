"""AGENTS.md Binding Contract Renderer and Integrity Table Generator (P2-T4).

Renders the root workspace governance contract AGENTS.md, embedding the
8-row SHA-256 control manifest table, dual-agent roles, and remote push bans.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, Optional, Union

from stagecheck.core.utils import sha256_file


AGENTS_MD_TEMPLATE = """# AGENTS.md — Governed Dual-Agent Operating Contract

> **Workspace Trust Root:** This document establishes the binding governance contract
> and operational invariants for all AI agents operating within this workspace.

---

## 1. Authoritative Control Descriptors (8-Row Integrity Binding Table)

The 8 workspace control descriptors located in `controls/` are human-owned and locked.
Their initial cryptographic digests are recorded below:

| Control Descriptor | Relative Path | Initial SHA-256 Digest | Governance Role |
|---|---|---|---|
| `STAGECHECK_ROOT.json` | `controls/STAGECHECK_ROOT.json` | `{stagecheck_root_sha256}` | Package root & dual-mode resolution |
| `EVIDENCE_ROOT.json` | `controls/EVIDENCE_ROOT.json` | `{evidence_root_sha256}` | Evidence store anchor & directory configuration |
| `PRODUCT_REPOSITORIES.json` | `controls/PRODUCT_REPOSITORIES.json` | `{product_repositories_sha256}` | Schema v2 multi-repo registry & commit heads |
| `QUALIFICATION_ROOT.json` | `controls/QUALIFICATION_ROOT.json` | `{qualification_root_sha256}` | Test suite and qualification discovery path |
| `ACTIVE_STATE.json` | `controls/ACTIVE_STATE.json` | `{active_state_sha256}` | Authoritative task state, attempts & circuit breaker |
| `OWNER_GRANTS.md` | `controls/OWNER_GRANTS.md` | `{owner_grants_sha256}` | Human owner authorizations & command grants |
| `FAILURE_PREVENTION.md` | `controls/FAILURE_PREVENTION.md` | `{failure_prevention_sha256}` | Known defect patterns & anti-regression constraints |
| `DISPOSITIONS.json` | `controls/DISPOSITIONS.json` | `{dispositions_sha256}` | Atomic ledger of human defect waivers |

---

## 2. Dual-Agent Role Boundaries & Authority

### Agent 1: Prompt Architect & Audit Verifier (`prompt_and_audit`)
* **Responsibilities:**
  1. Crafts Phase 1 prompt blueprints in `evidence/tasks/<task_id>/attempt_<N>/Phase-1/prompt.md`.
  2. Binds `quality_targets.json` thresholds and multi-repository target scopes.
  3. Executes `stagecheck verify-prompt` to freeze canonical `prompt_sha256`.
  4. Conducts Phase 2A pre-commit review (`stagecheck review-precommit`) evaluating diffs and coverage.
* **Prohibitions:**
  * Must never write implementation code directly into product repositories.
  * Must never bypass Phase 2A cooperative review findings.

### Agent 2: Code Implementer (`code_implementation`)
* **Responsibilities:**
  1. Checks out designated task branches (`fincore/<task_id>`).
  2. Implements code changes strictly within `approved_scope` across target repositories.
  3. Emits `pre_commit_status.json` and participates in Phase 2A review cycles.
  4. Commits changes **locally only** and generates delivery `claims.json` and `report.md`.
* **Prohibitions:**
  * **Zero Remote Pushes:** Executing `git push` or remote transport commands is strictly forbidden (Exit 126).
  * Direct commits to `main` or `master` branches are strictly prohibited (Exit 126).
  * Must never attempt to modify `controls/` or directly alter `verdict.json` or `seal.json`.

---

## 3. Mandatory Governance Invariants

1. **Advisory Workspace Locking:** All StageCheck state operations execute under exclusive `fcntl.flock` on `controls/.stagecheck.lock`.
2. **Controlled Write Protocol:** Changes to `controls/` require temporary permission elevation, `O_CREAT | O_EXCL` temp files, `fsync`, and mode restoration (`0555` / `0444`).
3. **Attempt Budget & Circuit Breaker:** Tasks have a maximum of 3 automated attempts. A third failure trips into `CIRCUIT_BREAKER_TRIPPED`, requiring human owner continuation (`stagecheck reset-attempts`).
4. **Append-Only Evidence:** Historical defects are cumulatively preserved in `TASK_<ID>_ISSUE_HISTORY.md` across repair attempts.
"""


def render_agents_contract(controls_dir: Path) -> str:
    """Calculate SHA-256 digests for all 8 controls and render the complete AGENTS.md contract text.

    Args:
        controls_dir: Path to the populated controls/ directory.

    Returns:
        Rendered AGENTS.md Markdown string with verified hashes.

    Raises:
        FileNotFoundError: If any of the 8 mandatory control files is missing.
    """
    required_files = [
        "STAGECHECK_ROOT.json",
        "EVIDENCE_ROOT.json",
        "PRODUCT_REPOSITORIES.json",
        "QUALIFICATION_ROOT.json",
        "ACTIVE_STATE.json",
        "OWNER_GRANTS.md",
        "FAILURE_PREVENTION.md",
        "DISPOSITIONS.json",
    ]

    digests: Dict[str, str] = {}
    for filename in required_files:
        file_path = controls_dir / filename
        if not file_path.is_file():
            raise FileNotFoundError(f"Cannot render AGENTS.md: missing control file '{file_path}'.")
        digests[filename] = sha256_file(file_path)

    contract_text = AGENTS_MD_TEMPLATE.format(
        stagecheck_root_sha256=digests["STAGECHECK_ROOT.json"],
        evidence_root_sha256=digests["EVIDENCE_ROOT.json"],
        product_repositories_sha256=digests["PRODUCT_REPOSITORIES.json"],
        qualification_root_sha256=digests["QUALIFICATION_ROOT.json"],
        active_state_sha256=digests["ACTIVE_STATE.json"],
        owner_grants_sha256=digests["OWNER_GRANTS.md"],
        failure_prevention_sha256=digests["FAILURE_PREVENTION.md"],
        dispositions_sha256=digests["DISPOSITIONS.json"],
    )

    return contract_text


def write_agents_contract(workspace_root: Path) -> Path:
    """Render and write AGENTS.md at the root of the workspace.

    Args:
        workspace_root: Canonical workspace root directory path.

    Returns:
        Path to the written AGENTS.md file.
    """
    root = Path(workspace_root).resolve()
    controls_dir = root / "controls"
    contract_content = render_agents_contract(controls_dir)

    agents_md_path = root / "AGENTS.md"
    agents_md_path.write_text(contract_content, encoding="utf-8")
    return agents_md_path

