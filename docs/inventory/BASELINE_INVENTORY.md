# StageCheck — Baseline Inventory & Current Behavior (P1-T1)

**Task ID:** P1-T1  
**Phase:** Phase 1 — Repository Baseline, Packaging, and Architecture Foundations  
**Target Repository:** `<workspace_root>`  
**Base Commit:** `b29c0e0` (branch: `main`, upstream: `https://github.com/Layavardhan011/StageCheck.git`)  
**Active Phase Branch:** `phase/phase-1-foundation`  
**Date of Audit:** 2026-11-04  

---

## 1. Executive Summary

This inventory documents the initial state of the StageCheck repository prior to modular refactoring and implementation. It catalogues all entrypoints, modules, verification checks, evaluation cases, schemas, configurations, and test suite execution results without modifying existing logic.

Key findings:
1. **Architecture & Packaging:** The repository currently has no root packaging metadata (`pyproject.toml` or `setup.py`). Modules are loose scripts located in `bin/` and `checks/`.
2. **External Machine Dependency:** The existing evaluation test suite (`evals/run_evals.py`, `evals/test_quality.py`, `evals/test_response.py`) contains a hardcoded absolute path pointing to an external developer machine (`/home/magnus/Desktop/Desk/WIP/1. Team/Dir/RWA/NewArc/3m/...`).
3. **Existing Test Execution:** Running `python3 -m unittest discover -s evals` executes 164 tests, resulting in **161 errors** specifically due to `FileNotFoundError` trying to access the missing external path `/home/magnus/.../verify_manifest.py`.
4. **Integrity Manifest:** `MANIFEST.sha256` tracks SHA-256 digests across 126 files in the repository.

---

## 2. Repository Structure & Module Map

### 2.1 Entrypoints and Orchestration (`bin/`)
The `bin/` directory contains legacy execution scripts:

| File | Purpose / Role | Key Dependencies | Migration Target |
|---|---|---|---|
| `bin/stagecheck.sh` | Shell launcher wrapper | Invokes `bin/orchestrate.py` | `stagecheck.cli` entrypoint |
| `bin/orchestrate.py` | 9-stage verification orchestrator | Runs `checks/*.py` sequentially | `stagecheck.core.orchestrator` |
| `bin/render_report.py` | Markdown report generation from verdict JSON | `schemas/verdict.schema.json` | `stagecheck.core.reporting` |
| `bin/response_hook.py` | Agent response validator hook | `config/response_hook.json` | `stagecheck.agent.hook` |
| `bin/agents.py` | Agent registry & model mapping | `config/agents.json` | `stagecheck.agent.registry` |
| `bin/response_tokens.py` | Token estimation and context-window limiter | `config/paths.json` | `stagecheck.agent.tokens` |
| `bin/quality_measure.py` | Code quality metrics aggregation | `config/quality_targets.json` | `stagecheck.core.quality` |
| `bin/quality_seeds.py` | Initial seeds for defect injection | `evals/` | `stagecheck.evals.fixtures` |
| `bin/quality_write.py` | Atomic writer for quality records | `schemas/quality_record.schema.json` | `stagecheck.core.storage` |
| `bin/quality.py` | Quality threshold evaluation | `config/quality_targets.json` | `stagecheck.checks.quality` |
| `bin/common.py` | Shared utility functions (JSON, logging, hashing) | Standard library | `stagecheck.core.utils` |

### 2.2 Verification Checks (`checks/`)
The `checks/` directory contains the 9 deterministic verification stages:

| Stage # | Module | Evaluated Condition | Exit Codes |
|:---:|---|---|:---:|
| 1 | `checks/preflight.py` | Environment allowlist, lock, prompt hash, tools | `0` (pass), `1` (defect) |
| 2 | `checks/scope_paths.py` | Repository file modification scope containment | `0` (pass), `1` (defect) |
| 3 | `checks/citations.py` | Working-tree line citation verification ($< 20$ MiB) | `0` (pass), `1` (defect) |
| 4 | `checks/report_lint.py` | Report defect regex format and prompt-injection defense | `0` (pass), `1` (defect) |
| 5 | `checks/authority.py` | Command authority and disposition waiver checking | `0` (pass), `1` (defect) |
| 6 | `checks/secrets.py` | Secret leak scanning (Gitleaks invocation) | `0` (pass), `1` (defect) |
| 7 | `checks/qual_naming.py` | Qualification file naming conventions (`test_*`) | `0` (pass), `1` (defect) |
| 8 | `checks/rerun.py` | Isolated clean-room rerun with mode `0600` capture logs | `0` (pass), `1` (defect) |
| 9 | `checks/carry_forward.py` | Defect carry-forward and regression prevention | `0` (pass), `1` (defect) |

### 2.3 JSON Schemas (`schemas/`)
| Schema File | Target Validated Artifact |
|---|---|
| `schemas/verdict.schema.json` | Phase 3 audit output verdict (`verdict.json`) |
| `schemas/claims.schema.json` | Agent 2 delivery claim citations (`claims.json`) |
| `schemas/quality_record.schema.json` | Code quality metrics record (`CODE_QUALITY_REPORT.json`) |

### 2.4 Configuration Descriptors (`config/`)
* `config/commands.json`: Whitelisted execution commands and arguments.
* `config/agents.json`: Specialist model mappings and prompt definitions.
* `config/paths.json`: Workspace relative path mappings.
* `config/quality_targets.json`: Quality thresholds (coverage targets, defect ceilings).
* `config/required_outcomes.json`: Mandatory stage pass outcomes.
* `config/modes.json`: Operational execution mode parameters.
* `config/response_hook.json`: Pre-commit hook interception rules.
* `config/remotes.json`: Permitted remote repository declarations.
* `config/depth.json`: Audit depth parameters.
* `config/controlled_vocabulary.json`: Standardized defect categories and naming.

### 2.5 Agent Instruction Manuals (`agent_instructions/`)
* `00_common.md`: Shared review discipline and instruction standards.
* `orchestrator.md`: Deterministic orchestration sequence.
* Specialist manuals: `claim_support.md`, `upstream_reuse.md`, `blast_radius.md`, `test_adequacy.md`, `independent_rerun.md`, `failure_class.md`, `eval_curator.md`.

---

## 3. Evaluation & Existing Test Suite Analysis

### 3.1 Test Files in `evals/`
* `evals/test_quality.py`: Test cases for code quality checks and damage recovery.
* `evals/test_response.py`: Test cases for agent response validation and scope probes.
* `evals/test_response_guards.py`: Test cases for prompt refusal and injection defense.
* `evals/cases/`: 40 discrete defect injection fixtures.
* `evals/heldout/`: 4 heldout validation fixtures.

### 3.2 Baseline Test Execution Evidence
* **Command Executed:** `python3 -m unittest discover -s evals`
* **Execution Environment:** Linux x86_64, Python 3.12.3
* **Total Tests Ran:** 164
* **Passing Tests:** 3
* **Failed / Errored Tests:** 161
* **Root Cause:**
  `evals/run_evals.py` line 71 hardcodes:
  ```python
  PROGRAMME = Path("/home/magnus/Desktop/Desk/WIP/1. Team/Dir/RWA/NewArc/3m")
  ...
  shutil.copyfile(programme_source / 'evidence/claude_audits/tools' / name, root / 'evidence/claude_audits/tools' / name)
  ```
  Because `/home/magnus/...` does not exist on this machine (or any standard deployment), 161 test fixtures fail during `setUp()` with `FileNotFoundError`.
* **Resolution Plan:**
  - In P1-T3, implement portable workspace root and relative path helpers.
  - In P1-T5 and P5-T1, replace external filesystem fixture assumptions with synthetic, self-contained fixtures.

---

## 4. Manifest Inventory (`MANIFEST.sha256`)

The repository root includes `MANIFEST.sha256` containing 126 entries. All entries hash repository files using SHA-256. This inventory forms the baseline against which module refactoring and migration to the `stagecheck` package hierarchy will be tracked in P1-T2.

---

## 5. Acceptance Criteria Checklist (P1-T1)

| Requirement | Evidence | Status |
|---|---|:---:|
| Baseline commit and branch captured | Commit `b29c0e0` on `phase/phase-1-foundation` recorded | **SATISFIED** |
| Module, entrypoint, check, and schema inventory | Sections 2.1–2.5 map every file in repository | **SATISFIED** |
| Existing test suite execution recorded | Section 3 records 164 tests, 161 errors, root cause | **SATISFIED** |
| Existing files left unaltered | No source code altered; documented in dedicated inventory | **SATISFIED** |

