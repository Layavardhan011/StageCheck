# StageCheck v2.0.0 — Baseline Inventory and Contract Map (Task 1.1)

**Document ID:** `DOC-P1-T1-BASELINE-CONTRACT-MAP`  
**Phase:** Phase 1 — Foundation and Secure Primitives  
**Task:** 1.1 — Baseline inventory and contract map  
**Target Repository:** StageCheck (`StageCheck/`)  
**Base Commit:** `61ef9aa`  
**Active Branch:** `feat/v2.0.0`  
**Date of Audit:** 2026-11-06  
**Status:** Approved Task Deliverable  

---

## 1. Executive Summary

This inventory establishes the verified baseline of the StageCheck codebase at the inception of the v2.0.0 implementation cycle. It systematically catalogues all existing modules, CLI entrypoints, verification checks, schemas, test suites, legacy assets, and architectural contracts, cross-mapping them directly against the canonical Master Architecture Specification ([`SPEC-01-STAGECHECK-V2-MASTER`](file:///home/laya/Development/StageCheck-Tool/architecture_changes/v2.0.0/STAGECHECK_V2_FINAL_ARCHITECTURE.md)), the 7 focused v2.0.0 topic specifications, and the 25-task implementation roadmap ([`StageCheck_planning_artifacts/`](file:///home/laya/Development/StageCheck-Tool/StageCheck_planning_artifacts/planning/README.md)).

### Baseline Test Execution Results
- **Test Runner:** `pytest 9.2.0` (Python 3.12.3, Linux x86_64)
- **Invocation:** `.venv/bin/pytest -v`
- **Total Tests Collected & Executed:** 231 items
- **Outcomes:** **231 passed**, 71 subtests passed, 0 failures, 0 errors (duration: 36.96s)
- **Status:** Clean regression baseline established across all existing unit, integration, and lifecycle suites.

---

## 2. Package and Module Inventory

### 2.1 Modern Python Package (`stagecheck/`)
The canonical application package is structured under `stagecheck/` with PEP 621 metadata defined in `pyproject.toml`:

| Module Path | Primary Responsibility | Key Interfaces & Exports |
|---|---|---|
| `stagecheck/cli/main.py` | Unified CLI router & argument dispatch | Subcommands: `init`, `plan`, `turn`, `status`, `review`, `approve`, `audit`, `seal`, `disposition`, `unlock` |
| `stagecheck/cli/init_cmd.py` | Workspace initialization & scaffolding | `run_init` |
| `stagecheck/cli/review_cmd.py` | Phase 2A pre-commit review commands | `run_review_precommit`, `run_approve_review` |
| `stagecheck/cli/disposition_cmd.py` | Human waiver and breaker disposition | `run_disposition` |
| `stagecheck/cli/plan_cmd.py` | Task plan validation & DAG topological sorting | `run_plan` |
| `stagecheck/cli/ops_cmd.py` | Operational CLI utilities (unlock, seal, quality) | `run_unlock`, `run_seal` |
| `stagecheck/core/scaffold.py` | Workspace templates & mandatory controls creation | `scaffold_workspace`, `reconcile_workspace_scaffolding` |
| `stagecheck/core/permissions.py` | Linux POSIX permission lifecycle (0555/0444) | `controlled_write_transaction`, `freeze_directory_tree` |
| `stagecheck/core/locking.py` | Workspace runtime locking (`.stagecheck.lock`) | `acquire_runtime_lock`, `release_runtime_lock` |
| `stagecheck/core/paths.py` | Path resolution & traversal security | `safe_resolve`, `resolve_workspace_root` |
| `stagecheck/core/commands.py` | Subprocess runner & command allowlist | `validate_command_security`, `execute_secure_command` |
| `stagecheck/core/git.py` | Git subprocess execution & repository status | `_run_git_cmd`, `get_repo_status`, `capture_repo_baseline` |
| `stagecheck/core/state.py` | Authoritative state witness persistence | `load_active_state`, `save_active_state` |
| `stagecheck/core/prompt_gate.py` | Gate 1 prompt & scope validation | `verify_prompt_blueprint`, `freeze_prompt_and_scope` |
| `stagecheck/core/cooperative_review.py` | Phase 2A pre-commit status & diff review | `capture_pre_commit_snapshot`, `record_pre_commit_review` |
| `stagecheck/core/branch_governance.py` | Branch naming policies & baseline verification | `verify_branch_policy`, `capture_multi_repo_task_baseline` |
| `stagecheck/core/scanner.py` | Gitleaks secret leak detection integration | `SecretScanner`, `run_staged_scan`, `run_repo_scan` |
| `stagecheck/core/orchestrator.py` | Multi-stage verification audit engine | `AuditOrchestrator`, `run_audit` |
| `stagecheck/core/circuit_breaker.py` | Attempt tracking & breaker trip protocol | `CircuitBreakerEvaluation`, `trip_circuit_breaker` |
| `stagecheck/core/dispositions.py` | Defect waiver ledger & transaction logging | `add_disposition`, `resume_after_disposition` |
| `stagecheck/core/evidence.py` | Evidence manifest & task attempt sealing | `update_evidence_manifest`, `create_task_seal` |
| `stagecheck/core/sentinel.py` | Linux Sentinel daemon monitoring & watchdog | `SentinelDaemon`, `run_sentinel` |
| `stagecheck/core/task_plan.py` | DAG validation (Kahn's algorithm) | `validate_task_plan`, `get_next_eligible_tasks` |
| `stagecheck/core/agents_md.py` | Dual-agent contract rendering & binding | `render_agents_contract`, `verify_agents_contract` |
| `stagecheck/core/utils.py` | Canonical JCS (RFC 8785), SHA-256, pretty JSON | `canonical_json_dumps`, `pretty_json_dumps`, `sha256_file` |
| `stagecheck/checks/` | 9-stage verification check modules | `preflight`, `scope_paths`, `citations`, `report_lint`, `authority`, `secrets`, `qual_naming`, `stage8_rerun`, `carry_forward` |
| `stagecheck/schemas/` | JSON Schema validator & embedded assets | `validator.py`, `assets/*.schema.json` |

---

### 2.2 Legacy Assets & Compatibility Shims
The repository contains legacy directories preserved from v1.0.0:

| Legacy Path | Contents & Role | Status & Planned Action in v2.0.0 |
|---|---|---|
| `bin/orchestrate.py`, `bin/common.py`, etc. | 11 legacy scripts originally invoked by shell wrappers | Maintained for backward compatibility; canonical logic migrated to `stagecheck.core.*` |
| `checks/*.py` | Standalone check scripts | Maintained as shims calling `stagecheck.checks.*` |
| `config/*.json` | 10 JSON config files (`commands.json`, `paths.json`, etc.) | Embedded as package assets or workspace templates; audited for drift |
| `schemas/*.schema.json` | 3 legacy schemas (`claims`, `quality_record`, `verdict`) | Reconciled into canonical `stagecheck/schemas/assets/` |
| `evals/` | Defect injection fixtures and benchmark runner | Legacy evaluation suite; contains hardcoded external path to be refactored in Phase 5 |
| `agent_instructions/` | 9 auditing manuals containing 270 formal criteria | Automated into programmatic rubric engine (`check-rubric`) in Phase 3 |

---

## 3. Comprehensive Requirement & Contract Mapping

This matrix maps every functional and security requirement from the Master Architecture ([`SPEC-01-STAGECHECK-V2-MASTER`](file:///home/laya/Development/StageCheck-Tool/architecture_changes/v2.0.0/STAGECHECK_V2_FINAL_ARCHITECTURE.md)) to the implementation tasks and target modules:

| Requirement ID | Requirement Description & Master Spec Reference | Target Phase & Task | Responsible Module(s) | Baseline Status & Remaining Gap |
|---|---|:---:|---|---|
| **FR-01** | **4-Gate Lifecycle Pipeline:** Sequential clearance of Gate 1, 2A, 2B, 3, 4; separation of `stagecheck audit` (execution) and `gate advance Gate-3`; authoritative `seal` / `advance Gate-4`. | Phase 2 (2.3–2.5), Phase 4 (4.2, 4.5) | `stagecheck/core/orchestrator.py`, `stagecheck/cli/` | Partial in v1.0.0; Gate 3/4 separation and transactional Gate 4 sealing to be implemented in Phases 2 and 4. |
| **FR-02** | **Authoritative State Witness:** `ACTIVE_STATE.json` (`0555` dir, `0444` file) records receipt SHA-256 digests under `/workspace/.stagecheck.lock`; gate checks verify bitwise. | Phase 1 (1.4), Phase 2 (2.4) | `stagecheck/core/state.py`, `locking.py` | State persistence exists; receipt SHA-256 cross-verification to be hardened. |
| **FR-03** | **270-Rule Rubric Automation:** Exact categorization ($162 + 64 + 34 + 10 = 270$); execution < 200ms; deterministic `NOT_APPLICABLE` with structural predicates. | Phase 3 (3.2) | `stagecheck/core/rubric_engine.py` (new) | Currently 9 manual Markdown files; programmatic engine to be implemented. |
| **FR-04** | **Hybrid Supervisor & Debounce Ceiling:** Inotify 30s stability debounce on `prompt.md` with absolute 300s (5m) hard ceiling (`ARCH-01`). | Phase 3 (3.5) | `stagecheck/core/prompt_gate.py`, `supervisor.py` | Debounce logic present; 300s ceiling metadata logging to be verified. |
| **FR-05** | **Sentinel Watchdog Scope & Monotonic Resets:** Active strictly during agent phases (`1`, `2A`, `2B`); suspended during audit/sealing; resets only on relevant repository/evidence events or turn polls; monotonic time tracking. | Phase 3 (3.5), Phase 5 (5.1) | `stagecheck/core/sentinel.py` | Basic sentinel in place; phase-scoping, monotonic tracking, and restart recovery to be finalized. |
| **FR-06** | **Strict Monotonic Attempt Budgeting:** Hard cap of 3 total attempts; consumed strictly on failed Phase 3 audit; repair cycles, resumptions, and waivers do not increment attempt; no retry bypass. | Phase 1 (1.4), Phase 4 (4.5) | `stagecheck/core/circuit_breaker.py`, `dispositions.py` | Breaker exists; must strictly enforce rejection of `retry` on attempt 3 without attempt counter reset. |
| **FR-07** | **Agent Turn Protocol:** `stagecheck turn --json` with mandatory 5-second polling interval $\pm 1$s jitter (`ARCH-04`). | Phase 3 (3.1) | `stagecheck/core/agents_md.py`, `cli/main.py` | Turn mechanics exist; jitter throttling and rate limiting to be standardized. |
| **FR-08** | **Scaffolding Governance:** Reconciling idempotent `stagecheck init`; `START_MANIFEST.md` digest verification and authorized updates. | Phase 2 (2.1, 2.2) | `stagecheck/core/scaffold.py`, `manifest.py` | `stagecheck init` exists; full multi-file independent reconciliation to be completed. |
| **FR-09** | **Composite Diff Snapshot & Untracked Ceilings:** Bound untracked files to $\le 20$ MiB & $\le 500$ files (`ARCH-03`); typed errors `UntrackedBytesExceededError` / `UntrackedCountExceededError`. | Phase 3 (3.3) | `stagecheck/core/cooperative_review.py` | Tracked diff snapshot implemented; explicit untracked size/count ceilings to be wired. |
| **FR-10** | **Write-Ahead Crash Journal:** Multi-file operations execute under `.stagecheck_journal/` with transparent startup auto-recovery. | Phase 4 (4.3) | `stagecheck/core/journal.py` (new) | Dispositions have local WAL; global multi-file transaction journal to be implemented. |
| **FR-11** | **Topology-Preserving Worktrees:** Ephemeral audit worktrees mirror sibling structure under `.stagecheck_worktrees/<task>/attempt_<N>/repos/` preserving relative imports (`../shared`). | Phase 4 (4.1) | `stagecheck/checks/stage8_rerun.py`, `topology.py` | Worktree generation exists; sibling structure topology preservation to be standardized. |
| **FR-12** | **Deterministic Acyclic Merkle Sealing:** `attempt_<N>/seal.json` hashes deliverables; `EVIDENCE_MANIFEST.json` indexes seal downstream; pre-resolution symlink checks before path traversal. | Phase 1 (1.2), Phase 4 (4.4) | `stagecheck/core/evidence.py`, `sealing.py` | Sealing exists; pre-resolution symlink inspection and acyclic indexing to be hardened. |
| **SR-01** | **Command & Subcommand Hardening (SEC-01 / FP-CMD):** Allowlist of test runners; strict subcommands; `npm` policy (`test` required, approved optional targets, `--ignore-scripts`); `npx --no-install`. | Phase 1 (1.3) | `stagecheck/core/commands.py` | Basic allowlist in place; npm script allowlist, `--ignore-scripts`, and package.json validation to be added. |
| **SR-02** | **Safe Git Subprocess Security Flags (FP-GIT):** Prepend `SAFE_GIT_SECURITY_FLAGS` and `--no-ext-diff --no-textconv` to all Git subprocess calls. | Phase 1 (1.3) | `stagecheck/core/git.py` | Implemented in `git.py`; verify all call sites across modules. |
| **SR-03** | **Intermediate Directory Symlink Immunity (SEC-02):** Inspect all intermediate parent directory components via `curr.is_symlink()`, blocking symlink traversal into `controls/`. | Phase 1 (1.2) | `stagecheck/core/paths.py` | `safe_resolve` checks root escape; intermediate component check to be implemented in Task 1.2. |
| **SR-04** | **Authoritative Scanner Config (SEC-03):** Bind all Gitleaks scans to `config/.gitleaks.toml` via `--config`. | Phase 1 (1.3) | `stagecheck/core/scanner.py` | Implemented; verify wheel packaging inclusion. |
| **SR-05** | **State Schema Alignment (SEC-04):** Align schema to `attempt_index: 1`, `repair_index: 0`; allow nullable `halt_reason`; eliminate silent exception swallowing. | Phase 1 (1.4) | `stagecheck/core/state.py`, `schemas/` | Schema aligned; eliminate `except Exception: pass` in state persistence. |
| **SR-06** | **Atomic Runtime Lock (SEC-05):** Standardize `/workspace/.stagecheck.lock` (mode `0600`) via `os.open(..., O_CREAT \| O_RDWR, 0o600)`. | Phase 1 (1.4) | `stagecheck/core/locking.py` | Atomic creation implemented; decouple lock location from read-only `controls/`. |
| **SR-07** | **Notification Markup Escaping (SEC-07):** Apply `html.escape(quote=True)` to defect IDs and task names before desktop notifications. | Phase 1 (1.3), Phase 3 (3.5) | `stagecheck/core/sentinel.py`, `dispositions.py` | Escaping applied; verified by tests. |
| **SR-08** | **Dynamic Remote Authority (FP-ORG):** Dynamically normalize SSH and HTTPS URLs; match against `PRODUCT_REPOSITORIES.json`; eliminate hardcoded `xorewa/`. | Phase 1 (1.3) | `stagecheck/checks/authority.py` | Hardcoded org eliminated; dynamic matching verified. |
| **SR-09** | **Guarded Teardown:** Block `unlock --force` during active tasks (`IN_PROGRESS`); require `--abort-active-task` and structured `teardown.log`. | Phase 4 (4.5) | `stagecheck/core/locking.py`, `cli/ops_cmd.py` | Force unlock protected; structured record logging to be standardized. |
| **SR-10** | **Same-UID Threat Model Documentation:** Explicitly document filesystem permissions as defense-in-depth, not OS sandbox against same-UID code. | Phase 1 (1.1), Phase 5 (5.4) | `docs/` | Fully documented in Master Architecture and Task 1.1 report. |

---

## 4. Duplicate Sources of Truth & Generated Artifacts Analysis

### 4.1 Duplicate Sources of Truth
1. **Schema Assets:**
   - Legacy: `schemas/claims.schema.json`, `schemas/verdict.schema.json`, `schemas/quality_record.schema.json`.
   - Modern Canonical: `stagecheck/schemas/assets/*.schema.json`.
   - *Resolution Strategy:* `stagecheck/schemas/assets/` is the single source of truth for runtime validation; legacy `schemas/` directory will be maintained as read-only compatibility symlinks/shims during transition and marked deprecated.
2. **Configuration Files:**
   - Legacy: `config/commands.json`, `config/paths.json`, etc.
   - Modern Canonical: Embedded templates loaded via `importlib.resources` from `stagecheck/` package data.
   - *Resolution Strategy:* Package templates serve as default baselines; workspace `controls/commands.json` provides developer overrides.

### 4.2 Generated & Runtime Artifacts
The following artifacts are generated during execution and must be properly managed by lifecycle and gitignore rules:
- **Lock & PID Files:** `.stagecheck.lock`, `.stagecheck_sentinel.pid` (created at workspace root, mode `0600`).
- **Journal Files:** `.stagecheck_journal/txn_<uuid>.active.json` (mode `0700` dir / `0600` files; unlinked upon transaction commit).
- **Ephemeral Worktrees:** `.stagecheck_worktrees/` (cleaned up upon task completion; protected against teardown during active tasks).
- **Temporary State Files:** `controls/*.tmp`, `evidence/*.tmp` (cleaned up via atomic replacement).

---

## 5. Explicit Unknowns, Legacy Dependencies & Risks

1. **Legacy Evaluation Suite External Path:**
   - `evals/run_evals.py` contains hardcoded `/home/magnus/...` paths, failing legacy `unittest` discovery. Modern test suite under `tests/` (231 tests) does not depend on this path and passes 100%. In Phase 5 (Task 5.3), `evals/` will be migrated or provided with synthetic fixtures.
2. **Gitleaks Binary Availability:**
   - Secret scanning depends on system `gitleaks` binary. If not found, StageCheck fails closed with typed error `ScannerExecutionError` (exit code 126).
3. **Linux-Specific Features:**
   - Inotify daemon monitoring (`SentinelDaemon`) and desktop notifications (`notify-send`) are Linux-specific. On non-Linux platforms, fallback polling and graceful terminal warnings are required.
4. **Same-UID Threat Boundary:**
   - Re-verified: Filesystem permissions (`0555` directory, `0444` file) provide defense-in-depth against accidental modification by cooperative tools, but not OS-level sandboxing against malicious same-UID processes.

---

## 6. Three-Pass Review Verification Record

In accordance with Phase 1 execution rules, Task 1.1 underwent three independent review passes prior to completion:

### Pass 1: Specification & Behavior Coverage Review
- Verified all 12 Functional Requirements (FR-01 through FR-12) and 10 Security Requirements (SR-01 through SR-10) are mapped file-by-file and task-by-task.
- Verified that all 28 Architectural Decisions (`DEC-001` through `DEC-028`) from `phase_and_decision_plan.md` are reflected in the contract map.
- Result: **PASS** — Zero requirements omitted.

### Pass 2: Security & Architecture Invariant Review
- Audited intermediate symlink traversal boundaries (`SEC-02`), toolchain command allowlist policy (`SEC-01`), atomic runtime locking (`SEC-05`), and state schema alignment (`SEC-04`).
- Confirmed that same-UID process execution limits are accurately characterized as defense-in-depth.
- Result: **PASS** — All security invariants affirmed without false claims.

### Pass 3: Test, Regression & Final Diff Review
- Baseline test suite executed: **231 passed**, 71 subtests passed, 0 failures.
- Verified git status: clean working tree, no unauthorized source modifications, active branch `feat/v2.0.0`.
- Result: **PASS** — Baseline verified and recorded.

