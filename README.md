# StageCheck

> **Enterprise AI Software Delivery Governance, Dual-Agent Verification & Multi-Repository Audit Harness**

StageCheck is a deterministic governance and verification harness for autonomous multi-agent software engineering workflows. It provides formal phase boundaries, cryptographic evidence manifests, dual-agent verification protocols, multi-repository tracking, advisory workspace locking, and an independent 9-stage verification engine.

---

## 1. System Overview

StageCheck enforces strict architectural, operational, and security invariants over AI coding agents:

* **Dual-Agent Governance:** Formal separation of responsibilities between **Agent 1** (Prompt Architect & Auditor) and **Agent 2** (Code Implementer).
* **Workspace Controls & Trust Roots:** 8 mandatory control files in `controls/` with directory-level read-only protection (`chmod 0555` / `0444`) and root trust binding via `AGENTS.md`.
* **Advisory Locking & Transaction Journal:** Workspace serialization via `fcntl.flock` on `controls/.stagecheck.lock`, paired with write-ahead journal recovery (`controls/.journal/`) executing under the lock.
* **Controlled Write Transactions:** A safe filesystem mutation protocol that temporarily elevates directory permissions under exclusive lock, writes via `O_CREAT | O_EXCL` temporary files, calls `os.fsync`, atomically commits via `os.replace`, and restores read-only at-rest modes.
* **Continuous Sentinel Daemon:** An inotify/event-driven background watchdog that observes file modification timestamps and process liveness, detecting stalled reviews and notifying operators without claiming verdict authority.
* **Multi-Repository Governance (Schema v2):** First-class support for multi-repo workspaces (`controls/PRODUCT_REPOSITORIES.json`) binding `<FOLDER_NAME/REPO_NAME>` with baseline commit capture and commit vector verification (`checked_heads`).
* **Independent 9-Stage Verification Engine:** A decoupled audit suite evaluating preflight invariants, multi-repo scope containment, working-tree citations, report defect schemas, authority grants, secret leaks (Gitleaks), test naming conventions, clean-room isolated reruns, and regression prevention.
* **Deterministic Evidence & Seals:** Append-only evidence directories (`evidence/tasks/<task_id>/attempt_<N>/`), SHA-256 integrity tree manifests (`EVIDENCE_MANIFEST.json`), RFC 8785 canonical JSON verdict payloads, and deterministic `seal.json` records.
* **Attempt Budgeting & Circuit Breaker:** Invariant 3-attempt ceiling per task (Initial Run, First Repair, Final Automated Repair). Trips into `CIRCUIT_BREAKER_TRIPPED` on third failure, preventing automated runaways while providing a human-authorized monotonic reset hatch (`stagecheck reset-attempts` allocating Attempt 4).

---

## 2. Core Architecture & Mandatory Controls

Every governed workspace maintains an authoritative `controls/` directory containing 8 mandatory descriptors:

| Control Descriptor | Scope & Purpose | Security Mode |
|---|---|:---:|
| `STAGECHECK_ROOT.json` | Toolchain root descriptor with dual-mode `@package` resolution | `0444` |
| `EVIDENCE_ROOT.json` | Evidence store configuration and directory anchor | `0444` |
| `PRODUCT_REPOSITORIES.json` | Schema v2 multi-repo registry binding `<FOLDER_NAME/REPO_NAME>` | `0444` |
| `QUALIFICATION_ROOT.json` | Test and qualification suite discovery configuration | `0444` |
| `ACTIVE_STATE.json` | Authoritative task state, attempt indexing, and phase progression | `0444` |
| `OWNER_GRANTS.md` | Human owner authorization grants and privileged command tokens | `0444` |
| `FAILURE_PREVENTION.md` | Prescribed failure patterns and anti-regression constraints | `0444` |
| `DISPOSITIONS.json` | Atomic ledger of human defect waivers and accepted risks | `0444` |

Root governance is sealed at initialization by `AGENTS.md`, which embeds a canonical SHA-256 digest table across all 8 control files.

---

## 3. Dual-Agent Lifecycle & Attempt State Machine

```
                                [ Operator: stagecheck start ]
                                              │
                                              ▼
                                   ┌─────────────────────┐
                                   │  PHASE 1: PLANNING  │  <── Agent 1 drafts prompt.md
                                   └──────────┬──────────┘  <── stagecheck verify-prompt
                                              │
                                              ▼
                                 ┌─────────────────────────┐
                        ┌──────> │ PHASE 2A: IMPLEMENT     │  <── Agent 2 codes on task branch
                        │        └────────────┬────────────┘  <── stagecheck review-precommit
     In-Phase Review    │                     │
     Loop (repair_index)│          [ Needs Changes? ] ──── (repair_index < max_repairs)
                        └─────────────────────┘
                                              │ Approved (stagecheck approve-review)
                                              ▼
                                 ┌─────────────────────────┐
                                 │    PHASE 2B: DELIVERY   │  <── Local Git commit (no push)
                                 └────────────┬────────────┘  <── claims.json + report.md
                                              │
                                              ▼
                                 ┌─────────────────────────┐
                                 │   PHASE 3: VERIFY       │  <── stagecheck audit (9 Stages)
                                 └────────────┬────────────┘
                                              │
                       ┌──────────────────────┴──────────────────────┐
                       │ PASS                                        │ FAIL (Formal attempt consumed)
                       ▼                                             ▼
            ┌─────────────────────┐                       ┌─────────────────────┐
            │   Task COMPLETED    │                       │ attempt_index < 3?  │
            │   Evidence Sealed   │                       └──────┬───────┬──────┘
            └─────────────────────┘                              │       │
                                                           Yes   │       │ No (3 attempts failed)
                                                                 ▼       ▼
                                                   ┌────────────────┐ ┌────────────────────────┐
                                                   │ PHASE 1 REPAIR │ │ CIRCUIT_BREAKER_TRIPPED│
                                                   └────────────────┘ └───────────┬────────────┘
                                                                                  │ stagecheck reset-attempts
                                                                                  ▼
                                                                      [ Monotonic Attempt 4 ]
```

---

## 4. The 9-Stage Independent Verification Suite

When `stagecheck audit --task <task_id>` runs, StageCheck executes 9 deterministic stages in strict order:

1. **Stage 1 — Preflight:** Validates lock acquisition, sanitized environment allowlist, prompt hash invariance, and scanner availability.
2. **Stage 2 — Scope Paths:** Confirms modified files across all product repositories strictly comply with `approved_scope` in `TASK_PLAN.json`.
3. **Stage 3 — Working-Tree Citations:** Validates line-level file citations cited in `claims.json` against real working trees (enforcing a 20 MiB per-file ceiling).
4. **Stage 4 — Report Defect Lint:** Validates `report.md` against formal 3-part defect regex and verifies prompt injection protections.
5. **Stage 5 — Authority Verification:** Confirms all modifications and commands are covered by `OWNER_GRANTS.md` or approved in `DISPOSITIONS.json`.
6. **Stage 6 — Secret Scanning:** Executes pinned Gitleaks (`gitleaks detect --source repos/<repo> --exit-code 1 --no-git`), halting on any unencrypted credential.
7. **Stage 7 — Qualification Naming:** Validates qualification and test files strictly follow `test_*` naming conventions relative to package roots.
8. **Stage 8 — Isolated Clean-Room Rerun:** Re-executes verification commands inside an isolated sandbox, capturing mode `0600` execution logs.
9. **Stage 9 — Carry-Forward Defect Regression:** Compares findings against cumulative defect history (`TASK_<ID>_ISSUE_HISTORY.md`), failing on any regression.

---

## 5. Phased Implementation Roadmap

StageCheck is developed across 5 modular phases (25 total tasks — **100% Complete**):

### Phase 1 — Repository Baseline and Architecture Foundations `[COMPLETED]`
* **P1-T0:** Comprehensive documentation update and architectural alignment (`README.md`).
* **P1-T1:** Repository baseline capture and inventory of current behavior.
* **P1-T2:** Canonical module boundaries and compatibility strategy (`stagecheck.core`, `stagecheck.cli`, etc.).
* **P1-T3:** Portable workspace root and component-normalized path primitives.
* **P1-T4:** Centralized schema validation, RFC 8785 JCS serialization, and provider-neutral agent slug utilities.
* **P1-T5:** PEP 621 package skeleton (`pyproject.toml`) and baseline CI test harness.

### Phase 2 — Workspace Scaffolding and Governance Contract `[COMPLETED]`
* **P2-T1:** Multi-repository discovery and baseline Git commit capture.
* **P2-T2:** Schema v2 multi-repository registry (`PRODUCT_REPOSITORIES.json`) and control schemas.
* **P2-T3:** Atomic generation and permission enforcement for all 8 workspace controls.
* **P2-T4:** Root `AGENTS.md` rendering and SHA-256 trust manifest calculation.
* **P2-T5:** Bootstrap-locked workspace initialization (`.stagecheck-init.lock`) and path containment validation.

### Phase 3 — Agent Protocol, Scope, Commands & Multi-Repository Verification `[COMPLETED]`
* **P3-T1:** Provider-neutral agent registration and evidence directory routing.
* **P3-T2:** Prompt verification (`stagecheck verify-prompt`) and declared-scope validation gate.
* **P3-T3:** Task branch governance (`fincore/<task_id>`) and multi-repo baseline binding.
* **P3-T4:** Tokenized command runner with argument whitelisting and process group cleanup.
* **P3-T5:** Phase 2A cooperative pre-commit review handshake (`review-precommit`, `approve-review`).

### Phase 4 — Sentinel, Audit Lifecycle, Evidence & Escalation `[COMPLETED]`
* **P4-T1:** Continuous event-driven Linux Sentinel daemon (`stagecheck sentinel start|stop|status|logs`).
* **P4-T2:** Independent 9-stage verification suite with multi-repo aggregation (`stagecheck audit`).
* **P4-T3:** SHA-256 evidence manifest (`EVIDENCE_MANIFEST.json`), deterministic task seals (`seal.json`), and immutable Merkle attempt chaining.
* **P4-T4:** 3-attempt circuit breaker, defect progression ledger, and escalation reporting (`escalation_report.md`).
* **P4-T5:** Human disposition CLI (`stagecheck disposition add`, `stagecheck resume`) and notification integration.

### Phase 5 — Portability, Hardening, Integration & Release Readiness `[COMPLETED]`
* **P5-T1:** Synthetic evaluation fixture factory (`evals/fixtures.py`) replacing all machine-specific external dependencies.
* **P5-T2:** Comprehensive hardcoded path decoupling, automated portability scanner (`stagecheck/core/portability.py`), and dual-mode asset resolution.
* **P5-T3:** End-to-end integration test scenarios covering full lifecycle, adversarial tampering, scope escapes, multi-repo partial failure, and circuit-breaker resets (`tests/test_e2e_lifecycle.py`).
* **P5-T4:** Unified CLI UX verification, POSIX exit codes, package metadata, and operator reference documentation (`tests/test_cli_ux.py`).
* **P5-T5:** Release gate verification, final three-pass review, manifest verification, and release readiness.

---

## 6. Command-Line Interface (CLI) Reference

StageCheck provides unified CLI subcommands conforming strictly to POSIX / GNU command conventions:

| Subcommand | Purpose & Scope | Exit Codes |
|---|---|:---:|
| `stagecheck init` | Scaffolds the 8 mandatory control files and binds git repositories | `0`, `1` |
| `stagecheck start` | Initializes a task in `PHASE_1_PLANNING` under transactional lock | `0`, `1` |
| `stagecheck verify-prompt` | Validates `prompt.md` + `declared_scope.json` and freezes SHA-256 digests | `0`, `1` |
| `stagecheck gate check <GATE>` | Non-mutating inspection of Gate 1, 2A, 2B, 3, or 4 criteria | `0`, `1` |
| `stagecheck gate advance <GATE>`| Formally advances phase gate and issues cryptographic receipt | `0`, `1` |
| `stagecheck review-precommit` | Evaluates Phase 2A pre-commit working tree diff against quality targets | `0`, `1` |
| `stagecheck approve-review` | Records dual-agent review approval in `pre_commit_review.json` | `0`, `1` |
| `stagecheck audit` | Executes the independent test, scanner, and rubric audit pipeline | `0` (CLEAR), `1` (BLOCKED) |
| `stagecheck seal` | Computes Merkle DAG seal and indexes attempt in evidence manifest | `0`, `1` |
| `stagecheck resume` | Resumes automated workflow from `AWAITING_HUMAN_DISPOSITION` | `0`, `1` |
| `stagecheck reset-attempts` | Human-authorized circuit breaker reset allocating monotonic Attempt 4+ | `0`, `1` |
| `stagecheck disposition add` | Records an explicit defect waiver in `controls/DISPOSITIONS.json` | `0`, `1` |
| `stagecheck check-rubric` | Evaluates 270-rule compliance catalog against workspace topology | `0`, `1` |
| `stagecheck sentinel start\|stop\|status` | Controls continuous event-driven background watchdog daemon | `0`, `1` |
| `stagecheck supervisor` | Autonomous live supervisor, debounce orchestrator, and watchdog | `0`, `1` |
| `stagecheck turn query` | Queries active agent turn, phase, and polling contract | `0`, `1` |
| `stagecheck verify-manifest` | Validates specification integrity against `START_MANIFEST.md` | `0`, `1` |
| `stagecheck update-manifest` | Explicitly updates specification digests in `START_MANIFEST.md` | `0`, `1` |
| `stagecheck unlock` | Elevates workspace permissions for teardown or clean recovery | `0`, `1` |

### Exit Code Reference

| Exit Code | Semantic Meaning | Description |
|:---:|---|---|
| `0` | **SUCCESS / CLEAR** | Command completed successfully; all gate criteria or audit checks passed. |
| `1` | **GENERAL FAILURE / BLOCKED** | Criteria unmet, verification defects found, dirty tree, or unhandled failure. |
| `2` | **ESCALATION REQUIRED** | Circuit breaker tripped; manual human operator disposition required. |
| `124` | **EXECUTION TIMEOUT** | Command or test execution exceeded its allotted runtime deadline. |
| `126` | **SECURITY POLICY VIOLATION** | Prohibited command runner, shell injection flag, or unapproved script target. |

### Operational Usage Examples

```bash
# Initialize a new governed workspace across target repositories
stagecheck init --repos payment-service,ledger-api,fraud-detector --agent1 agent1 --agent2 agent2

# Activate a task under exclusive lock
stagecheck start --task task-101

# Phase 1: Verify prompt blueprint and freeze prompt hash
stagecheck verify-prompt --task task-101

# Phase 1 -> Phase 2A: Formally advance Gate 1
stagecheck gate advance Gate-1 --task task-101

# Phase 2A: Run cooperative pre-commit review against quality targets
stagecheck review-precommit --task task-101

# Phase 2A: Human operator review approval gate
stagecheck approve-review --task task-101

# Phase 2A -> Phase 2B: Advance Gate 2A
stagecheck gate advance Gate-2A --task task-101

# Phase 2B -> Phase 3: Advance Gate 2B after clean local commit
stagecheck gate advance Gate-2B --task task-101

# Phase 3: Run independent verification pipeline and evaluate Gate 3
stagecheck audit --task task-101
stagecheck gate advance Gate-3 --task task-101

# Gate 4: Seal task evidence and finalize cryptographic Merkle DAG
stagecheck seal --task task-101
stagecheck gate advance Gate-4 --task task-101

# Background Sentinel continuous watchdog control
stagecheck sentinel start
stagecheck sentinel status
stagecheck sentinel stop
```

---

## 7. Operational Threat Model & Same-UID Boundaries

StageCheck enforces defense-in-depth, fail-closed security controls across multi-agent workspaces:

### Threat Model & Assumptions
1. **Host Boundary & Same-UID Model:**
   * StageCheck directory modes (`chmod 0555` on `controls/`) and file modes (`chmod 0444`) provide **defense-in-depth against accidental mutation**, errant agent tools, and unprivileged cross-user access.
   * Filesystem permissions do **not** constitute a kernel security sandbox against malicious code executing under the exact same POSIX UID, as any process running under the same UID could execute `chmod` or `ptrace`.
   * Untrusted third-party code from external repositories must be executed inside dedicated virtualization or container boundaries (e.g., Docker, gVisor, Firecracker).
2. **Command Injection & Environment Isolation (SEC-A1 & SEC-B3):**
   * Commands are executed strictly via tokenized argument arrays (`subprocess.run(argv, shell=False)`).
   * Prohibited shell metacharacters, redirection flags (`-exec`, `-o`, `--node-options`), and arbitrary scripts are rejected before subprocess launch (Exit Code 126).
   * Ambient environment credentials (`GITHUB_TOKEN`, `AWS_SECRET_ACCESS_KEY`, etc.) are stripped; only allowlisted variables (`PATH`, `LANG`, etc.) are passed to child processes.
3. **Repository Working-Tree Integrity (SEC-C1):**
   * Git status (`git status --porcelain=v1`) is captured before and after test execution; commands that leave untracked files or mutate working trees fail closed.
   * Commits directly to protected default branches (`main`, `master`) are strictly prohibited; agent changes must be committed to compliant task sprint branches.
4. **Audit Worktree Isolation (P4-T1):**
   * Verification tests and scanners execute in detached, read-only temporary git worktrees (`stagecheck-audit-worktrees/`) preserving the exact multi-repo directory topology. The active agent working trees are never mutated during audit.

---

## 8. Requirements & Decisions Traceability Matrix

| Requirement / Decision ID | Domain & Scope | Implementing Module | Primary Test Suite |
|---|---|---|---|
| **FR-01 / SR-01** | Tokenized Command Allowlist & Test Runner Policies | `stagecheck.core.commands` | `tests/test_commands.py` |
| **FR-02 / SR-02** | Dual-Agent Governance, Role Instructions & Contract | `stagecheck.core.agents`, `agents_md` | `tests/test_agents.py`, `test_agents_md.py` |
| **FR-03** | 270-Rule Rubric Engine & Non-Applicable Waivers | `stagecheck.core.rubric_engine` | `tests/test_rubric_engine.py` |
| **FR-04 / SR-03** | Multi-Repo Git Topology, Baselines & Untouched Auditing | `stagecheck.core.topology`, `branch_governance` | `tests/test_multi_repo_scenarios.py` |
| **FR-05** | Linux Inotify Sentinel Daemon & Watchdog Debounce | `stagecheck.core.sentinel`, `supervisor` | `tests/test_sentinel.py`, `test_supervisor.py` |
| **FR-06** | 3-Attempt Budget Ceiling & Monotonic Circuit Breaker | `stagecheck.core.circuit_breaker` | `tests/test_circuit_breaker.py` |
| **FR-07** | Cryptographic Phase Gate Engine (Gates 1, 2A, 2B, 3, 4) | `stagecheck.core.gate_engine` | `tests/test_gate_engine.py`, `test_gate_receipts.py` |
| **FR-08** | Dual-Agent Cooperative Pre-Commit Review Handshake | `stagecheck.core.cooperative_review` | `tests/test_cooperative_review.py` |
| **FR-09** | Acyclic Merkle DAG Sealing & Evidence Manifest | `stagecheck.core.sealing`, `evidence` | `tests/test_sealing.py`, `test_gate4_sealing.py` |
| **FR-10** | Write-Ahead Transaction Journal & Crash Recovery | `stagecheck.core.journal` | `tests/test_journal.py` |
| **SR-04** | Symlink Validation & Path Escape Prevention | `stagecheck.core.sealing`, `paths` | `tests/test_adversarial_security.py` |
| **SR-05** | At-Rest Read-Only Permissions & Controlled Mutations | `stagecheck.core.permissions` | `tests/test_controls.py` |
| **SR-06** | Exclusive Workspace Runtime Locking (`.stagecheck.lock`) | `stagecheck.core.locking` | `tests/test_locking.py` |
| **SR-07** | Automated Hardcoded Path Portability Scanner | `stagecheck.core.portability` | `tests/test_portability.py` |
| **SR-08** | Dynamic Git Remote Whitelisting & Push Authorization | `stagecheck.core.branch_governance` | `tests/test_authority.py` |
| **DEC-001..030** | Master Architecture Technical Decisions & Invariants | `stagecheck.core.*` | `tests/test_e2e_lifecycle.py` |

---

## 9. License & Compliance

Internal Enterprise Software Delivery Governance Harness. Built in accordance with StageCheck Architecture Specifications (Series 01–14).
