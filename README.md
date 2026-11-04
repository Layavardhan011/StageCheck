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

StageCheck is developed across 5 modular phases (25 total tasks):

### Phase 1 — Repository Baseline and Architecture Foundations
* **P1-T0:** Comprehensive documentation update and architectural alignment (`README.md`).
* **P1-T1:** Repository baseline capture and inventory of current behavior.
* **P1-T2:** Canonical module boundaries and compatibility strategy (`stagecheck.core`, `stagecheck.cli`, etc.).
* **P1-T3:** Portable workspace root and component-normalized path primitives.
* **P1-T4:** Centralized schema validation, RFC 8785 JCS serialization, and provider-neutral agent slug utilities.
* **P1-T5:** PEP 621 package skeleton (`pyproject.toml`) and baseline CI test harness.

### Phase 2 — Workspace Scaffolding and Governance Contract
* **P2-T1:** Multi-repository discovery and baseline Git commit capture.
* **P2-T2:** Schema v2 multi-repository registry (`PRODUCT_REPOSITORIES.json`) and control schemas.
* **P2-T3:** Atomic generation and permission enforcement for all 8 workspace controls.
* **P2-T4:** Root `AGENTS.md` rendering and SHA-256 trust manifest calculation.
* **P2-T5:** Bootstrap-locked workspace initialization (`.stagecheck-init.lock`) and path containment validation.

### Phase 3 — Agent Protocol, Scope, Commands & Multi-Repository Verification
* **P3-T1:** Provider-neutral agent registration and evidence directory routing.
* **P3-T2:** Prompt verification (`stagecheck verify-prompt`) and declared-scope validation gate.
* **P3-T3:** Task branch governance (`fincore/<task_id>`) and multi-repo baseline binding.
* **P3-T4:** Tokenized command runner with argument whitelisting and process group cleanup.
* **P3-T5:** Phase 2A cooperative pre-commit review handshake (`review-precommit`, `approve-review`).

### Phase 4 — Sentinel, Audit Lifecycle, Evidence & Escalation
* **P4-T1:** Continuous event-driven Linux Sentinel daemon (observer / watchdog).
* **P4-T2:** Independent 9-stage verification suite with multi-repo aggregation.
* **P4-T3:** SHA-256 evidence manifest (`EVIDENCE_MANIFEST.json`) and deterministic task seals (`seal.json`).
* **P4-T4:** 3-attempt circuit breaker, defect progression ledger, and escalation reporting.
* **P4-T5:** Human disposition CLI (`stagecheck disposition add`) and notification integration.

### Phase 5 — Portability, Hardening, Integration & Release Readiness
* **P5-T1:** Synthetic evaluation fixture factory replacing external dependencies.
* **P5-T2:** Comprehensive hardcoded path audit and portability hardening.
* **P5-T3:** End-to-end lifecycle verification and adversarial attack regressions.
* **P5-T4:** Unified CLI packaging (`stagecheck`) and operational operator manuals.
* **P5-T5:** Release gate verification, final three-pass audit, and release tagging.

---

## 6. Command-Line Interface (CLI) Reference

```bash
# Initialize a new governed workspace across target repositories
stagecheck init --repos payment-service,ledger-api,fraud-detector

# Activate a task under exclusive lock
stagecheck start --task task-101

# Phase 1: Verify prompt blueprint and freeze prompt hash
stagecheck verify-prompt --task task-101

# Phase 2A: Run cooperative pre-commit review against quality targets
stagecheck review-precommit --task task-101

# Phase 2A: Human operator review approval gate
stagecheck approve-review --task task-101

# Phase 3: Run independent 9-stage verification engine
stagecheck audit --task task-101

# Resume automation from AWAITING_HUMAN_DISPOSITION
stagecheck resume --task task-101

# Record a human defect waiver in controls/DISPOSITIONS.json
stagecheck disposition add --task task-101 --defect SEC-01 --rationale "Approved waiver"

# Monotonically allocate Attempt 4 after circuit breaker activation
stagecheck reset-attempts --task task-101 --authorized-by owner@fincore.local
```

---

## 7. License & Compliance

Internal Enterprise Software Delivery Governance Harness. Built in accordance with StageCheck Architecture Specifications (Series 01–14).
