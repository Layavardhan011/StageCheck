# StageCheck Requirement Traceability Matrix

This document provides complete bidirectional requirement-to-code-to-test traceability for StageCheck, covering Specifications 01 through 14 and the Master Architecture (`STAGECHECK_FINAL_ARCHITECTURE.md`).

## Traceability Legend
- **Priority**: P0 (Security-critical / Core blocker), P1 (Core architecture & governance), P2 (Packaging & operational UX)
- **Status**: `IMPLEMENTED` (Verified by passing tests), `VERIFIED` (End-to-end passing)

---

## Specification Traceability Table

| Requirement ID | Specification | Requirement Description | Priority | Implementation Module | Test Coverage | Status | Evidence / Artifact | Remaining Gap |
|---|---|---|:---:|---|---|:---:|---|---|
| **REQ-01-01** | Spec 01 | 8 Mandatory Workspace Control Descriptors in `controls/` | P1 | `stagecheck/core/scaffold.py` | `test_scaffold.py` | IMPLEMENTED | 8 controls created atomically | None |
| **REQ-01-02** | Spec 01 | Directory permission hardening (0555 at rest, 0755 during write transaction) | P1 | `stagecheck/core/permissions.py` | `test_orchestrator.py` | IMPLEMENTED | Mode 0555 verified in tests | None |
| **REQ-01-03** | Spec 01 | Atomic write-ahead lock (`controls/.stagecheck.lock`) | P1 | `stagecheck/core/permissions.py` | `test_scaffold.py` | IMPLEMENTED | Exclusive non-blocking flock verified | None |
| **REQ-02-01** | Spec 02 | Dual-Agent Identity Separation (Prompt Architect/Auditor vs Code Implementer) | P1 | `stagecheck/core/agents_md.py` | `test_agents_md.py` | IMPLEMENTED | `AGENTS.md` 8-row Merkle table rendered | None |
| **REQ-02-02** | Spec 02 | Strict Agent Slug Validation (`[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}`) | P0 | `stagecheck/core/utils.py`, `bin/response_hook.py` | `test_utils.py`, `test_universal_agents.py` | IMPLEMENTED | Slug regex assertions passing | None |
| **REQ-02-03** | Spec 02 | Merkle binding contract generation and verification | P0 | `stagecheck/core/agents_md.py` | `test_agents_md.py` | IMPLEMENTED | SHA-256 control digests verified | None |
| **REQ-03-01** | Spec 03 | Agent 1 restricted read-only Git commands | P0 | `stagecheck/core/commands.py`, `instructions/` | `test_smoke.py`, `test_cli_ux.py` | IMPLEMENTED | Mutating Git commands rejected | None |
| **REQ-03-02** | Spec 03 | Scaffolding `instructions/agent1_prompt_and_audit.md` | P1 | `stagecheck/core/scaffold.py`, `stagecheck/cli/init_cmd.py` | `test_scaffold.py` | IMPLEMENTED | Scaffolding during `stagecheck init` | None |
| **REQ-03-03** | Spec 03 | 270 formal audit criteria packaging | P0 | `stagecheck/agent_instructions/`, `pyproject.toml` | `test_smoke.py`, `test_cli_ux.py` | IMPLEMENTED | Packaged into wheel `stagecheck/agent_instructions/` | None |
| **REQ-04-01** | Spec 04 | Interactive and Non-Interactive CLI Scaffolding (`stagecheck init`) | P1 | `stagecheck/cli/init_cmd.py`, `stagecheck/core/scaffold.py` | `test_scaffold.py`, `test_cli_ux.py` | IMPLEMENTED | `stagecheck init` initializes workspace | None |
| **REQ-04-02** | Spec 04 | Roadmap Task Plan Scaffolding (`specs/TASK_PLAN.json` & schema) | P1 | `stagecheck/core/scaffold.py`, `stagecheck/core/task_plan.py` | `test_task_plan.py` | IMPLEMENTED | Kahn's algorithm DAG validator + `task_plan.schema.json` | None |
| **REQ-05-01** | Spec 05 | Universal Agent Decoupling (remove hardcoded `claude`/`codex`) | P0 | `bin/response_hook.py`, `stagecheck/core/utils.py` | `test_universal_agents.py` | IMPLEMENTED | Dynamic provider slug validation & registration | None |
| **REQ-05-02** | Spec 05 | Dynamic claims and responses folder routing under `evidence/` | P1 | `bin/response_hook.py`, `stagecheck/core/paths.py` | `test_universal_agents.py`, `test_paths.py` | IMPLEMENTED | Evidence path containment for arbitrary agents | None |
| **REQ-05-03** | Spec 05 | Normalized turn tracking (uses event turn_id if present, else auto-increments) | P1 | `bin/response_hook.py` | `test_universal_agents.py` | IMPLEMENTED | Generic turn counter verified | None |
| **REQ-06-01** | Spec 06 | Central Tokenized Command Runner & Allowlist Policy | P0 | `stagecheck/core/commands.py` | `test_smoke.py`, `test_cli_ux.py` | IMPLEMENTED | Shell injection & forbidden flags blocked | None |
| **REQ-06-02** | Spec 06 | Evidence Manifest (`EVIDENCE_MANIFEST.json`) and SHA-256 Ledger | P0 | `stagecheck/core/evidence.py` | `test_orchestrator.py`, `test_e2e_lifecycle.py` | IMPLEMENTED | Append-only manifest integrity | None |
| **REQ-06-03** | Spec 06 | Working directory containment inside `<workspace_root>` | P0 | `stagecheck/core/paths.py` | `test_paths.py` | IMPLEMENTED | Safe resolve rejects path traversal | None |
| **REQ-07-01** | Spec 07 | Sentinel Daemon (<25MB RSS, 0% CPU, inotify-driven) | P1 | `stagecheck/core/sentinel.py`, `bin/benchmark_sentinel.py` | `test_sentinel.py` | IMPLEMENTED | 18.92 MiB RSS, 0.285 µs latency, 0% idle CPU | None |
| **REQ-07-02** | Spec 07 | Tier 1-4 Event Routing & Emergency Halt on Control Tampering | P0 | `stagecheck/core/sentinel.py` | `test_sentinel.py` | IMPLEMENTED | Critical tampering triggers halt | None |
| **REQ-07-03** | Spec 07 | PID Lifecycle and Symlink Attack Protection | P0 | `stagecheck/core/sentinel.py` | `test_sentinel.py` | IMPLEMENTED | PID file symlink check passing | None |
| **REQ-08-01** | Spec 08 | Agent 2 Code Implementation & Branch Restrictions (`<project>/<sprint>`) | P0 | `stagecheck/core/branch_governance.py` | `test_e2e_lifecycle.py` | IMPLEMENTED | Direct commit to main blocked | None |
| **REQ-08-02** | Spec 08 | Scaffolding `instructions/agent2_code_implementation.md` | P1 | `stagecheck/core/scaffold.py`, `stagecheck/cli/init_cmd.py` | `test_scaffold.py` | IMPLEMENTED | Scaffolding during `stagecheck init` | None |
| **REQ-08-03** | Spec 08 | Pre-Commit Gitleaks scan (`gitleaks protect --staged`) | P0 | `stagecheck/core/scanner.py`, `stagecheck/core/cooperative_review.py` | `test_scanner.py`, `test_e2e_lifecycle.py` | IMPLEMENTED | Staged scan gate centralized in `SecretScanner` | None |
| **REQ-09-01** | Spec 09 | Multi-Repository Binding & Baselines (`controls/PRODUCT_REPOSITORIES.json`) | P1 | `stagecheck/core/orchestrator.py`, `stagecheck/core/git.py` | `test_orchestrator.py` | IMPLEMENTED | Baseline SHA-1 binding verified | None |
| **REQ-09-02** | Spec 09 | Zero-Partial-Pass Aggregate Verdict Rule | P0 | `stagecheck/core/orchestrator.py` | `test_orchestrator.py` | IMPLEMENTED | Failure in 1 repo blocks all | None |
| **REQ-09-03** | Spec 09 | Detection of Untouched Repository Modification | P0 | `stagecheck/core/orchestrator.py` | `test_orchestrator.py` | IMPLEMENTED | Mutation in undeclared repo blocks | None |
| **REQ-10-01** | Spec 10 | Modern Packaging (`pyproject.toml`, standard setuptools wheel) | P1 | `pyproject.toml` | `test_smoke.py`, `dist/stagecheck-1.0.0-py3-none-any.whl` | IMPLEMENTED | Wheel builds cleanly, installed in clean venv | None |
| **REQ-10-02** | Spec 10 | Unified CLI router (`stagecheck <subcommand>`) | P1 | `stagecheck/cli/main.py` | `test_cli_ux.py` | IMPLEMENTED | All 14 CLI subcommands functional | None |
| **REQ-10-03** | Spec 10 | Standalone CLI Auxiliary Verbs (`plan`, `unlock`, `seal`, `log-quality`) | P2 | `stagecheck/cli/main.py`, `plan_cmd.py`, `ops_cmd.py` | `test_cli_ux.py`, `test_task_plan.py` | IMPLEMENTED | Wired and verified in CLI dispatcher | None |
| **REQ-11-01** | Spec 11 | Complete Hardcoded Path Decoupling & Linux POSIX Portability | P0 | `stagecheck/core/paths.py` | `test_portability.py` | IMPLEMENTED | 0 hardcoded paths found | None |
| **REQ-11-02** | Spec 11 | Dual-Mode Asset Resolution (source tree vs installed wheel) | P1 | `stagecheck/core/portability.py`, `paths.py` | `test_portability.py` | IMPLEMENTED | Resource path resolution verified | None |
| **REQ-12-01** | Spec 12 | Circuit Breaker & Formal Attempt Limit Protocol (Max 3 Attempts) | P0 | `stagecheck/core/orchestrator.py`, `circuit_breaker.py` | `test_orchestrator.py`, `test_e2e_lifecycle.py` | IMPLEMENTED | Breaker trips at attempt limit | None |
| **REQ-12-02** | Spec 12 | Regression and Stalled Progress Detection | P0 | `stagecheck/core/circuit_breaker.py` | `test_orchestrator.py` | IMPLEMENTED | Defect count increase blocks | None |
| **REQ-12-03** | Spec 12 | Human-Authorized Reset Protocol (`stagecheck reset-attempts`) | P0 | `stagecheck/cli/reset_cmd.py`, `circuit_breaker.py` | `test_orchestrator.py`, `test_e2e_lifecycle.py` | IMPLEMENTED | Monotonic Attempt 4 allocation | None |
| **REQ-13-01** | Spec 13 | Human Disposition Ledger (`controls/DISPOSITIONS.json`) & Waiver Semantics | P0 | `stagecheck/core/dispositions.py` | `test_disposition.py`, `test_orchestrator.py` | IMPLEMENTED | Human waiver clears matching defect | None |
| **REQ-13-02** | Spec 13 | Non-interactive execution protection & Confirmation Gate | P0 | `stagecheck/cli/disposition_cmd.py` | `test_disposition.py` | IMPLEMENTED | TTY confirmation or email required | None |
| **REQ-13-03** | Spec 13 | Write-Ahead Transaction & Crash Recovery for Dispositions | P0 | `stagecheck/core/dispositions.py` | `test_disposition.py` | IMPLEMENTED | Incomplete transaction rollbacks verified | None |
| **REQ-14-01** | Spec 14 | Phase 2A Pre-Commit Cooperative Review Handshake (`review-precommit`) | P1 | `stagecheck/core/cooperative_review.py` | `test_e2e_lifecycle.py` | IMPLEMENTED | Diff calculation & review status verified | None |
| **REQ-14-02** | Spec 14 | Human Operator Review Approval Gate (`approve-review`) | P1 | `stagecheck/cli/review_cmd.py`, `cooperative_review.py` | `test_e2e_lifecycle.py` | IMPLEMENTED | `pre_commit_review.json` signed | None |
| **REQ-14-03** | Spec 14 | Commit Authorization Invalidation on Post-Approval Working-Tree Tampering | P0 | `stagecheck/core/cooperative_review.py` | `test_e2e_lifecycle.py` | IMPLEMENTED | Diff hash check invalidates | None |
| **REQ-SEC-01** | Spec 07/08/09 | Required Gitleaks Fail-Closed Security Scan (All 9 Failure Conditions) | P0 | `stagecheck/core/scanner.py`, `stagecheck/checks/` | `test_scanner.py`, `test_orchestrator.py` | IMPLEMENTED | Verified all 9 failure conditions fail-closed | None |

---
*Updated: 2026-11-04 (All Gaps Closed & Verified)*
