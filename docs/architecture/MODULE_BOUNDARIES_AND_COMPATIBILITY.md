# StageCheck — Canonical Module Boundaries & Compatibility Strategy (P1-T2)

**Task ID:** P1-T2  
**Phase:** Phase 1 — Repository Baseline, Packaging, and Architecture Foundations  
**Target Repository:** `/home/laya/Development/StageCheck-Tool/StageCheck`  
**Active Phase Branch:** `phase/phase-1-foundation`  
**Date:** 2026-11-04  

---

## 1. Overview & Objectives

StageCheck transitions from a loose collection of standalone scripts in `bin/` and `checks/` to a structured, pip-installable Python package under the canonical namespace `stagecheck`.

This document defines:
1. The canonical package hierarchy and layer boundaries.
2. The 1-to-1 migration mapping for all existing legacy files.
3. The compatibility shim strategy ensuring legacy shell wrappers and check invocations remain functional.
4. Compatibility risks and mitigation protocols.

---

## 2. Canonical Package Hierarchy (`stagecheck/`)

The modern package structure establishes a clear separation of concerns:

```text
stagecheck/
├── __init__.py                     # Package entrypoint, version metadata (__version__ = "1.0.0")
├── cli/                            # Unified Command Line Interface
│   ├── __init__.py
│   ├── main.py                     # Root CLI dispatcher (argparse/click hierarchy)
│   ├── init_cmd.py                 # "stagecheck init" (workspace scaffolding & bootstrap lock)
│   ├── start_cmd.py                # "stagecheck start" (task initialization & attempt-1 allocation)
│   ├── prompt_cmd.py               # "stagecheck verify-prompt" (Phase 1 prompt hash freezing)
│   ├── review_cmd.py               # "stagecheck review-precommit" & "approve-review" (Phase 2A)
│   ├── audit_cmd.py                # "stagecheck audit" (Phase 3 9-stage verification)
│   ├── resume_cmd.py               # "stagecheck resume" (resume from AWAITING_HUMAN_DISPOSITION)
│   ├── reset_cmd.py                # "stagecheck reset-attempts" (monotonic Attempt 4 allocation)
│   └── disposition_cmd.py          # "stagecheck disposition add" (defect waivers)
├── core/                           # Authoritative Core Engine
│   ├── __init__.py
│   ├── paths.py                    # Root discovery & normalized component containment
│   ├── locking.py                  # Advisory fcntl.flock & bootstrap lock primitives
│   ├── journal.py                  # Write-ahead transaction journal & crash recovery
│   ├── permissions.py              # Controlled write transaction permission elevator
│   ├── orchestrator.py             # 9-stage audit execution engine
│   ├── state.py                    # ACTIVE_STATE.json manager & attempt state machine
│   ├── evidence.py                 # EVIDENCE_MANIFEST.json & seal.json generation
│   ├── quality.py                  # Quality record aggregator (CODE_QUALITY_REPORT.json)
│   ├── reporting.py                # verdict.json, escalation_report.md & renderers
│   └── utils.py                    # RFC 8785 canonical JCS hashing & JSON serializers
├── checks/                         # 9 Independent Verification Stages
│   ├── __init__.py
│   ├── base.py                     # BaseCheck abstract interface & Defect dataclass
│   ├── stage1_preflight.py         # Stage 1: Preflight invariants & prompt hash
│   ├── stage2_scope_paths.py       # Stage 2: Multi-repo scope containment
│   ├── stage3_citations.py         # Stage 3: Working-tree line citation verification
│   ├── stage4_report_lint.py       # Stage 4: Defect regex & anti-prompt injection
│   ├── stage5_authority.py         # Stage 5: OWNER_GRANTS.md & DISPOSITIONS.json check
│   ├── stage6_secrets.py           # Stage 6: Pinned Gitleaks scanner
│   ├── stage7_qual_naming.py       # Stage 7: test_* qualification conventions
│   ├── stage8_rerun.py             # Stage 8: Isolated clean sandbox rerun
│   └── stage9_carry_forward.py     # Stage 9: Cumulative defect regression prevention
├── daemon/                         # Sentinel Continuous Watchdog
│   ├── __init__.py
│   ├── sentinel.py                 # inotify/event-driven file & process watchdog
│   ├── events.py                   # STALL_DETECTED event record serializer
│   └── notifications.py            # Desktop D-Bus alert dispatcher
├── schemas/                        # Embedded JSON Schema Assets & Validators
│   ├── __init__.py
│   ├── validator.py                # jsonschema validation wrapper
│   └── assets/                     # Packaged schemas (*.schema.json)
└── config/                         # Embedded System Defaults
    ├── __init__.py
    └── defaults/                   # Default quality_targets.json, commands.json, etc.
```

---

## 3. Migration Mapping Matrix

| Legacy File | Canonical Target | Migration Role & Strategy |
|---|---|---|
| `bin/stagecheck.sh` | Wrapper $\to$ `stagecheck.cli.main` | Thin shell wrapper delegating directly to `python3 -m stagecheck.cli` |
| `bin/orchestrate.py` | `stagecheck.core.orchestrator` | Replaced by modular orchestrator; legacy file shims to modern core |
| `bin/render_report.py` | `stagecheck.core.reporting` | Refactored as reusable report rendering utility |
| `bin/response_hook.py` | `stagecheck.cli.review_cmd` | Refactored into review hook handler |
| `bin/agents.py` | `stagecheck.core.utils` | Agent slug validator & provider-neutral identifier handler |
| `bin/response_tokens.py` | `stagecheck.core.utils` | Token estimation helper integrated into core utilities |
| `bin/quality_measure.py` | `stagecheck.core.quality` | Refactored into core quality metric evaluator |
| `bin/quality_write.py` | `stagecheck.core.permissions` | Refactored into controlled write transaction protocol |
| `bin/quality.py` | `stagecheck.core.quality` | Reusable quality evaluator |
| `bin/common.py` | `stagecheck.core.utils` | Standard library JSON, hashing, and logging utilities |
| `checks/preflight.py` | `stagecheck.checks.stage1_preflight` | Migrated to Stage 1 check class; legacy file shims to module |
| `checks/scope_paths.py` | `stagecheck.checks.stage2_scope_paths` | Migrated to Stage 2 check class; legacy file shims to module |
| `checks/citations.py` | `stagecheck.checks.stage3_citations` | Migrated to Stage 3 check class; legacy file shims to module |
| `checks/report_lint.py` | `stagecheck.checks.stage4_report_lint` | Migrated to Stage 4 check class; legacy file shims to module |
| `checks/authority.py` | `stagecheck.checks.stage5_authority` | Migrated to Stage 5 check class; legacy file shims to module |
| `checks/secrets.py` | `stagecheck.checks.stage6_secrets` | Migrated to Stage 6 check class; legacy file shims to module |
| `checks/qual_naming.py` | `stagecheck.checks.stage7_qual_naming` | Migrated to Stage 7 check class; legacy file shims to module |
| `checks/rerun.py` | `stagecheck.checks.stage8_rerun` | Migrated to Stage 8 check class; legacy file shims to module |
| `checks/carry_forward.py` | `stagecheck.checks.stage9_carry_forward` | Migrated to Stage 9 check class; legacy file shims to module |
| `schemas/*.json` | `stagecheck/schemas/assets/*.json` | Packaged as package data assets |
| `config/*.json` | `stagecheck/config/defaults/*.json` | Packaged as default configuration assets |

---

## 4. Compatibility Shim Strategy

To ensure zero regression for operators or CI scripts relying on legacy CLI syntax during phased delivery:

1. **`bin/stagecheck.sh` Compatibility Shim:**
   ```bash
   #!/usr/bin/env bash
   set -euo pipefail
   exec python3 -m stagecheck.cli "$@"
   ```
2. **`bin/orchestrate.py` Compatibility Shim:**
   ```python
   #!/usr/bin/env python3
   import sys
   from stagecheck.core.orchestrator import run_orchestrator
   if __name__ == "__main__":
       sys.exit(run_orchestrator(sys.argv[1:]))
   ```
3. **`checks/*.py` Compatibility Shims:**
   Each script in `checks/` will import its modern counterpart:
   ```python
   #!/usr/bin/env python3
   import sys
   from stagecheck.checks.stage1_preflight import PreflightCheck
   if __name__ == "__main__":
       sys.exit(PreflightCheck().run_standalone(sys.argv[1:]))
   ```
4. **No Duplicate Source-of-Truth:**
   All domain logic, state validation, and cryptographic operations reside strictly within `stagecheck/`. Shims only parse CLI arguments and forward to the package layer.

---

## 5. Compatibility Risks & Mitigation Protocols

| Identified Risk | Impact | Mitigation Strategy |
|---|---|---|
| **Python Package Discovery** | `python3 -m stagecheck.cli` fails if package is not installed or `PYTHONPATH` not set | P1-T5 establishes PEP 621 `pyproject.toml` supporting `pip install -e .` and automatic `sys.path` bootstrapping in entrypoint wrappers |
| **Direct Script Execution** | External tools invoking `python3 checks/secrets.py` directly | Legacy shims preserve argument parsing and exit codes identical to original scripts |
| **Schema Path Assumptions** | Hardcoded references to `schemas/verdict.schema.json` | Core provides `stagecheck.schemas.get_schema_path(name)` resolving via `importlib.resources` with fallback to local path |
| **External Machine Paths in Tests** | Evaluation fixtures failing due to `/home/magnus/...` paths | P1-T3 root discovery dynamically discovers workspace root relative to module location |

---

## 6. Acceptance Criteria Checklist (P1-T2)

| Requirement | Evidence | Status |
|---|---|:---:|
| Architecture map and package layers defined | Section 2 outlines `stagecheck/` directory layout | **SATISFIED** |
| 1-to-1 migration mapping of legacy files | Section 3 maps all files in `bin/`, `checks/`, `schemas/`, `config/` | **SATISFIED** |
| Compatibility shims defined | Section 4 provides shim implementations for legacy entrypoints | **SATISFIED** |
| No duplicate source of truth | Domain logic centralized in `stagecheck/`; shims act as thin adapters | **SATISFIED** |
| Compatibility risks & mitigations listed | Section 5 documents risks and mitigation protocols | **SATISFIED** |
