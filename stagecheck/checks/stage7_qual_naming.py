"""Stage 7: Qualification Test Naming and Suite Verification (P4-T2).

Enforces qualification test naming conventions (qual_*_test.go, TestQual*, qual_*.py,
test_*.py) and evaluates the qualification directory under controls/QUALIFICATION_ROOT.json
with milestone-aware empty-suite semantics (GAP-B2, GAP-AE1).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List

from stagecheck.checks.base import AuditContext, Defect, StageResult

# Supported qualification test file patterns across major language ecosystems
QUAL_TEST_NAME_PATTERNS = [
    re.compile(r"^qual_.*_test\.go$"),
    re.compile(r"^TestQual.*\.go$"),
    re.compile(r"^(qual_|test_).*\.py$"),
    re.compile(r"^.*_test\.py$"),
    re.compile(r"^(qual_|test_).*\.(js|ts|jsx|tsx|sh)$"),
    re.compile(r"^.*\.(qual|test|spec)\.(js|ts|jsx|tsx)$"),
]

# Non-test companion/meta files permitted inside qualification directories
ALLOWED_COMPANION_PATTERNS = [
    re.compile(r"^__init__\.py$"),
    re.compile(r"^conftest\.py$"),
    re.compile(r"^.*\.(json|yaml|yml|md|txt|csv|sql|toml)$"),
    re.compile(r"^\..*"),  # hidden files / configs
]


def _is_valid_qual_test_name(filename: str) -> bool:
    return any(p.match(filename) for p in QUAL_TEST_NAME_PATTERNS)


def _is_allowed_companion(filename: str) -> bool:
    return any(p.match(filename) for p in ALLOWED_COMPANION_PATTERNS)


def run_stage7_qual_naming(ctx: AuditContext) -> StageResult:
    """Execute Stage 7 Qualification Test Naming verification."""
    stage_id = "qual_naming"
    defects: List[Defect] = []
    errors: List[str] = []

    # 1. Resolve qualification root path from controls/QUALIFICATION_ROOT.json
    qual_config_path = ctx.workspace_root / "controls" / "QUALIFICATION_ROOT.json"
    qual_root_rel = "evals"
    requires_qualification_tests = False

    if qual_config_path.is_file():
        try:
            with open(qual_config_path, "r", encoding="utf-8") as f:
                qual_data = json.load(f)
            qual_root_rel = qual_data.get("qualification_root", "evals")
            requires_qualification_tests = bool(qual_data.get("require_qualification_tests", False))
        except Exception as err:
            errors.append(f"Failed to read controls/QUALIFICATION_ROOT.json: {err}")
    else:
        # Fall back to checking specs/TASK_PLAN.json if present
        task_plan_path = ctx.workspace_root / "specs" / "TASK_PLAN.json"
        if task_plan_path.is_file():
            try:
                with open(task_plan_path, "r", encoding="utf-8") as f:
                    plan_data = json.load(f)
                requires_qualification_tests = bool(plan_data.get("requires_qualification_tests", False))
            except Exception:
                pass

    # Check context declared scope override for requires_qualification_tests
    if ctx.declared_scope and "requires_qualification_tests" in ctx.declared_scope:
        requires_qualification_tests = bool(ctx.declared_scope["requires_qualification_tests"])

    qual_dir = ctx.workspace_root / qual_root_rel
    if not qual_dir.exists() or not qual_dir.is_dir():
        defects.append(
            Defect(
                defect_id="qual_naming.directory_missing",
                message=f"Qualification directory does not exist or is not a directory: '{qual_root_rel}'",
                stage=stage_id,
                severity="CRITICAL",
                blocking=True,
            )
        )
        return StageResult(stage_id=stage_id, status="FAIL", defects=defects, errors=errors)

    # 2. Enumerate qualification test files
    qual_test_files: List[Path] = []
    invalid_test_files: List[Path] = []

    try:
        for path in qual_dir.rglob("*"):
            if not path.is_file():
                continue
            fname = path.name
            if _is_allowed_companion(fname):
                continue
            if _is_valid_qual_test_name(fname):
                qual_test_files.append(path)
            else:
                # Potential code/test file that violates naming conventions
                invalid_test_files.append(path)
    except Exception as err:
        errors.append(f"Error scanning qualification directory '{qual_root_rel}': {err}")

    # 3. Check for naming violations
    for invalid_file in invalid_test_files:
        rel_f = invalid_file.relative_to(ctx.workspace_root)
        defects.append(
            Defect(
                defect_id="qual_naming.invalid_test_name",
                message=(
                    f"Qualification test file '{rel_f}' violates naming conventions "
                    "(must match qual_*_test.go, TestQual*, qual_*.py, or test_*.py)"
                ),
                stage=stage_id,
                severity="CRITICAL",
                blocking=True,
                citation={"path": str(rel_f)},
            )
        )

    # 4. Check suite completeness against milestone requirement
    if not qual_test_files:
        if requires_qualification_tests:
            defects.append(
                Defect(
                    defect_id="qual_naming.required_suite_empty",
                    message=(
                        f"Active task requires qualification tests, but 0 qualification "
                        f"tests were found under '{qual_root_rel}'"
                    ),
                    stage=stage_id,
                    severity="CRITICAL",
                    blocking=True,
                )
            )
        else:
            # Clean bootstrapping / initial phase without tests
            defects.append(
                Defect(
                    defect_id="qual_naming.empty_suite",
                    message=(
                        f"Qualification directory '{qual_root_rel}' contains zero qualification tests "
                        "(active task does not require qualification tests)"
                    ),
                    stage=stage_id,
                    severity="INFO",
                    blocking=False,
                )
            )

    has_blocking = any(d.blocking for d in defects)
    return StageResult(
        stage_id=stage_id,
        status="FAIL" if has_blocking else "CLEAR",
        defects=defects,
        errors=errors,
    )
