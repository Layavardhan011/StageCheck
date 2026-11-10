"""Stage 3: Evidence Citation Verification against Working Tree (P4-T2).

Verifies that file and code citations referenced in claims.json point to actual files
in the working tree under 20 MiB, validates line ranges, and checks that quoted snippets
match actual line contents to prevent hallucinated citations (SEC-F2, SEC-N1).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from stagecheck.checks.base import AuditContext, Defect, StageResult
from stagecheck.core.paths import StageCheckPathError, safe_resolve

MAX_CITATION_FILE_SIZE = 20 * 1024 * 1024  # 20 MiB


def run_stage3_citations(ctx: AuditContext) -> StageResult:
    """Execute Stage 3 Citations Verification."""
    stage_id = "citations"
    defects: List[Defect] = []
    errors: List[str] = []

    claims = ctx.claims.get("claims", [])
    for claim in claims:
        citations = claim.get("citations", [])
        for cite in citations:
            cite_type = cite.get("type")
            if cite_type in ("file", "document", "code"):
                file_rel = cite.get("path") or cite.get("file")
                lines = cite.get("lines")
                expected_quote = cite.get("quote")

                if not isinstance(file_rel, str) or not file_rel.strip() or Path(file_rel).is_absolute():
                    defects.append(
                        Defect(
                            defect_id="citations.path_escaped",
                            message=f"Cited path '{file_rel}' must be a non-empty workspace-relative string.",
                            stage=stage_id,
                            severity="CRITICAL",
                            blocking=True,
                            citation=cite,
                        )
                    )
                    continue

                try:
                    target_file = safe_resolve(file_rel, ctx.workspace_root, allow_symlinks=False)
                except StageCheckPathError as err:
                    defects.append(
                        Defect(
                            defect_id="citations.path_escaped",
                            message=f"Cited path '{file_rel}' escapes workspace root or traverses symlink: {err}",
                            stage=stage_id,
                            severity="CRITICAL",
                            blocking=True,
                            citation=cite,
                        )
                    )
                    continue

                if not target_file.is_file():
                    defects.append(
                        Defect(
                            defect_id="citations.missing_file",
                            message=f"Cited file '{file_rel}' does not exist on disk.",
                            stage=stage_id,
                            severity="HIGH",
                            blocking=True,
                            citation=cite,
                        )
                    )
                    continue

                # File size check (< 20 MiB)
                try:
                    file_size = target_file.stat().st_size
                    if file_size > MAX_CITATION_FILE_SIZE:
                        defects.append(
                            Defect(
                                defect_id="citations.file_oversized",
                                message=f"Cited file '{file_rel}' size ({file_size} bytes) exceeds 20 MiB limit.",
                                stage=stage_id,
                                severity="HIGH",
                                blocking=True,
                                citation=cite,
                            )
                        )
                        continue
                except Exception as err:
                    errors.append(f"Failed to check size of '{file_rel}': {err}")
                    defects.append(
                        Defect(
                            defect_id="citations.unreadable_file",
                            message=f"Failed to stat cited file '{file_rel}': {err}",
                            stage=stage_id,
                            severity="HIGH",
                            blocking=True,
                            citation=cite,
                        )
                    )
                    continue

                # Content line inspection (validate shape whenever lines or quote is present)
                if lines is not None or expected_quote is not None:
                    if (
                        not isinstance(lines, list)
                        or len(lines) != 2
                        or any(not isinstance(v, int) or isinstance(v, bool) for v in lines)
                    ):
                        defects.append(
                            Defect(
                                defect_id="citations.invalid_citation",
                                message=f"Invalid line range {lines!r} for '{file_rel}'. Must be [start, end] integers.",
                                stage=stage_id,
                                severity="HIGH",
                                blocking=True,
                                citation=cite,
                            )
                        )
                        continue

                    try:
                        content_lines = target_file.read_text(encoding="utf-8", errors="ignore").splitlines()
                        start_line = lines[0]
                        end_line = lines[1]
                        total_lines = len(content_lines)

                        if start_line < 1 or end_line > total_lines or start_line > end_line:
                            defects.append(
                                Defect(
                                    defect_id="citations.line_out_of_bounds",
                                    message=(
                                        f"Cited line range [{start_line}, {end_line}] in '{file_rel}' "
                                        f"exceeds file boundary (total lines: {total_lines})."
                                    ),
                                    stage=stage_id,
                                    severity="HIGH",
                                    blocking=True,
                                    citation=cite,
                                )
                            )
                        elif expected_quote is not None:
                            actual_slice = "\n".join(content_lines[start_line - 1 : end_line])
                            if (
                                not isinstance(expected_quote, str)
                                or not expected_quote.strip()
                                or not actual_slice.strip()
                                or expected_quote.strip() not in actual_slice
                            ):
                                defects.append(
                                    Defect(
                                        defect_id="citations.content_mismatch",
                                        message=(
                                            f"Content cited in '{file_rel}#L{start_line}-L{end_line}' does not match "
                                            f"actual non-empty file content in working tree."
                                        ),
                                        stage=stage_id,
                                        severity="HIGH",
                                        blocking=True,
                                        citation=cite,
                                    )
                                )
                    except Exception as err:
                        errors.append(f"Failed to read cited file '{file_rel}': {err}")
                        defects.append(
                            Defect(
                                defect_id="citations.unreadable_file",
                                message=f"Failed to read cited file '{file_rel}': {err}",
                                stage=stage_id,
                                severity="HIGH",
                                blocking=True,
                                citation=cite,
                            )
                        )

    status = "FAIL" if (errors or any(d.blocking for d in defects)) else "CLEAR"
    return StageResult(stage_id=stage_id, status=status, defects=defects, errors=errors)
