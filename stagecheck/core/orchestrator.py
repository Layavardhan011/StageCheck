"""StageCheck Nine-Stage Audit Orchestrator (P4-T2).

Executes the complete 9-stage verification pipeline across all registered and touched
repositories, evaluates human disposition waivers, and aggregates the multi-repository
verdict with strict zero partial pass semantics (GAP-04, GAP-AE1).
"""

from __future__ import annotations

import datetime
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from stagecheck.checks import (
    AuditContext,
    Defect,
    StageResult,
    run_stage1_preflight,
    run_stage2_scope_paths,
    run_stage3_citations,
    run_stage4_report_lint,
    run_stage5_authority,
    run_stage6_secrets,
    run_stage7_qual_naming,
    run_stage8_rerun,
    run_stage9_carry_forward,
)
from stagecheck.core.agents import resolve_task_attempt_dir
from stagecheck.core.evidence import (
    append_issue_history,
    update_evidence_manifest,
)
from stagecheck.core.git import run_safe_git
from stagecheck.core.paths import find_workspace_root, resolve_task_dir
from stagecheck.core.utils import (
    canonical_json_dumps,
    pretty_json_dumps,
    sha256_file,
    validate_schema,
)
from stagecheck.schemas.validator import get_schema_path, load_json_file


def _load_optional_json(path: Path) -> Dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _match_disposition(
    defect: Defect,
    dispositions: List[Dict[str, Any]],
    task_id: str,
    workspace_root: Optional[Path] = None,
    attempt: Optional[int] = None,
) -> bool:
    """Check if a defect is waived by a provenance-verified human disposition for (task_id, attempt)."""
    if workspace_root is None or attempt is None:
        return False
    from stagecheck.core.dispositions import validate_waiver_provenance

    for disp in dispositions:
        if not isinstance(disp, dict):
            continue
        disp_repo = disp.get("repo")
        if disp_repo and defect.repo and disp_repo != defect.repo:
            continue
        ok, _ = validate_waiver_provenance(
            workspace_root=workspace_root,
            entry=disp,
            task_id=task_id,
            attempt=attempt,
            required_rule_id=defect.defect_id,
            all_entries=dispositions,
        )
        if ok:
            return True
    return False


class AuditOrchestrator:
    """Executes the nine independent verification stages and generates verdict.json."""

    def __init__(self, workspace_root: Optional[Path] = None):
        self.workspace_root = workspace_root or find_workspace_root()

    def discover_context(
        self,
        task_id: Optional[str] = None,
        attempt: Optional[int] = None,
    ) -> AuditContext:
        """Discover and construct the audit context from controls and workspace files."""
        # 1. Active State
        active_state = _load_optional_json(self.workspace_root / "controls" / "ACTIVE_STATE.json")
        resolved_task_id = task_id or active_state.get("task_id", "task-default")
        resolved_attempt = attempt or active_state.get("attempt_index", 1)

        # 2. Product Repositories
        prod_repos = _load_optional_json(self.workspace_root / "controls" / "PRODUCT_REPOSITORIES.json")
        repo_dict = prod_repos.get("repositories", {})
        all_registered = list(repo_dict.keys())
        base_commits: Dict[str, str] = {}
        target_commits: Dict[str, str] = {}

        for name, meta in repo_dict.items():
            base_commits[name] = meta.get("baseline_head", "0" * 40)
            rel_p = meta.get("path", f"repos/{name}")
            repo_path = self.workspace_root / rel_p
            if (repo_path / ".git").exists():
                try:
                    head_res = run_safe_git(repo_path, ["rev-parse", "HEAD"])
                    if head_res.returncode == 0:
                        target_commits[name] = head_res.stdout.strip()
                except Exception:
                    pass

        # If no repos in PRODUCT_REPOSITORIES.json but root is git
        if not all_registered and (self.workspace_root / ".git").exists():
            all_registered = ["root"]
            try:
                head_res = run_safe_git(self.workspace_root, ["rev-parse", "HEAD"])
                if head_res.returncode == 0:
                    target_commits["root"] = head_res.stdout.strip()
                    base_commits["root"] = target_commits["root"]
            except Exception:
                pass

        # Detect touched repos
        touched: List[str] = []
        for name in all_registered:
            rel_p = repo_dict.get(name, {}).get("path", f"repos/{name}" if name != "root" else ".")
            repo_path = self.workspace_root / rel_p
            if not repo_path.exists():
                continue
            # If target HEAD differs from base commit, repo was touched
            if target_commits.get(name) and base_commits.get(name) and target_commits[name] != base_commits[name]:
                touched.append(name)
            else:
                # Also check working tree changes
                try:
                    diff_res = run_safe_git(repo_path, ["status", "--porcelain=v1"])
                    if diff_res.stdout.strip():
                        touched.append(name)
                except Exception:
                    pass
        if not touched and all_registered:
            touched = list(all_registered)

        # 3. Claims
        attempt_dir = resolve_task_attempt_dir(self.workspace_root, resolved_task_id, resolved_attempt)
        claims_path = attempt_dir / "Phase-2B" / "claims.json"
        if not claims_path.is_file():
            claims_path = self.workspace_root / "claims.json"
        claims = _load_optional_json(claims_path)

        # 4. Dispositions
        disp_doc = _load_optional_json(self.workspace_root / "controls" / "DISPOSITIONS.json")
        dispositions = disp_doc.get("dispositions", [])

        # 5. Declared Scope
        scope_path = attempt_dir / "Phase-1" / "declared_scope.json"
        if not scope_path.is_file():
            scope_path = self.workspace_root / "controls" / "declared_scope.json"
        if not scope_path.is_file():
            scope_path = self.workspace_root / "specs" / "TASK_PLAN.json"
        declared_scope = _load_optional_json(scope_path)

        return AuditContext(
            workspace_root=self.workspace_root,
            task_id=resolved_task_id,
            attempt=resolved_attempt,
            touched_repos=touched,
            all_registered_repos=all_registered,
            claims=claims,
            base_commits=base_commits,
            target_commits=target_commits,
            dispositions=dispositions,
            declared_scope=declared_scope,
        )

    def run_all_stages(self, ctx: AuditContext) -> Tuple[bool, Dict[str, Any]]:
        """Run all nine stages in sequence, evaluate dispositions, and format verdict."""
        from stagecheck.core.isolation import run_bwrap_deployment_preflight

        # Fail closed before running any audit stage or rerun if OS isolation preflight fails (GAP-03)
        run_bwrap_deployment_preflight(workspace_root=ctx.workspace_root, raise_on_failure=True)

        stage_runners = [
            ("preflight", run_stage1_preflight),
            ("scope_paths", run_stage2_scope_paths),
            ("citations", run_stage3_citations),
            ("report_lint", run_stage4_report_lint),
            ("authority", run_stage5_authority),
            ("secrets", run_stage6_secrets),
            ("qual_naming", run_stage7_qual_naming),
            ("rerun", run_stage8_rerun),
            ("carry_forward", run_stage9_carry_forward),
        ]

        stage_results: List[StageResult] = []
        all_defects: List[Defect] = []
        all_errors: List[str] = []

        for stage_id, runner in stage_runners:
            try:
                res = runner(ctx)
            except Exception as err:
                res = StageResult(
                    stage_id=stage_id,
                    status="FAIL",
                    defects=[
                        Defect(
                            defect_id=f"{stage_id}.exception",
                            message=f"Unhandled exception during stage execution: {err}",
                            stage=stage_id,
                            severity="CRITICAL",
                            blocking=True,
                        )
                    ],
                    errors=[str(err)],
                )
            stage_results.append(res)
            all_defects.extend(res.defects)
            all_errors.extend(res.errors)
            if res.errors and not any(d.blocking for d in res.defects):
                err_defect = Defect(
                    defect_id=f"{res.stage_id}.stage_error",
                    message=f"Stage '{res.stage_id}' reported errors: {'; '.join(res.errors)}",
                    stage=res.stage_id,
                    severity="HIGH",
                    blocking=True,
                )
                res.defects.append(err_defect)
                all_defects.append(err_defect)

        # Check multi-repository availability (zero partial pass)
        for repo_name in ctx.all_registered_repos:
            repo_p = self.workspace_root / "repos" / repo_name if repo_name != "root" else self.workspace_root
            if not repo_p.is_dir():
                all_defects.append(
                    Defect(
                        defect_id="multi_repo.repository_unavailable",
                        message=f"Registered repository '{repo_name}' is unavailable or missing at '{repo_p}'.",
                        stage="preflight",
                        severity="CRITICAL",
                        blocking=True,
                        repo=repo_name,
                    )
                )

        # 10. Run 270-Rule Rubric Evaluation (FR-03 / DEC-003 / DEC-026)
        rubric_payload: Dict[str, Any] = {}
        try:
            from stagecheck.core.rubric_engine import run_rubric_evaluation

            rerun_stage = next((r for r in stage_results if r.stage_id == "rerun"), None)
            sec_stage = next((r for r in stage_results if r.stage_id == "secrets"), None)
            stage_summaries = [r.to_dict() for r in stage_results]
            audit_rubric_ctx: Dict[str, Any] = {
                "stage_results": stage_summaries,
                "claims": ctx.claims,
                "rerun_results": {
                    "status": rerun_stage.status if rerun_stage else "UNKNOWN",
                    "errors": rerun_stage.errors if rerun_stage else ["rerun_stage_missing"],
                    "defects": [d.defect_id for d in rerun_stage.defects] if rerun_stage else [],
                },
            }
            if sec_stage and sec_stage.status == "PASS" and not any(d.blocking for d in sec_stage.defects):
                audit_rubric_ctx["scanner_report_doc"] = {"status": "PASSED", "defects": []}

            rubric_payload, _ = run_rubric_evaluation(
                workspace_root=self.workspace_root,
                task_id=ctx.task_id,
                attempt=ctx.attempt,
                context=audit_rubric_ctx,
            )
            if rubric_payload.get("evaluation_completeness") != "COMPLETE" or rubric_payload.get("evaluated_rule_count") != 270:
                all_defects.append(
                    Defect(
                        defect_id="rubric.incomplete_evaluation",
                        message=(
                            f"Phase 3 audit rubric is '{rubric_payload.get('evaluation_completeness')}' "
                            f"({rubric_payload.get('evaluated_rule_count')}/{rubric_payload.get('expected_rule_count', 270)})."
                        ),
                        stage="rubric",
                        severity="CRITICAL",
                        blocking=True,
                    )
                )
            if rubric_payload.get("overall_verdict") != "PASS":
                added_rubric_defect = False
                for eval_item in rubric_payload.get("evaluations", []):
                    st = eval_item.get("status")
                    if st in ("FAIL", "BLOCKED", "NOT_EVALUATED"):
                        added_rubric_defect = True
                        all_defects.append(
                            Defect(
                                defect_id=eval_item.get("rule_id", "RUBRIC_DEFECT"),
                                message=eval_item.get("message")
                                or eval_item.get("rationale")
                                or f"Rubric rule {eval_item.get('rule_id')} returned status {st}.",
                                stage="rubric",
                                severity="CRITICAL",
                                blocking=True,
                                repo=eval_item.get("repository"),
                            )
                        )
                if not added_rubric_defect:
                    all_defects.append(
                        Defect(
                            defect_id="rubric.incomplete_or_failed",
                            message=f"Rubric overall_verdict is '{rubric_payload.get('overall_verdict')}'.",
                            stage="rubric",
                            severity="CRITICAL",
                            blocking=True,
                        )
                    )
        except Exception as r_err:
            all_defects.append(
                Defect(
                    defect_id="rubric.evaluation_error",
                    message=f"Rubric evaluation failed: {r_err}",
                    stage="rubric",
                    severity="CRITICAL",
                    blocking=True,
                )
            )

        # Evaluate human dispositions / waivers (strictly validated for GAP-03 provenance)
        for defect in all_defects:
            if defect.blocking and _match_disposition(
                defect,
                ctx.dispositions,
                ctx.task_id,
                workspace_root=self.workspace_root,
                attempt=ctx.attempt,
            ):
                defect.blocking = False
                defect.severity = "WAIVED"

        # Tally counts
        blocking_count = sum(1 for d in all_defects if d.blocking)
        report_only_count = len(all_defects) - blocking_count

        overall_passed = (blocking_count == 0 and len(all_errors) == 0)
        overall_result = "CLEAR" if overall_passed else "BLOCKED"
        overall_status = "PASSED" if overall_passed else "FAILED"

        # Format checks for verdict.schema.json
        checks_payload = []
        for res in stage_results:
            checks_payload.append({
                "type": "check",
                "id": res.stage_id,
                "version": "0" * 64,
                "defects": [],
                "errors": res.errors,
                "not_run": [],
                "files": [],
                "commands": [],
                "unbound": False,
                "escalate": False,
            })

        # Format defects payload for verdict.schema.json
        formatted_defects = []
        for d in all_defects:
            location_path = d.citation.get("path", "AGENTS.md") if d.citation else "AGENTS.md"
            formatted_defects.append({
                "defect_id": d.defect_id,
                "check_id": d.stage,
                "source": "verification_engine",
                "mode": "blocking" if d.blocking else "report_only",
                "clause": "1.0",
                "claim_id": "",
                "location": {
                    "path": str(location_path),
                    "lines": [1, 1],
                },
                "evidence": [
                    {
                        "type": "file",
                        "path": str(location_path),
                        "sha256": "0" * 64,
                        "lines": [1, 1],
                        "quote": d.message[:120],
                    }
                ],
                "required_outcome": "Defect resolved or waived",
                "status": "new",
            })

        # Calculate contract hash (AGENTS.md)
        agents_md_path = self.workspace_root / "AGENTS.md"
        contract_sha256 = "0" * 64
        if agents_md_path.is_file():
            contract_sha256 = sha256_file(agents_md_path)

        # Primary checked head
        checked_head = "0" * 40
        if ctx.target_commits:
            checked_head = next(iter(ctx.target_commits.values()))

        # Assemble strictly compliant verdict.schema.json Branch 2 structure
        verdict_data = {
            "type": "verdict",
            "task_id": ctx.task_id,
            "iteration": ctx.attempt,
            "contract_sha256": contract_sha256,
            "checked_head": checked_head,
            "manifest_sha256": "0" * 64,
            "bound": True,
            "depth": "code",
            "input_hashes": {},
            "previous": {},
            "checks": checks_payload,
            "agents": [{"agent_slug": "developer"}],
            "defects": formatted_defects,
            "not_run": [],
            "errors": all_errors,
            "result": overall_result,
            "status": overall_status,
            "questions": [],
            "counts": {
                "blocking": blocking_count,
                "report_only": report_only_count,
                "not_run": 0,
            },
        }

        # Write Phase-3 directory artifacts
        phase3_dir = resolve_task_attempt_dir(self.workspace_root, ctx.task_id, ctx.attempt) / "Phase-3"
        phase3_dir.mkdir(parents=True, exist_ok=True)

        # 1. verdict.json
        verdict_path = phase3_dir / "verdict.json"
        with open(verdict_path, "w", encoding="utf-8") as f:
            f.write(pretty_json_dumps(verdict_data))

        # 2. test_execution.json
        rerun_res = next((r.to_dict() for r in stage_results if r.stage_id == "rerun"), {})
        test_exec_data = {
            "schema_version": "2.0.0",
            "task_id": ctx.task_id,
            "attempt_index": ctx.attempt,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "status": "PASSED" if not any(d.stage == "rerun" and d.blocking for d in all_defects) else "FAILED",
            "repositories": ctx.all_registered_repos,
            "stage_summary": rerun_res,
        }
        test_exec_path = phase3_dir / "test_execution.json"
        test_exec_path.write_text(pretty_json_dumps(test_exec_data), encoding="utf-8")

        # 3. scanner_report.json
        sec_res = next((r.to_dict() for r in stage_results if r.stage_id == "secrets"), {})
        scanner_data = {
            "schema_version": "2.0.0",
            "task_id": ctx.task_id,
            "attempt_index": ctx.attempt,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "scanner": "gitleaks",
            "pinned_config": "config/.gitleaks.toml",
            "status": "PASSED" if not any(d.stage == "secrets" and d.blocking for d in all_defects) else "FAILED",
            "repositories": ctx.all_registered_repos,
            "stage_summary": sec_res,
        }
        scanner_path = phase3_dir / "scanner_report.json"
        scanner_path.write_text(pretty_json_dumps(scanner_data), encoding="utf-8")

        # 4. rubric_evaluation.json
        rubric_path = phase3_dir / "rubric_evaluation.json"
        rubric_path.write_text(pretty_json_dumps(rubric_payload), encoding="utf-8")

        # Also write task root verdict.json for high-level tools
        task_root_dir = resolve_task_dir(self.workspace_root, ctx.task_id)
        task_root_dir.mkdir(parents=True, exist_ok=True)
        with open(task_root_dir / "verdict.json", "w", encoding="utf-8") as f:
            f.write(pretty_json_dumps(verdict_data))

        # Update evidence manifest with all Phase-3 audit deliverables
        update_evidence_manifest(
            self.workspace_root,
            [
                verdict_path,
                test_exec_path,
                scanner_path,
                rubric_path,
                task_root_dir / "verdict.json",
            ],
        )

        # Handle failure history and circuit breaker (sealing is deferred strictly to Gate 4)
        if not overall_passed:
            append_issue_history(
                workspace_root=self.workspace_root,
                task_id=ctx.task_id,
                attempt=ctx.attempt,
                outcome="FAILED",
                defects=formatted_defects,
            )
            # Evaluate circuit breaker triggers
            from stagecheck.core.circuit_breaker import evaluate_circuit_breaker, trip_circuit_breaker
            active_state = _load_optional_json(self.workspace_root / "controls" / "ACTIVE_STATE.json")
            cb_eval = evaluate_circuit_breaker(
                workspace_root=self.workspace_root,
                task_id=ctx.task_id,
                attempt=ctx.attempt,
                current_defects=formatted_defects,
                active_state=active_state,
            )
            if cb_eval.tripped:
                trip_circuit_breaker(
                    workspace_root=self.workspace_root,
                    task_id=ctx.task_id,
                    attempt=ctx.attempt,
                    evaluation=cb_eval,
                    current_defects=formatted_defects,
                )
            else:
                from stagecheck.core.gate_engine import handle_audit_verdict
                handle_audit_verdict(
                    workspace_root=self.workspace_root,
                    task_id=ctx.task_id,
                    attempt=ctx.attempt,
                    verdict_data=verdict_data,
                )

        return overall_passed, verdict_data


def run_audit(
    workspace_root: Optional[Path] = None,
    task_id: Optional[str] = None,
    attempt: Optional[int] = None,
) -> Tuple[bool, Dict[str, Any]]:
    """Convenience functional interface to run full audit."""
    orchestrator = AuditOrchestrator(workspace_root)
    ctx = orchestrator.discover_context(task_id=task_id, attempt=attempt)
    return orchestrator.run_all_stages(ctx)
