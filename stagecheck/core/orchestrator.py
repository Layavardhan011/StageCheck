"""StageCheck Nine-Stage Audit Orchestrator (P4-T2).

Executes the complete 9-stage verification pipeline across all registered and touched
repositories, evaluates human disposition waivers, and aggregates the multi-repository
verdict with strict zero partial pass semantics (GAP-04, GAP-AE1).
"""

from __future__ import annotations

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
from stagecheck.core.evidence import (
    append_issue_history,
    create_task_seal,
    update_evidence_manifest,
)
from stagecheck.core.paths import find_workspace_root
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


def _match_disposition(defect: Defect, dispositions: List[Dict[str, Any]]) -> bool:
    """Check if a defect is waived by an approved human disposition."""
    for disp in dispositions:
        if disp.get("defect_id") == defect.defect_id:
            # If disposition specifies repo, it must match
            disp_repo = disp.get("repo")
            if disp_repo and defect.repo and disp_repo != defect.repo:
                continue
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
                    import subprocess
                    head_res = subprocess.run(
                        ["git", "-C", str(repo_path), "rev-parse", "HEAD"],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        check=False,
                    )
                    if head_res.returncode == 0:
                        target_commits[name] = head_res.stdout.strip()
                except Exception:
                    pass

        # If no repos in PRODUCT_REPOSITORIES.json but root is git
        if not all_registered and (self.workspace_root / ".git").exists():
            all_registered = ["root"]
            try:
                import subprocess
                head_res = subprocess.run(
                    ["git", "-C", str(self.workspace_root), "rev-parse", "HEAD"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False,
                )
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
                    import subprocess
                    diff_res = subprocess.run(
                        ["git", "-C", str(repo_path), "status", "--porcelain=v1"],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        check=False,
                    )
                    if diff_res.stdout.strip():
                        touched.append(name)
                except Exception:
                    pass
        if not touched and all_registered:
            touched = list(all_registered)

        # 3. Claims
        claims_path = (
            self.workspace_root
            / "evidence"
            / "tasks"
            / resolved_task_id
            / f"attempt_{resolved_attempt}"
            / "Phase-2B"
            / "claims.json"
        )
        if not claims_path.is_file():
            claims_path = self.workspace_root / "claims.json"
        claims = _load_optional_json(claims_path)

        # 4. Dispositions
        disp_doc = _load_optional_json(self.workspace_root / "controls" / "DISPOSITIONS.json")
        dispositions = disp_doc.get("dispositions", [])

        # 5. Declared Scope
        scope_path = (
            self.workspace_root
            / "evidence"
            / "tasks"
            / resolved_task_id
            / f"attempt_{resolved_attempt}"
            / "Phase-1"
            / "declared_scope.json"
        )
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

        # Evaluate human dispositions / waivers
        for defect in all_defects:
            if defect.blocking and _match_disposition(defect, ctx.dispositions):
                defect.blocking = False
                defect.severity = "WAIVED"

        # Tally counts
        blocking_count = sum(1 for d in all_defects if d.blocking)
        report_only_count = len(all_defects) - blocking_count

        overall_passed = (blocking_count == 0)
        overall_result = "CLEAR" if overall_passed else "BLOCKED"

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
            "questions": [],
            "counts": {
                "blocking": blocking_count,
                "report_only": report_only_count,
                "not_run": 0,
            },
        }

        # Write verdict.json
        phase3_dir = (
            self.workspace_root
            / "evidence"
            / "tasks"
            / ctx.task_id
            / f"attempt_{ctx.attempt}"
            / "Phase-3"
        )
        phase3_dir.mkdir(parents=True, exist_ok=True)
        verdict_path = phase3_dir / "verdict.json"
        with open(verdict_path, "w", encoding="utf-8") as f:
            f.write(pretty_json_dumps(verdict_data))

        # Also write task root verdict.json for high-level tools
        task_root_dir = self.workspace_root / "evidence" / "tasks" / ctx.task_id
        task_root_dir.mkdir(parents=True, exist_ok=True)
        with open(task_root_dir / "verdict.json", "w", encoding="utf-8") as f:
            f.write(pretty_json_dumps(verdict_data))

        # Update evidence manifest with verdicts
        update_evidence_manifest(self.workspace_root, [verdict_path, task_root_dir / "verdict.json"])

        # Create task seal or append issue history
        if overall_passed:
            create_task_seal(
                workspace_root=self.workspace_root,
                task_id=ctx.task_id,
                attempt=ctx.attempt,
                verdict_data=verdict_data,
                checked_heads=ctx.target_commits,
                outcome="PASSED",
            )
        else:
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
