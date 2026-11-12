"""StageCheck Unified Command-Line Interface Dispatcher.

Dispatches subcommands to modular command handlers while providing backward
compatibility with legacy invocations.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional

import stagecheck


def build_parser() -> argparse.ArgumentParser:
    """Construct the root command-line parser."""
    parser = argparse.ArgumentParser(
        prog="stagecheck",
        description="StageCheck — Enterprise AI Delivery Governance & Verification Harness",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"StageCheck v{stagecheck.__version__}",
        help="Show program version and exit.",
    )

    subparsers = parser.add_subparsers(
        dest="subcommand",
        title="Governed Lifecycle Subcommands",
        description="Run 'stagecheck <subcommand> --help' for details on each subcommand.",
    )

    # 1. init
    p_init = subparsers.add_parser("init", help="Initialize a new governed workspace.")
    p_init.add_argument("--repos", help="Comma-separated target repository names.")
    p_init.add_argument("--workspace", help="Explicit workspace root path.")
    p_init.add_argument("--force", "--reinit", action="store_true", dest="force", help="Force re-initialization with owner grant.")
    p_init.add_argument("--agent1", help="Agent 1 name (Prompt Architect & Auditor).")
    p_init.add_argument("--agent2", help="Agent 2 name (Code Implementer).")
    p_init.add_argument(
        "--approve-remote",
        action="append",
        dest="approve_remotes",
        help="Approve a remote git push URL in controls/remotes.json (repeatable).",
    )

    # 2. start
    p_start = subparsers.add_parser("start", help="Activate a new task under exclusive lock.")
    p_start.add_argument("--task", required=True, help="Task identifier (e.g. task-101).")
    p_start.add_argument("--workspace", help="Explicit workspace root path.")

    # 3. verify-prompt
    p_vp = subparsers.add_parser("verify-prompt", help="Verify Phase 1 prompt blueprint and freeze hash.")
    p_vp.add_argument("--task", required=True, help="Task identifier.")
    p_vp.add_argument("--attempt", type=int, default=1, help="Attempt index (default: 1).")
    p_vp.add_argument("--workspace", help="Explicit workspace root path.")

    # 4. review-precommit
    p_rev = subparsers.add_parser("review-precommit", help="Execute Phase 2A pre-commit cooperative review.")
    p_rev.add_argument("--task", required=True, help="Task identifier.")
    p_rev.add_argument("--attempt", type=int, default=1, help="Attempt index (default: 1).")
    p_rev.add_argument("--workspace", help="Explicit workspace root path.")

    # 5. approve-review
    p_appr = subparsers.add_parser("approve-review", help="Human operator review approval gate.")
    p_appr.add_argument("--task", required=True, help="Task identifier.")
    p_appr.add_argument("--attempt", type=int, default=1, help="Attempt index (default: 1).")
    p_appr.add_argument("--workspace", help="Explicit workspace root path.")

    # 6. audit
    p_audit = subparsers.add_parser("audit", help="Run independent Phase 3 9-stage verification suite.")
    p_audit.add_argument("--task", required=True, help="Task identifier.")
    p_audit.add_argument("--attempt", type=int, default=1, help="Attempt index (default: 1).")
    p_audit.add_argument("--workspace", help="Explicit workspace root path.")

    # 7. resume
    p_resume = subparsers.add_parser("resume", help="Resume automation from AWAITING_HUMAN_DISPOSITION.")
    p_resume.add_argument("--task", required=True, help="Task identifier.")
    p_resume.add_argument("--workspace", help="Explicit workspace root path.")

    # 8. reset-attempts
    p_reset = subparsers.add_parser("reset-attempts", help="Monotonically allocate Attempt 4 after circuit breaker.")
    p_reset.add_argument("--task", required=True, help="Task identifier.")
    p_reset.add_argument("--authorized-by", required=True, help="Authorized owner identity.")
    p_reset.add_argument("--yes", "-y", action="store_true", help="Bypass interactive confirmation prompt.")
    p_reset.add_argument("--workspace", help="Explicit workspace root path.")

    # 9. disposition
    p_disp = subparsers.add_parser("disposition", help="Manage defect waivers and risk acceptances.")
    p_disp.add_argument("--task", help="Task identifier.")
    p_disp.add_argument("--action", default="waive", choices=["waive", "revoke", "retry", "resume", "abort", "ACCEPT_AS_INTENTIONAL", "WAIVE_TEMPORARY", "NOT_APPLICABLE"], help="Disposition action (default: waive).")
    p_disp.add_argument("--defect", help="Defect code.")
    p_disp.add_argument("--disposition-id", help="Explicit disposition ID (used for revoke).")
    p_disp.add_argument("--rationale", help="Justification rationale.")
    p_disp.add_argument("--authorized-by", default="", help="Authorized human owner identity (must be granted in OWNER_GRANTS.md).")
    p_disp.add_argument("--attempt", type=int, help="Target attempt index.")
    p_disp.add_argument("--evidence", help="Relative workspace path to supporting waiver evidence file.")
    p_disp.add_argument("--expires-at", help="UTC ISO-8601 expiration timestamp for the waiver.")
    p_disp.add_argument("--role", default="OWNER", help="Authorized human role (default: OWNER).")
    p_disp.add_argument("--yes", "-y", action="store_true", help="Bypass interactive confirmation prompt.")
    p_disp.add_argument("--workspace", help="Explicit workspace root path.")
    disp_subs = p_disp.add_subparsers(dest="disposition_action")
    p_disp_add = disp_subs.add_parser("add", help="Record a defect waiver.")
    p_disp_add.add_argument("--task", required=True, help="Task identifier.")
    p_disp_add.add_argument("--defect", required=True, help="Defect code.")
    p_disp_add.add_argument("--rationale", required=True, help="Justification rationale.")
    p_disp_add.add_argument("--action", default="ACCEPT_AS_INTENTIONAL", choices=["ACCEPT_AS_INTENTIONAL", "WAIVE_TEMPORARY", "NOT_APPLICABLE"], help="Disposition action.")
    p_disp_add.add_argument("--authorized-by", default="", help="Authorized human owner identity.")
    p_disp_add.add_argument("--attempt", type=int, help="Target attempt index.")
    p_disp_add.add_argument("--evidence", help="Relative workspace path to supporting waiver evidence file.")
    p_disp_add.add_argument("--expires-at", help="UTC ISO-8601 expiration timestamp for the waiver.")
    p_disp_add.add_argument("--role", default="OWNER", help="Authorized human role (default: OWNER).")
    p_disp_add.add_argument("--yes", "-y", action="store_true", help="Bypass interactive confirmation prompt.")
    p_disp_add.add_argument("--workspace", help="Explicit workspace root path.")
    p_disp_rev = disp_subs.add_parser("revoke", help="Revoke an active defect waiver.")
    p_disp_rev.add_argument("--task", required=True, help="Task identifier.")
    p_disp_rev.add_argument("--disposition-id", help="Explicit disposition ID to revoke.")
    p_disp_rev.add_argument("--defect", help="Defect code to revoke.")
    p_disp_rev.add_argument("--attempt", type=int, help="Target attempt index.")
    p_disp_rev.add_argument("--authorized-by", required=True, help="Authorized human operator revoking the waiver.")
    p_disp_rev.add_argument("--rationale", required=True, help="Revocation reason.")
    p_disp_rev.add_argument("--yes", "-y", action="store_true", help="Bypass interactive confirmation prompt.")
    p_disp_rev.add_argument("--workspace", help="Explicit workspace root path.")

    # 10. sentinel
    p_sentinel = subparsers.add_parser("sentinel", help="Manage background continuous sentinel daemon.")
    p_sentinel.add_argument("sentinel_action", choices=["start", "stop", "status", "logs"], help="Sentinel action to execute.")
    p_sentinel.add_argument("--daemon", action="store_true", default=True, help="Run as background daemon (default).")
    p_sentinel.add_argument("--foreground", action="store_false", dest="daemon", help="Run in foreground.")
    p_sentinel.add_argument("--workspace", help="Explicit workspace root path.")
    p_sentinel.add_argument("--ready-fd", type=int, default=-1, help=argparse.SUPPRESS)

    # 11. plan (GAP-05, GAP-H4, GAP-L1)
    p_plan = subparsers.add_parser("plan", help="Manage and validate project task roadmap.")
    p_plan.add_argument("plan_action", choices=["validate", "next", "show"], help="Roadmap action.")
    p_plan.add_argument("--activate", action="store_true", help="Activate next eligible task.")
    p_plan.add_argument("--workspace", help="Explicit workspace root path.")

    # 12. unlock (GAP-J2 / Spec M11)
    p_unlock = subparsers.add_parser("unlock", help="Elevate workspace permissions for teardown/cleanup.")
    p_unlock.add_argument("--force", action="store_true", help="Bypass interactive confirmation.")
    p_unlock.add_argument("--abort-active-task", action="store_true", help="Force termination and abortion of active in-progress task.")
    p_unlock.add_argument("--workspace", help="Explicit workspace root path.")

    # 13. seal (SEC-02)
    p_seal = subparsers.add_parser("seal", help="Seal task evidence and generate cryptographic seal.")
    p_seal.add_argument("--task", required=True, help="Task identifier.")
    p_seal.add_argument("--attempt", type=int, default=1, help="Attempt index.")
    p_seal.add_argument("--workspace", help="Explicit workspace root path.")

    # 14. log-quality (GAP-F2)
    p_lq = subparsers.add_parser("log-quality", help="Update workspace code quality ledger.")
    p_lq.add_argument("--task", required=True, help="Task identifier.")
    p_lq.add_argument("--attempt", type=int, default=1, help="Attempt index.")
    p_lq.add_argument("--workspace", help="Explicit workspace root path.")

    # 15. verify-manifest (DEC-008 / FR-08)
    p_vm = subparsers.add_parser("verify-manifest", help="Verify specification integrity against START_MANIFEST.md.")
    p_vm.add_argument("--workspace", help="Explicit workspace root path.")

    # 16. update-manifest (DEC-008 / FR-08)
    p_um = subparsers.add_parser("update-manifest", help="Explicitly update specification digests in START_MANIFEST.md.")
    p_um.add_argument("--workspace", help="Explicit workspace root path.")

    # 17. gate (FR-01 / Spec 01 / DEC-001)
    p_gate = subparsers.add_parser("gate", help="Evaluate and advance formal lifecycle phase gates.")
    gate_subs = p_gate.add_subparsers(dest="gate_action")
    p_gate_check = gate_subs.add_parser("check", help="Inspect gate criteria without mutating state.")
    p_gate_check.add_argument("gate", help="Gate identifier (e.g. Gate-1, Gate-2A, Gate-2B, Gate-3, Gate-4).")
    p_gate_check.add_argument("--task", "--task-id", dest="task", help="Task identifier.")
    p_gate_check.add_argument("--attempt", type=int, help="Attempt index.")
    p_gate_check.add_argument("--workspace", help="Explicit workspace root path.")

    p_gate_adv = gate_subs.add_parser("advance", help="Advance workspace lifecycle phase across gate.")
    p_gate_adv.add_argument("gate", help="Gate identifier (e.g. Gate-1, Gate-2A, Gate-2B, Gate-3, Gate-4).")
    p_gate_adv.add_argument("--task", "--task-id", dest="task", help="Task identifier.")
    p_gate_adv.add_argument("--attempt", type=int, help="Attempt index.")
    p_gate_adv.add_argument("--workspace", help="Explicit workspace root path.")

    # 18. turn (FR-07 / Spec 04 / ARCH-04)
    p_turn = subparsers.add_parser("turn", help="Query active agent turn, phase, and polling contract.")
    p_turn.add_argument("--task", "--task-id", dest="task", help="Task identifier.")
    p_turn.add_argument("--attempt", type=int, help="Attempt index.")
    p_turn.add_argument("--json", action="store_true", dest="json_output", help="Emit machine-readable JSON status payload.")
    p_turn.add_argument("--workspace", help="Explicit workspace root path.")

    # 19. check-rubric (FR-03 / Spec 02 / DEC-026)
    p_cr = subparsers.add_parser("check-rubric", help="Execute automated 270-rule compliance scan.")
    p_cr.add_argument("--task", "--task-id", dest="task", help="Task identifier.")
    p_cr.add_argument("--attempt", type=int, help="Attempt index.")
    p_cr.add_argument("--cycle", type=int, help="Review cycle index.")
    p_cr.add_argument("--domain", help="Restrict evaluation to single domain.")
    p_cr.add_argument("--update-json", action="store_true", help="Write rubric_evaluation.json and update pre_commit_review.json.")
    p_cr.add_argument("--fail-fast", action="store_true", help="Stop on first blocking defect.")
    p_cr.add_argument("--quiet", action="store_true", help="Suppress console report.")
    p_cr.add_argument("--workspace", help="Explicit workspace root path.")

    # 20. supervisor (FR-04 / FR-05 / Spec 03 / ARCH-01)
    p_super = subparsers.add_parser("supervisor", help="Interactive live supervisor, debounce, and watchdog orchestrator.")
    p_super.add_argument("supervisor_action", nargs="?", choices=["check-task", "check-stability", "check-watchdog", "preflight"], help="Optional supervisor sub-action.")
    p_super.add_argument("--watch", action="store_true", help="Run continuous supervisor loop.")
    p_super.add_argument("--once", action="store_true", help="Execute single supervisor step.")
    p_super.add_argument("--task", "--task-id", dest="task", help="Target task identifier.")
    p_super.add_argument("--attempt", type=int, help="Target attempt index.")
    p_super.add_argument("--file", dest="file_path", help="Target file for stability check.")
    p_super.add_argument("--seconds", type=float, default=30.0, help="Quiet seconds for stability check.")
    p_super.add_argument("--ceiling", type=float, default=300.0, help="Hard ceiling seconds for stability check.")
    p_super.add_argument("--timeout", type=float, default=1800.0, help="Watchdog timeout seconds.")
    p_super.add_argument("--json", action="store_true", dest="json_output", help="Emit JSON output.")
    p_super.add_argument("--workspace", help="Explicit workspace root path.")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """Entry point for CLI execution."""
    if argv is None:
        argv = sys.argv[1:]

    parser = build_parser()
    if not argv:
        parser.print_help()
        return 0

    args = parser.parse_args(argv)

    if not args.subcommand:
        parser.print_help()
        return 0

    # Startup auto-recovery of interrupted transactions (FR-10 / DEC-010)
    ws_arg = getattr(args, "workspace", None)
    ws_root = None
    try:
        from stagecheck.core.journal import recover_interrupted_transactions
        from stagecheck.core.paths import WorkspaceRootNotFoundError, find_workspace_root
        ws_root = Path(ws_arg).resolve() if ws_arg else find_workspace_root()
    except WorkspaceRootNotFoundError:
        ws_root = None

    if ws_root is not None:
        try:
            recover_interrupted_transactions(ws_root, verbose=True)
        except Exception as err:
            print(f"ERROR: [journal.recovery_failed] {err}", file=sys.stderr)
            return 1

    if args.subcommand == "init":
        from stagecheck.cli.init_cmd import run_init
        return run_init(
            workspace=getattr(args, "workspace", None),
            repos=getattr(args, "repos", None),
            force=getattr(args, "force", False),
            agent1=getattr(args, "agent1", None),
            agent2=getattr(args, "agent2", None),
            approve_remotes=getattr(args, "approve_remotes", None),
        )

    if args.subcommand == "start":
        from stagecheck.cli.start_cmd import run_start
        from stagecheck.core.paths import WorkspaceRootNotFoundError, find_workspace_root
        ws = getattr(args, "workspace", None)
        if ws:
            return run_start(
                workspace=Path(ws).resolve(),
                task=args.task,
            )
        try:
            ws_root = find_workspace_root()
        except WorkspaceRootNotFoundError:
            print(f"StageCheck v{stagecheck.__version__}: Dispatched subcommand 'start'")
            return 0
        if (ws_root / "controls").is_dir():
            return run_start(
                workspace=ws_root,
                task=args.task,
            )
        print(f"StageCheck v{stagecheck.__version__}: Dispatched subcommand 'start'")
        return 0

    if args.subcommand == "verify-prompt":
        from stagecheck.cli.prompt_cmd import run_verify_prompt
        return run_verify_prompt(
            task=args.task,
            attempt=getattr(args, "attempt", 1),
            workspace=getattr(args, "workspace", None),
        )

    if args.subcommand == "review-precommit":
        from stagecheck.cli.review_cmd import run_review_precommit
        return run_review_precommit(
            task=args.task,
            attempt=getattr(args, "attempt", 1),
            workspace=getattr(args, "workspace", None),
        )

    if args.subcommand == "approve-review":
        from stagecheck.cli.review_cmd import run_approve_review
        return run_approve_review(
            task=args.task,
            attempt=getattr(args, "attempt", 1),
            workspace=getattr(args, "workspace", None),
        )

    if args.subcommand == "audit":
        from stagecheck.cli.audit_cmd import run_audit_cmd
        return run_audit_cmd(
            task=args.task,
            attempt=getattr(args, "attempt", 1),
            workspace=getattr(args, "workspace", None),
        )

    if args.subcommand == "reset-attempts":
        from stagecheck.cli.reset_cmd import run_reset_attempts
        return run_reset_attempts(
            task=args.task,
            authorized_by=args.authorized_by,
            yes=getattr(args, "yes", False),
            workspace=getattr(args, "workspace", None),
        )

    if args.subcommand == "resume":
        from stagecheck.cli.resume_cmd import run_resume
        return run_resume(
            task=args.task,
            workspace=getattr(args, "workspace", None),
        )

    if args.subcommand == "disposition":
        if getattr(args, "disposition_action", None) == "add":
            from stagecheck.cli.disposition_cmd import run_disposition_add
            return run_disposition_add(
                task=args.task,
                defect=args.defect,
                rationale=args.rationale,
                action=getattr(args, "action", "ACCEPT_AS_INTENTIONAL"),
                authorized_by=getattr(args, "authorized_by", ""),
                yes=getattr(args, "yes", False),
                workspace=getattr(args, "workspace", None),
                attempt=getattr(args, "attempt", None),
                evidence=getattr(args, "evidence", None),
                expires_at=getattr(args, "expires_at", None),
                role=getattr(args, "role", "OWNER"),
            )
        elif getattr(args, "disposition_action", None) == "revoke":
            from stagecheck.cli.disposition_cmd import run_disposition_revoke
            return run_disposition_revoke(
                task=args.task,
                revoked_by=args.authorized_by,
                reason=args.rationale,
                disposition_id=getattr(args, "disposition_id", None),
                defect=getattr(args, "defect", None),
                attempt=getattr(args, "attempt", None),
                yes=getattr(args, "yes", False),
                workspace=getattr(args, "workspace", None),
            )
        elif getattr(args, "task", None):
            from stagecheck.cli.disposition_cmd import run_disposition
            return run_disposition(
                task=args.task,
                action=getattr(args, "action", "waive"),
                defect=getattr(args, "defect", None),
                rationale=getattr(args, "rationale", None),
                authorized_by=getattr(args, "authorized_by", ""),
                yes=getattr(args, "yes", False),
                workspace=getattr(args, "workspace", None),
                attempt=getattr(args, "attempt", None),
                evidence=getattr(args, "evidence", None),
                expires_at=getattr(args, "expires_at", None),
                role=getattr(args, "role", "OWNER"),
                disposition_id=getattr(args, "disposition_id", None),
            )
        print("Usage: stagecheck disposition [--task <ID> --action <waive|retry|resume|abort> ...] or disposition add ...", file=sys.stderr)
        return 1

    if args.subcommand == "sentinel":
        from stagecheck.cli.sentinel_cmd import run_sentinel
        ready_fd = args.ready_fd if getattr(args, "ready_fd", -1) >= 0 else None
        return run_sentinel(
            action=args.sentinel_action,
            daemon=getattr(args, "daemon", True),
            workspace=getattr(args, "workspace", None),
            ready_fd=ready_fd,
        )

    if args.subcommand == "plan":
        from stagecheck.cli.plan_cmd import run_plan
        return run_plan(
            action=args.plan_action,
            workspace=getattr(args, "workspace", None),
            activate=getattr(args, "activate", False),
        )

    if args.subcommand == "unlock":
        from stagecheck.cli.ops_cmd import run_unlock
        return run_unlock(
            workspace=getattr(args, "workspace", None),
            force=getattr(args, "force", False),
            abort_active=getattr(args, "abort_active_task", False),
        )

    if args.subcommand == "seal":
        from stagecheck.cli.ops_cmd import run_seal
        return run_seal(
            task_id=args.task,
            attempt=getattr(args, "attempt", 1),
            workspace=getattr(args, "workspace", None),
        )

    if args.subcommand == "log-quality":
        from stagecheck.cli.ops_cmd import run_log_quality
        return run_log_quality(
            task_id=args.task,
            attempt=getattr(args, "attempt", 1),
            workspace=getattr(args, "workspace", None),
        )

    if args.subcommand == "verify-manifest":
        from stagecheck.cli.manifest_cmd import run_verify_manifest
        return run_verify_manifest(
            workspace=getattr(args, "workspace", None),
        )

    if args.subcommand == "update-manifest":
        from stagecheck.cli.manifest_cmd import run_update_manifest
        return run_update_manifest(
            workspace=getattr(args, "workspace", None),
        )

    if args.subcommand == "gate":
        from stagecheck.cli.gate_cmd import run_gate_advance, run_gate_check
        if args.gate_action == "check":
            return run_gate_check(
                gate=args.gate,
                task=getattr(args, "task", None),
                attempt=getattr(args, "attempt", None),
                workspace=getattr(args, "workspace", None),
            )
        elif args.gate_action == "advance":
            return run_gate_advance(
                gate=args.gate,
                task=getattr(args, "task", None),
                attempt=getattr(args, "attempt", None),
                workspace=getattr(args, "workspace", None),
            )
        else:
            p_gate.print_help()
            return 1

    if args.subcommand == "turn":
        from stagecheck.cli.turn_cmd import run_turn
        return run_turn(
            task=getattr(args, "task", None),
            attempt=getattr(args, "attempt", None),
            json_output=getattr(args, "json_output", False),
            workspace=getattr(args, "workspace", None),
        )

    if args.subcommand == "check-rubric":
        from stagecheck.cli.rubric_cmd import run_check_rubric
        return run_check_rubric(
            task=getattr(args, "task", None),
            attempt=getattr(args, "attempt", None),
            cycle=getattr(args, "cycle", None),
            domain=getattr(args, "domain", None),
            update_json=getattr(args, "update_json", False),
            fail_fast=getattr(args, "fail_fast", False),
            quiet=getattr(args, "quiet", False),
            workspace=getattr(args, "workspace", None),
        )

    if args.subcommand == "supervisor":
        from stagecheck.cli.supervisor_cmd import run_supervisor_cmd
        return run_supervisor_cmd(
            action=getattr(args, "supervisor_action", None),
            task=getattr(args, "task", None),
            attempt=getattr(args, "attempt", None),
            workspace=getattr(args, "workspace", None),
            watch=getattr(args, "watch", False),
            once=getattr(args, "once", False),
            file_path=getattr(args, "file_path", None),
            seconds=getattr(args, "seconds", 30.0),
            ceiling=getattr(args, "ceiling", 300.0),
            timeout=getattr(args, "timeout", 1800.0),
            output_json=getattr(args, "json_output", False),
        )

    # In Phase 2, subcommands acknowledge dispatch; full execution wired in Phase 3-4
    print(f"StageCheck v{stagecheck.__version__}: Dispatched subcommand '{args.subcommand}'")
    return 0


if __name__ == "__main__":
    sys.exit(main())

