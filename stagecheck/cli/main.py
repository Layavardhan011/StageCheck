"""StageCheck Unified Command-Line Interface Dispatcher.

Dispatches subcommands to modular command handlers while providing backward
compatibility with legacy invocations.
"""

from __future__ import annotations

import argparse
import sys
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

    # 2. start
    p_start = subparsers.add_parser("start", help="Activate a new task under exclusive lock.")
    p_start.add_argument("--task", required=True, help="Task identifier (e.g. task-101).")

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
    p_reset.add_argument("--workspace", help="Explicit workspace root path.")

    # 9. disposition
    p_disp = subparsers.add_parser("disposition", help="Manage defect waivers and risk acceptances.")
    disp_subs = p_disp.add_subparsers(dest="disposition_action")
    p_disp_add = disp_subs.add_parser("add", help="Record a defect waiver.")
    p_disp_add.add_argument("--task", required=True, help="Task identifier.")
    p_disp_add.add_argument("--defect", required=True, help="Defect code.")
    p_disp_add.add_argument("--rationale", required=True, help="Justification rationale.")
    p_disp_add.add_argument("--action", default="ACCEPT_AS_INTENTIONAL", choices=["ACCEPT_AS_INTENTIONAL", "WAIVE_TEMPORARY", "NOT_APPLICABLE"], help="Disposition action.")
    p_disp_add.add_argument("--authorized-by", default="human-operator", help="Authorized owner identity.")
    p_disp_add.add_argument("--yes", "-y", action="store_true", help="Bypass interactive confirmation prompt.")
    p_disp_add.add_argument("--workspace", help="Explicit workspace root path.")

    # 10. sentinel
    p_sentinel = subparsers.add_parser("sentinel", help="Manage background continuous sentinel daemon.")
    p_sentinel.add_argument("sentinel_action", choices=["start", "stop", "status", "logs"], help="Sentinel action to execute.")
    p_sentinel.add_argument("--daemon", action="store_true", default=True, help="Run as background daemon (default).")
    p_sentinel.add_argument("--foreground", action="store_false", dest="daemon", help="Run in foreground.")
    p_sentinel.add_argument("--workspace", help="Explicit workspace root path.")

    # 11. plan (GAP-05, GAP-H4, GAP-L1)
    p_plan = subparsers.add_parser("plan", help="Manage and validate project task roadmap.")
    p_plan.add_argument("plan_action", choices=["validate", "next", "show"], help="Roadmap action.")
    p_plan.add_argument("--activate", action="store_true", help="Activate next eligible task.")
    p_plan.add_argument("--workspace", help="Explicit workspace root path.")

    # 12. unlock (GAP-J2)
    p_unlock = subparsers.add_parser("unlock", help="Elevate workspace permissions for teardown/cleanup.")
    p_unlock.add_argument("--force", action="store_true", help="Bypass interactive confirmation.")
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

    if args.subcommand == "init":
        from stagecheck.cli.init_cmd import run_init
        return run_init(
            workspace=getattr(args, "workspace", None),
            repos=getattr(args, "repos", None),
            force=getattr(args, "force", False),
        )

    if args.subcommand == "start":
        from stagecheck.cli.start_cmd import run_start
        from stagecheck.core.paths import find_workspace_root
        ws = getattr(args, "workspace", None)
        try:
            ws_root = Path(ws).resolve() if ws else find_workspace_root()
            if (ws_root / "controls").is_dir():
                return run_start(
                    workspace=ws_root,
                    task=args.task,
                )
        except Exception:
            pass
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
                authorized_by=getattr(args, "authorized_by", "human-operator"),
                yes=getattr(args, "yes", False),
                workspace=getattr(args, "workspace", None),
            )
        print("Usage: stagecheck disposition add ...", file=sys.stderr)
        return 1

    if args.subcommand == "sentinel":
        from stagecheck.cli.sentinel_cmd import run_sentinel
        return run_sentinel(
            action=args.sentinel_action,
            daemon=getattr(args, "daemon", True),
            workspace=getattr(args, "workspace", None),
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

    # In Phase 2, subcommands acknowledge dispatch; full execution wired in Phase 3-4
    print(f"StageCheck v{stagecheck.__version__}: Dispatched subcommand '{args.subcommand}'")
    return 0


if __name__ == "__main__":
    sys.exit(main())

