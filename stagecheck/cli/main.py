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

    # 7. resume
    p_resume = subparsers.add_parser("resume", help="Resume automation from AWAITING_HUMAN_DISPOSITION.")
    p_resume.add_argument("--task", required=True, help="Task identifier.")

    # 8. reset-attempts
    p_reset = subparsers.add_parser("reset-attempts", help="Monotonically allocate Attempt 4 after circuit breaker.")
    p_reset.add_argument("--task", required=True, help="Task identifier.")
    p_reset.add_argument("--authorized-by", required=True, help="Authorized owner identity.")

    # 9. disposition
    p_disp = subparsers.add_parser("disposition", help="Manage defect waivers and risk acceptances.")
    disp_subs = p_disp.add_subparsers(dest="disposition_action")
    p_disp_add = disp_subs.add_parser("add", help="Record a defect waiver.")
    p_disp_add.add_argument("--task", required=True, help="Task identifier.")
    p_disp_add.add_argument("--defect", required=True, help="Defect code.")
    p_disp_add.add_argument("--rationale", required=True, help="Justification rationale.")

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

    # In Phase 2, subcommands acknowledge dispatch; full execution wired in Phase 3-4
    print(f"StageCheck v{stagecheck.__version__}: Dispatched subcommand '{args.subcommand}'")
    return 0


if __name__ == "__main__":
    sys.exit(main())

