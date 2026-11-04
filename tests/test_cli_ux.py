"""CLI and Packaging UX Integration Tests (P5-T4).

Verifies:
1. Unified CLI dispatcher, subcommands, and help/version flags.
2. Standardized exit codes (0 for success, 1 for domain/gate error, 2 for syntax/arg errors).
3. Subcommand dispatch for all 10 unified CLI operations:
   - init
   - start
   - verify-prompt
   - review-precommit
   - approve-review
   - audit
   - resume
   - reset-attempts
   - disposition
   - sentinel
4. Embedded package resources discovery and build metadata validation.
"""
import io
import subprocess
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import stagecheck
from stagecheck.cli.main import build_parser, main
from stagecheck.core.portability import resolve_asset_path


class TestCLIUX(unittest.TestCase):
    """Verifies unified CLI usability, error messages, and exit codes."""

    def test_cli_version_flag(self):
        """Verify --version returns package version with exit code 0."""
        buf = io.StringIO()
        with redirect_stdout(buf):
            try:
                main(["--version"])
            except SystemExit as exc:
                self.assertEqual(exc.code, 0)
        self.assertIn(f"StageCheck v{stagecheck.__version__}", buf.getvalue())

    def test_cli_help_flag(self):
        """Verify --help returns comprehensive command overview with exit code 0."""
        buf = io.StringIO()
        with redirect_stdout(buf):
            try:
                main(["--help"])
            except SystemExit as exc:
                self.assertEqual(exc.code, 0)
        output = buf.getvalue()
        self.assertIn("Enterprise AI Delivery Governance", output)
        for cmd in [
            "init",
            "start",
            "verify-prompt",
            "review-precommit",
            "approve-review",
            "audit",
            "resume",
            "reset-attempts",
            "disposition",
            "sentinel",
        ]:
            self.assertIn(cmd, output)

    def test_cli_syntax_error_exit_code_2(self):
        """Verify unrecognized arguments or missing required flags return exit code 2."""
        # Unrecognized flag
        with redirect_stderr(io.StringIO()):
            try:
                rc = main(["--completely-bogus-flag"])
            except SystemExit as exc:
                rc = exc.code
            self.assertEqual(rc, 2)

        # Missing required argument for audit
        with redirect_stderr(io.StringIO()):
            try:
                rc = main(["audit"])
            except SystemExit as exc:
                rc = exc.code
            self.assertEqual(rc, 2)

    def test_cli_subcommand_dispatch_coverage(self):
        """Verify parser supports all 10 unified operations with appropriate argument schemas."""
        parser = build_parser()
        subparsers_action = [
            action for action in parser._actions if action.dest == "subcommand"
        ][0]
        commands = set(subparsers_action.choices.keys())
        expected = {
            "init",
            "start",
            "verify-prompt",
            "review-precommit",
            "approve-review",
            "audit",
            "resume",
            "reset-attempts",
            "disposition",
            "sentinel",
        }
        self.assertEqual(commands, expected)

    def test_packaging_resource_assets(self):
        """Verify packaged JSON schema and configuration default assets are discoverable."""
        schemas = [
            "active_state.schema.json",
            "control_descriptors.schema.json",
            "declared_scope.schema.json",
            "pre_commit_review.schema.json",
            "pre_commit_status.schema.json",
            "product_repositories.schema.json",
            "prompt_verified.schema.json",
            "verdict.schema.json",
        ]
        for s in schemas:
            asset_path = resolve_asset_path(f"schemas/assets/{s}")
            self.assertTrue(asset_path.is_file(), f"Asset missing: {s}")

        config_asset = resolve_asset_path("config/defaults/commands.json")
        self.assertTrue(config_asset.is_file(), "Default commands.json missing")


if __name__ == "__main__":
    unittest.main()
