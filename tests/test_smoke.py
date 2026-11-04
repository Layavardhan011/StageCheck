"""Package Skeleton & Smoke Tests (P1-T5)."""

from __future__ import annotations

import io
import unittest
from contextlib import redirect_stdout

import stagecheck
from stagecheck.cli.main import build_parser, main
from stagecheck.config import get_config_path
from stagecheck.schemas import get_schema_path


class TestSmoke(unittest.TestCase):
    """Smoke tests verifying package structure, importability, CLI, and asset resolution."""

    def test_package_metadata(self) -> None:
        """Verify package version and exports."""
        self.assertEqual(stagecheck.__version__, "1.0.0")

    def test_cli_parser_subcommands(self) -> None:
        """Verify CLI parser has all 9 lifecycle subcommands registered."""
        parser = build_parser()
        expected_commands = {
            "init",
            "start",
            "verify-prompt",
            "review-precommit",
            "approve-review",
            "audit",
            "resume",
            "reset-attempts",
            "disposition",
        }
        # inspect subparsers
        subparsers_action = next(
            action for action in parser._actions if action.dest == "subcommand"
        )
        self.assertTrue(expected_commands.issubset(set(subparsers_action.choices.keys())))

    def test_cli_execution_smoke(self) -> None:
        """Verify running main() with subcommands."""
        buf = io.StringIO()
        with redirect_stdout(buf):
            ret = main(["start", "--task", "task-101"])
        self.assertEqual(ret, 0)
        self.assertIn("Dispatched subcommand 'start'", buf.getvalue())

    def test_embedded_schema_assets(self) -> None:
        """Verify schema asset discovery."""
        verdict_schema = get_schema_path("verdict.schema.json")
        self.assertTrue(verdict_schema.is_file())

        claims_schema = get_schema_path("claims.schema.json")
        self.assertTrue(claims_schema.is_file())

    def test_embedded_config_assets(self) -> None:
        """Verify configuration asset discovery."""
        commands_config = get_config_path("commands.json")
        self.assertTrue(commands_config.is_file())

        targets_config = get_config_path("quality_targets.json")
        self.assertTrue(targets_config.is_file())


if __name__ == "__main__":
    unittest.main()

