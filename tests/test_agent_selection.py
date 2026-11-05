"""Tests for Spec 04 Agent Selection in 'stagecheck init' (Interactive and Non-Interactive)."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from stagecheck.cli.init_cmd import run_init
from stagecheck.cli.main import main
from stagecheck.core.agents import load_registered_agents
from stagecheck.core.agents_md import render_agents_contract
from stagecheck.core.permissions import elevate_permissions_for_teardown
from stagecheck.core.scaffold import scaffold_controls_atomic, ScaffoldingRollbackError
from stagecheck.core.utils import sha256_file
from stagecheck.schemas.validator import validate_active_state, validate_control_descriptor


class TestAgentSelectionSpec04(unittest.TestCase):
    """Verification suite for all 14 Spec 04 agent selection requirements."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp_dir.name).resolve()

        # Create a mock repository under repos/
        self.repo_dir = self.workspace / "repos" / "backend"
        self.repo_dir.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "init", "-b", "main"], cwd=str(self.repo_dir), check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Test Committer"], cwd=str(self.repo_dir), check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "test@stagecheck.local"], cwd=str(self.repo_dir), check=True, capture_output=True)
        readme = self.repo_dir / "README.md"
        readme.write_text("# Backend\n", encoding="utf-8")
        subprocess.run(["git", "add", "README.md"], cwd=str(self.repo_dir), check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=str(self.repo_dir), check=True, capture_output=True)

    def tearDown(self) -> None:
        try:
            elevate_permissions_for_teardown(self.workspace)
        except Exception:
            pass
        self.temp_dir.cleanup()

    # 1. Interactive dual-agent input
    def test_01_interactive_dual_agent_input(self) -> None:
        """Verify interactive prompting when running stagecheck init without flags."""
        stdout_buf = io.StringIO()
        inputs = ["Claude", "Codex"]

        with patch("sys.stdin.isatty", return_value=True), patch("builtins.input", side_effect=inputs), redirect_stdout(stdout_buf):
            ret = run_init(workspace=str(self.workspace), repos="backend")

        self.assertEqual(ret, 0)
        output = stdout_buf.getvalue()
        self.assertIn("STAGECHECK PROGRAMME WORKSPACE SETUP", output)
        self.assertIn("Dual-Agent Mode detected", output)
        self.assertIn("instructions/claude_prompt_and_audit.md", output)
        self.assertIn("instructions/codex_code_implementation.md", output)

        # Instructions exist
        self.assertTrue((self.workspace / "instructions" / "claude_prompt_and_audit.md").is_file())
        self.assertTrue((self.workspace / "instructions" / "codex_code_implementation.md").is_file())

        # Active state configuration
        state_file = self.workspace / "controls" / "ACTIVE_STATE.json"
        state = json.loads(state_file.read_text(encoding="utf-8"))
        self.assertFalse(state["single_agent_mode"])
        self.assertEqual(len(state["registered_agents"]), 2)
        self.assertEqual(state["registered_agents"][0]["name"], "claude")
        self.assertEqual(state["registered_agents"][0]["role"], "prompt_and_audit")
        self.assertEqual(state["registered_agents"][1]["name"], "codex")
        self.assertEqual(state["registered_agents"][1]["role"], "code_implementation")

    # 2. Interactive single-agent input
    def test_02_interactive_single_agent_input(self) -> None:
        """Verify interactive single-agent mode when identical agent names are provided."""
        stdout_buf = io.StringIO()
        inputs = ["Gemini", "Gemini"]

        with patch("sys.stdin.isatty", return_value=True), patch("builtins.input", side_effect=inputs), redirect_stdout(stdout_buf):
            ret = run_init(workspace=str(self.workspace), repos="backend")

        self.assertEqual(ret, 0)
        output = stdout_buf.getvalue()
        self.assertIn("Single-Agent Mode detected", output)
        self.assertIn("instructions/gemini_dual_role.md", output)

        # Single dual-role instruction exists
        self.assertTrue((self.workspace / "instructions" / "gemini_dual_role.md").is_file())
        self.assertFalse((self.workspace / "instructions" / "gemini_prompt_and_audit.md").exists())

        # Active state configuration
        state_file = self.workspace / "controls" / "ACTIVE_STATE.json"
        state = json.loads(state_file.read_text(encoding="utf-8"))
        self.assertTrue(state["single_agent_mode"])
        self.assertEqual(len(state["registered_agents"]), 1)
        self.assertEqual(state["registered_agents"][0]["name"], "gemini")
        self.assertEqual(state["registered_agents"][0]["role"], "dual_role")

    # 3. Case-insensitive identity comparison
    def test_03_case_insensitive_identity_comparison(self) -> None:
        """Verify case-insensitive matching treats 'Claude' and 'claude' as the same agent."""
        stdout_buf = io.StringIO()
        inputs = ["Claude", "claude"]

        with patch("sys.stdin.isatty", return_value=True), patch("builtins.input", side_effect=inputs), redirect_stdout(stdout_buf):
            ret = run_init(workspace=str(self.workspace), repos="backend")

        self.assertEqual(ret, 0)
        output = stdout_buf.getvalue()
        self.assertIn("Single-Agent Mode detected", output)
        self.assertTrue((self.workspace / "instructions" / "claude_dual_role.md").is_file())

        state_file = self.workspace / "controls" / "ACTIVE_STATE.json"
        state = json.loads(state_file.read_text(encoding="utf-8"))
        self.assertTrue(state["single_agent_mode"])
        self.assertEqual(len(state["registered_agents"]), 1)
        self.assertEqual(state["registered_agents"][0]["name"], "claude")

    # 4. CLI flags with both agents
    def test_04_cli_flags_both_agents(self) -> None:
        """Verify non-interactive execution with --agent1 and --agent2 flags."""
        with patch("sys.stdin.isatty", return_value=False):
            ret = main([
                "init",
                "--workspace", str(self.workspace),
                "--repos", "backend",
                "--agent1", "Claude",
                "--agent2", "Codex",
            ])

        self.assertEqual(ret, 0)
        self.assertTrue((self.workspace / "instructions" / "claude_prompt_and_audit.md").is_file())
        self.assertTrue((self.workspace / "instructions" / "codex_code_implementation.md").is_file())

    # 5. Partial flags in interactive mode
    def test_05_partial_flags_in_interactive_mode(self) -> None:
        """Verify that when one flag is given in interactive mode, only the missing agent is prompted."""
        stdout_buf = io.StringIO()
        with patch("sys.stdin.isatty", return_value=True), patch("builtins.input", return_value="Codex") as mock_input, redirect_stdout(stdout_buf):
            ret = main([
                "init",
                "--workspace", str(self.workspace),
                "--repos", "backend",
                "--agent1", "Claude",
            ])

        self.assertEqual(ret, 0)
        # Exactly one prompt call was made (for Agent 2)
        self.assertEqual(mock_input.call_count, 1)
        self.assertTrue((self.workspace / "instructions" / "claude_prompt_and_audit.md").is_file())
        self.assertTrue((self.workspace / "instructions" / "codex_code_implementation.md").is_file())

    # 6. Missing agent arguments in non-interactive mode
    def test_06_missing_agent_arguments_in_non_interactive_mode(self) -> None:
        """Verify non-interactive mode halts with clear error if agents are missing."""
        stderr_buf = io.StringIO()
        with patch("sys.stdin.isatty", return_value=False), redirect_stderr(stderr_buf):
            ret = main([
                "init",
                "--workspace", str(self.workspace),
                "--repos", "backend",
            ])
        self.assertEqual(ret, 1)
        self.assertIn("[init.missing_agent]", stderr_buf.getvalue())
        self.assertIn("both --agent1 and --agent2 flags are required", stderr_buf.getvalue())

        # Partial flag in non-interactive
        stderr_buf2 = io.StringIO()
        with patch("sys.stdin.isatty", return_value=False), redirect_stderr(stderr_buf2):
            ret2 = main([
                "init",
                "--workspace", str(self.workspace),
                "--repos", "backend",
                "--agent1", "Claude",
            ])
        self.assertEqual(ret2, 1)
        self.assertIn("[init.missing_agent]", stderr_buf2.getvalue())

    # 7. Empty and invalid agent names
    def test_07_empty_and_invalid_agent_names(self) -> None:
        """Verify rejection of empty, illegal characters, and invalid slugs with retry."""
        stderr_buf = io.StringIO()
        # Input sequence: empty string -> invalid slug -> valid Claude -> valid Codex
        inputs = ["", "bad/name/unsafe", "ab", "Claude", "Codex"]

        with patch("sys.stdin.isatty", return_value=True), patch("builtins.input", side_effect=inputs), redirect_stderr(stderr_buf):
            ret = run_init(workspace=str(self.workspace), repos="backend")

        self.assertEqual(ret, 0)
        err_out = stderr_buf.getvalue()
        self.assertIn("Agent name cannot be empty", err_out)
        self.assertIn("Invalid agent name 'bad/name/unsafe'", err_out)
        self.assertIn("Invalid agent name 'ab'", err_out)

        # Invalid CLI flag
        stderr_buf_cli = io.StringIO()
        with patch("sys.stdin.isatty", return_value=False), redirect_stderr(stderr_buf_cli):
            ret_cli = main([
                "init",
                "--workspace", str(self.workspace),
                "--repos", "backend",
                "--agent1", "bad:character",
                "--agent2", "Codex",
            ])
        self.assertEqual(ret_cli, 1)
        self.assertIn("[init.invalid_agent]", stderr_buf_cli.getvalue())

    # 8. EOF and Ctrl+C handling
    def test_08_eof_and_ctrl_c_handling(self) -> None:
        """Verify clean exit without stacktrace on EOFError or KeyboardInterrupt."""
        stderr_eof = io.StringIO()
        with patch("sys.stdin.isatty", return_value=True), patch("builtins.input", side_effect=EOFError), redirect_stderr(stderr_eof):
            ret_eof = run_init(workspace=str(self.workspace), repos="backend")
        self.assertEqual(ret_eof, 1)
        self.assertIn("Initialization aborted by user", stderr_eof.getvalue())

        stderr_sig = io.StringIO()
        with patch("sys.stdin.isatty", return_value=True), patch("builtins.input", side_effect=KeyboardInterrupt), redirect_stderr(stderr_sig):
            ret_sig = run_init(workspace=str(self.workspace), repos="backend")
        self.assertEqual(ret_sig, 1)
        self.assertIn("Initialization aborted by user", stderr_sig.getvalue())

    # 9. Correct instruction files for dual-agent mode
    def test_09_correct_instruction_files_dual_agent(self) -> None:
        """Verify role instructions for dual-agent mode include necessary duties and negative prohibitions."""
        ret = run_init(workspace=str(self.workspace), repos="backend", agent1="Claude", agent2="Codex")
        self.assertEqual(ret, 0)

        a1_text = (self.workspace / "instructions" / "claude_prompt_and_audit.md").read_text(encoding="utf-8")
        self.assertIn("Role: `prompt_and_audit`", a1_text)
        self.assertIn("MUST NOT execute mutating Git commands", a1_text)
        self.assertIn("MUST NOT write product code", a1_text)

        a2_text = (self.workspace / "instructions" / "codex_code_implementation.md").read_text(encoding="utf-8")
        self.assertIn("Role: `code_implementation`", a2_text)
        self.assertIn("MUST NOT execute remote push operations", a2_text)
        self.assertIn("MUST NOT commit directly to `main`", a2_text)

    # 10. Correct unified instruction file for single-agent mode
    def test_10_correct_unified_instruction_file_single_agent(self) -> None:
        """Verify single-agent instruction clearly separates planning/auditing from code implementation."""
        ret = run_init(workspace=str(self.workspace), repos="backend", agent1="Gemini", agent2="gemini")
        self.assertEqual(ret, 0)

        single_text = (self.workspace / "instructions" / "gemini_dual_role.md").read_text(encoding="utf-8")
        self.assertIn("Role: `dual_role`", single_text)
        self.assertIn("Part 1: Planning & Auditing Responsibilities", single_text)
        self.assertIn("Part 2: Code Implementation Responsibilities", single_text)
        self.assertIn("NEVER execute remote push commands (`git push`)", single_text)
        self.assertIn("MUST NOT commit directly to `main` or `master` branch", single_text)

    # 11. Correct agent registration in ACTIVE_STATE.json
    def test_11_correct_agent_registration_active_state(self) -> None:
        """Verify ACTIVE_STATE schema validation and load_registered_agents for both modes."""
        # Dual agent
        run_init(workspace=str(self.workspace), repos="backend", agent1="Claude", agent2="Codex")
        state_file = self.workspace / "controls" / "ACTIVE_STATE.json"
        state_data = json.loads(state_file.read_text(encoding="utf-8"))
        validate_active_state(state_data)
        registered = load_registered_agents(state_data)
        self.assertEqual(len(registered), 2)

        # Single agent with force
        run_init(workspace=str(self.workspace), repos="backend", force=True, agent1="Claude", agent2="claude")
        elevate_permissions_for_teardown(self.workspace)
        state_data_single = json.loads(state_file.read_text(encoding="utf-8"))
        validate_active_state(state_data_single)
        registered_single = load_registered_agents(state_data_single)
        self.assertEqual(len(registered_single), 1)
        self.assertEqual(registered_single[0].role.value, "dual_role")

    # 12. Preservation of existing security and governance restrictions
    def test_12_preservation_of_existing_security_and_governance(self) -> None:
        """Verify directory and file POSIX modes, lock lifecycle, and AGENTS.md contract rendering."""
        ret = run_init(workspace=str(self.workspace), repos="backend", agent1="Claude", agent2="Codex")
        self.assertEqual(ret, 0)

        controls_dir = self.workspace / "controls"
        self.assertEqual(oct(controls_dir.stat().st_mode)[-3:], "555")
        self.assertEqual(oct((controls_dir / "ACTIVE_STATE.json").stat().st_mode)[-3:], "444")
        self.assertFalse((self.workspace / ".stagecheck-init.lock").exists())
        self.assertTrue((controls_dir / ".stagecheck.lock").is_file())

    # 13. Readable JSON output without breaking hash verification
    def test_13_readable_json_output_without_breaking_hash_verification(self) -> None:
        """Verify human-readable JSON indentation on control files and canonical hash verification."""
        ret = run_init(workspace=str(self.workspace), repos="backend", agent1="Claude", agent2="Codex")
        self.assertEqual(ret, 0)

        elevate_permissions_for_teardown(self.workspace)
        plan_content = (self.workspace / "specs" / "TASK_PLAN.json").read_text(encoding="utf-8")
        self.assertIn('\n  "schema_version": 1,', plan_content)

        state_content = (self.workspace / "controls" / "ACTIVE_STATE.json").read_text(encoding="utf-8")
        self.assertIn('\n  "schema_version": "2.0",', state_content)

        # AGENTS.md integrity hashes must accurately match file hashes
        controls_dir = self.workspace / "controls"
        rendered_contract = render_agents_contract(controls_dir)
        actual_state_sha = sha256_file(controls_dir / "ACTIVE_STATE.json")
        self.assertIn(actual_state_sha, rendered_contract)

    # 14. Atomic rollback if initialization fails
    def test_14_atomic_rollback_if_initialization_fails(self) -> None:
        """Verify clean rollback with no partial files if fault occurs during scaffolding."""
        def faulty_scaffold(*args, **kwargs):
            raise ScaffoldingRollbackError("Simulated failure during scaffolding")

        with patch("stagecheck.cli.init_cmd.scaffold_controls_atomic", side_effect=faulty_scaffold):
            ret = run_init(workspace=str(self.workspace), repos="backend", agent1="Claude", agent2="Codex")

        self.assertEqual(ret, 1)
        self.assertFalse((self.workspace / "controls").exists())
        self.assertFalse((self.workspace / "instructions").exists())
        self.assertFalse((self.workspace / "specs").exists())


if __name__ == "__main__":
    unittest.main()

