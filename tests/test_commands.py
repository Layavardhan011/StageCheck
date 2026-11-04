"""Unit and Integration Tests for Tokenized Command Registry & Secure Runner (P3-T4)."""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from stagecheck.core.commands import (
    CommandTimeoutError,
    ForbiddenCommandFlagError,
    TreeMutationError,
    build_sanitized_environment,
    execute_secure_command,
    validate_command_security,
)


class TestSecureCommandRunner(unittest.TestCase):
    """Test suite covering flag validation, environment sanitization, timeouts, logs, and tree integrity."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp_dir.name).resolve()

        # Set up a mock git repository to test tree mutation checks
        self.repo_dir = self.workspace / "test-repo"
        self.repo_dir.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "init", "-b", "main"], cwd=str(self.repo_dir), check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Test User"], cwd=str(self.repo_dir), check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "test@stagecheck.local"], cwd=str(self.repo_dir), check=True, capture_output=True)
        readme = self.repo_dir / "README.md"
        readme.write_text("# Test Repo\n", encoding="utf-8")
        subprocess.run(["git", "add", "README.md"], cwd=str(self.repo_dir), check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=str(self.repo_dir), check=True, capture_output=True)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_forbidden_command_flags_rejected_with_126(self) -> None:
        """Verify injection and execution-redirection flags raise ForbiddenCommandFlagError with code 126."""
        prohibited_commands = [
            ["python3", "-c", "import os; os.system('echo pwned')"],
            ["python", "-c", "print('injection')"],
            ["go", "test", "-exec", "malicious_runner", "./..."],
            ["pytest", "-o", "override=value", "tests/"],
            ["pytest", "-p", "malicious_plugin", "tests/"],
            ["npm", "test", "--node-options=--require=evil.js"],
            ["cargo", "test", "--runner", "custom_binary"],
        ]
        for cmd in prohibited_commands:
            with self.subTest(cmd=cmd):
                with self.assertRaises(ForbiddenCommandFlagError) as ctx:
                    validate_command_security(cmd)
                self.assertEqual(ctx.exception.exit_code, 126)

    def test_allowed_command_flags_pass_validation(self) -> None:
        """Verify standard permitted test commands pass validation."""
        allowed_commands = [
            ["python3", "-m", "unittest", "discover"],
            ["pytest", "-v", "-k", "test_math", "tests/"],
            ["go", "test", "-v", "-run", "TestOrder", "./..."],
            ["npm", "test", "--", "-t", "AuthTest"],
            ["cargo", "test", "--package", "core", "--lib"],
        ]
        for cmd in allowed_commands:
            with self.subTest(cmd=cmd):
                # Should not raise
                validate_command_security(cmd)

    def test_environment_credential_sanitization(self) -> None:
        """Verify all tokens, keys, secrets, and cloud credentials are stripped."""
        # Inject sensitive test variables into os.environ
        os.environ["AWS_SECRET_ACCESS_KEY"] = "super-secret-aws-key"
        os.environ["GITHUB_TOKEN"] = "ghp_1234567890"
        os.environ["SSH_AUTH_SOCK"] = "/tmp/ssh.sock"
        os.environ["DATABASE_PASSWORD"] = "dbpass"
        os.environ["GITLEAKS_CONFIG"] = "/path/to/custom"

        try:
            clean = build_sanitized_environment({"SAFE_VAR": "safe_value"})

            # Must NOT contain any secrets
            self.assertNotIn("AWS_SECRET_ACCESS_KEY", clean)
            self.assertNotIn("GITHUB_TOKEN", clean)
            self.assertNotIn("SSH_AUTH_SOCK", clean)
            self.assertNotIn("DATABASE_PASSWORD", clean)
            self.assertNotIn("GITLEAKS_CONFIG", clean)

            # Must contain safe variables
            self.assertEqual(clean.get("SAFE_VAR"), "safe_value")
            self.assertEqual(clean.get("PYTHONDONTWRITEBYTECODE"), "1")
            self.assertIn("PATH", clean)
        finally:
            os.environ.pop("AWS_SECRET_ACCESS_KEY", None)
            os.environ.pop("GITHUB_TOKEN", None)
            os.environ.pop("SSH_AUTH_SOCK", None)
            os.environ.pop("DATABASE_PASSWORD", None)
            os.environ.pop("GITLEAKS_CONFIG", None)

    def test_command_execution_timeout_raises_124(self) -> None:
        """Verify command execution timing out raises CommandTimeoutError with code 124."""
        # Run a command that sleeps for 3 seconds with a 1-second timeout
        cmd = ["python3", "-c", "import time; time.sleep(3)"]
        # Note: python3 -c is blocked by validate_command_security, so test with sleep via shell-free command
        sleep_cmd = ["sleep", "2"]
        with self.assertRaises(CommandTimeoutError) as ctx:
            execute_secure_command(
                argv=sleep_cmd,
                working_directory=self.repo_dir,
                timeout_seconds=1,
                check_tree_integrity=False,
            )
        self.assertEqual(ctx.exception.exit_code, 124)

    def test_command_execution_logging_and_digests(self) -> None:
        """Verify stdout.log, stderr.log, and SHA-256 digests are recorded."""
        log_dir = self.workspace / "logs"
        cmd = ["python3", "-m", "unittest", "--help"]

        record = execute_secure_command(
            argv=cmd,
            working_directory=self.repo_dir,
            timeout_seconds=10,
            log_dir=log_dir,
            check_tree_integrity=True,
        )

        self.assertEqual(record.exit_code, 0)
        self.assertIn("usage", record.stdout.lower())
        self.assertEqual(len(record.stdout_sha256), 64)
        self.assertEqual(len(record.stderr_sha256), 64)
        self.assertFalse(record.tree_mutated)

        # Check logs on disk
        self.assertTrue((log_dir / "stdout.log").is_file())
        self.assertTrue((log_dir / "stderr.log").is_file())
        self.assertEqual((log_dir / "stdout.log").read_text(encoding="utf-8"), record.stdout)

    def test_tree_mutation_detection_fails_closed(self) -> None:
        """Verify test execution mutating working tree triggers TreeMutationError."""
        # Run a script that creates an untracked file inside repo_dir
        # We write a helper script to avoid forbidden flags
        helper_script = self.workspace / "mutate.py"
        helper_script.write_text(
            f"with open('{self.repo_dir}/leak.txt', 'w') as f: f.write('dirty')\n",
            encoding="utf-8",
        )

        cmd = ["python3", str(helper_script)]
        with self.assertRaises(TreeMutationError):
            execute_secure_command(
                argv=cmd,
                working_directory=self.repo_dir,
                timeout_seconds=10,
                check_tree_integrity=True,
            )


if __name__ == "__main__":
    unittest.main()

