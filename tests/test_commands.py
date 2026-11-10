"""Unit and Integration Tests for Tokenized Command Registry & Secure Runner (P3-T4)."""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from stagecheck.core.commands import (
    CommandSecurityError,
    CommandTimeoutError,
    ForbiddenCommandFlagError,
    InvalidPackageJsonError,
    MissingNpmTestScriptError,
    TreeMutationError,
    build_sanitized_environment,
    execute_secure_command,
    resolve_runner_category,
    validate_command_security,
    validate_npm_package_json,
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
            ["npm", "test", "--ignore-scripts", "--", "-t", "AuthTest"],
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
        timeout_script = self.workspace / "hang.py"
        timeout_script.write_text("import time; time.sleep(5)\n", encoding="utf-8")
        cmd = ["python3", str(timeout_script)]
        with self.assertRaises(CommandTimeoutError) as ctx:
            execute_secure_command(
                argv=cmd,
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

    def test_npm_package_and_flag_security(self) -> None:
        """Verify NPM execution policy, hook suppression, script allowlist, and package.json validation (DEC-014 / SR-01)."""
        node_dir = self.workspace / "node-app"
        node_dir.mkdir(parents=True, exist_ok=True)

        # 1. npm test without --ignore-scripts is rejected immediately (exit 126)
        with self.assertRaises(ForbiddenCommandFlagError) as ctx:
            validate_command_security(["npm", "test"])
        self.assertEqual(ctx.exception.exit_code, 126)
        self.assertIn("NPM_LIFECYCLE_SCRIPTS", str(ctx.exception))

        # 2. npm run without --ignore-scripts is rejected (exit 126)
        with self.assertRaises(ForbiddenCommandFlagError) as ctx:
            validate_command_security(["npm", "run", "test:unit"])
        self.assertEqual(ctx.exception.exit_code, 126)

        # 3. npm run with unauthorized target (e.g. build, start) is rejected (exit 126)
        with self.assertRaises(ForbiddenCommandFlagError) as ctx:
            validate_command_security(["npm", "run", "build", "--ignore-scripts"])
        self.assertEqual(ctx.exception.exit_code, 126)
        self.assertIn("UNAUTHORIZED_NPM_SCRIPT", str(ctx.exception))

        # 4. npm run missing script target is rejected (exit 126)
        with self.assertRaises(ForbiddenCommandFlagError) as ctx:
            validate_command_security(["npm", "run", "--ignore-scripts"])
        self.assertEqual(ctx.exception.exit_code, 126)

        # 5. npm run with extra positional arguments is rejected (exit 126)
        with self.assertRaises(ForbiddenCommandFlagError) as ctx:
            validate_command_security(["npm", "run", "test:unit", "extra_script", "--ignore-scripts"])
        self.assertEqual(ctx.exception.exit_code, 126)
        self.assertIn("EXTRA_POSITIONAL_ARGS", str(ctx.exception))

        # 6. package.json missing in cwd raises InvalidPackageJsonError (exit 126)
        with self.assertRaises(InvalidPackageJsonError) as ctx:
            validate_command_security(["npm", "test", "--ignore-scripts"], cwd=node_dir)
        self.assertEqual(ctx.exception.exit_code, 126)
        self.assertIn("PACKAGE_JSON_MISSING", str(ctx.exception))

        # 7. package.json malformed raises InvalidPackageJsonError (exit 126)
        pkg_file = node_dir / "package.json"
        pkg_file.write_text("{malformed json", encoding="utf-8")
        with self.assertRaises(InvalidPackageJsonError) as ctx:
            validate_command_security(["npm", "test", "--ignore-scripts"], cwd=node_dir)
        self.assertEqual(ctx.exception.exit_code, 126)
        self.assertIn("PACKAGE_JSON_MALFORMED", str(ctx.exception))

        # 8. package.json missing required "test" script raises MissingNpmTestScriptError (exit 126)
        pkg_file.write_text('{"scripts": {"build": "webpack"}}', encoding="utf-8")
        with self.assertRaises(MissingNpmTestScriptError) as ctx:
            validate_command_security(["npm", "test", "--ignore-scripts"], cwd=node_dir)
        self.assertEqual(ctx.exception.exit_code, 126)
        self.assertIn("MISSING_TEST_SCRIPT", str(ctx.exception))

        # 9. package.json has test but lacks requested target raises MissingNpmTestScriptError (exit 126)
        pkg_file.write_text('{"scripts": {"test": "mocha"}}', encoding="utf-8")
        with self.assertRaises(MissingNpmTestScriptError) as ctx:
            validate_command_security(["npm", "run", "test:coverage", "--ignore-scripts"], cwd=node_dir)
        self.assertEqual(ctx.exception.exit_code, 126)
        self.assertIn("SCRIPT_NOT_FOUND", str(ctx.exception))

        # 10. Valid package.json with test and target passes validation
        pkg_file.write_text('{"scripts": {"test": "mocha", "test:unit": "mocha tests/unit"}}', encoding="utf-8")
        validate_command_security(["npm", "test", "--ignore-scripts"], cwd=node_dir)
        validate_command_security(["npm", "run", "test:unit", "--ignore-scripts"], cwd=node_dir)

    def test_unauthorized_runners_blocked(self) -> None:
        """Verify unvetted binaries (bash, sh, curl, socat) raise code 126."""
        blocked_runners = [
            ["bash", "-c", "echo test"],
            ["sh", "script.sh"],
            ["curl", "https://example.com"],
            ["socat", "-", "-"],
            ["ruby", "test.rb"],
        ]
        for cmd in blocked_runners:
            with self.subTest(cmd=cmd):
                with self.assertRaises(ForbiddenCommandFlagError) as ctx:
                    validate_command_security(cmd)
                self.assertEqual(ctx.exception.exit_code, 126)
                self.assertIn("UNAUTHORIZED_RUNNER", str(ctx.exception))

    def test_npx_security_policies(self) -> None:
        """Verify npx requires --no-install and restricts subcommands."""
        # npx without --no-install is rejected
        with self.assertRaises(ForbiddenCommandFlagError) as ctx:
            validate_command_security(["npx", "test"])
        self.assertEqual(ctx.exception.exit_code, 126)
        self.assertIn("NPX_REMOTE_INSTALL", str(ctx.exception))

        # npx with unapproved subcommand is rejected
        with self.assertRaises(ForbiddenCommandFlagError) as ctx:
            validate_command_security(["npx", "--no-install", "express-generator"])
        self.assertEqual(ctx.exception.exit_code, 126)
        self.assertIn("UNAUTHORIZED_SUBCOMMAND", str(ctx.exception))

        # npx with approved subcommand passes
        validate_command_security(["npx", "--no-install", "test"])

    def test_python_module_restrictions(self) -> None:
        """Verify python module allowlist blocks pip, venv, http.server, etc."""
        forbidden_modules = ["pip", "ensurepip", "http.server", "venv", "site", "pydoc"]
        for mod in forbidden_modules:
            with self.subTest(module=mod):
                with self.assertRaises(ForbiddenCommandFlagError) as ctx:
                    validate_command_security(["python3", "-m", mod])
                self.assertEqual(ctx.exception.exit_code, 126)
                self.assertIn("FORBIDDEN_MODULE", str(ctx.exception))

        # Allowed python module unittest passes
        validate_command_security(["python3", "-m", "unittest", "discover"])

    def test_runner_category_resolution(self) -> None:
        """Verify versioned runner resolution for python and pytest."""
        self.assertEqual(resolve_runner_category("python"), "python")
        self.assertEqual(resolve_runner_category("python3"), "python")
        self.assertEqual(resolve_runner_category("python3.11"), "python")
        self.assertEqual(resolve_runner_category("python3.12"), "python")
        self.assertEqual(resolve_runner_category("pytest"), "pytest")
        self.assertEqual(resolve_runner_category("pytest-3"), "pytest")
        self.assertEqual(resolve_runner_category("go"), "go")
        self.assertEqual(resolve_runner_category("npm"), "npm")
        self.assertEqual(resolve_runner_category("cargo"), "cargo")
        self.assertIsNone(resolve_runner_category("bash"))
        self.assertIsNone(resolve_runner_category("python2"))

    def test_attached_bundled_and_negated_flag_bypasses_blocked(self) -> None:
        """Verify attached/bundled short options, attached -m, and negated flags are rejected (SC-SEC-08)."""
        bypass_cmds = [
            ["python3", "-cprint(123)"],
            ["python3", "-Icprint(123)"],
            ["python3", "-mhttp.server"],
            ["python3", "-Impip", "list"],
            ["pytest", "-c/tmp/evil.ini"],
            ["pytest", "-vc/tmp/evil.ini"],
            ["pytest", "-ojunit_family=xunit2"],
            ["pytest", "-peval"],
            ["go", "test", "--exec=/bin/sh", "./..."],
            ["npm", "test", "--ignore-scripts", "--ignore-scripts=false"],
            ["npm", "test", "--ignore-scripts", "--no-ignore-scripts"],
            ["npm", "test", "--ignore-scripts", "--foreground-scripts"],
            ["npx", "pytest", "--no-install", "--no-install=false"],
            ["npx", "pytest", "--no-install", "--yes"],
            ["npx", "pytest", "--no-install", "-vy"],
        ]
        for cmd in bypass_cmds:
            with self.subTest(cmd=cmd):
                with self.assertRaises(ForbiddenCommandFlagError) as ctx:
                    validate_command_security(cmd)
                self.assertEqual(ctx.exception.exit_code, 126)

        # Legitimate value-taking short flags & post-script args must still pass without false positives
        legit_cmds = [
            ["python3", "-Wonce", "-m", "unittest", "discover"],
            ["pytest", "-ktest_copy", "tests/"],
            ["python3", "tests/runner.py", "-c", "app_config_arg"],
            ["npm", "test", "--ignore-scripts", "--", "-t", "AuthTest"],
        ]
        for cmd in legit_cmds:
            with self.subTest(legit_cmd=cmd):
                validate_command_security(cmd)

    def test_untrusted_binary_path_rejected_in_execute_secure_command(self) -> None:
        """Verify executing binaries located inside working directory or repos/ fails closed (SEC-B3 / SC-SEC-06)."""
        evil_bin = self.repo_dir / "python3"
        evil_bin.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        evil_bin.chmod(0o755)

        # Prepend repo_dir to PATH so shutil.which would find evil_bin
        dirty_env = {"PATH": f"{self.repo_dir}:{os.environ.get('PATH', '')}"}
        with self.assertRaises(ForbiddenCommandFlagError) as ctx:
            execute_secure_command(
                argv=["python3", "-m", "unittest"],
                working_directory=self.repo_dir,
                extra_env=dirty_env,
                check_tree_integrity=False,
            )
        self.assertEqual(ctx.exception.exit_code, 126)
        self.assertIn("UNTRUSTED_BINARY_PATH", str(ctx.exception))

    def test_git_environment_variables_purged(self) -> None:
        """Verify git environment controls (GIT_CONFIG, GIT_DIR, GIT_WORK_TREE) are purged."""
        for var in ("GIT_CONFIG", "GIT_CONFIG_GLOBAL", "GIT_DIR", "GIT_WORK_TREE", "GIT_ASKPASS"):
            os.environ[var] = "/etc/malicious"
        try:
            clean = build_sanitized_environment({"SAFE_FLAG": "1"})
            for var in ("GIT_CONFIG", "GIT_CONFIG_GLOBAL", "GIT_DIR", "GIT_WORK_TREE", "GIT_ASKPASS"):
                self.assertNotIn(var, clean)
        finally:
            for var in ("GIT_CONFIG", "GIT_CONFIG_GLOBAL", "GIT_DIR", "GIT_WORK_TREE", "GIT_ASKPASS"):
                os.environ.pop(var, None)

    def test_disallowed_runner_flags_comprehensive(self) -> None:
        """Verify --override-ini, -exec, --config, and --prefix are blocked across toolchains."""
        disallowed = [
            ["pytest", "-o", "python_files=evil*.py"],
            ["pytest", "--override-ini", "python_files=evil*.py"],
            ["go", "test", "-exec", "/bin/sh", "./..."],
            ["cargo", "test", "--config", "build.rustc-wrapper='evil'"],
            ["npx", "--no-install", "test", "--prefix", "/evil"],
        ]
        for cmd in disallowed:
            with self.subTest(cmd=cmd):
                with self.assertRaises(ForbiddenCommandFlagError) as ctx:
                    validate_command_security(cmd)
                self.assertEqual(ctx.exception.exit_code, 126)


if __name__ == "__main__":
    unittest.main()

