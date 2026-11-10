"""Tokenized Command Registry, Runner Policies, and Secure Command Execution (P3-T4).

Enforces runner-specific flag allowlists (SEC-B3), environment credential stripping (SEC-A1),
command timeouts, structured execution logs, and before/after Git working tree integrity.
"""

from __future__ import annotations

import datetime
import json
import os
import re
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from stagecheck.core.git import SAFE_GIT_SECURITY_FLAGS
from stagecheck.core.utils import sha256_digest


class CommandSecurityError(Exception):
    """Base error for command security and execution policy violations."""

    def __init__(self, message: str, exit_code: int = 126) -> None:
        super().__init__(message)
        self.exit_code = exit_code


class ForbiddenCommandFlagError(CommandSecurityError):
    """Raised when an injection or execution-redirection flag is detected (exit code 126)."""


class InvalidPackageJsonError(ForbiddenCommandFlagError):
    """Raised when package.json is missing or malformed during npm test execution (exit code 126)."""


class MissingNpmTestScriptError(ForbiddenCommandFlagError):
    """Raised when package.json lacks a required 'test' script target (exit code 126)."""


class CommandTimeoutError(CommandSecurityError):
    """Raised when command execution exceeds its maximum allocated timeout."""

    def __init__(self, message: str) -> None:
        super().__init__(message, exit_code=124)


class TreeMutationError(CommandSecurityError):
    """Raised when command execution alters the Git working tree or creates untracked files."""

    def __init__(self, message: str) -> None:
        super().__init__(message, exit_code=1)


# Allowlisted environment variables (SEC-A1 & commands.json)
ALLOWLISTED_ENV_VARS = {
    "PATH",
    "LANG",
    "LC_ALL",
    "USER",
    "TERM",
    "PYTHONDONTWRITEBYTECODE",
    "HOME",
    "TMPDIR",
}

# Substring patterns identifying sensitive credentials to purge
SENSITIVE_ENV_SUBSTRINGS = (
    "TOKEN",
    "KEY",
    "SECRET",
    "PASSWORD",
    "AUTH",
    "AWS_",
    "GCP_",
    "GITHUB_",
    "GIT_ASKPASS",
    "SSH_",
    "GITLEAKS_",
)


def build_sanitized_environment(
    extra_env: Optional[Dict[str, str]] = None,
) -> Dict[str, str]:
    """Construct minimal subprocess environment with all secrets and tokens stripped.

    Enforces SEC-A1: Only allowlisted environment variables are inherited from host,
    and any variable with credential keywords is purged.

    Args:
        extra_env: Optional non-sensitive variables to include.

    Returns:
        Sanitized environment dictionary.
    """
    clean: Dict[str, str] = {}

    for var in ALLOWLISTED_ENV_VARS:
        if var in os.environ:
            val = os.environ[var]
            # Extra safety check: ensure the value or name doesn't contain secret indicators
            if not any(sub in var.upper() for sub in SENSITIVE_ENV_SUBSTRINGS):
                clean[var] = val

    # Enforce bytecode suppression
    clean["PYTHONDONTWRITEBYTECODE"] = "1"

    if extra_env:
        for k, v in extra_env.items():
            if not any(sub in k.upper() for sub in SENSITIVE_ENV_SUBSTRINGS):
                clean[k] = v

    return clean


PYTHON_VERSIONED_REGEX = re.compile(r"^python3(?:\.\d+)?$")
PYTEST_VERSIONED_REGEX = re.compile(r"^pytest(?:-\d+(?:\.\d+)?)?$")

AUTHORIZED_RUNNERS: Dict[str, str] = {
    "pytest": "pytest",
    "pytest-3": "pytest",
    "go": "go",
    "python": "python",
    "python3": "python",
    "npm": "npm",
    "yarn": "npm",
    "pnpm": "npm",
    "npx": "npx",
    "cargo": "cargo",
}

AUTHORIZED_SUBCOMMANDS: Dict[str, Set[str]] = {
    "go": {"test"},
    "cargo": {"test"},
    "npm": {"test", "run"},
    "npx": {"test", "pytest"},
}

AUTHORIZED_NPM_RUN_TARGETS: Set[str] = {
    "test",
    "test:unit",
    "test:integration",
    "test:coverage",
    "test:e2e",
}

FORBIDDEN_PYTHON_MODULES: Set[str] = {
    "pip",
    "ensurepip",
    "http",
    "http.server",
    "venv",
    "site",
    "pydoc",
    "idlelib",
}

# Runner-specific security allowlists and prohibited flags (SEC-B3 & Spec 06 & Spec 07)
PROHIBITED_FLAGS: Dict[str, Set[str]] = {
    "go": {"-exec", "-toolexec"},
    "pytest": {"-o", "--override-ini", "-c", "-p"},
    "python": {"-c", "-e"},
    "npm": {"--node-options", "--inspect", "--inspect-brk", "--globalSetup"},
    "npx": {"--node-options", "--inspect", "--inspect-brk", "--globalSetup"},
    "cargo": {"--config", "--runner"},
}

# Short options per runner whose remainder in the same argv token is a value, not bundled flags
_VALUE_TAKING_SHORT_OPTS: Dict[str, Set[str]] = {
    "python": {"m", "W", "X", "Q"},
    "pytest": {"k", "m", "W", "r", "n"},
}

_PROHIBITED_SHORT_FLAGS: Dict[str, Set[str]] = {
    "python": {"c", "e"},
    "pytest": {"c", "o", "p"},
}


def _check_python_args(args: List[str]) -> None:
    """Inspect Python interpreter options before script/module entrypoint."""
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--" or arg == "-" or not arg.startswith("-"):
            # Reached script filename or end-of-options; interpreter flag parsing stops here
            break

        if arg.startswith("--"):
            flag = arg.split("=")[0].strip()
            if flag in PROHIBITED_FLAGS["python"]:
                raise ForbiddenCommandFlagError(
                    f"Security policy violation [FORBIDDEN_FLAG]: Flag '{flag}' is prohibited for runner 'python'.",
                    exit_code=126,
                )
            i += 1
            continue

        # Single-dash short option(s), possibly bundled or with attached value
        chars = arg[1:]
        consumed_next = False
        for idx, ch in enumerate(chars):
            if ch in _PROHIBITED_SHORT_FLAGS["python"]:
                raise ForbiddenCommandFlagError(
                    f"Security policy violation [FORBIDDEN_FLAG]: Flag '-{ch}' is prohibited for runner 'python'.",
                    exit_code=126,
                )
            if ch == "m":
                raw_mod = chars[idx + 1 :]
                if not raw_mod:
                    if i + 1 >= len(args):
                        break
                    raw_mod = args[i + 1]
                    consumed_next = True
                mod_lower = raw_mod.lower()
                root_mod = mod_lower.split(".")[0]
                if mod_lower in FORBIDDEN_PYTHON_MODULES or root_mod in FORBIDDEN_PYTHON_MODULES:
                    raise ForbiddenCommandFlagError(
                        f"Security policy violation [FORBIDDEN_MODULE]: Execution of module '{raw_mod}' is prohibited.",
                        exit_code=126,
                    )
                # -m <module> terminates interpreter option parsing; remainder of argv goes to module
                return
            if ch in _VALUE_TAKING_SHORT_OPTS["python"]:
                if idx + 1 == len(chars):
                    consumed_next = True
                break

        i += 2 if consumed_next else 1


def _check_short_bundle(runner: str, arg: str) -> None:
    """Validate single-dash short options and bundles against _PROHIBITED_SHORT_FLAGS."""
    prohibited_short = _PROHIBITED_SHORT_FLAGS.get(runner)
    if not prohibited_short:
        return
    value_opts = _VALUE_TAKING_SHORT_OPTS.get(runner, set())
    for ch in arg[1:]:
        if ch in prohibited_short:
            raise ForbiddenCommandFlagError(
                f"Security policy violation [FORBIDDEN_FLAG]: Flag '-{ch}' is prohibited for runner '{runner}'.",
                exit_code=126,
            )
        if ch in value_opts:
            # Rest of this token is the option's argument value, not further flags
            break


def resolve_runner_category(binary_name: str) -> Optional[str]:
    """Resolve binary name to authorized runner category, supporting versioned variants."""
    b_lower = binary_name.lower()
    if b_lower in AUTHORIZED_RUNNERS:
        return AUTHORIZED_RUNNERS[b_lower]
    if PYTHON_VERSIONED_REGEX.match(b_lower):
        return "python"
    if PYTEST_VERSIONED_REGEX.match(b_lower):
        return "pytest"
    return None


def validate_npm_package_json(cwd: Path, target_script: str) -> None:
    """Validate package.json existence, JSON format, required 'test' script, and target script."""
    pkg_file = cwd / "package.json"
    if not pkg_file.is_file():
        raise InvalidPackageJsonError(
            f"Security policy violation [PACKAGE_JSON_MISSING]: package.json not found in '{cwd}'.",
            exit_code=126,
        )
    try:
        data = json.loads(pkg_file.read_text(encoding="utf-8"))
    except Exception as err:
        raise InvalidPackageJsonError(
            f"Security policy violation [PACKAGE_JSON_MALFORMED]: package.json in '{cwd}' is invalid JSON: {err}",
            exit_code=126,
        ) from err

    scripts = data.get("scripts", {})
    if not isinstance(scripts, dict):
        raise InvalidPackageJsonError(
            "Security policy violation [PACKAGE_JSON_SCHEMA]: 'scripts' section must be a JSON object.",
            exit_code=126,
        )
    if "test" not in scripts:
        raise MissingNpmTestScriptError(
            "Security policy violation [MISSING_TEST_SCRIPT]: package.json must define a 'test' script.",
            exit_code=126,
        )
    if target_script not in scripts:
        raise MissingNpmTestScriptError(
            f"Security policy violation [SCRIPT_NOT_FOUND]: Requested script '{target_script}' not found in package.json.",
            exit_code=126,
        )


def validate_command_security(argv: List[str], cwd: Optional[Path] = None) -> None:
    """Validate argument vector against runner-specific allowlists and flag policies.

    Enforces SEC-B3 & SR-01:
      - Validates executable identity and subcommand against fail-closed allowlist (exit code 126)
      - Strictly validates python module execution (-m)
      - Requires --no-install on npx
      - Requires --ignore-scripts and approved target scripts on npm
      - Validates package.json when cwd is provided
      - Strictly rejects execution redirection flags (-exec, -c, --node-options, -p)
      - Fails closed before any subprocess creation

    Args:
        argv: Command argument array.
        cwd: Optional working directory for package.json inspection.

    Raises:
        ForbiddenCommandFlagError: If prohibited or unapproved flags/runners are present (exit 126).
        ValueError: If argv is empty or malformed.
    """
    if not argv or not isinstance(argv, list):
        raise ValueError("Command argv must be a non-empty list of strings.")

    binary = Path(argv[0]).name.lower()
    runner = resolve_runner_category(binary)

    if not runner:
        raise ForbiddenCommandFlagError(
            f"Security policy violation [UNAUTHORIZED_RUNNER]: Binary '{binary}' is not an approved test runner.",
            exit_code=126,
        )

    args = argv[1:]
    sep_idx = args.index("--") if "--" in args else len(args)
    runner_args = args[:sep_idx]

    if runner == "python":
        _check_python_args(args)
    elif runner == "npx":
        if "--no-install" not in runner_args:
            raise ForbiddenCommandFlagError(
                "Security policy violation [NPX_REMOTE_INSTALL]: npx must be invoked with '--no-install'.",
                exit_code=126,
            )
        for arg in runner_args:
            base = arg.split("=")[0].strip()
            if base in {"--install", "--yes", "-y"} or arg.startswith("--no-install="):
                raise ForbiddenCommandFlagError(
                    f"Security policy violation [NPX_REMOTE_INSTALL]: Conflicting/install flag '{arg}' is prohibited.",
                    exit_code=126,
                )
            if arg.startswith("-") and not arg.startswith("--") and "y" in arg[1:]:
                raise ForbiddenCommandFlagError(
                    f"Security policy violation [NPX_REMOTE_INSTALL]: Conflicting short flag '{arg}' is prohibited.",
                    exit_code=126,
                )
        subcmd = next((a for a in runner_args if not a.startswith("-")), None)
        if subcmd and subcmd.lower() not in AUTHORIZED_SUBCOMMANDS["npx"]:
            raise ForbiddenCommandFlagError(
                f"Security policy violation [UNAUTHORIZED_SUBCOMMAND]: Subcommand '{subcmd}' is prohibited for npx.",
                exit_code=126,
            )
    elif runner == "npm":
        if "--ignore-scripts" not in runner_args:
            raise ForbiddenCommandFlagError(
                "Security policy violation [NPM_LIFECYCLE_SCRIPTS]: npm test/run must include '--ignore-scripts'.",
                exit_code=126,
            )
        for arg in runner_args:
            base = arg.split("=")[0].strip()
            if arg.startswith("--ignore-scripts=") or base in {"--no-ignore-scripts", "--foreground-scripts"}:
                raise ForbiddenCommandFlagError(
                    f"Security policy violation [NPM_LIFECYCLE_SCRIPTS]: Lifecycle override flag '{arg}' is prohibited.",
                    exit_code=126,
                )
        subcmd = next((a for a in runner_args if not a.startswith("-")), None)
        if not subcmd or subcmd.lower() not in AUTHORIZED_SUBCOMMANDS["npm"]:
            raise ForbiddenCommandFlagError(
                f"Security policy violation [UNAUTHORIZED_SUBCOMMAND]: Subcommand '{subcmd}' is prohibited for npm.",
                exit_code=126,
            )

        # Enforce script target allowlist and validate against package.json
        target_script = "test"
        if subcmd == "run":
            run_index = runner_args.index("run")
            positional_after_run = [a for a in runner_args[run_index + 1 :] if not a.startswith("-")]
            if not positional_after_run:
                raise ForbiddenCommandFlagError(
                    "Security policy violation [MISSING_SCRIPT_TARGET]: 'npm run' requires a target script.",
                    exit_code=126,
                )
            target_script = positional_after_run[0]
            if len(positional_after_run) > 1:
                raise ForbiddenCommandFlagError(
                    f"Security policy violation [EXTRA_POSITIONAL_ARGS]: Additional script names {positional_after_run[1:]} prohibited.",
                    exit_code=126,
                )
            if target_script.lower() not in AUTHORIZED_NPM_RUN_TARGETS:
                raise ForbiddenCommandFlagError(
                    f"Security policy violation [UNAUTHORIZED_NPM_SCRIPT]: 'npm run {target_script}' is not an approved test target.",
                    exit_code=126,
                )

        if cwd:
            validate_npm_package_json(cwd, target_script)

    elif runner in AUTHORIZED_SUBCOMMANDS:
        allowed = AUTHORIZED_SUBCOMMANDS[runner]
        subcmd = next((a for a in runner_args if not a.startswith("-")), None)
        if subcmd and subcmd.lower() not in allowed:
            raise ForbiddenCommandFlagError(
                f"Security policy violation [UNAUTHORIZED_SUBCOMMAND]: Subcommand '{subcmd}' is prohibited for '{runner}'.",
                exit_code=126,
            )

    # Prohibited flags check across all arguments for non-python runners
    # (Python interpreter flags stop at script/-m and are checked by _check_python_args)
    if runner != "python":
        prohibited = PROHIBITED_FLAGS.get(runner, set())
        for arg in args:
            flag = arg.split("=")[0].strip()
            if runner == "go" and flag.startswith("--"):
                flag = "-" + flag[2:]
            if flag in prohibited:
                raise ForbiddenCommandFlagError(
                    f"Security policy violation [FORBIDDEN_FLAG]: Flag '{flag}' is prohibited for runner '{runner}'.",
                    exit_code=126,
                )
            if arg.startswith("-") and not arg.startswith("--") and len(arg) > 1:
                _check_short_bundle(runner, arg)


def capture_git_status_porcelain(repo_path: Union[str, Path]) -> str:
    """Capture clean git status including untracked files."""
    cmd = [
        "git",
        *SAFE_GIT_SECURITY_FLAGS,
        "-C",
        str(repo_path),
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
    ]
    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        return res.stdout.strip()
    except Exception as err:
        raise CommandSecurityError(f"Failed to inspect working tree status in '{repo_path}': {err}") from err


@dataclass
class CommandExecutionRecord:
    """Structured execution record adhering to command_execution.schema.json (SEC-05)."""

    command_argv: List[str]
    working_directory: str
    timestamp_start: str
    timestamp_end: str
    duration_ms: int
    timeout_seconds: int
    timed_out: bool
    exit_code: int
    stdout: str
    stderr: str
    stdout_sha256: str
    stderr_sha256: str
    tree_mutated: bool

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def execute_secure_command(
    argv: List[str],
    working_directory: Union[str, Path],
    timeout_seconds: int = 300,
    extra_env: Optional[Dict[str, str]] = None,
    log_dir: Optional[Union[str, Path]] = None,
    check_tree_integrity: bool = True,
) -> CommandExecutionRecord:
    """Execute a test or verification command in an isolated, secure subprocess.

    Enforces:
      1. Pre-execution argument policy check (SEC-B3)
      2. Environment credential stripping (SEC-A1)
      3. Strict execution timeout
      4. Working-tree status equality audit before/after (SEC-C1)
      5. Execution record generation with SHA-256 digests (SEC-05)

    Args:
        argv: Command arguments array.
        working_directory: Execution directory path.
        timeout_seconds: Maximum allowed runtime in seconds.
        extra_env: Optional safe environment variables.
        log_dir: Optional directory to persist stdout.log and stderr.log.
        check_tree_integrity: Whether to audit git working tree cleanliness before and after.

    Returns:
        Structured CommandExecutionRecord.
    """
    cwd = Path(working_directory).resolve()
    validate_command_security(argv, cwd=cwd)
    clean_env_dict = build_sanitized_environment(extra_env)

    before_status = ""
    if check_tree_integrity and (cwd / ".git").exists():
        before_status = capture_git_status_porcelain(cwd)

    t0 = time.time()
    t_start_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    timed_out = False
    exit_code = 0
    stdout_str = ""
    stderr_str = ""

    try:
        proc = subprocess.run(
            argv,
            cwd=str(cwd),
            env=clean_env_dict,
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_seconds,
        )
        exit_code = proc.returncode
        stdout_str = proc.stdout
        stderr_str = proc.stderr
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        exit_code = 124
        stdout_str = exc.stdout or ""
        stderr_str = exc.stderr or ""

    t1 = time.time()
    t_end_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    duration_ms = int((t1 - t0) * 1000)

    # Calculate digests
    stdout_sha256 = sha256_digest(stdout_str.encode("utf-8"))
    stderr_sha256 = sha256_digest(stderr_str.encode("utf-8"))

    # Audit tree integrity after execution
    tree_mutated = False
    if check_tree_integrity and (cwd / ".git").exists():
        after_status = capture_git_status_porcelain(cwd)
        if before_status != after_status:
            tree_mutated = True

    # Persist logs if requested
    if log_dir:
        log_path = Path(log_dir).resolve()
        log_path.mkdir(parents=True, exist_ok=True)
        (log_path / "stdout.log").write_text(stdout_str, encoding="utf-8")
        (log_path / "stderr.log").write_text(stderr_str, encoding="utf-8")

    record = CommandExecutionRecord(
        command_argv=argv,
        working_directory=str(cwd),
        timestamp_start=t_start_iso,
        timestamp_end=t_end_iso,
        duration_ms=duration_ms,
        timeout_seconds=timeout_seconds,
        timed_out=timed_out,
        exit_code=exit_code,
        stdout=stdout_str,
        stderr=stderr_str,
        stdout_sha256=stdout_sha256,
        stderr_sha256=stderr_sha256,
        tree_mutated=tree_mutated,
    )

    if timed_out:
        raise CommandTimeoutError(
            f"Command execution timed out after {timeout_seconds} seconds: {argv}"
        )

    if tree_mutated:
        raise TreeMutationError(
            f"Test execution mutated repository working tree or created untracked artifacts in '{cwd}'."
        )

    return record

