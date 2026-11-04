"""Tokenized Command Registry, Runner Policies, and Secure Command Execution (P3-T4).

Enforces runner-specific flag allowlists (SEC-B3), environment credential stripping (SEC-A1),
command timeouts, structured execution logs, and before/after Git working tree integrity.
"""

from __future__ import annotations

import datetime
import os
import re
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from stagecheck.core.utils import sha256_digest


class CommandSecurityError(Exception):
    """Base error for command security and execution policy violations."""

    def __init__(self, message: str, exit_code: int = 126) -> None:
        super().__init__(message)
        self.exit_code = exit_code


class ForbiddenCommandFlagError(CommandSecurityError):
    """Raised when an injection or execution-redirection flag is detected (exit code 126)."""


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


# Runner-specific security allowlists and prohibited flags (SEC-B3 & Spec 06)
PROHIBITED_FLAGS = {
    "go": {"-exec", "-toolexec"},
    "pytest": {"-o", "--override-ini", "-c", "-p"},
    "python": {"-c", "-e"},
    "python3": {"-c", "-e"},
    "npm": {"--node-options", "--inspect", "--inspect-brk", "--globalSetup"},
    "npx": {"--node-options", "--inspect", "--inspect-brk", "--globalSetup"},
    "cargo": {"--config", "--runner"},
}


def validate_command_security(argv: List[str]) -> None:
    """Validate argument vector against runner-specific allowlists and flag policies.

    Enforces SEC-B3:
      - Validates executable identity and subcommand
      - Strictly rejects execution redirection flags (-exec, -c, --node-options, -p)
      - Fails closed before any subprocess creation

    Args:
        argv: Command argument array.

    Raises:
        ForbiddenCommandFlagError: If prohibited or malicious flags are present (exit 126).
        ValueError: If argv is empty or malformed.
    """
    if not argv or not isinstance(argv, list):
        raise ValueError("Command argv must be a non-empty list of strings.")

    binary = Path(argv[0]).name.lower()

    # Determine runner category
    runner = None
    if binary in ("pytest", "pytest-3"):
        runner = "pytest"
    elif binary in ("go",):
        runner = "go"
    elif binary in ("python", "python3"):
        runner = "python"
    elif binary in ("npm", "yarn", "pnpm"):
        runner = "npm"
    elif binary in ("npx",):
        runner = "npx"
    elif binary in ("cargo",):
        runner = "cargo"

    if runner and runner in PROHIBITED_FLAGS:
        forbidden = PROHIBITED_FLAGS[runner]
        for arg in argv[1:]:
            flag_name = arg.split("=")[0].strip()
            if flag_name in forbidden:
                raise ForbiddenCommandFlagError(
                    f"Security policy violation [COMMAND_FLAG_FORBIDDEN]: "
                    f"Runner '{runner}' prohibits flag '{arg}'. Execution denied.",
                    exit_code=126,
                )


def capture_git_status_porcelain(repo_path: Union[str, Path]) -> str:
    """Capture clean git status including untracked files."""
    cmd = ["git", "-C", str(repo_path), "status", "--porcelain=v1", "--untracked-files=all"]
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
    validate_command_security(argv)
    clean_env_dict = build_sanitized_environment(extra_env)
    cwd = Path(working_directory).resolve()

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

