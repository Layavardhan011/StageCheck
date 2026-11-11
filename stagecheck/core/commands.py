"""Tokenized Command Registry, Runner Policies, and Secure Command Execution (P3-T4).

Enforces runner-specific flag allowlists (SEC-B3), environment credential stripping (SEC-A1),
command timeouts, structured execution logs, and before/after Git working tree integrity.
"""

from __future__ import annotations

import datetime
import json
import os
import re
import shutil
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from stagecheck.core.git import SAFE_GIT_SECURITY_FLAGS, run_safe_git
from stagecheck.core.isolation import (
    SandboxPolicy,
    SandboxUnavailableError as BaseSandboxUnavailableError,
    prepare_isolated_command,
)
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


class SandboxUnavailableError(CommandSecurityError, BaseSandboxUnavailableError):
    """Raised fail-closed when mandatory OS-level sandbox isolation is unavailable."""

    def __init__(self, message: str) -> None:
        CommandSecurityError.__init__(self, message, exit_code=126)


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
    "yarn": "yarn",
    "pnpm": "pnpm",
    "npx": "npx",
    "cargo": "cargo",
}

AUTHORIZED_SUBCOMMANDS: Dict[str, Set[str]] = {
    "go": {"test"},
    "cargo": {"test"},
    "npm": {"test", "run"},
    "yarn": {"test", "run"},
    "pnpm": {"test", "run"},
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
    "go": {"-exec", "-toolexec", "-C"},
    "pytest": {"-o", "--override-ini", "-c", "--config-file", "-p"},
    "python": {"-c", "-e"},
    "npm": {
        "--node-options",
        "--inspect",
        "--inspect-brk",
        "--globalSetup",
        "-c",
        "--call",
        "--prefix",
        "-C",
        "--script-shell",
        "--userconfig",
        "--globalconfig",
    },
    "yarn": {
        "--node-options",
        "--inspect",
        "--inspect-brk",
        "--globalSetup",
        "-c",
        "--call",
        "--cwd",
        "--use-yarnrc",
    },
    "pnpm": {
        "--node-options",
        "--inspect",
        "--inspect-brk",
        "--globalSetup",
        "-c",
        "--call",
        "-C",
        "--dir",
        "--config",
        "--shell-emulator",
    },
    "npx": {
        "--node-options",
        "--inspect",
        "--inspect-brk",
        "--globalSetup",
        "-c",
        "--call",
        "-p",
        "--package",
        "--prefix",
        "-C",
        "--script-shell",
        "--shell-auto-fallback",
    },
    "cargo": {"--config", "--runner", "-C", "--manifest-path"},
}

# Short options per runner whose remainder in the same argv token is a value, not bundled flags
_VALUE_TAKING_SHORT_OPTS: Dict[str, Set[str]] = {
    "python": {"m", "W", "X", "Q"},
    "pytest": {"k", "m", "W", "r", "n"},
}

_PROHIBITED_SHORT_FLAGS: Dict[str, Set[str]] = {
    "python": {"c", "e"},
    "pytest": {"c", "o", "p"},
    "npm": {"c", "C"},
    "npx": {"c", "C", "p", "y"},
    "yarn": {"c"},
    "pnpm": {"c", "C"},
    "cargo": {"C"},
}

# Safe pre-subcommand boolean flags for Node package runners so flag values cannot disguise subcommands
_NODE_SAFE_PRE_SUBCMD_FLAGS: Dict[str, Set[str]] = {
    "npm": {"--ignore-scripts", "-s", "--silent", "-q", "--quiet", "--verbose", "-d", "--no-audit", "--no-fund", "--offline", "--prefer-offline", "--no-progress"},
    "yarn": {"--ignore-scripts", "-s", "--silent", "--verbose", "--offline", "--prefer-offline", "--non-interactive", "--no-progress"},
    "pnpm": {"--ignore-scripts", "-s", "--silent", "--reporter", "--offline", "--prefer-offline", "--no-color"},
    "npx": {"--no-install", "-q", "--quiet"},
}


def _check_python_args(args: List[str], cwd: Optional[Path] = None) -> None:
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
            if flag == "--check-hash-based-pycs" and "=" not in arg:
                i += 2
                continue
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
                sub_runner = resolve_runner_category(root_mod)
                if sub_runner and sub_runner != "python":
                    next_idx = i + 2 if consumed_next else i + 1
                    validate_command_security([root_mod, *args[next_idx:]], cwd=cwd)
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


def _extract_positional_subcommand(
    runner: str,
    runner_args: List[str],
    safe_pre_flags: Set[str],
) -> Tuple[str, int]:
    """Extract subcommand while rejecting unapproved pre-subcommand flags."""
    for idx, arg in enumerate(runner_args):
        if arg.startswith("-"):
            base = arg.split("=")[0].strip()
            if base not in safe_pre_flags and arg not in safe_pre_flags:
                raise ForbiddenCommandFlagError(
                    f"Security policy violation [FORBIDDEN_PRE_SUBCOMMAND_FLAG]: Flag '{arg}' is prohibited before subcommand for '{runner}'.",
                    exit_code=126,
                )
            continue
        return arg, idx
    raise ForbiddenCommandFlagError(
        f"Security policy violation [MISSING_SUBCOMMAND]: Runner '{runner}' requires an authorized subcommand.",
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

    raw_bin = argv[0]
    if not isinstance(raw_bin, str) or not raw_bin or "/" in raw_bin or "\\" in raw_bin or raw_bin in {".", ".."}:
        raise ForbiddenCommandFlagError(
            f"Security policy violation [UNTRUSTED_BINARY_PATH]: Path-qualified or invalid runner '{raw_bin}' is prohibited.",
            exit_code=126,
        )

    binary = raw_bin.lower()
    runner = resolve_runner_category(binary)

    if not runner:
        raise ForbiddenCommandFlagError(
            f"Security policy violation [UNAUTHORIZED_RUNNER]: Binary '{binary}' is not an approved test runner.",
            exit_code=126,
        )

    if cwd is not None:
        cwd_resolved = Path(cwd).resolve()
        resolved_bin = shutil.which(raw_bin)
        if resolved_bin:
            resolved_path = Path(resolved_bin).resolve()
            if resolved_path.is_relative_to(cwd_resolved):
                raise ForbiddenCommandFlagError(
                    f"Security policy violation [UNTRUSTED_BINARY_PATH]: Runner resolves inside working directory '{resolved_bin}'.",
                    exit_code=126,
                )

    args = argv[1:]
    sep_idx = args.index("--") if "--" in args else len(args)
    runner_args = args[:sep_idx]

    # Prohibited flags check across all arguments for non-python runners first
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

    if runner == "python":
        _check_python_args(args, cwd=cwd)
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
        subcmd, sub_idx = _extract_positional_subcommand("npx", runner_args, _NODE_SAFE_PRE_SUBCMD_FLAGS["npx"])
        if subcmd.lower() not in AUTHORIZED_SUBCOMMANDS["npx"]:
            raise ForbiddenCommandFlagError(
                f"Security policy violation [UNAUTHORIZED_SUBCOMMAND]: Subcommand '{subcmd}' is prohibited for npx.",
                exit_code=126,
            )
        if subcmd.lower() == "pytest":
            trailing = [a for a in runner_args[sub_idx + 1 :] if a != "--no-install"]
            validate_command_security(["pytest", *trailing, *args[sep_idx:]], cwd=cwd)
    elif runner in {"npm", "yarn", "pnpm"}:
        if "--ignore-scripts" not in runner_args:
            raise ForbiddenCommandFlagError(
                f"Security policy violation [NPM_LIFECYCLE_SCRIPTS]: {runner} test/run must include '--ignore-scripts'.",
                exit_code=126,
            )
        for arg in runner_args:
            base = arg.split("=")[0].strip()
            if arg.startswith("--ignore-scripts=") or base in {"--no-ignore-scripts", "--foreground-scripts"}:
                raise ForbiddenCommandFlagError(
                    f"Security policy violation [NPM_LIFECYCLE_SCRIPTS]: Lifecycle override flag '{arg}' is prohibited.",
                    exit_code=126,
                )
        subcmd, sub_idx = _extract_positional_subcommand(runner, runner_args, _NODE_SAFE_PRE_SUBCMD_FLAGS[runner])
        subcmd_lower = subcmd.lower()
        if subcmd_lower not in AUTHORIZED_SUBCOMMANDS[runner]:
            raise ForbiddenCommandFlagError(
                f"Security policy violation [UNAUTHORIZED_SUBCOMMAND]: Subcommand '{subcmd}' is prohibited for {runner}.",
                exit_code=126,
            )

        target_script = "test"
        if subcmd_lower == "run":
            post_run = runner_args[sub_idx + 1 :]
            positional_after_run: List[str] = []
            for a in post_run:
                if a.startswith("-"):
                    base = a.split("=")[0].strip()
                    if base not in _NODE_SAFE_PRE_SUBCMD_FLAGS[runner]:
                        raise ForbiddenCommandFlagError(
                            f"Security policy violation [FORBIDDEN_FLAG]: Flag '{a}' is prohibited in '{runner} run'.",
                            exit_code=126,
                        )
                else:
                    positional_after_run.append(a)
            if not positional_after_run:
                raise ForbiddenCommandFlagError(
                    f"Security policy violation [MISSING_SCRIPT_TARGET]: '{runner} run' requires a target script.",
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
                    f"Security policy violation [UNAUTHORIZED_NPM_SCRIPT]: '{runner} run {target_script}' is not an approved test target.",
                    exit_code=126,
                )

        if cwd:
            validate_npm_package_json(cwd, target_script)

    elif runner in AUTHORIZED_SUBCOMMANDS:
        allowed = AUTHORIZED_SUBCOMMANDS[runner]
        if not runner_args or runner_args[0].startswith("-") or runner_args[0].lower() not in allowed:
            bad = runner_args[0] if runner_args else "<empty>"
            raise ForbiddenCommandFlagError(
                f"Security policy violation [UNAUTHORIZED_SUBCOMMAND]: Subcommand '{bad}' is prohibited for '{runner}'.",
                exit_code=126,
            )


def capture_git_status_porcelain(repo_path: Union[str, Path]) -> str:
    """Capture clean git status including untracked files."""
    try:
        res = run_safe_git(
            Path(repo_path),
            ["status", "--porcelain=v1", "--untracked-files=all"],
            check=True,
        )
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
    workspace_root: Optional[Union[str, Path]] = None,
    require_isolation: bool = True,
    allow_network: bool = False,
    allow_cwd_write: bool = True,
    mask_governance_dirs: bool = False,
) -> CommandExecutionRecord:
    """Execute a test or verification command in an OS-isolated, secure subprocess.

    Enforces:
      1. Pre-execution argument policy check (SEC-B3)
      2. Environment credential stripping (SEC-A1)
      3. OS-enforced Bubblewrap namespace/mount/capability sandbox (GAP-05)
      4. Strict execution timeout
      5. Working-tree status equality audit before/after (SEC-C1)
      6. Execution record generation with SHA-256 digests (SEC-05)

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

    resolved_bin = shutil.which(argv[0], path=clean_env_dict.get("PATH"))
    if not resolved_bin:
        raise CommandSecurityError(
            f"Approved test runner '{argv[0]}' not found in sanitized PATH.",
            exit_code=127,
        )
    resolved_bin_path = Path(resolved_bin).resolve()
    if resolved_bin_path.is_relative_to(cwd):
        raise ForbiddenCommandFlagError(
            f"Security policy violation [UNTRUSTED_BINARY_PATH]: Runner '{argv[0]}' resolves inside working directory '{resolved_bin_path}'.",
            exit_code=126,
        )
    # Also ensure resolved binary does not live inside any sibling workspace repos/ directory
    for ancestor in cwd.parents:
        if ancestor.name == "repos" and resolved_bin_path.is_relative_to(ancestor):
            raise ForbiddenCommandFlagError(
                f"Security policy violation [UNTRUSTED_BINARY_PATH]: Runner '{argv[0]}' resolves inside workspace repos directory '{resolved_bin_path}'.",
                exit_code=126,
            )

    in_git_repo = (cwd / ".git").exists() or any((p / ".git").exists() for p in cwd.parents)
    before_status = ""
    if check_tree_integrity and in_git_repo:
        before_status = capture_git_status_porcelain(cwd)

    t0 = time.time()
    t_start_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    timed_out = False
    exit_code = 0
    stdout_str = ""
    stderr_str = ""

    exec_argv = [str(resolved_bin_path), *argv[1:]]
    policy = SandboxPolicy(
        working_directory=cwd,
        workspace_root=Path(workspace_root).resolve() if workspace_root else None,
        allow_cwd_write=allow_cwd_write,
        unshare_net=not allow_network,
        mask_governance_dirs=mask_governance_dirs,
    )
    try:
        launch_argv, _sandbox_enforced = prepare_isolated_command(
            exec_argv=exec_argv,
            policy=policy,
            mandatory=require_isolation,
        )
    except BaseSandboxUnavailableError as err:
        raise SandboxUnavailableError(str(err)) from err

    try:
        proc = subprocess.run(
            launch_argv,
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
        raw_out = exc.stdout or ""
        raw_err = exc.stderr or ""
        stdout_str = raw_out.decode("utf-8", errors="replace") if isinstance(raw_out, bytes) else raw_out
        stderr_str = raw_err.decode("utf-8", errors="replace") if isinstance(raw_err, bytes) else raw_err

    t1 = time.time()
    t_end_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    duration_ms = int((t1 - t0) * 1000)

    # Calculate digests
    stdout_sha256 = sha256_digest(stdout_str.encode("utf-8"))
    stderr_sha256 = sha256_digest(stderr_str.encode("utf-8"))

    # Audit tree integrity after execution
    tree_mutated = False
    if check_tree_integrity and in_git_repo:
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

