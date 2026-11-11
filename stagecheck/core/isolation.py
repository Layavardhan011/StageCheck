"""OS-Enforced Same-UID Execution Isolation via Linux Namespaces / Bubblewrap (GAP-05 / SR-10).

Provides real kernel-enforced filesystem, PID, IPC, UTS, network, and capability
isolation for untrusted command and agent/test-runner subprocesses running under
the same local UID as the StageCheck supervisor/verifier.

Important security contract:
- POSIX chmod / advisory flock alone DO NOT isolate hostile code executing under
  the same UID (since a same-UID process can chmod files back or bypass advisory locks).
- This module enforces an OS-level mount + PID + IPC + UTS + network + cap-drop
  sandbox via Bubblewrap (`bwrap`) and FAILS CLOSED with SandboxUnavailableError
  whenever mandatory isolation cannot be established.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys

_REAL_SUBPROCESS_RUN = subprocess.run
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union


class IsolationError(Exception):
    """Base exception for OS isolation and sandbox boundary enforcement."""

    exit_code: int = 126


class SandboxUnavailableError(IsolationError):
    """Raised fail-closed when mandatory OS-level isolation cannot be enforced."""

    exit_code: int = 126


SENSITIVE_HOME_RELPATHS: Tuple[str, ...] = (
    ".ssh",
    ".aws",
    ".gnupg",
    ".kube",
    ".docker",
    ".config/gcloud",
)

GOVERNANCE_DIR_NAMES: Tuple[str, ...] = (
    "controls",
    "evidence",
    "specs",
    ".stagecheck_journal",
)

GOVERNANCE_FILE_NAMES: Tuple[str, ...] = (
    "AGENTS.md",
)

IPC_RUNTIME_NAMES: Tuple[str, ...] = (
    ".stagecheck.lock",
    ".stagecheck_sentinel.sock",
    ".stagecheck_sentinel.pid",
)


@dataclass(frozen=True)
class SandboxPolicy:
    """Immutable kernel isolation policy for an untrusted subprocess."""

    working_directory: Path
    workspace_root: Optional[Path] = None
    allow_cwd_write: bool = True
    unshare_pid: bool = True
    unshare_ipc: bool = True
    unshare_net: bool = True
    unshare_uts: bool = True
    drop_caps: bool = True
    mask_home_credentials: bool = True
    mask_governance_dirs: bool = False
    extra_ro_binds: Tuple[Path, ...] = field(default_factory=tuple)
    extra_masked_paths: Tuple[Path, ...] = field(default_factory=tuple)


def resolve_bwrap_binary(bwrap_path: Optional[Union[str, Path]] = None) -> Optional[str]:
    """Locate an executable Bubblewrap (`bwrap`) binary without implicit unsafe fallback."""
    if bwrap_path is not None:
        candidate = Path(bwrap_path)
        if candidate.is_file() and os.access(str(candidate), os.X_OK):
            return str(candidate)
        return None

    found = shutil.which("bwrap")
    if found and Path(found).is_file() and os.access(found, os.X_OK):
        return found
    return None


def find_workspace_root_for_cwd(cwd: Path) -> Optional[Path]:
    """Infer StageCheck workspace root from cwd by scanning ancestors for controls/."""
    resolved = cwd.resolve()
    for candidate in (resolved, *resolved.parents):
        if (candidate / "controls").is_dir():
            return candidate
    return None


def _is_relative_to(path: Path, ancestor: Path) -> bool:
    try:
        path.resolve().relative_to(ancestor.resolve())
        return True
    except ValueError:
        return False


def _is_governance_protected_path(path: Path, workspace_root: Optional[Path]) -> bool:
    if workspace_root is None:
        return False
    ws = workspace_root.resolve()
    for rel_dir in GOVERNANCE_DIR_NAMES:
        if _is_relative_to(path, ws / rel_dir):
            return True
    for rel_file in GOVERNANCE_FILE_NAMES + IPC_RUNTIME_NAMES:
        if path.resolve() == (ws / rel_file).resolve():
            return True
    return False


def _collect_argv_ephemeral_ro_binds(
    exec_argv: Sequence[str],
    cwd: Path,
    workspace_root: Optional[Path],
) -> List[Path]:
    """Identify existing script/file inputs under /tmp or /var/tmp so bwrap can expose them read-only."""
    mounts: List[Path] = []
    seen: set[Path] = set()
    tmp_roots = (Path("/tmp").resolve(), Path("/var/tmp").resolve())

    for token in exec_argv[1:]:
        if not token or token.startswith("-"):
            continue
        try:
            candidate = Path(token)
            if not candidate.is_absolute():
                candidate = cwd / candidate
            resolved = candidate.resolve()
        except Exception:
            continue

        if not resolved.exists():
            continue
        if _is_relative_to(resolved, cwd):
            continue
        if _is_governance_protected_path(resolved, workspace_root):
            continue
        if any(_is_relative_to(resolved, tr) for tr in tmp_roots):
            if resolved not in seen:
                seen.add(resolved)
                mounts.append(resolved)

    return mounts


def build_bwrap_argv(
    exec_argv: Sequence[str],
    policy: SandboxPolicy,
    bwrap_bin: str,
) -> List[str]:
    """Construct an OS-enforced Bubblewrap command line wrapping `exec_argv`."""
    if not exec_argv:
        raise IsolationError("Cannot build sandbox command for empty exec_argv.")

    cwd = policy.working_directory.resolve()
    ws_root = policy.workspace_root.resolve() if policy.workspace_root else find_workspace_root_for_cwd(cwd)

    argv: List[str] = [
        bwrap_bin,
        "--ro-bind", "/", "/",
        "--dev", "/dev",
        "--proc", "/proc",
        "--tmpfs", "/tmp",
        "--tmpfs", "/var/tmp",
    ]

    # Mask sensitive user credential directories so same-UID child cannot read SSH/cloud keys.
    if policy.mask_home_credentials:
        home_dir = Path.home().resolve()
        py_prefix = Path(sys.prefix).resolve()
        for rel in SENSITIVE_HOME_RELPATHS:
            target = (home_dir / rel).resolve()
            if not target.exists():
                continue
            if _is_relative_to(cwd, target) or _is_relative_to(py_prefix, target):
                continue
            if target.is_dir():
                argv.extend(["--tmpfs", str(target)])
            elif target.is_file():
                argv.extend(["--ro-bind", "/dev/null", str(target)])

    # Bind the authorized execution directory (either rw within repo or strict ro).
    if cwd.is_dir():
        bind_flag = "--bind" if policy.allow_cwd_write else "--ro-bind"
        argv.extend([bind_flag, str(cwd), str(cwd)])

    # Expose explicit read-only script arguments that live inside /tmp or extra_ro_binds.
    seen_ro: set[Path] = set()
    for ro_path in (
        list(policy.extra_ro_binds)
        + _collect_argv_ephemeral_ro_binds(exec_argv, cwd, ws_root)
    ):
        resolved_ro = ro_path.resolve()
        if resolved_ro.exists() and resolved_ro not in seen_ro:
            seen_ro.add(resolved_ro)
            argv.extend(["--ro-bind", str(resolved_ro), str(resolved_ro)])

    # Enforce immutability of StageCheck package code itself (prevents verifier self-patching).
    package_root = Path(__file__).resolve().parent.parent
    if package_root.is_dir() and package_root not in seen_ro:
        argv.extend(["--ro-bind", str(package_root), str(package_root)])

    # Enforce immutability/isolation of StageCheck workspace governance & runtime artifacts
    # AFTER mounting cwd so even if cwd is workspace_root or an ancestor, controls/ cannot be altered.
    if ws_root is not None and ws_root.is_dir():
        for dir_name in GOVERNANCE_DIR_NAMES:
            gdir = (ws_root / dir_name).resolve()
            if not gdir.is_dir():
                continue
            if policy.mask_governance_dirs and dir_name in ("evidence", ".stagecheck_journal") and not _is_relative_to(cwd, gdir):
                argv.extend(["--tmpfs", str(gdir)])
            else:
                argv.extend(["--ro-bind", str(gdir), str(gdir)])

        for file_name in GOVERNANCE_FILE_NAMES:
            gfile = (ws_root / file_name).resolve()
            if gfile.is_file():
                argv.extend(["--ro-bind", str(gfile), str(gfile)])

        for ipc_name in IPC_RUNTIME_NAMES:
            ipc_path = (ws_root / ipc_name).resolve()
            if ipc_path.exists() and not ipc_path.is_dir():
                argv.extend(["--ro-bind", "/dev/null", str(ipc_path)])

    for mpath in policy.extra_masked_paths:
        resolved_m = mpath.resolve()
        if resolved_m.is_dir():
            argv.extend(["--tmpfs", str(resolved_m)])
        elif resolved_m.exists():
            argv.extend(["--ro-bind", "/dev/null", str(resolved_m)])

    if policy.unshare_pid:
        argv.append("--unshare-pid")
    if policy.unshare_ipc:
        argv.append("--unshare-ipc")
    if policy.unshare_net:
        argv.append("--unshare-net")
    if policy.unshare_uts:
        argv.append("--unshare-uts")
    if policy.drop_caps:
        argv.extend(["--cap-drop", "ALL"])

    argv.extend(["--die-with-parent", "--new-session", "--chdir", str(cwd), "--"])
    argv.extend(list(exec_argv))
    return argv


def probe_bwrap_sandbox(
    bwrap_path: Optional[Union[str, Path]] = None,
    unshare_net: bool = True,
    timeout_seconds: float = 5.0,
) -> Dict[str, Any]:
    """Verify at runtime that Bubblewrap kernel namespace isolation works."""
    bwrap_bin = resolve_bwrap_binary(bwrap_path=bwrap_path)
    if not bwrap_bin:
        return {
            "available": False,
            "bwrap_path": None,
            "namespaces_supported": False,
            "reason": "Bubblewrap ('bwrap') executable not found in PATH.",
        }

    probe_cmd = [
        bwrap_bin,
        "--ro-bind", "/", "/",
        "--dev", "/dev",
        "--proc", "/proc",
        "--tmpfs", "/tmp",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
    ]
    if unshare_net:
        probe_cmd.append("--unshare-net")
    probe_cmd.extend([
        "--cap-drop", "ALL",
        "--die-with-parent",
        "--new-session",
        "--",
        sys.executable,
        "-c",
        "",
    ])

    try:
        res = _REAL_SUBPROCESS_RUN(
            probe_cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except Exception as err:
        return {
            "available": False,
            "bwrap_path": bwrap_bin,
            "namespaces_supported": False,
            "reason": f"Bubblewrap probe failed to execute: {err}",
        }

    if res.returncode != 0:
        err_detail = (res.stderr or res.stdout or f"exit {res.returncode}").strip()
        return {
            "available": False,
            "bwrap_path": bwrap_bin,
            "namespaces_supported": False,
            "reason": f"Kernel namespace isolation unusable: {err_detail}",
        }

    return {
        "available": True,
        "bwrap_path": bwrap_bin,
        "namespaces_supported": True,
        "reason": "OS mount/pid/ipc/uts/net namespace sandbox verified via bwrap.",
    }


def prepare_isolated_command(
    exec_argv: Sequence[str],
    policy: SandboxPolicy,
    mandatory: bool = True,
    bwrap_path: Optional[Union[str, Path]] = None,
) -> Tuple[List[str], bool]:
    """Wrap `exec_argv` in an OS-enforced Bubblewrap sandbox or fail closed.

    Returns:
        Tuple of (wrapped_argv, sandbox_enforced_bool).
    """
    probe = probe_bwrap_sandbox(bwrap_path=bwrap_path, unshare_net=policy.unshare_net)
    if not probe["available"]:
        if mandatory:
            raise SandboxUnavailableError(
                f"Mandatory OS-enforced same-UID sandbox isolation is unavailable: {probe['reason']} "
                "Fail-closed: refusing to execute untrusted command without kernel isolation."
            )
        return list(exec_argv), False

    wrapped = build_bwrap_argv(
        exec_argv=exec_argv,
        policy=policy,
        bwrap_bin=str(probe["bwrap_path"]),
    )
    return wrapped, True
