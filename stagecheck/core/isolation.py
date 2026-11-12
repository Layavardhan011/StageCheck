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

import json
import os
import shutil
import stat
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


_UNTRUSTED_BWRAP_PREFIXES: Tuple[Path, ...] = (
    Path("/tmp"),
    Path("/var/tmp"),
    Path("/dev/shm"),
)


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


def validate_bwrap_binary(
    bwrap_path: Optional[Union[str, Path]] = None,
    workspace_root: Optional[Path] = None,
    working_directory: Optional[Path] = None,
) -> Tuple[Optional[str], Optional[str]]:
    """Validate that resolved `bwrap` exists, is executable, and resides in a trusted non-writable location."""
    resolved_str = resolve_bwrap_binary(bwrap_path=bwrap_path)
    if not resolved_str:
        detail = f"'{bwrap_path}'" if bwrap_path is not None else "PATH"
        return None, f"Bubblewrap ('bwrap') executable not found or not executable in {detail}."

    raw_path = Path(resolved_str)
    try:
        real_path = raw_path.resolve(strict=True)
    except OSError as err:
        return None, f"Bubblewrap path '{resolved_str}' cannot be resolved: {err}"

    if not real_path.is_file() or not os.access(str(real_path), os.X_OK):
        return None, f"Bubblewrap target '{real_path}' is not an executable regular file."

    st_mode = stat.S_IMODE(real_path.stat().st_mode)
    if st_mode & stat.S_IWOTH:
        return None, f"Untrusted world-writable bwrap binary rejected: '{real_path}' ({oct(st_mode)})."

    disallowed_roots: List[Path] = [p.resolve() if p.exists() else p for p in _UNTRUSTED_BWRAP_PREFIXES]
    if workspace_root is not None:
        disallowed_roots.append(workspace_root.resolve())
    if working_directory is not None:
        disallowed_roots.append(working_directory.resolve())

    for bad_root in disallowed_roots:
        if _is_relative_to(raw_path.absolute(), bad_root) or _is_relative_to(real_path, bad_root):
            return None, f"Untrusted bwrap binary location rejected (inside '{bad_root}'): '{real_path}'."

    return str(real_path), None


def find_workspace_root_for_cwd(cwd: Path) -> Optional[Path]:
    """Infer StageCheck workspace root from cwd using authoritative root markers.

    Ignores nested `repos/<name>/...` directories and prefers the outermost ancestor
    bearing an authoritative workspace marker (`controls/STAGECHECK_ROOT.json`,
    `controls/ACTIVE_STATE.json`, `.stagecheck_root`, or `.stagecheck-init.lock`).
    """
    resolved = cwd.resolve()
    matched: Optional[Path] = None
    for candidate in (resolved, *resolved.parents):
        if "repos" in candidate.parts and candidate.name != "repos":
            # A repo subdirectory may not spoof the enclosing StageCheck workspace root.
            repos_ancestors = [p for p in candidate.parents if p.name == "repos"]
            if repos_ancestors:
                continue
        if (
            (candidate / "controls" / "STAGECHECK_ROOT.json").is_file()
            or (candidate / "controls" / "ACTIVE_STATE.json").is_file()
            or (candidate / ".stagecheck_root").is_file()
            or (candidate / ".stagecheck-init.lock").exists()
        ):
            matched = candidate
    return matched


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

    if ws_root is not None and (cwd == ws_root or _is_relative_to(ws_root, cwd)) and policy.allow_cwd_write:
        raise IsolationError(
            f"Refusing writable sandbox mount for workspace root or ancestor '{cwd}'."
        )

    argv: List[str] = [
        bwrap_bin,
        "--ro-bind", "/", "/",
        "--dev", "/dev",
        "--proc", "/proc",
        "--tmpfs", "/tmp",
        "--tmpfs", "/var/tmp",
    ]

    # Mask the entire user home directory when credential masking is enabled so
    # ambient tokens (.npmrc, .netrc, .git-credentials, .pypirc, .ssh, etc.) are hidden.
    if policy.mask_home_credentials:
        home_dir = Path.home().resolve()
        if _is_relative_to(home_dir, cwd):
            raise IsolationError(
                f"Refusing to execute sandboxed command with working_directory equal to or ancestor of HOME ('{cwd}')."
            )
        if home_dir.is_dir() and home_dir != Path("/"):
            argv.extend(["--tmpfs", str(home_dir)])
        seen_toolchain: set[Path] = set()
        for tc_cand in (
            Path(sys.prefix).resolve(),
            Path(sys.base_prefix).resolve(),
            Path(sys.executable).resolve().parent.parent,
        ):
            if (
                tc_cand.is_dir()
                and tc_cand not in seen_toolchain
                and _is_relative_to(tc_cand, home_dir)
                and not _is_relative_to(tc_cand, cwd)
            ):
                seen_toolchain.add(tc_cand)
                argv.extend(["--ro-bind", str(tc_cand), str(tc_cand)])

        raw_exe = Path(exec_argv[0])
        if raw_exe.is_absolute():
            resolved_exe = raw_exe.resolve()
            if (
                resolved_exe.is_file()
                and (_is_relative_to(raw_exe, home_dir) or _is_relative_to(resolved_exe, home_dir))
                and not _is_relative_to(resolved_exe, cwd)
                and not _is_governance_protected_path(resolved_exe, ws_root)
            ):
                target_mount = str(raw_exe) if _is_relative_to(raw_exe, home_dir) else str(resolved_exe)
                argv.extend(["--ro-bind", str(resolved_exe), target_mount])
                if target_mount != str(resolved_exe) and _is_relative_to(resolved_exe, home_dir):
                    argv.extend(["--ro-bind", str(resolved_exe), str(resolved_exe)])

    # Bind the authorized execution directory (either rw within repo or strict ro).
    if cwd.is_dir():
        bind_flag = "--bind" if policy.allow_cwd_write else "--ro-bind"
        argv.extend([bind_flag, str(cwd), str(cwd)])

    # Expose only explicitly authorized read-only inputs via policy.extra_ro_binds
    # (never trusting untrusted exec_argv tokens and never unmasking /tmp or /var/tmp roots).
    tmp_roots = {Path("/tmp").resolve(), Path("/var/tmp").resolve()}
    seen_ro: set[Path] = set()
    for ro_path in policy.extra_ro_binds:
        resolved_ro = ro_path.resolve()
        if resolved_ro in tmp_roots or _is_governance_protected_path(resolved_ro, ws_root):
            continue
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
    bwrap_bin, bin_err = validate_bwrap_binary(bwrap_path=bwrap_path)
    if not bwrap_bin:
        return {
            "available": False,
            "bwrap_path": None,
            "namespaces_supported": False,
            "reason": bin_err or "Bubblewrap ('bwrap') executable not found in PATH.",
        }

    probe_cmd = [
        bwrap_bin,
        "--ro-bind", "/", "/",
        "--dev", "/dev",
        "--proc", "/proc",
        "--tmpfs", "/tmp",
    ]
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        probe_cmd.append("--unshare-user")
    probe_cmd.extend([
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
    ])
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


@dataclass(frozen=True)
class IsolationPreflightResult:
    """Structured deployment preflight report for mandatory Bubblewrap isolation (GAP-03 / Specs 06 & 07)."""

    passed: bool
    bwrap_path: Optional[str]
    checks: Dict[str, bool]
    failures: List[str]
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        """Serialize preflight result to a JSON-compatible dictionary."""
        return {
            "passed": self.passed,
            "bwrap_path": self.bwrap_path,
            "checks": dict(self.checks),
            "failures": list(self.failures),
            "reason": self.reason,
        }


def _read_proc_ns(names: Sequence[str]) -> Dict[str, str]:
    ns_map: Dict[str, str] = {}
    for name in names:
        p = Path(f"/proc/self/ns/{name}")
        if p.exists():
            try:
                ns_map[name] = os.readlink(p)
            except OSError:
                pass
    return ns_map


def run_bwrap_deployment_preflight(
    workspace_root: Optional[Path] = None,
    working_directory: Optional[Path] = None,
    bwrap_path: Optional[Union[str, Path]] = None,
    require_network_isolation: bool = True,
    raise_on_failure: bool = True,
    timeout_seconds: float = 8.0,
) -> IsolationPreflightResult:
    """Verify full Bubblewrap deployment readiness (binary trust, namespaces, RO governance, net unsharing).

    Executes fail-closed checks prior to starting autonomous agent tasks. Never falls back silently.
    """
    ws_root = workspace_root.resolve() if workspace_root else None
    cwd = (working_directory or ws_root or Path(__file__).resolve().parent.parent).resolve()
    checks: Dict[str, bool] = {
        "bwrap_binary_trusted": False,
        "namespaces_isolated": False,
        "root_readonly": False,
        "governance_readonly": False,
        "package_readonly": False,
        "credentials_masked": False,
        "network_unshared": False,
    }
    failures: List[str] = []

    bwrap_bin, bin_err = validate_bwrap_binary(
        bwrap_path=bwrap_path,
        workspace_root=ws_root,
        working_directory=working_directory,
    )
    if not bwrap_bin:
        reason = bin_err or "Bubblewrap binary unavailable or untrusted."
        failures.append(reason)
        result = IsolationPreflightResult(False, None, checks, failures, reason)
        if raise_on_failure:
            raise SandboxUnavailableError(
                f"Bubblewrap deployment preflight failed: {reason} Fail-closed: cannot start autonomous task."
            )
        return result
    checks["bwrap_binary_trusted"] = True

    host_ns = _read_proc_ns(("mnt", "pid", "ipc", "uts", "net", "user"))
    package_root = Path(__file__).resolve().parent.parent
    gov_targets: List[str] = []
    if ws_root and ws_root.is_dir():
        for name in GOVERNANCE_DIR_NAMES:
            cand = ws_root / name
            if cand.exists():
                gov_targets.append(str(cand))
        active_state = ws_root / "controls" / "ACTIVE_STATE.json"
        if active_state.is_file():
            gov_targets.append(str(active_state))
        agents_md = ws_root / "AGENTS.md"
        if agents_md.is_file():
            gov_targets.append(str(agents_md))

    home_dir = Path.home().resolve()
    cred_targets = [
        str((home_dir / rel).resolve())
        for rel in SENSITIVE_HOME_RELPATHS
        if (home_dir / rel).exists()
        and not _is_relative_to(cwd, (home_dir / rel).resolve())
        and not _is_relative_to(Path(sys.prefix).resolve(), (home_dir / rel).resolve())
    ]

    probe_spec = json.dumps({
        "host_ns": host_ns,
        "host_pid": os.getpid(),
        "is_non_root": bool(hasattr(os, "geteuid") and os.geteuid() != 0),
        "gov_targets": gov_targets,
        "package_root": str(package_root),
        "cred_targets": cred_targets,
        "require_net": require_network_isolation,
    })

    probe_code = (
        "import json, os, pathlib, socket, sys\n"
        "spec = json.loads(sys.argv[1])\n"
        "out = {'checks': {}, 'failures': []}\n"
        "host_ns = spec['host_ns']\n"
        "required_ns = ['mnt', 'pid', 'ipc', 'uts']\n"
        "if spec['require_net']: required_ns.append('net')\n"
        "if spec['is_non_root']: required_ns.append('user')\n"
        "ns_ok = True\n"
        "for n in required_ns:\n"
        "    p = f'/proc/self/ns/{n}'\n"
        "    if not os.path.exists(p) or os.readlink(p) == host_ns.get(n):\n"
        "        ns_ok = False\n"
        "        out['failures'].append(f'namespace {n} not isolated')\n"
        "if os.getpid() > 2 or os.getpid() == spec['host_pid']:\n"
        "    ns_ok = False\n"
        "    out['failures'].append(f'pid namespace inactive (pid={os.getpid()})')\n"
        "out['checks']['namespaces_isolated'] = ns_ok\n"
        "def is_ro_path(path_str):\n"
        "    p = pathlib.Path(path_str)\n"
        "    probe = (p / '.bwrap_ro_probe') if p.is_dir() else p\n"
        "    try:\n"
        "        with open(probe, 'ab'):\n"
        "            pass\n"
        "        return False\n"
        "    except OSError:\n"
        "        return True\n"
        "root_ro = is_ro_path('/')\n"
        "if not root_ro: out['failures'].append('/ is writable inside sandbox')\n"
        "out['checks']['root_readonly'] = root_ro\n"
        "gov_ok = all(is_ro_path(t) for t in spec['gov_targets'])\n"
        "if not gov_ok: out['failures'].append('governance path writable inside sandbox')\n"
        "out['checks']['governance_readonly'] = gov_ok\n"
        "pkg_ok = is_ro_path(spec['package_root'])\n"
        "if not pkg_ok: out['failures'].append('stagecheck package writable inside sandbox')\n"
        "out['checks']['package_readonly'] = pkg_ok\n"
        "cred_ok = True\n"
        "for c in spec['cred_targets']:\n"
        "    cp = pathlib.Path(c)\n"
        "    if cp.is_dir() and any(cp.iterdir()):\n"
        "        cred_ok = False\n"
        "        out['failures'].append(f'credential directory unmasked: {c}')\n"
        "    elif cp.is_file() and cp.stat().st_size > 0:\n"
        "        cred_ok = False\n"
        "        out['failures'].append(f'credential file unmasked: {c}')\n"
        "out['checks']['credentials_masked'] = cred_ok\n"
        "net_ok = True\n"
        "if spec['require_net']:\n"
        "    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
        "    try:\n"
        "        s.connect(('1.1.1.1', 53))\n"
        "        net_ok = False\n"
        "        out['failures'].append('external network reachable despite --unshare-net')\n"
        "    except OSError:\n"
        "        net_ok = True\n"
        "    finally:\n"
        "        s.close()\n"
        "out['checks']['network_unshared'] = net_ok\n"
        "print(json.dumps(out))\n"
    )

    policy = SandboxPolicy(
        working_directory=cwd,
        workspace_root=ws_root,
        allow_cwd_write=False,
        unshare_pid=True,
        unshare_ipc=True,
        unshare_net=require_network_isolation,
        unshare_uts=True,
        drop_caps=True,
        mask_home_credentials=True,
        mask_governance_dirs=False,
    )
    wrapped = build_bwrap_argv(
        exec_argv=[sys.executable, "-c", probe_code, probe_spec],
        policy=policy,
        bwrap_bin=bwrap_bin,
    )
    # Explicitly add --unshare-user for non-root user-namespace availability verification
    if hasattr(os, "geteuid") and os.geteuid() != 0 and "--unshare-user" not in wrapped:
        sep_idx = wrapped.index("--")
        wrapped.insert(sep_idx, "--unshare-user")

    try:
        proc = _REAL_SUBPROCESS_RUN(
            wrapped,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except Exception as err:
        reason = f"Bubblewrap preflight subprocess error: {err}"
        failures.append(reason)
        res = IsolationPreflightResult(False, bwrap_bin, checks, failures, reason)
        if raise_on_failure:
            raise SandboxUnavailableError(
                f"Bubblewrap deployment preflight failed: {reason} Fail-closed: cannot start autonomous task."
            )
        return res

    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or f"exit {proc.returncode}").strip()
        reason = f"Bubblewrap namespace execution failed: {detail}"
        failures.append(reason)
        res = IsolationPreflightResult(False, bwrap_bin, checks, failures, reason)
        if raise_on_failure:
            raise SandboxUnavailableError(
                f"Bubblewrap deployment preflight failed: {reason} Fail-closed: cannot start autonomous task."
            )
        return res

    try:
        parsed = json.loads(proc.stdout.strip().splitlines()[-1])
    except Exception as err:
        reason = f"Malformed Bubblewrap preflight probe output: {err}"
        failures.append(reason)
        res = IsolationPreflightResult(False, bwrap_bin, checks, failures, reason)
        if raise_on_failure:
            raise SandboxUnavailableError(
                f"Bubblewrap deployment preflight failed: {reason} Fail-closed: cannot start autonomous task."
            )
        return res

    for k, v in parsed.get("checks", {}).items():
        if k in checks:
            checks[k] = bool(v)
    failures.extend(str(f) for f in parsed.get("failures", []))

    passed = all(checks.values()) and not failures
    reason = (
        "Bubblewrap deployment preflight passed (trusted bwrap, namespaces, RO root/governance/package, credential masking, net unshared)."
        if passed
        else "; ".join(failures) or "Bubblewrap deployment preflight check failed."
    )
    res = IsolationPreflightResult(passed, bwrap_bin, checks, failures, reason)
    if not passed and raise_on_failure:
        raise SandboxUnavailableError(
            f"Bubblewrap deployment preflight failed: {reason} Fail-closed: cannot start autonomous task."
        )
    return res


def _cli_main(argv: Optional[Sequence[str]] = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="StageCheck Bubblewrap isolation preflight")
    parser.add_argument("--preflight", action="store_true", help="Run Bubblewrap deployment preflight check.")
    parser.add_argument("--workspace", type=str, default=None, help="Optional workspace root to check RO governance.")
    parser.add_argument("--json", action="store_true", dest="output_json", help="Emit JSON result.")
    args = parser.parse_args(argv)

    if not args.preflight:
        parser.print_help()
        return 2

    ws = Path(args.workspace).resolve() if args.workspace else find_workspace_root_for_cwd(Path.cwd())
    res = run_bwrap_deployment_preflight(workspace_root=ws, raise_on_failure=False)
    if args.output_json:
        print(json.dumps(res.to_dict(), indent=2))
    else:
        status = "PASS" if res.passed else "FAIL"
        print(f"[ISOLATION PREFLIGHT: {status}] {res.reason}")
    return 0 if res.passed else 126


if __name__ == "__main__":
    raise SystemExit(_cli_main())
