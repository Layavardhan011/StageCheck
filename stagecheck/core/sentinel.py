"""Event-Driven Continuous Sentinel Daemon & 4-Tier Boundary Watcher (P4-T1).

Runs autonomous workspace supervision using Linux Kernel inotify + select.epoll:
- Zero idle CPU and <25MB RSS memory profile
- 4-Tier event router (Governance guard, Cache filter, Evidence lifecycle, Scope monitor)
- Advisory PID lifecycle with symlink protection and stale PID auto-recovery
- Desktop notifications via notify-send with HTML/D-Bus escaping (SEC-H1)
- Single-agent transparency logging (SEC-07)
"""

from __future__ import annotations

import ctypes
import datetime
import html
import json
import os
import re
import select
import signal
import stat
import struct
import subprocess
import sys
import time
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union


class SentinelError(Exception):
    """Base error for Sentinel daemon operations."""


class StalePidError(SentinelError):
    """Raised when a stale PID file is detected."""


class PidConflictError(SentinelError):
    """Raised when PID file is owned by another process or user."""


# Linux inotify constants
IN_CLOEXEC = 0o2000000
IN_NONBLOCK = 0o0004000
IN_MODIFY = 0x00000002
IN_CREATE = 0x00000100
IN_DELETE = 0x00000200
IN_MOVED_FROM = 0x00000040
IN_MOVED_TO = 0x00000080
IN_ISDIR = 0x40000000
IN_Q_OVERFLOW = 0x00004000

WATCH_MASK = IN_MODIFY | IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO


# Tier 1 Governance Paths
TIER_1_PREFIXES = (
    "controls/",
    "specs/",
    "stagecheck/",
    "AGENTS.md",
    "evidence/EVIDENCE_MANIFEST.json",
)

# Critical Git Controls monitored under Tier 1
TIER_1_GIT_SUFFIXES = (
    "/.git/config",
    "/.git/info/exclude",
    "/.git/hooks",
)

# Tier 2 Cache Noise Patterns (Silently dropped)
TIER_2_SUBSTRINGS = (
    "/.git/objects",
    "/.git/index",
    "/.git/logs",
    "/.stagecheck_worktrees",
    "/__pycache__",
    "/.pytest_cache",
    ".tmp.",
    ".swp",
    ".pyc",
    "sentinel.log",
    ".stagecheck_sentinel.pid",
)

# Directories pruned from recursive inotify traversal to save watches and memory
PRUNE_DIR_NAMES = {
    "objects",
    "logs",
    ".stagecheck_worktrees",
    "__pycache__",
    ".pytest_cache",
    "node_modules",
    "dist",
    "build",
    "vendor",
    ".venv",
    ".cache",
    ".tox",
    ".mypy_cache",
    ".ruff_cache",
}


def send_desktop_notification(
    title: str,
    message: str,
    urgency: str = "normal",
    icon: str = "dialog-information",
) -> None:
    """Send native Linux desktop notification via notify-send.

    Escapes HTML/D-Bus markup to prevent Pango injection vulnerabilities (SEC-H1).
    Fails silently if notify-send or desktop environment is absent.
    """
    safe_title = html.escape(str(title), quote=True)
    safe_message = html.escape(str(message), quote=True)

    cmd = [
        "notify-send",
        "--urgency", urgency,
        "--icon", icon,
        "--app-name", "StageCheck Sentinel",
        safe_title,
        safe_message,
    ]
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    except (FileNotFoundError, OSError):
        pass


def _is_path_in_scope(rel_path: str, declared_scope: Dict[str, Any]) -> bool:
    """Internal lightweight scope evaluator."""
    norm = rel_path.strip().replace("\\", "/")
    for forb in declared_scope.get("forbidden_paths", []):
        forb_norm = forb.strip().replace("\\", "/")
        prefix = forb_norm.rstrip("/*")
        if norm == forb_norm or (prefix and (norm == prefix or norm.startswith(prefix + "/"))) or fnmatch(norm, forb_norm):
            return False
    for allow in declared_scope.get("allowed_paths", []):
        allow_norm = allow.strip().replace("\\", "/")
        prefix = allow_norm.rstrip("/*")
        if norm == allow_norm or (prefix and (norm == prefix or norm.startswith(prefix + "/"))) or fnmatch(norm, allow_norm):
            return True
    return False


def get_process_rss_mib(pid: int) -> float:
    """Return current resident memory (RSS) for a process in MiB."""
    statm_path = Path(f"/proc/{pid}/statm")
    if not statm_path.is_file():
        return 0.0

    try:
        fields = statm_path.read_text(encoding="utf-8").split()
        if len(fields) < 2:
            return 0.0

        resident_pages = int(fields[1])
        page_size_bytes = os.sysconf("SC_PAGE_SIZE")
        rss_bytes = resident_pages * page_size_bytes
        return rss_bytes / (1024.0 * 1024.0)
    except (OSError, ValueError):
        return 0.0


def is_process_alive(pid: int) -> bool:
    """Check if process is alive and not a zombie/dead process."""
    if pid <= 1:
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False

    proc_status = Path(f"/proc/{pid}/status")
    if proc_status.is_file():
        try:
            for line in proc_status.read_text(encoding="utf-8").splitlines():
                if line.startswith("State:"):
                    state = line.split()[1]
                    if state.upper() in ("Z", "X"):
                        # Reaping child if directly owned
                        try:
                            os.waitpid(pid, os.WNOHANG)
                        except OSError:
                            pass
                        return False
                    break
        except OSError:
            return False
    return True


def classify_event_path(
    workspace_root: Union[str, Path],
    rel_path: str,
    declared_scope: Optional[Dict[str, Any]] = None,
    active_transaction: bool = False,
) -> Tuple[int, str]:
    """Route filesystem event through the 4-Tier Sentinel pipeline.

    Returns:
        Tuple of (tier_number, classification_label).
    """
    norm = rel_path.strip().replace("\\", "/")
    while norm.startswith("./"):
        norm = norm[2:]
    norm = norm.lstrip("/")

    # ----------------------------------------------------
    # Tier 1: Governance Guard & Critical Git Controls
    # ----------------------------------------------------
    is_tier_1 = False
    for pref in TIER_1_PREFIXES:
        if norm == pref.rstrip("/") or norm.startswith(pref):
            is_tier_1 = True
            break

    if not is_tier_1:
        for git_suff in TIER_1_GIT_SUFFIXES:
            if git_suff in norm or norm.endswith(git_suff):
                is_tier_1 = True
                break

    if is_tier_1:
        if active_transaction:
            return 1, "AUTHORIZED_TRANSACTION"
        return 1, "GOVERNANCE_BREACH"

    # ----------------------------------------------------
    # Tier 2: Build & Compiler Noise Filter
    # ----------------------------------------------------
    for cache_sub in TIER_2_SUBSTRINGS:
        clean_sub = cache_sub.lstrip("/")
        if cache_sub in norm or norm.startswith(clean_sub) or norm.endswith(cache_sub):
            return 2, "SILENT_DROP"

    # ----------------------------------------------------
    # Tier 3: Task Evidence Lifecycle Router
    # ----------------------------------------------------
    if norm.startswith("evidence/tasks/") or norm == "evidence/CODE_QUALITY_REPORT.json":
        if "Phase-1/prompt.md" in norm:
            return 3, "PROMPT_SUBMISSION"
        if "Phase-2A/pre_commit_status.json" in norm:
            return 3, "REVIEW_REQUEST"
        if "Phase-2B/claims.json" in norm or "Phase-2B/task_state.json" in norm:
            return 3, "DELIVERY_COMPLETE"
        return 3, "EVIDENCE_LIFECYCLE"

    # ----------------------------------------------------
    # Tier 4: Repository Scope Enforcement
    # ----------------------------------------------------
    if norm.startswith("repos/"):
        if declared_scope:
            if _is_path_in_scope(norm, declared_scope):
                return 4, "ALLOWED_SCOPE"
            return 4, "SCOPE_BREACH"
        return 4, "UNAUDITED_REPO_EVENT"

    return 4, "UNCLASSIFIED_EVENT"


class SentinelDaemon:
    """Continuous background supervisor managing inotify watches and PID state."""

    def __init__(self, workspace_root: Union[str, Path]) -> None:
        self.root = Path(workspace_root).resolve()
        self.pid_file = self.root / ".stagecheck_sentinel.pid"
        self.log_file = self.root / "evidence" / "sentinel.log"
        self._libc: Optional[ctypes.CDLL] = None
        self._inotify_fd: Optional[int] = None
        self._watch_descriptors: Dict[int, str] = {}
        self.last_activity_monotonic: float = time.monotonic()

        # Restore monotonic tracking from ACTIVE_STATE.json if present (DEC-027)
        state_file = self.root / "controls" / "ACTIVE_STATE.json"
        if state_file.is_file():
            try:
                from stagecheck.core.state import load_active_state
                state = load_active_state(self.root)
                last_ts_str = state.get("watchdog", {}).get("last_active_timestamp")
                if last_ts_str:
                    last_ts = datetime.datetime.fromisoformat(last_ts_str.replace("Z", "+00:00"))
                    now = datetime.datetime.now(datetime.timezone.utc)
                    elapsed = max(0.0, (now - last_ts).total_seconds())
                    self.last_activity_monotonic = time.monotonic() - elapsed
            except Exception:
                pass

    def _init_libc(self) -> None:
        if self._libc is None:
            import ctypes.util
            libc_name = ctypes.util.find_library("c") or "libc.so.6"
            try:
                self._libc = ctypes.CDLL(libc_name)
            except OSError:
                self._libc = ctypes.CDLL(None)

    def write_pid(self) -> None:
        """Write current PID atomically to .stagecheck_sentinel.pid with symlink defense (SEC-AA1)."""
        pid_path = self.pid_file

        # Check existing PID file for symlink attack
        if pid_path.is_symlink() or (pid_path.exists() and stat.S_ISLNK(os.lstat(str(pid_path)).st_mode)):
            raise SentinelError("Security violation: .stagecheck_sentinel.pid is a symbolic link.")

        # Atomic write via temporary file + rename to prevent race conditions
        temp_pid = pid_path.with_name(f".stagecheck_sentinel.pid.tmp.{os.getpid()}")
        flags = os.O_CREAT | os.O_WRONLY | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(str(temp_pid), flags, 0o644)
        try:
            os.write(fd, f"{os.getpid()}\n".encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)

        os.replace(str(temp_pid), str(pid_path))

    def read_pid(self) -> Optional[int]:
        """Read and validate PID from .stagecheck_sentinel.pid."""
        if not self.pid_file.exists():
            return None

        st = os.lstat(str(self.pid_file))
        if stat.S_ISLNK(st.st_mode):
            raise SentinelError("Security violation: .stagecheck_sentinel.pid is a symbolic link.")

        try:
            content = self.pid_file.read_text(encoding="utf-8").strip()
            return int(content) if content.isdigit() else None
        except Exception:
            return None

    def is_running(self) -> Tuple[bool, Optional[int]]:
        """Check whether the Sentinel daemon process is currently alive."""
        pid = self.read_pid()
        if not pid or pid <= 1:
            if self.pid_file.is_file() and not self.pid_file.is_symlink():
                try:
                    content = self.pid_file.read_text(encoding="utf-8").strip()
                    if not content.isdigit():
                        self.pid_file.unlink(missing_ok=True)
                except Exception:
                    pass
            return False, None

        if not is_process_alive(pid):
            # Stale PID file: auto-recover
            self.pid_file.unlink(missing_ok=True)
            return False, None

        return True, pid

    def start(self, daemon: bool = True, timeout: float = 10.0, ready_fd: Optional[int] = None) -> int:
        """Start the Sentinel daemon in background or foreground with IPC readiness protocol."""
        running, pid = self.is_running()
        if running:
            if not daemon and pid == os.getpid():
                # Already running as current process
                pass
            else:
                print(f"Sentinel daemon already running (PID {pid}).")
                return 0

        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / "evidence").mkdir(parents=True, exist_ok=True)

        # Transparency banner for single-agent mode
        state_file = self.root / "controls" / "ACTIVE_STATE.json"
        if state_file.is_file():
            try:
                from stagecheck.core.agents import load_registered_agents
                state_data = json.loads(state_file.read_text(encoding="utf-8"))
                agents = load_registered_agents(state_data)
                if len(agents) == 1:
                    print("[INFO] Single-Agent Mode Active: Independent AI review is NOT claimed.")
            except Exception:
                pass

        if daemon:
            r_pipe, w_pipe = os.pipe()
            os.set_inheritable(w_pipe, True)

            log_path = self.root / "evidence" / "sentinel_daemon.log"
            try:
                log_path.parent.mkdir(parents=True, exist_ok=True)
                if not log_path.exists():
                    log_path.touch(mode=0o644, exist_ok=True)
                else:
                    try:
                        os.chmod(str(log_path), 0o644)
                    except OSError:
                        pass
            except (PermissionError, OSError):
                try:
                    from stagecheck.core.permissions import controlled_write_transaction
                    with controlled_write_transaction(self.root / "evidence"):
                        log_path.touch(mode=0o644, exist_ok=True)
                        (self.root / "evidence" / "sentinel.log").touch(mode=0o644, exist_ok=True)
                except Exception:
                    pass

            # Launch Sentinel with a clean, isolated Python runtime.
            # -I: ignore Python environment variables and user site-packages
            # -S: do not initialize site-packages or sitecustomize
            # Execute this module by absolute file path so the daemon does not
            # depend on PYTHONPATH or the parent's imported Python environment.
            sentinel_script = Path(__file__).resolve()
            python_bin = os.path.realpath(sys.executable or "/usr/bin/python3")

            env = os.environ.copy()

            # Remove Python startup configuration inherited from pytest, IDEs,
            # application launchers, or other instrumented parent processes.
            for key in (
                "PYTHONPATH",
                "PYTHONHOME",
                "PYTHONSTARTUP",
                "PYTHONUSERBASE",
                "PYTHONINSPECT",
                "PYTHONPROFILEIMPORTTIME",
            ):
                env.pop(key, None)

            env["PYTHONNOUSERSITE"] = "1"

            cmd = [
                python_bin,
                "-I",
                "-S",
                str(sentinel_script),
                "--workspace",
                str(self.root),
                "--ready-fd",
                str(w_pipe),
            ]

            process: Optional[subprocess.Popen] = None
            try:
                with open(log_path, "ab", buffering=0) as daemon_log:
                    process = subprocess.Popen(
                        cmd,
                        stdin=subprocess.DEVNULL,
                        stdout=daemon_log,
                        stderr=daemon_log,
                        env=env,
                        cwd=str(self.root),
                        close_fds=True,
                        pass_fds=(w_pipe,),
                        start_new_session=True,
                    )

                os.close(w_pipe)
                w_pipe = -1

                deadline = time.monotonic() + timeout
                ready_data = b""

                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        break

                    remaining = max(0.01, deadline - time.monotonic())
                    readable, _, _ = select.select([r_pipe], [], [], min(remaining, 0.2))
                    if not readable:
                        continue

                    chunk = os.read(r_pipe, 1024)
                    if not chunk:
                        break

                    ready_data += chunk
                    if b"\n" in ready_data:
                        break

                marker = ready_data.decode("utf-8", errors="replace").strip()
                actual_pid = None
                if marker.startswith("READY "):
                    try:
                        actual_pid = int(marker.split()[1])
                    except (IndexError, ValueError):
                        actual_pid = None

                if actual_pid is not None and is_process_alive(actual_pid) and self.read_pid() == actual_pid:
                    print(f"Started StageCheck Sentinel daemon in background (PID {actual_pid}).")
                    return 0

                print(f"[FAIL] Sentinel daemon failed to initialize within {timeout:.1f}s.")
                if process and process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=2.0)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=2.0)

                if log_path.is_file():
                    try:
                        log_content = log_path.read_text(encoding="utf-8", errors="replace").strip()
                        if log_content:
                            print(f"Daemon process log:\n{log_content}")
                    except Exception:
                        pass

                return 1

            except Exception as exc:
                print(f"[FAIL] Sentinel startup error: {exc}")
                if process is not None and process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=2.0)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=2.0)
                return 1

            finally:
                if r_pipe >= 0:
                    try:
                        os.close(r_pipe)
                    except OSError:
                        pass
                if w_pipe >= 0:
                    try:
                        os.close(w_pipe)
                    except OSError:
                        pass
        else:
            def _handle_term(signum, frame):
                sys.exit(0)
            signal.signal(signal.SIGTERM, _handle_term)
            signal.signal(signal.SIGINT, _handle_term)
            print(f"Starting StageCheck Sentinel in foreground (PID {os.getpid()}). Press Ctrl+C to stop.")
            try:
                self._run_loop(ready_fd=ready_fd)
            except (KeyboardInterrupt, SystemExit):
                pass
            finally:
                self.pid_file.unlink(missing_ok=True)
            return 0

    def stop(self) -> int:
        """Gracefully terminate background Sentinel daemon."""
        running, pid = self.is_running()
        if not running or not pid:
            print("Sentinel daemon is not running.")
            return 0

        print(f"Stopping Sentinel daemon (PID {pid})...")
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass

        # Poll liveness for up to 5 seconds
        for _ in range(50):
            time.sleep(0.1)
            try:
                reaped, _ = os.waitpid(pid, os.WNOHANG)
                if reaped == pid:
                    break
            except OSError:
                pass
            if not is_process_alive(pid):
                break
        else:
            # Escalate to SIGKILL
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
            try:
                os.waitpid(pid, os.WNOHANG)
            except OSError:
                pass

        self.pid_file.unlink(missing_ok=True)
        print("Sentinel daemon stopped successfully.")
        return 0

    def status(self) -> Dict[str, Any]:
        """Query status, RSS memory footprint, and active task info."""
        running, pid = self.is_running()
        rss_mb = 0.0
        active_task = "None"
        single_agent = False

        state_file = self.root / "controls" / "ACTIVE_STATE.json"
        if state_file.is_file():
            try:
                from stagecheck.core.agents import load_registered_agents
                state_data = json.loads(state_file.read_text(encoding="utf-8"))
                active_task = state_data.get("task_id", "None")
                agents = load_registered_agents(state_data)
                single_agent = len(agents) == 1
            except Exception:
                pass

        if running and pid:
            rss_mb = get_process_rss_mib(pid)

        return {
            "running": running,
            "pid": pid,
            "rss_mb": round(rss_mb, 2),
            "active_task": active_task,
            "single_agent_mode": single_agent,
            "log_file": str(self.log_file),
        }

        return {
            "running": running,
            "pid": pid,
            "rss_mb": round(rss_mb, 2),
            "active_task": active_task,
            "single_agent_mode": single_agent,
            "log_file": str(self.log_file),
        }

    def _attach_recursive_watches(self) -> None:
        """Attach inotify watches across source and evidence directories, pruning noise."""
        if not self._libc or self._inotify_fd is None:
            return

        watch_roots = [
            self.root / "controls",
            self.root / "specs",
            self.root / "evidence",
            self.root / "repos",
        ]

        for target in watch_roots:
            if not target.is_dir():
                continue
            for cur_dir, dirnames, _ in os.walk(str(target)):
                # If a .git directory is found, prune it from recursive walking but watch critical control paths
                if ".git" in dirnames:
                    git_dir = Path(cur_dir) / ".git"
                    dirnames.remove(".git")
                    # Watch .git itself and hooks / info
                    for p in [git_dir, git_dir / "hooks", git_dir / "info"]:
                        if p.is_dir():
                            wd = self._libc.inotify_add_watch(self._inotify_fd, str(p).encode("utf-8"), WATCH_MASK)
                            if wd >= 0:
                                self._watch_descriptors[wd] = str(p)

                # Prune noise directories
                dirnames[:] = [d for d in dirnames if d not in PRUNE_DIR_NAMES and not d.endswith((".egg-info", ".dist-info"))]
                wd = self._libc.inotify_add_watch(
                    self._inotify_fd,
                    cur_dir.encode("utf-8"),
                    WATCH_MASK,
                )
                if wd >= 0:
                    self._watch_descriptors[wd] = cur_dir

    def _run_loop(self, ready_fd: Optional[int] = None) -> None:
        """Main event loop using Linux inotify and epoll."""
        self._init_libc()
        if not self._libc:
            sys.stderr.write("Failed to initialize libc for inotify.\n")
            sys.stderr.flush()
            if ready_fd is not None:
                try:
                    os.close(ready_fd)
                except OSError:
                    pass
            return

        self._inotify_fd = self._libc.inotify_init1(IN_NONBLOCK | IN_CLOEXEC)
        if self._inotify_fd < 0:
            err = ctypes.get_errno() if hasattr(ctypes, "get_errno") else -1
            sys.stderr.write(f"inotify_init1 failed with descriptor {self._inotify_fd} (errno: {err}).\n")
            sys.stderr.flush()
            if ready_fd is not None:
                try:
                    os.close(ready_fd)
                except OSError:
                    pass
            return

        self._attach_recursive_watches()
        import gc
        gc.collect()
        if hasattr(self._libc, "malloc_trim"):
            try:
                self._libc.malloc_trim(0)
            except Exception:
                pass

        # Write PID file atomically before notifying readiness
        self.write_pid()

        epoll = select.epoll()
        epoll.register(self._inotify_fd, select.EPOLLIN)

        # Notify parent process that watches are attached, PID is registered, and epoll is ready
        if ready_fd is not None:
            try:
                os.write(ready_fd, f"READY {os.getpid()}\n".encode("utf-8"))
            finally:
                try:
                    os.close(ready_fd)
                except OSError:
                    pass

        try:
            while True:
                try:
                    events = epoll.poll(timeout=1.0)
                except (InterruptedError, OSError):
                    break
                for fd, event in events:
                    if fd == self._inotify_fd and (event & select.EPOLLIN):
                        try:
                            data = os.read(self._inotify_fd, 4096)
                            self._process_inotify_buffer(data)
                        except BlockingIOError:
                            pass

                # Check watchdog periodically for active agent phases
                try:
                    from stagecheck.core.supervisor import evaluate_watchdog
                    evaluate_watchdog(self.root, timeout_seconds=600.0)
                except Exception:
                    pass
        finally:
            try:
                epoll.unregister(self._inotify_fd)
                epoll.close()
                os.close(self._inotify_fd)
            except OSError:
                pass

    def _process_inotify_buffer(self, buffer: bytes) -> None:
        """Parse inotify event structures from raw buffer."""
        offset = 0
        while offset + 16 <= len(buffer):
            wd, mask, cookie, length = struct.unpack_from("iIII", buffer, offset)
            offset += 16
            name = ""
            if length > 0:
                raw_name = buffer[offset : offset + length]
                name = raw_name.split(b"\0", 1)[0].decode("utf-8", errors="replace")
                offset += length

            parent_dir = self._watch_descriptors.get(wd, "")
            if parent_dir and name:
                full_path = Path(parent_dir) / name
                rel_path = str(full_path.relative_to(self.root))
                tier, label = classify_event_path(self.root, rel_path)
                self._log_event(rel_path, tier, label)

    def _log_event(self, rel_path: str, tier: int, label: str) -> None:
        """Append event to sentinel.log and update watchdog activity for relevant paths (FR-05 / DEC-027)."""
        if tier == 2 or rel_path.endswith("sentinel.log") or rel_path.endswith(".stagecheck_sentinel.pid"):
            return  # Silently drop Tier 2 and internal daemon log/pid files

        ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
        entry = f"[{ts}] [Tier {tier}] [{label}] {rel_path}\n"
        try:
            with self.log_file.open("a", encoding="utf-8") as f:
                f.write(entry)
        except OSError:
            pass

        # Relevant path filtering (FR-05 / Issue 4)
        from stagecheck.core.supervisor import is_relevant_sentinel_path
        if is_relevant_sentinel_path(rel_path):
            self.last_activity_monotonic = time.monotonic()
            try:
                state_file = self.root / "controls" / "ACTIVE_STATE.json"
                if state_file.is_file():
                    from stagecheck.core.permissions import controlled_write_transaction
                    from stagecheck.core.state import load_active_state, save_active_state
                    with controlled_write_transaction(self.root / "controls"):
                        state = load_active_state(self.root)
                        state.setdefault("watchdog", {})["last_active_timestamp"] = ts
                        save_active_state(self.root, state)
            except Exception:
                pass


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="StageCheck Sentinel Background Daemon Runner")
    parser.add_argument("--workspace", required=True, help="Workspace root path")
    parser.add_argument("--ready-fd", type=int, default=-1, help="Readiness notification pipe fd")
    args = parser.parse_args()

    daemon_inst = SentinelDaemon(args.workspace)
    ready_pipe = args.ready_fd if args.ready_fd >= 0 else None

    def _handle_term(signum, frame):
        sys.exit(0)

    signal.signal(signal.SIGTERM, _handle_term)
    signal.signal(signal.SIGINT, _handle_term)
    try:
        daemon_inst._run_loop(ready_fd=ready_pipe)
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        daemon_inst.pid_file.unlink(missing_ok=True)
    sys.exit(0)
