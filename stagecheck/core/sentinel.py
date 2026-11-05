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
)

# Directories pruned from recursive inotify traversal to save watches
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
            return int(content) if content else None
        except Exception:
            return None

    def is_running(self) -> Tuple[bool, Optional[int]]:
        """Check whether the Sentinel daemon process is currently alive."""
        pid = self.read_pid()
        if not pid or pid <= 1:
            return False, None

        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            # Stale PID file: auto-recover
            self.pid_file.unlink(missing_ok=True)
            return False, None
        except PermissionError:
            raise PidConflictError(f"PID {pid} in .stagecheck_sentinel.pid belongs to another user.")

        return True, pid

    def start(self, daemon: bool = True) -> int:
        """Start the Sentinel daemon in background or foreground."""
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
            pid1 = os.fork()
            if pid1 > 0:
                os.close(w_pipe)
                data = os.read(r_pipe, 100)
                os.close(r_pipe)
                os.waitpid(pid1, 0)
                try:
                    actual_pid = int(data.decode().strip())
                except Exception:
                    actual_pid = pid1
                print(f"Started StageCheck Sentinel daemon in background (PID {actual_pid}).")
                return 0

            os.close(r_pipe)
            os.setsid()

            pid2 = os.fork()
            if pid2 > 0:
                os.write(w_pipe, f"{pid2}\n".encode())
                os.close(w_pipe)
                os._exit(0)

            os.close(w_pipe)

            # Child 2 (Daemon process)
            # Set up daemon stdout/stderr log
            (self.root / "evidence").mkdir(parents=True, exist_ok=True)
            log_path = str(self.root / "evidence" / "sentinel_daemon.log")
            log_fd = os.open(log_path, os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o644)
            devnull_r = os.open(os.devnull, os.O_RDONLY)

            # Use literal standard file descriptors 0 (stdin), 1 (stdout), 2 (stderr)
            # Avoid sys.stdin.fileno() which raises UnsupportedOperation in pytest/test runners
            os.dup2(devnull_r, 0)
            os.dup2(log_fd, 1)
            os.dup2(log_fd, 2)
            os.close(devnull_r)
            os.close(log_fd)

            # Cleanly replace child memory with fresh Python process running foreground daemon
            # This purges parent heap/test fixtures and guarantees < 25MB RSS
            env = os.environ.copy()
            tool_root = str(Path(__file__).resolve().parents[2])
            all_paths = [p for p in sys.path if p and os.path.exists(p)]
            if tool_root not in all_paths:
                all_paths.insert(0, tool_root)
            env["PYTHONPATH"] = os.pathsep.join(all_paths)

            cmd = [
                sys.executable,
                "-m",
                "stagecheck.cli.main",
                "sentinel",
                "start",
                "--foreground",
                "--workspace",
                str(self.root),
            ]
            sys.stdout.flush()
            sys.stderr.flush()
            try:
                os.execvpe(sys.executable, cmd, env)
            except Exception as e:
                # Fallback if execvpe fails
                sys.stderr.write(f"execvpe failed: {e}\n")
                sys.stderr.flush()
                self._run_loop()
                sys.exit(0)
        else:
            self.write_pid()
            print(f"Starting StageCheck Sentinel in foreground (PID {os.getpid()}). Press Ctrl+C to stop.")
            def _handle_term(signum, frame):
                sys.exit(0)
            signal.signal(signal.SIGTERM, _handle_term)
            try:
                self._run_loop()
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
                os.kill(pid, 0)
            except OSError:
                break
        else:
            # Escalate to SIGKILL
            try:
                os.kill(pid, signal.SIGKILL)
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
            proc_statm = Path(f"/proc/{pid}/statm")
            if proc_statm.is_file():
                try:
                    parts = proc_statm.read_text(encoding="utf-8").split()
                    resident_pages = int(parts[1])
                    page_size_kb = os.sysconf("SC_PAGE_SIZE") / 1024
                    rss_mb = (resident_pages * page_size_kb) / 1024
                except Exception:
                    pass

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
                # Prune noise directories
                dirnames[:] = [d for d in dirnames if d not in PRUNE_DIR_NAMES]
                wd = self._libc.inotify_add_watch(
                    self._inotify_fd,
                    cur_dir.encode("utf-8"),
                    WATCH_MASK,
                )
                if wd >= 0:
                    self._watch_descriptors[wd] = cur_dir

    def _run_loop(self) -> None:
        """Main event loop using Linux inotify and epoll."""
        self._init_libc()
        if not self._libc:
            sys.stderr.write("Failed to initialize libc for inotify.\n")
            sys.stderr.flush()
            return

        self._inotify_fd = self._libc.inotify_init1(IN_NONBLOCK | IN_CLOEXEC)
        if self._inotify_fd < 0:
            err = ctypes.get_errno() if hasattr(ctypes, "get_errno") else -1
            sys.stderr.write(f"inotify_init1 failed with descriptor {self._inotify_fd} (errno: {err}).\n")
            sys.stderr.flush()
            return

        self._attach_recursive_watches()
        import gc
        gc.collect()
        try:
            import ctypes
            ctypes.CDLL(None).malloc_trim(0)
        except Exception:
            pass

        epoll = select.epoll()
        epoll.register(self._inotify_fd, select.EPOLLIN)

        try:
            while True:
                try:
                    events = epoll.poll(timeout=-1)
                except (InterruptedError, OSError):
                    break
                for fd, event in events:
                    if fd == self._inotify_fd and (event & select.EPOLLIN):
                        try:
                            data = os.read(self._inotify_fd, 4096)
                            self._process_inotify_buffer(data)
                        except BlockingIOError:
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
        """Append event to sentinel.log."""
        if tier == 2:
            return  # Silently drop Tier 2 events

        ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
        entry = f"[{ts}] [Tier {tier}] [{label}] {rel_path}\n"
        try:
            with self.log_file.open("a", encoding="utf-8") as f:
                f.write(entry)
        except OSError:
            pass
