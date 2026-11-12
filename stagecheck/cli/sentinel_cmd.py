"""Sentinel CLI Command Handler: 'stagecheck sentinel' (P4-T1).

Provides lifecycle commands: start, stop, status, and logs.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

from stagecheck.core.sentinel import SentinelDaemon


def run_sentinel(
    action: str,
    daemon: bool = True,
    workspace: Optional[str] = None,
    ready_fd: Optional[int] = None,
) -> int:
    """Execute Sentinel lifecycle actions.

    Args:
        action: One of 'start', 'stop', 'status', 'logs'.
        daemon: Whether to run in background daemon mode.
        workspace: Optional workspace root directory path.
        ready_fd: Optional readiness notification pipe fd.

    Returns:
        0 on success, non-zero on failure.
    """
    workspace_root = Path(workspace).resolve() if workspace else Path.cwd().resolve()
    sentinel = SentinelDaemon(workspace_root)

    if action == "start":
        return sentinel.start(daemon=daemon, ready_fd=ready_fd)

    elif action == "stop":
        return sentinel.stop()

    elif action == "status":
        info = sentinel.status()
        state_str = "RUNNING" if info["running"] else "STOPPED"
        print(f"StageCheck Sentinel: {state_str}")
        if info["running"]:
            print(f"  PID:               {info['pid']}")
            print(f"  RSS Memory:        {info['rss_mb']} MB (Limit: < 25MB)")
            print(f"  Active Task:       {info['active_task']}")
            print(f"  Single-Agent Mode: {info['single_agent_mode']}")
            print(f"  Logs:              {info['log_file']}")
        return 0

    elif action == "logs":
        import os
        log_file = Path(sentinel.status()["log_file"])
        if log_file.is_symlink():
            print(f"ERROR: Sentinel log '{log_file}' is a symbolic link.", file=sys.stderr)
            return 1
        if not log_file.is_file():
            print(f"No Sentinel logs found at '{log_file}'.")
            return 0
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(str(log_file), flags)
        with os.fdopen(fd, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            offset = max(0, size - 65536)
            f.seek(offset, os.SEEK_SET)
            raw = f.read()
        if offset > 0 and b"\n" in raw:
            raw = raw.split(b"\n", 1)[1]
        lines = raw.decode("utf-8", errors="replace").split("\n")[-200:]
        content = "\n".join(lines).strip()
        print(content if content else "Sentinel log file is empty.")
        return 0

    else:
        print(f"Unknown sentinel action '{action}'. Choices: start, stop, status, logs.", file=sys.stderr)
        return 1

