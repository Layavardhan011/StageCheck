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
) -> int:
    """Execute Sentinel lifecycle actions.

    Args:
        action: One of 'start', 'stop', 'status', 'logs'.
        daemon: Whether to run in background daemon mode.
        workspace: Optional workspace root directory path.

    Returns:
        0 on success, non-zero on failure.
    """
    workspace_root = Path(workspace).resolve() if workspace else Path.cwd().resolve()
    sentinel = SentinelDaemon(workspace_root)

    if action == "start":
        return sentinel.start(daemon=daemon)

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
        log_file = Path(sentinel.status()["log_file"])
        if not log_file.is_file():
            print(f"No Sentinel logs found at '{log_file}'.")
            return 0
        content = log_file.read_text(encoding="utf-8").strip()
        print(content if content else "Sentinel log file is empty.")
        return 0

    else:
        print(f"Unknown sentinel action '{action}'. Choices: start, stop, status, logs.", file=sys.stderr)
        return 1

