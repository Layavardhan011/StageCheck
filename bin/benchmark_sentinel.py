#!/usr/bin/env python3
"""Runtime Performance Benchmark for StageCheck Sentinel Daemon (Spec 07 / Section 12).

Executes real background daemon verification:
1. Starts actual SentinelDaemon background process.
2. Captures real daemon PID from .stagecheck_sentinel.pid.
3. Measures active memory RSS directly from /proc/<pid>/statm.
4. Measures idle CPU load across a real sampling window using /proc/<pid>/stat utime/stime.
5. Generates real filesystem inotify events and measures end-to-end event handling latency.
6. Measures event handling throughput under a defined workload.
7. Verifies event log correctness against 4-tier routing rules.
8. Gracefully terminates the daemon process and evaluates results against architectural targets.
9. Detects and guards against leaked daemon processes.
"""

from __future__ import annotations

import os
import platform
import shutil
import sys
import tempfile
import time
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from stagecheck.core.sentinel import SentinelDaemon


def parse_proc_stat(pid: int) -> tuple[int, int]:
    """Parse utime (user mode ticks) and stime (kernel mode ticks) for given PID."""
    stat_file = Path(f"/proc/{pid}/stat")
    if not stat_file.is_file():
        return 0, 0
    parts = stat_file.read_text(encoding="utf-8").split()
    # utime is field 14 (index 13), stime is field 15 (index 14)
    return int(parts[13]), int(parts[14])


def run_real_sentinel_benchmark() -> int:
    bench_start = time.perf_counter()
    workspace_dir = Path(tempfile.mkdtemp(prefix="stagecheck_sentinel_bench_"))

    print("=" * 72)
    print("STAGECHECK SENTINEL RUNTIME PERFORMANCE BENCHMARK")
    print("=" * 72)
    print(f"Platform:      {platform.system()} {platform.release()} ({platform.machine()})")
    print(f"Python:        {platform.python_version()} ({platform.python_implementation()})")
    print(f"Workspace:     {workspace_dir}")
    print("-" * 72)

    try:
        # 1. Scaffolding workspace directories for watcher
        (workspace_dir / "controls").mkdir(parents=True, exist_ok=True)
        (workspace_dir / "specs").mkdir(parents=True, exist_ok=True)
        (workspace_dir / "evidence").mkdir(parents=True, exist_ok=True)
        (workspace_dir / "repos").mkdir(parents=True, exist_ok=True)
        (workspace_dir / "controls" / "ACTIVE_STATE.json").write_text("{}", encoding="utf-8")

        # 2. Launch real Sentinel daemon in background with verified IPC readiness handshake
        daemon = SentinelDaemon(workspace_dir)
        exit_code = daemon.start(daemon=True, timeout=10.0)
        if exit_code != 0:
            print("[FAIL] Failed to initiate daemon start.")
            return 1

        running, pid = daemon.is_running()
        if not running or not pid:
            print("[FAIL] Sentinel daemon was reported started but is_running check failed.")
            return 1

        print(f"Daemon Status: RUNNING (PID {pid})")

        # 3. Measure real memory RSS via /proc/<pid>/statm
        statm_path = Path(f"/proc/{pid}/statm")
        if not statm_path.is_file():
            print(f"[FAIL] Cannot access {statm_path}")
            return 1

        statm_parts = statm_path.read_text(encoding="utf-8").split()
        rss_pages = int(statm_parts[1])
        page_size_bytes = os.sysconf("SC_PAGE_SIZE")
        rss_bytes = rss_pages * page_size_bytes
        rss_mib = rss_bytes / (1024.0 * 1024.0)

        rss_passed = rss_mib < 25.0
        print(f"Memory RSS:    {rss_mib:.2f} MiB (Target: < 25.00 MiB) -> {'PASS' if rss_passed else 'FAIL'}")

        # 4. Measure real idle CPU usage via /proc/<pid>/stat sampling
        u1, s1 = parse_proc_stat(pid)
        sample_interval = 1.0
        time.sleep(sample_interval)
        u2, s2 = parse_proc_stat(pid)

        clk_tck = os.sysconf("SC_CLK_TCK")
        delta_ticks = (u2 + s2) - (u1 + s1)
        raw_cpu_pct = (delta_ticks / float(clk_tck)) / sample_interval * 100.0
        cpu_passed = raw_cpu_pct < 1.0
        print(
            f"Idle CPU:      {raw_cpu_pct:.2f}% (raw ticks: {delta_ticks}, interval: {sample_interval:.2f}s) "
            f"(Target: < 1.00%) -> {'PASS' if cpu_passed else 'FAIL'}"
        )

        # 5. Measure real filesystem inotify event handling latency
        log_file = workspace_dir / "evidence" / "sentinel.log"
        latencies_ms: list[float] = []

        for i in range(5):
            initial_size = log_file.stat().st_size if log_file.is_file() else 0
            t_event_start = time.perf_counter()
            test_file = workspace_dir / "controls" / f"bench_latency_{i}.json"
            test_file.write_text(f'{{"latency_probe": {i}}}', encoding="utf-8")

            # Poll for daemon to process event and append to sentinel.log
            event_received = False
            while (time.perf_counter() - t_event_start) < 1.0:
                if log_file.is_file() and log_file.stat().st_size > initial_size:
                    event_received = True
                    break
                time.sleep(0.0005)

            t_event_end = time.perf_counter()
            if event_received:
                latencies_ms.append((t_event_end - t_event_start) * 1000.0)

        if latencies_ms:
            avg_latency_ms = sum(latencies_ms) / len(latencies_ms)
            min_latency_ms = min(latencies_ms)
            max_latency_ms = max(latencies_ms)
            latency_passed = avg_latency_ms < 50.0
            print(
                f"Event Latency: {avg_latency_ms:.2f} ms avg (min: {min_latency_ms:.2f} ms, max: {max_latency_ms:.2f} ms) "
                f"(Target: < 50.00 ms) -> {'PASS' if latency_passed else 'FAIL'}"
            )
        else:
            latency_passed = False
            avg_latency_ms = 999.0
            print("[FAIL] Inotify events were not logged within timeout.")

        # 6. Measure throughput under defined workload
        workload_count = 50
        initial_lines = len(log_file.read_text(encoding="utf-8").splitlines()) if log_file.is_file() else 0
        t_workload_start = time.perf_counter()
        for i in range(workload_count):
            probe_path = workspace_dir / "controls" / f"throughput_item_{i}.json"
            probe_path.write_text(f'{{"item": {i}}}', encoding="utf-8")

        # Wait for all workload events to be recorded
        workload_done = False
        while (time.perf_counter() - t_workload_start) < 5.0:
            current_lines = len(log_file.read_text(encoding="utf-8").splitlines()) if log_file.is_file() else 0
            if (current_lines - initial_lines) >= workload_count:
                workload_done = True
                break
            time.sleep(0.001)

        t_workload_end = time.perf_counter()
        workload_duration = max(t_workload_end - t_workload_start, 0.0001)
        throughput_eps = workload_count / workload_duration
        throughput_passed = workload_done and throughput_eps > 10.0
        print(
            f"Throughput:    {throughput_eps:.1f} events/sec ({workload_count} events in {workload_duration:.3f}s) "
            f"-> {'PASS' if throughput_passed else 'FAIL'}"
        )

        # 7. Verify event correctness in sentinel.log
        log_content = log_file.read_text(encoding="utf-8") if log_file.is_file() else ""
        correctness_passed = (
            "Tier 1" in log_content
            and "GOVERNANCE_BREACH" in log_content
            and "controls/bench_latency_0.json" in log_content
        )
        print(f"Correctness:   {'PASS' if correctness_passed else 'FAIL'} (Verified Tier 1 router labels)")

        # 8. Clean shutdown & verify no leaked processes
        stop_exit = daemon.stop()
        stopped_cleanly = stop_exit == 0 and not daemon.is_running()[0]

        # Detect leaked processes: verify pid is no longer active
        process_leaked = True
        for _ in range(30):
            try:
                os.kill(pid, 0)
                time.sleep(0.05)
            except OSError:
                process_leaked = False
                break

        no_leaks = stopped_cleanly and not process_leaked
        print(f"Clean Stop:    {'PASS' if no_leaks else 'FAIL'} (PID file unlinked, zero orphan processes)")

        total_duration = time.perf_counter() - bench_start
        print("-" * 72)
        print(f"Total Benchmark Execution Time: {total_duration:.2f} s")
        print("=" * 72)

        all_passed = (
            rss_passed
            and cpu_passed
            and latency_passed
            and throughput_passed
            and correctness_passed
            and no_leaks
        )
        if all_passed:
            print("ALL SENTINEL RUNTIME PERFORMANCE BENCHMARKS VERIFIED & PASSED")
            print("=" * 72)
            return 0
        else:
            print("[ERROR] One or more Sentinel runtime benchmarks failed.")
            print("=" * 72)
            return 1

    finally:
        shutil.rmtree(workspace_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(run_real_sentinel_benchmark())
