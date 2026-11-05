"""Pytest Configuration and Fixtures for StageCheck Test Suite.

Ensures the test environment has access to compliant tool stubs (e.g. gitleaks v8.18+)
via a controlled, portable test launcher that does NOT rely solely on Unix executable bits
and works reliably after clean archive extraction on any platform.
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path


def setup_test_scanner():
    """Configure portable test scanner launcher for the test harness."""
    from stagecheck.core.scanner import SecretScanner

    # If host has real Gitleaks (not inside tests/), verify and use if present
    host_gitleaks = shutil.which("gitleaks")
    if host_gitleaks and not SecretScanner.is_test_stub(host_gitleaks):
        # Host has native gitleaks installed
        return

    # Otherwise, configure the hermetic Python test stub launcher
    test_stub = Path(__file__).resolve().parent / "bin" / "gitleaks"
    if test_stub.is_file():
        try:
            os.chmod(test_stub, 0o755)
        except OSError:
            pass

        def test_launcher(cmd, env=None, timeout=30, cwd=None):
            # Execute python script directly via sys.executable
            # This is 100% portable and does not require Unix +x permissions!
            full_cmd = [sys.executable, str(test_stub)] + list(cmd[1:])
            return subprocess.run(
                full_cmd,
                env=env,
                capture_output=True,
                text=True,
                check=False,
                timeout=timeout,
                cwd=cwd,
            )

        SecretScanner.set_test_launcher(test_launcher, stub_path=test_stub, allow_test_stub=True)


def pytest_configure(config):
    """Pytest hook to initialize test environment fixtures."""
    setup_test_scanner()
