"""Pytest Configuration and Fixtures for StageCheck Test Suite.

Ensures the test environment has access to compliant tool stubs (e.g. gitleaks v8.18+)
when executing in environments without host system binary installations.
"""

import os
import shutil
from pathlib import Path

def pytest_configure(config):
    """Ensure tests/bin is in PATH if gitleaks is not present in system PATH."""
    tests_bin = Path(__file__).resolve().parent / "bin"
    current_path = os.environ.get("PATH", "")
    
    # If gitleaks is not resolvable or resolves to missing, prepend tests/bin
    gitleaks_bin = shutil.which("gitleaks")
    if not gitleaks_bin or not os.access(gitleaks_bin, os.X_OK):
        if tests_bin.is_dir() and str(tests_bin) not in current_path.split(os.pathsep):
            os.environ["PATH"] = f"{tests_bin}{os.pathsep}{current_path}"

