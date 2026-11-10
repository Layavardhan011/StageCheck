"""Centralized Secret Scanner Execution Engine (Specs 08, 09, 14, SEC-L2, SEC-D4).

Enforces fail-closed security scanning with zero silent bypasses across all 9
scanner operational conditions.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from stagecheck.checks.base import Defect


class ScannerStatus(str, Enum):
    """Explicit status model for secret scanner execution (Spec 08, 09, 14, SEC-L2)."""

    PASS = "PASS"
    FINDINGS = "FINDINGS"
    SCANNER_UNAVAILABLE = "SCANNER_UNAVAILABLE"
    SCANNER_ERROR = "SCANNER_ERROR"
    SCANNER_TIMEOUT = "SCANNER_TIMEOUT"
    INVALID_SCANNER_OUTPUT = "INVALID_SCANNER_OUTPUT"


@dataclass
class ScanExecutionResult:
    """Result of executing the secret scanner."""

    is_clear: bool
    defects: List[Defect]
    status: ScannerStatus = ScannerStatus.PASS
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0


class SecretScanner:
    """Authoritative Gitleaks scanner execution wrapper.
    
    Guarantees fail-closed enforcement across:
    1. Scanner missing
    2. Scanner version mismatch
    3. Scanner cannot execute
    4. Permission denied
    5. Scanner timeout
    6. Scanner exits unexpectedly
    7. Secret detected
    8. Scan succeeds with no findings
    9. Scanner output malformed
    """

    DEFAULT_TIMEOUT_SECONDS = 30
    MIN_MAJOR_VERSION = 8
    MIN_MINOR_VERSION = 18

    _test_launcher: Optional[Any] = None
    _allow_test_stub: bool = False
    _test_stub_path: Optional[Path] = None

    def __init__(self, binary_override: Optional[str] = None):
        self.binary_override = binary_override

    @classmethod
    def set_test_launcher(
        cls,
        launcher: Optional[Any],
        stub_path: Optional[Path] = None,
        allow_test_stub: bool = True,
    ) -> None:
        """Register a controlled test launcher for test harnesses (Item 2)."""
        cls._test_launcher = launcher
        cls._test_stub_path = stub_path
        cls._allow_test_stub = allow_test_stub

    @classmethod
    def reset_test_launcher(cls) -> None:
        """Reset test launcher to production fail-closed defaults."""
        cls._test_launcher = None
        cls._test_stub_path = None
        cls._allow_test_stub = False

    @classmethod
    def is_test_stub(cls, path_str: Optional[str]) -> bool:
        """Identify if a binary path is an unverified test fixture stub."""
        if not path_str:
            return False
        norm = str(path_str).replace("\\", "/")
        return (
            "/tests/bin/" in norm
            or norm.startswith("tests/bin/")
            or "gitleaks[test-fixture]" in norm
            or "test_stub" in norm
        )

    @classmethod
    def resolve_config_flags(cls, repo_dir: Optional[Path] = None) -> List[str]:
        """Locate authoritative packaged Gitleaks config and fail closed if absent (SEC-03)."""
        pkg_candidate = Path(__file__).resolve().parent.parent / "config" / ".gitleaks.toml"
        if pkg_candidate.is_file():
            return [f"--config={pkg_candidate}"]

        try:
            from stagecheck.core.portability import resolve_asset_path
            pkg_root = Path(__file__).resolve().parents[2]
            asset_path = resolve_asset_path("config/.gitleaks.toml", fallback_root=pkg_root)
            if asset_path.is_file():
                return [f"--config={asset_path}"]
        except Exception:
            pass

        raise FileNotFoundError(
            f"Authoritative packaged Gitleaks config missing at '{pkg_candidate}'. Failing closed."
        )

    def resolve_binary(self) -> Optional[str]:
        """Resolve path to the scanner executable."""
        if self.binary_override:
            if not self._allow_test_stub and self.is_test_stub(self.binary_override):
                return None
            return self.binary_override

        # Check if shutil.which is patched by a test fixture
        if hasattr(shutil.which, "mock_calls"):
            mocked_res = shutil.which("gitleaks")
            if not mocked_res:
                return None
            if not self._allow_test_stub and self.is_test_stub(mocked_res):
                return None
            return mocked_res

        found = shutil.which("gitleaks")
        if found:
            # Production mode: refuse any test stub accidentally placed in PATH
            if not self._allow_test_stub and self.is_test_stub(found):
                return None
            return found

        if self._allow_test_stub and self._test_stub_path and self._test_stub_path.is_file():
            return str(self._test_stub_path)

        return None

    def _execute_cmd(
        self,
        cmd: List[str],
        env: Optional[Dict[str, str]] = None,
        timeout: int = 30,
        cwd: Optional[Path] = None,
    ) -> subprocess.CompletedProcess:
        """Execute scanner command via registered test launcher or real subprocess."""
        launcher = self.__class__._test_launcher
        if launcher is not None:
            return launcher(cmd, env=env, timeout=timeout, cwd=cwd)

        return subprocess.run(
            cmd,
            env=env,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
            cwd=cwd,
        )

    def verify_scanner_binary(self, stage: str = "preflight") -> Tuple[bool, List[Defect]]:
        """Verify presence, permissions, and pinned version (v8.18+) of gitleaks binary."""
        binary = self.resolve_binary()
        if not binary:
            return False, [
                Defect(
                    defect_id="preflight.gitleaks_missing",
                    message="Gitleaks scanner binary not found in PATH.",
                    stage=stage,
                    severity="CRITICAL",
                    blocking=True,
                )
            ]

        if self.__class__._test_launcher is None:
            if not os.path.isfile(binary) or not os.access(binary, os.X_OK):
                return False, [
                    Defect(
                        defect_id="preflight.gitleaks_permission_denied",
                        message=f"Gitleaks binary at '{binary}' is not executable (Permission denied).",
                        stage=stage,
                        severity="CRITICAL",
                        blocking=True,
                    )
                ]

        try:
            res = self._execute_cmd([binary, "version"], timeout=10)
            if res.returncode != 0:
                return False, [
                    Defect(
                        defect_id="preflight.gitleaks_execution_failed",
                        message=f"Gitleaks version check exited unexpectedly with code {res.returncode}.",
                        stage=stage,
                        severity="CRITICAL",
                        blocking=True,
                    )
                ]

            match = re.search(r"v?([0-9]+)\.([0-9]+)\.([0-9]+)", res.stdout)
            if not match:
                return False, [
                    Defect(
                        defect_id="preflight.gitleaks_output_malformed",
                        message=f"Gitleaks version output could not be parsed: '{res.stdout.strip()}'.",
                        stage=stage,
                        severity="CRITICAL",
                        blocking=True,
                    )
                ]

            major, minor = int(match.group(1)), int(match.group(2))
            if major != self.MIN_MAJOR_VERSION or minor < self.MIN_MINOR_VERSION:
                return False, [
                    Defect(
                        defect_id="preflight.gitleaks_version_incompatible",
                        message=f"Installed Gitleaks version '{res.stdout.strip()}' does not satisfy requirement (v8.18+).",
                        stage=stage,
                        severity="CRITICAL",
                        blocking=True,
                    )
                ]

            return True, []

        except subprocess.TimeoutExpired:
            return False, [
                Defect(
                    defect_id="preflight.gitleaks_timeout",
                    message="Gitleaks version check timed out.",
                    stage=stage,
                    severity="CRITICAL",
                    blocking=True,
                )
            ]
        except PermissionError as err:
            return False, [
                Defect(
                    defect_id="preflight.gitleaks_permission_denied",
                    message=f"Permission denied executing Gitleaks binary: {err}",
                    stage=stage,
                    severity="CRITICAL",
                    blocking=True,
                )
            ]
        except (FileNotFoundError, OSError) as err:
            return False, [
                Defect(
                    defect_id="preflight.gitleaks_cannot_execute",
                    message=f"Cannot execute Gitleaks binary: {err}",
                    stage=stage,
                    severity="CRITICAL",
                    blocking=True,
                )
            ]

    def scan_commit_range(
        self,
        repo_dir: Path,
        base_commit: str,
        target_commit: str,
        repo_name: str,
        stage: str = "secrets",
        timeout: int = DEFAULT_TIMEOUT_SECONDS,
    ) -> ScanExecutionResult:
        """Scan commits between base_commit and target_commit for secrets."""
        # 1. Preflight binary check
        is_valid, binary_defects = self.verify_scanner_binary(stage=stage)
        if not is_valid:
            status = ScannerStatus.SCANNER_UNAVAILABLE
            for d in binary_defects:
                if "output_malformed" in d.defect_id:
                    status = ScannerStatus.INVALID_SCANNER_OUTPUT
                elif "timeout" in d.defect_id:
                    status = ScannerStatus.SCANNER_TIMEOUT
                elif "execution_failed" in d.defect_id:
                    status = ScannerStatus.SCANNER_ERROR

            mapped_defects = [
                Defect(
                    defect_id=d.defect_id.replace("preflight.gitleaks_", "secrets.scanner_"),
                    message=f"{d.message} (repo '{repo_name}')",
                    stage=stage,
                    severity="CRITICAL",
                    blocking=True,
                    repo=repo_name,
                )
                for d in binary_defects
            ]
            return ScanExecutionResult(is_clear=False, defects=mapped_defects, status=status)

        binary = self.resolve_binary()
        try:
            config_flags = self.resolve_config_flags(repo_dir)
        except FileNotFoundError as err:
            return ScanExecutionResult(
                is_clear=False,
                defects=[
                    Defect(
                        defect_id="secrets.config_missing",
                        message=str(err),
                        stage=stage,
                        severity="CRITICAL",
                        blocking=True,
                        repo=repo_name,
                    )
                ],
                status=ScannerStatus.SCANNER_ERROR,
            )
        cmd = [
            binary,
            "detect",
            f"--source={repo_dir}",
            f"--log-opts={base_commit}..{target_commit}",
            *config_flags,
            "--verbose",
            "--no-banner",
        ]

        # Sanitized clean environment (purge GITLEAKS_* vars per SEC-Q1)
        env = {k: v for k, v in os.environ.items() if not k.startswith("GITLEAKS_")}

        try:
            res = self._execute_cmd(
                cmd,
                env=env,
                timeout=timeout,
                cwd=repo_dir,
            )

            # Condition 7: Secret detected (exit code 1)
            if res.returncode == 1:
                return ScanExecutionResult(
                    is_clear=False,
                    defects=[
                        Defect(
                            defect_id="secrets.detected_credential",
                            message=f"Secret credentials detected in '{repo_name}' commit history:\n{res.stdout.strip()[:200]}",
                            stage=stage,
                            severity="CRITICAL",
                            blocking=True,
                            repo=repo_name,
                        )
                    ],
                    status=ScannerStatus.FINDINGS,
                    stdout=res.stdout,
                    stderr=res.stderr,
                    returncode=res.returncode,
                )

            # Condition 8: Scan succeeds with no findings (exit code 0)
            if res.returncode == 0:
                return ScanExecutionResult(
                    is_clear=True,
                    defects=[],
                    status=ScannerStatus.PASS,
                    stdout=res.stdout,
                    stderr=res.stderr,
                    returncode=0,
                )

            # Condition 6: Scanner exits unexpectedly (exit code != 0 and != 1)
            return ScanExecutionResult(
                is_clear=False,
                defects=[
                    Defect(
                        defect_id="secrets.scanner_unexpected_exit",
                        message=f"Gitleaks exited unexpectedly with code {res.returncode} for repo '{repo_name}'.",
                        stage=stage,
                        severity="CRITICAL",
                        blocking=True,
                        repo=repo_name,
                    )
                ],
                status=ScannerStatus.SCANNER_ERROR,
                stdout=res.stdout,
                stderr=res.stderr,
                returncode=res.returncode,
            )

        except subprocess.TimeoutExpired:
            return ScanExecutionResult(
                is_clear=False,
                defects=[
                    Defect(
                        defect_id="secrets.scanner_timeout",
                        message=f"Gitleaks scan timed out after {timeout}s on repo '{repo_name}'.",
                        stage=stage,
                        severity="CRITICAL",
                        blocking=True,
                        repo=repo_name,
                    )
                ],
                status=ScannerStatus.SCANNER_TIMEOUT,
            )
        except PermissionError as err:
            return ScanExecutionResult(
                is_clear=False,
                defects=[
                    Defect(
                        defect_id="secrets.scanner_permission_denied",
                        message=f"Permission denied executing scanner on '{repo_name}': {err}",
                        stage=stage,
                        severity="CRITICAL",
                        blocking=True,
                        repo=repo_name,
                    )
                ],
                status=ScannerStatus.SCANNER_UNAVAILABLE,
            )
        except OSError as err:
            return ScanExecutionResult(
                is_clear=False,
                defects=[
                    Defect(
                        defect_id="secrets.scanner_cannot_execute",
                        message=f"Error executing scanner on '{repo_name}': {err}",
                        stage=stage,
                        severity="CRITICAL",
                        blocking=True,
                        repo=repo_name,
                    )
                ],
                status=ScannerStatus.SCANNER_UNAVAILABLE,
            )

    def scan_staged_changes(
        self,
        repo_dir: Path,
        repo_name: str,
        timeout: int = DEFAULT_TIMEOUT_SECONDS,
    ) -> ScanExecutionResult:
        """Scan staged changes before commit authorization (Spec 14 / SEC-M1)."""
        is_valid, binary_defects = self.verify_scanner_binary(stage="pre_commit")
        if not is_valid:
            status = ScannerStatus.SCANNER_UNAVAILABLE
            for d in binary_defects:
                if "output_malformed" in d.defect_id:
                    status = ScannerStatus.INVALID_SCANNER_OUTPUT
                elif "timeout" in d.defect_id:
                    status = ScannerStatus.SCANNER_TIMEOUT
                elif "execution_failed" in d.defect_id:
                    status = ScannerStatus.SCANNER_ERROR

            mapped_defects = [
                Defect(
                    defect_id=d.defect_id.replace("preflight.gitleaks_", "pre_commit.scanner_"),
                    message=f"{d.message} (staged scan for '{repo_name}')",
                    stage="pre_commit",
                    severity="CRITICAL",
                    blocking=True,
                    repo=repo_name,
                )
                for d in binary_defects
            ]
            return ScanExecutionResult(is_clear=False, defects=mapped_defects, status=status)

        binary = self.resolve_binary()
        try:
            config_flags = self.resolve_config_flags(repo_dir)
        except FileNotFoundError as err:
            return ScanExecutionResult(
                is_clear=False,
                defects=[
                    Defect(
                        defect_id="pre_commit.scanner_config_missing",
                        message=str(err),
                        stage="pre_commit",
                        severity="CRITICAL",
                        blocking=True,
                        repo=repo_name,
                    )
                ],
                status=ScannerStatus.SCANNER_ERROR,
            )
        cmd = [
            binary,
            "protect",
            "--staged",
            f"--source={repo_dir}",
            *config_flags,
            "--verbose",
            "--no-banner",
        ]
        env = {k: v for k, v in os.environ.items() if not k.startswith("GITLEAKS_")}

        try:
            res = self._execute_cmd(
                cmd,
                env=env,
                timeout=timeout,
                cwd=repo_dir,
            )
            if res.returncode == 1:
                return ScanExecutionResult(
                    is_clear=False,
                    defects=[
                        Defect(
                            defect_id="pre_commit.staged_secret_detected",
                            message=f"Secret detected in staged changes for repo '{repo_name}'.",
                            stage="pre_commit",
                            severity="CRITICAL",
                            blocking=True,
                            repo=repo_name,
                        )
                    ],
                    status=ScannerStatus.FINDINGS,
                    stdout=res.stdout,
                    stderr=res.stderr,
                    returncode=1,
                )
            if res.returncode == 0:
                return ScanExecutionResult(is_clear=True, defects=[], status=ScannerStatus.PASS, stdout=res.stdout, stderr=res.stderr)

            return ScanExecutionResult(
                is_clear=False,
                defects=[
                    Defect(
                        defect_id="pre_commit.scanner_unexpected_exit",
                        message=f"Gitleaks staged scan exited with code {res.returncode}.",
                        stage="pre_commit",
                        severity="CRITICAL",
                        blocking=True,
                        repo=repo_name,
                    )
                ],
                status=ScannerStatus.SCANNER_ERROR,
            )
        except subprocess.TimeoutExpired:
            return ScanExecutionResult(
                is_clear=False,
                defects=[
                    Defect(
                        defect_id="pre_commit.scanner_timeout",
                        message="Pre-commit staged secret scan timed out.",
                        stage="pre_commit",
                        severity="CRITICAL",
                        blocking=True,
                        repo=repo_name,
                    )
                ],
                status=ScannerStatus.SCANNER_TIMEOUT,
            )
        except Exception as err:
            return ScanExecutionResult(
                is_clear=False,
                defects=[
                    Defect(
                        defect_id="pre_commit.scanner_execution_error",
                        message=f"Failed to execute staged secret scan: {err}",
                        stage="pre_commit",
                        severity="CRITICAL",
                        blocking=True,
                        repo=repo_name,
                    )
                ],
                status=ScannerStatus.SCANNER_ERROR,
            )

