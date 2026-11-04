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
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from stagecheck.checks.base import Defect


@dataclass
class ScanExecutionResult:
    """Result of executing the secret scanner."""

    is_clear: bool
    defects: List[Defect]
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

    def __init__(self, binary_override: Optional[str] = None):
        self.binary_override = binary_override

    def resolve_binary(self) -> Optional[str]:
        """Resolve path to the scanner executable."""
        if self.binary_override:
            return self.binary_override
        return shutil.which("gitleaks")

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
            res = subprocess.run(
                [binary, "version"],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
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
            # Map preflight defects to secrets stage defect IDs
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
            return ScanExecutionResult(is_clear=False, defects=mapped_defects)

        binary = self.resolve_binary()
        cmd = [
            binary,
            "detect",
            f"--source={repo_dir}",
            f"--log-opts={base_commit}..{target_commit}",
            "--verbose",
            "--no-banner",
        ]

        # Sanitized clean environment (purge GITLEAKS_* vars per SEC-Q1)
        env = {k: v for k, v in os.environ.items() if not k.startswith("GITLEAKS_")}

        try:
            res = subprocess.run(
                cmd,
                env=env,
                capture_output=True,
                text=True,
                check=False,
                timeout=timeout,
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
                    stdout=res.stdout,
                    stderr=res.stderr,
                    returncode=res.returncode,
                )

            # Condition 8: Scan succeeds with no findings (exit code 0)
            if res.returncode == 0:
                return ScanExecutionResult(
                    is_clear=True,
                    defects=[],
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
            return ScanExecutionResult(is_clear=False, defects=mapped_defects)

        binary = self.resolve_binary()
        cmd = [
            binary,
            "protect",
            "--staged",
            f"--source={repo_dir}",
            "--verbose",
            "--no-banner",
        ]
        env = {k: v for k, v in os.environ.items() if not k.startswith("GITLEAKS_")}

        try:
            res = subprocess.run(
                cmd,
                env=env,
                capture_output=True,
                text=True,
                check=False,
                timeout=timeout,
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
                    stdout=res.stdout,
                    stderr=res.stderr,
                    returncode=1,
                )
            if res.returncode == 0:
                return ScanExecutionResult(is_clear=True, defects=[], stdout=res.stdout, stderr=res.stderr)

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
            )

