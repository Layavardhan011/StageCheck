"""Unit and Integration Tests for Fail-Closed Secret Scanner (Section 7, Specs 08, 09, 14).

Verifies all 9 scanner operational conditions fail-closed with zero silent bypasses.
"""

import subprocess
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from stagecheck.core.scanner import ScannerStatus, SecretScanner


class TestSecretScannerFailClosed(unittest.TestCase):
    """Test all 9 scanner operational conditions fail closed with explicit status."""

    def setUp(self):
        SecretScanner.reset_test_launcher()
        self.scanner = SecretScanner()
        self.dummy_repo = Path("/tmp/dummy_repo")

    def tearDown(self):
        from tests.conftest import setup_test_scanner
        setup_test_scanner()

    def test_condition_1_scanner_missing(self):
        """Condition 1: Scanner missing in PATH -> Blocking finding, SCANNER_UNAVAILABLE."""
        with patch.object(self.scanner, "resolve_binary", return_value=None):
            res = self.scanner.scan_commit_range(
                self.dummy_repo, "HEAD~1", "HEAD", repo_name="backend"
            )
            self.assertFalse(res.is_clear)
            self.assertEqual(res.status, ScannerStatus.SCANNER_UNAVAILABLE)
            self.assertTrue(any(d.defect_id == "secrets.scanner_missing" and d.blocking for d in res.defects))

    def test_condition_2_scanner_version_mismatch(self):
        """Condition 2: Scanner version incompatible (v7.x or v8.10) -> Blocking finding."""
        with patch.object(self.scanner, "resolve_binary", return_value="/usr/bin/gitleaks"):
            with patch("os.path.isfile", return_value=True), patch("os.access", return_value=True):
                # Major version 7 instead of 8
                mock_run = MagicMock(returncode=0, stdout="v7.5.0\n")
                with patch("subprocess.run", return_value=mock_run):
                    res = self.scanner.scan_commit_range(
                        self.dummy_repo, "HEAD~1", "HEAD", repo_name="backend"
                    )
                    self.assertFalse(res.is_clear)
                    self.assertEqual(res.status, ScannerStatus.SCANNER_UNAVAILABLE)
                    self.assertTrue(any("version_incompatible" in d.defect_id and d.blocking for d in res.defects))

    def test_condition_3_scanner_cannot_execute(self):
        """Condition 3: Scanner binary cannot execute (OSError / Exec format error) -> Blocking finding."""
        with patch.object(self.scanner, "resolve_binary", return_value="/usr/bin/gitleaks"):
            with patch("os.path.isfile", return_value=True), patch("os.access", return_value=True):
                with patch("subprocess.run", side_effect=OSError("Exec format error")):
                    res = self.scanner.scan_commit_range(
                        self.dummy_repo, "HEAD~1", "HEAD", repo_name="backend"
                    )
                    self.assertFalse(res.is_clear)
                    self.assertEqual(res.status, ScannerStatus.SCANNER_UNAVAILABLE)
                    self.assertTrue(any("cannot_execute" in d.defect_id and d.blocking for d in res.defects))

    def test_condition_4_permission_denied(self):
        """Condition 4: Scanner binary permission denied (EACCES) -> Blocking finding."""
        with patch.object(self.scanner, "resolve_binary", return_value="/usr/bin/gitleaks"):
            with patch("os.path.isfile", return_value=True), patch("os.access", return_value=False):
                res = self.scanner.scan_commit_range(
                    self.dummy_repo, "HEAD~1", "HEAD", repo_name="backend"
                )
                self.assertFalse(res.is_clear)
                self.assertEqual(res.status, ScannerStatus.SCANNER_UNAVAILABLE)
                self.assertTrue(any("permission_denied" in d.defect_id and d.blocking for d in res.defects))

    def test_condition_5_scanner_timeout(self):
        """Condition 5: Scanner hangs / times out -> Blocking finding."""
        with patch.object(self.scanner, "resolve_binary", return_value="/usr/bin/gitleaks"):
            with patch("os.path.isfile", return_value=True), patch("os.access", return_value=True):
                mock_version = MagicMock(returncode=0, stdout="v8.18.4\n")
                with patch("subprocess.run", side_effect=[mock_version, subprocess.TimeoutExpired("gitleaks", 30)]):
                    res = self.scanner.scan_commit_range(
                        self.dummy_repo, "HEAD~1", "HEAD", repo_name="backend"
                    )
                    self.assertFalse(res.is_clear)
                    self.assertEqual(res.status, ScannerStatus.SCANNER_TIMEOUT)
                    self.assertTrue(any("timeout" in d.defect_id and d.blocking for d in res.defects))

    def test_condition_6_scanner_exits_unexpectedly(self):
        """Condition 6: Scanner exits unexpectedly (e.g. SIGSEGV exit code 139) -> Blocking finding."""
        with patch.object(self.scanner, "resolve_binary", return_value="/usr/bin/gitleaks"):
            with patch("os.path.isfile", return_value=True), patch("os.access", return_value=True):
                mock_version = MagicMock(returncode=0, stdout="v8.18.4\n")
                mock_scan_crash = MagicMock(returncode=139, stdout="", stderr="Segmentation fault")
                with patch("subprocess.run", side_effect=[mock_version, mock_scan_crash]):
                    res = self.scanner.scan_commit_range(
                        self.dummy_repo, "HEAD~1", "HEAD", repo_name="backend"
                    )
                    self.assertFalse(res.is_clear)
                    self.assertEqual(res.status, ScannerStatus.SCANNER_ERROR)
                    self.assertTrue(any("unexpected_exit" in d.defect_id and d.blocking for d in res.defects))

    def test_condition_7_secret_detected(self):
        """Condition 7: Scanner detects credential leak (exit code 1) -> Blocking finding."""
        with patch.object(self.scanner, "resolve_binary", return_value="/usr/bin/gitleaks"):
            with patch("os.path.isfile", return_value=True), patch("os.access", return_value=True):
                mock_version = MagicMock(returncode=0, stdout="v8.18.4\n")
                mock_leak = MagicMock(returncode=1, stdout="Finding: generic-api-key at repos/app/config.py:12\n")
                with patch("subprocess.run", side_effect=[mock_version, mock_leak]):
                    res = self.scanner.scan_commit_range(
                        self.dummy_repo, "HEAD~1", "HEAD", repo_name="backend"
                    )
                    self.assertFalse(res.is_clear)
                    self.assertEqual(res.status, ScannerStatus.FINDINGS)
                    self.assertTrue(any(d.defect_id == "secrets.detected_credential" and d.blocking for d in res.defects))

    def test_condition_8_clean_scan_succeeds(self):
        """Condition 8: Scanner runs clean without findings (exit code 0) -> Clean result."""
        with patch.object(self.scanner, "resolve_binary", return_value="/usr/bin/gitleaks"):
            with patch("os.path.isfile", return_value=True), patch("os.access", return_value=True):
                mock_version = MagicMock(returncode=0, stdout="v8.18.4\n")
                mock_clean = MagicMock(returncode=0, stdout="Scan completed with 0 leaks found.\n")
                with patch("subprocess.run", side_effect=[mock_version, mock_clean]):
                    res = self.scanner.scan_commit_range(
                        self.dummy_repo, "HEAD~1", "HEAD", repo_name="backend"
                    )
                    self.assertTrue(res.is_clear)
                    self.assertEqual(res.status, ScannerStatus.PASS)
                    self.assertEqual(len(res.defects), 0)

    def test_condition_9_scanner_output_malformed(self):
        """Condition 9: Scanner output cannot be parsed / malformed version string -> Blocking finding."""
        with patch.object(self.scanner, "resolve_binary", return_value="/usr/bin/gitleaks"):
            with patch("os.path.isfile", return_value=True), patch("os.access", return_value=True):
                mock_bad_version = MagicMock(returncode=0, stdout="Gibberish output without version numbers")
                with patch("subprocess.run", return_value=mock_bad_version):
                    res = self.scanner.scan_commit_range(
                        self.dummy_repo, "HEAD~1", "HEAD", repo_name="backend"
                    )
                    self.assertFalse(res.is_clear)
                    self.assertEqual(res.status, ScannerStatus.INVALID_SCANNER_OUTPUT)
                    self.assertTrue(any("output_malformed" in d.defect_id and d.blocking for d in res.defects))

    def test_condition_10_production_scanner_selection_rejects_test_stubs(self):
        """Condition 10: In production mode, test stubs in tests/ are rejected, failing closed."""
        # Ensure production mode (allow_test_stub is False)
        SecretScanner.reset_test_launcher()
        scanner = SecretScanner()

        # If PATH points to tests/bin/gitleaks, production mode refuses to use it
        with patch("shutil.which", return_value="/home/user/repo/tests/bin/gitleaks"):
            self.assertIsNone(scanner.resolve_binary())
            valid, defects = scanner.verify_scanner_binary()
            self.assertFalse(valid)
            self.assertTrue(any(d.defect_id == "preflight.gitleaks_missing" and d.blocking for d in defects))

        # Binary override pointing to tests/bin/gitleaks is also rejected in production
        stub_override = SecretScanner(binary_override="/tmp/tests/bin/gitleaks")
        self.assertIsNone(stub_override.resolve_binary())

    def test_scanner_discovery(self):
        """Verify standard discovery of native production scanner binary."""
        SecretScanner.reset_test_launcher()
        scanner = SecretScanner()
        with patch("shutil.which", return_value="/usr/local/bin/gitleaks"):
            resolved = scanner.resolve_binary()
            self.assertEqual(resolved, "/usr/local/bin/gitleaks")

    def test_gitleaks_pinned_config(self):
        """Verify authoritative Gitleaks --config binding prevents rule drift (DEC-017 / SR-04)."""
        SecretScanner.reset_test_launcher()
        scanner = SecretScanner()

        with patch.object(scanner, "resolve_binary", return_value="/usr/bin/gitleaks"):
            with patch("os.path.isfile", return_value=True), patch("os.access", return_value=True):
                mock_version = MagicMock(returncode=0, stdout="v8.18.4\n")
                mock_scan = MagicMock(returncode=0, stdout="Scan completed with 0 leaks found.\n")

                with patch("subprocess.run", side_effect=[mock_version, mock_scan]) as mock_sub:
                    res = scanner.scan_commit_range(
                        self.dummy_repo, "HEAD~1", "HEAD", repo_name="backend"
                    )
                    self.assertTrue(res.is_clear)
                    self.assertEqual(mock_sub.call_count, 2)
                    call_cmd = mock_sub.call_args[0][0]
                    self.assertEqual(call_cmd[0], "/usr/bin/gitleaks")
                    self.assertEqual(call_cmd[1], "detect")
                    # Check --config argument is present
                    has_config = any(arg.startswith("--config=") for arg in call_cmd)
                    self.assertTrue(has_config, f"Expected --config in {call_cmd}")


if __name__ == "__main__":
    unittest.main()

