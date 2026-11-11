"""OS-Enforced Same-UID Isolation & Fail-Closed Sandbox Tests (GAP-05 / SR-10)."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from stagecheck.core.commands import SandboxUnavailableError as CommandSandboxError
from stagecheck.core.commands import execute_secure_command
from stagecheck.core.isolation import (
    SandboxPolicy,
    SandboxUnavailableError,
    prepare_isolated_command,
    probe_bwrap_sandbox,
)
from stagecheck.core.permissions import assert_os_sandbox_boundary
from stagecheck.core.utils import sha256_file


class TestSameUidIsolation(unittest.TestCase):
    """Verify kernel-enforced same-UID Bubblewrap isolation and fail-closed checks."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.ws = Path(self.temp_dir.name).resolve()
        self.repo_dir = self.ws / "repos" / "app"
        self.controls_dir = self.ws / "controls"
        self.evidence_dir = self.ws / "evidence"
        self.specs_dir = self.ws / "specs"
        for d in (self.repo_dir, self.controls_dir, self.evidence_dir, self.specs_dir):
            d.mkdir(parents=True, exist_ok=True)

        self.active_state = self.controls_dir / "ACTIVE_STATE.json"
        self.active_state.write_text('{"phase":"PHASE_2A_CODING"}\n', encoding="utf-8")
        self.evidence_file = self.evidence_dir / "audit_marker.txt"
        self.evidence_file.write_text("immutable-evidence\n", encoding="utf-8")
        self.agents_md = self.ws / "AGENTS.md"
        self.agents_md.write_text("# Contract\n", encoding="utf-8")
        self.lock_file = self.ws / ".stagecheck.lock"
        self.lock_file.write_text("lock-secret\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_bwrap_probe_available_on_host(self) -> None:
        """Confirm OS Bubblewrap namespace probe succeeds in current environment."""
        probe = probe_bwrap_sandbox()
        self.assertTrue(probe["available"], f"bwrap probe failed: {probe}")
        assert_os_sandbox_boundary()

    def test_kernel_blocks_same_uid_writes_chmod_and_unlink_on_governance_and_package(self) -> None:
        """Verify untrusted same-UID child cannot mutate controls, evidence, AGENTS.md, or StageCheck package."""
        pkg_file = Path(__file__).resolve().parent.parent / "stagecheck" / "core" / "gate_engine.py"
        before_state_sha = sha256_file(self.active_state)
        before_ev_sha = sha256_file(self.evidence_file)
        before_pkg_sha = sha256_file(pkg_file)

        # Malicious test suite executed via python3 -m unittest inside execute_secure_command
        # attempting same-UID chmod, write, and unlink against governance artifacts and StageCheck core.
        attack_test = self.repo_dir / "test_attack.py"
        attack_test.write_text(
            "import os, pathlib, unittest\n\n"
            "class TestHostileSameUidAttack(unittest.TestCase):\n"
            "    def test_attack_governance_files(self):\n"
            f"        targets = [{str(self.active_state)!r}, {str(self.evidence_file)!r}, {str(self.agents_md)!r}, {str(pkg_file)!r}]\n"
            "        for p in targets:\n"
            "            with self.assertRaises(OSError):\n"
            "                os.chmod(p, 0o644)\n"
            "            with self.assertRaises(OSError):\n"
            "                pathlib.Path(p).write_text('PWNED', encoding='utf-8')\n"
            "            with self.assertRaises(OSError):\n"
            "                os.unlink(p)\n"
            "        pathlib.Path('work_output.txt').write_text('ok', encoding='utf-8')\n",
            encoding="utf-8",
        )
        res = execute_secure_command(
            ["python3", "-m", "unittest", "discover"],
            working_directory=self.repo_dir,
            timeout_seconds=10,
            require_isolation=True,
        )
        self.assertEqual(res.exit_code, 0, f"stderr={res.stderr}\nstdout={res.stdout}")
        self.assertEqual(sha256_file(self.active_state), before_state_sha)
        self.assertEqual(sha256_file(self.evidence_file), before_ev_sha)
        self.assertEqual(sha256_file(pkg_file), before_pkg_sha)
        self.assertEqual((self.repo_dir / "work_output.txt").read_text(encoding="utf-8"), "ok")

    def test_pid_net_tmp_ipc_and_home_credential_isolation(self) -> None:
        """Verify PID, network, /tmp, lockfile, and ~/.ssh credential isolation inside bwrap child."""
        with tempfile.TemporaryDirectory() as fake_home_tmp:
            fake_home = Path(fake_home_tmp).resolve()
            ssh_dir = fake_home / ".ssh"
            ssh_dir.mkdir(parents=True, exist_ok=True)
            (ssh_dir / "id_rsa").write_text("TOP-SECRET-KEY\n", encoding="utf-8")

            host_tmp_marker = Path(tempfile.gettempdir()) / f"sc_host_secret_{os.getpid()}.txt"
            host_tmp_marker.write_text("host-tmp-secret", encoding="utf-8")
            try:
                probe_script = (
                    "import os, pathlib, socket\n"
                    # 1. Parent PID must not exist in isolated PID namespace
                    f"assert not os.path.exists('/proc/{os.getpid()}'), 'parent pid visible'\n"
                    # 2. Fake ~/.ssh secret must be masked by tmpfs
                    f"assert not pathlib.Path({str(ssh_dir / 'id_rsa')!r}).exists(), 'ssh key leaked'\n"
                    # 3. Host /tmp marker must be hidden
                    f"assert not pathlib.Path({str(host_tmp_marker)!r}).exists(), 'host tmp leaked'\n"
                    # 4. .stagecheck.lock masked to /dev/null (empty or EACCES under nodev tmpfs; never leaks secret)
                    "try:\n"
                    f"    assert pathlib.Path({str(self.lock_file)!r}).read_text() == '', 'lock leaked'\n"
                    "except PermissionError:\n"
                    "    pass\n"
                    # 5. Network isolated (outbound UDP connect to public IP fails with ENETUNREACH/EPERM)
                    "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
                    "try:\n"
                    "    s.connect(('1.1.1.1', 53))\n"
                    "    raise AssertionError('network unexpectedly reachable')\n"
                    "except OSError:\n"
                    "    pass\n"
                    "finally:\n"
                    "    s.close()\n"
                )
                policy = SandboxPolicy(
                    working_directory=self.repo_dir,
                    workspace_root=self.ws,
                    allow_cwd_write=False,
                    mask_home_credentials=True,
                )
                with patch("pathlib.Path.home", return_value=fake_home):
                    wrapped, enforced = prepare_isolated_command(
                        [sys.executable, "-c", probe_script],
                        policy=policy,
                        mandatory=True,
                    )
                self.assertTrue(enforced)
                proc = subprocess.run(wrapped, capture_output=True, text=True, timeout=10, check=False)
                self.assertEqual(proc.returncode, 0, f"Isolation invariant check failed: {proc.stderr}")
            finally:
                host_tmp_marker.unlink(missing_ok=True)

    def test_scanner_policy_enforces_readonly_cwd(self) -> None:
        """Verify scanner sandbox (allow_cwd_write=False) denies writes even inside repos/."""
        policy = SandboxPolicy(
            working_directory=self.repo_dir,
            workspace_root=self.ws,
            allow_cwd_write=False,
            mask_governance_dirs=True,
        )
        wrapped, enforced = prepare_isolated_command(
            [sys.executable, "-c", "import pathlib; pathlib.Path('mutated.py').write_text('bad')"],
            policy=policy,
            mandatory=True,
        )
        self.assertTrue(enforced)
        proc = subprocess.run(wrapped, capture_output=True, text=True, timeout=10, check=False)
        self.assertNotEqual(proc.returncode, 0)
        self.assertFalse((self.repo_dir / "mutated.py").exists())

    def test_fails_closed_when_bwrap_missing_or_probe_fails(self) -> None:
        """Mandatory isolation must fail closed (exit 126 / SandboxUnavailableError), never run unsandboxed."""
        policy = SandboxPolicy(working_directory=self.repo_dir, workspace_root=self.ws)
        with patch("stagecheck.core.isolation.resolve_bwrap_binary", return_value=None):
            with self.assertRaises(SandboxUnavailableError) as ctx:
                prepare_isolated_command([sys.executable, "-c", "print('ok')"], policy=policy, mandatory=True)
            self.assertEqual(ctx.exception.exit_code, 126)

            with self.assertRaises(CommandSandboxError) as cmd_ctx:
                execute_secure_command(
                    ["python3", "-m", "unittest", "--help"],
                    working_directory=self.repo_dir,
                    require_isolation=True,
                )
            self.assertEqual(cmd_ctx.exception.exit_code, 126)

        with patch(
            "stagecheck.core.isolation.probe_bwrap_sandbox",
            return_value={"available": False, "bwrap_path": None, "namespaces_supported": False, "reason": "EPERM"},
        ):
            with self.assertRaises(SandboxUnavailableError):
                prepare_isolated_command([sys.executable, "-c", "print('ok')"], policy=policy, mandatory=True)

    def test_gap03_deployment_preflight_checks_all_isolation_invariants(self) -> None:
        """Verify run_bwrap_deployment_preflight checks namespaces, RO governance/package, credentials, and network (GAP-03)."""
        import json
        from stagecheck.core.isolation import run_bwrap_deployment_preflight
        from stagecheck.cli.main import main

        res = run_bwrap_deployment_preflight(workspace_root=self.ws, working_directory=self.repo_dir)
        self.assertTrue(res.passed, f"Expected host preflight to pass: {res.reason}")
        self.assertEqual(
            set(res.checks.keys()),
            {
                "bwrap_binary_trusted",
                "namespaces_isolated",
                "root_readonly",
                "governance_readonly",
                "package_readonly",
                "credentials_masked",
                "network_unshared",
            },
        )
        self.assertTrue(all(res.checks.values()), f"Expected all preflight checks True: {res.checks}")

        # Verify CLI supervisor preflight --json exits 0
        import io
        from contextlib import redirect_stdout

        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["supervisor", "preflight", "--workspace", str(self.ws), "--json"])
        self.assertEqual(rc, 0)
        parsed = json.loads(buf.getvalue())
        self.assertTrue(parsed["passed"])

    def test_gap03_preflight_rejects_missing_untrusted_and_unsupported_namespaces(self) -> None:
        """Verify preflight fails closed on missing, world-writable, /tmp/repo-local bwrap, and unsupported namespaces (GAP-03)."""
        from stagecheck.core.isolation import run_bwrap_deployment_preflight, validate_bwrap_binary

        # 1. Missing bwrap binary
        with patch("stagecheck.core.isolation.resolve_bwrap_binary", return_value=None):
            with self.assertRaises(SandboxUnavailableError) as err_missing:
                run_bwrap_deployment_preflight(workspace_root=self.ws, raise_on_failure=True)
            self.assertEqual(err_missing.exception.exit_code, 126)

        # 2. Untrusted bwrap binary in /tmp or workspace/repo or non-executable or symlink to /tmp
        fake_in_ws = self.repo_dir / "bwrap"
        fake_in_ws.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        os.chmod(fake_in_ws, 0o755)
        ok_ws, msg_ws = validate_bwrap_binary(bwrap_path=fake_in_ws, workspace_root=self.ws)
        self.assertIsNone(ok_ws)
        self.assertIn("Untrusted bwrap binary location", msg_ws or "")

        fake_tmp = self.ws / "tmp_bwrap"
        fake_tmp.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        os.chmod(fake_tmp, 0o644)
        ok_nonexec, _ = validate_bwrap_binary(bwrap_path=fake_tmp)
        self.assertIsNone(ok_nonexec)

        # World-writable bwrap outside /tmp (use symlink/mock stat check in non-tmp path via validate logic on /tmp)
        with tempfile.TemporaryDirectory() as td:
            rogue = Path(td) / "bwrap"
            rogue.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            os.chmod(rogue, 0o777)
            ok_rogue, msg_rogue = validate_bwrap_binary(bwrap_path=rogue)
            self.assertIsNone(ok_rogue)
            self.assertIn("world-writable", (msg_rogue or "").lower())

        # 3. Unsupported namespaces (subprocess fails with EPERM) -> fail closed with exact reason
        fake_proc = subprocess.CompletedProcess(
            args=["bwrap"], returncode=1, stdout="", stderr="bwrap: No permissions to create a new namespace (EPERM)"
        )
        with patch("stagecheck.core.isolation.validate_bwrap_binary", return_value=("/usr/bin/bwrap", None)):
            with patch("stagecheck.core.isolation._REAL_SUBPROCESS_RUN", return_value=fake_proc):
                res_ns = run_bwrap_deployment_preflight(workspace_root=self.ws, raise_on_failure=False)
                self.assertFalse(res_ns.passed)
                self.assertIn("EPERM", res_ns.reason)

    def test_gap03_start_supervisor_and_orchestrator_block_without_preflight(self) -> None:
        """Verify stagecheck start, SupervisorEngine.step, and AuditOrchestrator fail closed if preflight fails (GAP-03)."""
        from stagecheck.cli.main import main
        from stagecheck.core.isolation import IsolationPreflightResult
        from stagecheck.core.orchestrator import AuditContext, AuditOrchestrator
        from stagecheck.core.supervisor import SupervisorEngine

        failed_preflight = IsolationPreflightResult(
            passed=False,
            bwrap_path=None,
            checks={"bwrap_binary_trusted": False},
            failures=["Kernel user namespaces disabled by sysctl"],
            reason="Kernel user namespaces disabled by sysctl",
        )

        # 1. stagecheck supervisor preflight exits 126
        with patch("stagecheck.cli.supervisor_cmd.run_bwrap_deployment_preflight", return_value=failed_preflight):
            rc_pre = main(["supervisor", "preflight", "--workspace", str(self.ws)])
            self.assertEqual(rc_pre, 126)

        # 2. stagecheck start blocks task initialization before mutating workspace
        (self.controls_dir / "STAGECHECK_ROOT.json").write_text('{"schema_version":"2.0"}\n', encoding="utf-8")
        with patch("stagecheck.cli.start_cmd.run_bwrap_deployment_preflight", side_effect=SandboxUnavailableError("bwrap unavailable")):
            rc_start = main(["start", "--task", "task-blocked", "--workspace", str(self.ws)])
            self.assertEqual(rc_start, 126)
            self.assertFalse((self.ws / "evidence" / "tasks" / "task-blocked").exists())

        # 3. SupervisorEngine.step halts fail-closed
        sup = SupervisorEngine(self.ws)
        with patch("stagecheck.core.isolation.run_bwrap_deployment_preflight", return_value=failed_preflight):
            step_res = sup.step(task_id="task-blocked", attempt=1)
            self.assertEqual(step_res.status, "HALTED")
            self.assertEqual(step_res.action_taken, "ISOLATION_PREFLIGHT_FAILED")
            self.assertIn("user namespaces disabled", step_res.message)

        # 4. AuditOrchestrator.run_all_stages raises SandboxUnavailableError before running stages
        orch = AuditOrchestrator(self.ws)
        ctx = AuditContext(
            workspace_root=self.ws,
            task_id="task-blocked",
            attempt=1,
            touched_repos=["app"],
            all_registered_repos=["app"],
        )
        with patch("stagecheck.core.isolation.run_bwrap_deployment_preflight", side_effect=SandboxUnavailableError("no bwrap")):
            with self.assertRaises(SandboxUnavailableError):
                orch.run_all_stages(ctx)


if __name__ == "__main__":
    unittest.main()
