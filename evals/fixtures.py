"""Self-contained synthetic test fixture factory for StageCheck.

Zero external dependencies. Does not read /home or any external machine path.
Generates fully valid synthetic programmes with all 8 controls, Merkle binding
tables, synthetic verifiers, specs, evidence roots, and mock Git repositories.
"""
import contextlib
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import zlib
from pathlib import Path
from typing import Any, Dict, NamedTuple, Optional

sys.dont_write_bytecode = True

# Ensure bin/ and checks/ are in sys.path
_TOOL_ROOT = Path(__file__).resolve().parents[1]
_BIN_DIR = _TOOL_ROOT / "bin"
if str(_BIN_DIR) not in sys.path:
    sys.path.insert(0, str(_BIN_DIR))

from common import canonical, command, create, digest, encode, load


class SyntheticFixture(NamedTuple):
    run: Dict[str, Any]
    data: Dict[str, Any]
    root: Path
    tool: Path
    workspace: Path


def _git_fixture(repo: Path, files: Dict[str, bytes]) -> str:
    """Builds a deterministic in-memory Git repository."""
    repo.mkdir(parents=True, exist_ok=True)
    g = repo / ".git"
    g.mkdir(exist_ok=True)
    (g / "objects").mkdir(exist_ok=True)
    (g / "refs").mkdir(exist_ok=True)
    (g / "refs/heads").mkdir(exist_ok=True)
    (g / "config").write_text("[core]\nrepositoryformatversion = 0\nbare = false\n")

    def object_bytes(kind: str, data: bytes) -> str:
        raw = (kind + " " + str(len(data)) + "\0").encode() + data
        oid = hashlib.sha1(raw).hexdigest()
        folder = g / "objects" / oid[:2]
        folder.mkdir(exist_ok=True)
        (folder / oid[2:]).write_bytes(zlib.compress(raw))
        return oid

    tree = b""
    for name, content in sorted(files.items()):
        blob = object_bytes("blob", content)
        tree += f"100644 {name}\0".encode() + bytes.fromhex(blob)
    tree_oid = object_bytes("tree", tree)
    commit = object_bytes(
        "commit",
        f"tree {tree_oid}\nauthor Fixture <fixture@example.invalid> 0 +0000\ncommitter Fixture <fixture@example.invalid> 0 +0000\n\nSynthetic test input\n".encode(),
    )
    (g / "refs/heads/fixture").write_text(commit + "\n")
    (g / "refs/heads/main").write_text(commit + "\n")
    (g / "HEAD").write_text("ref: refs/heads/fixture\n")
    return commit


def manifest(tool: Path) -> None:
    """Computes MANIFEST.sha256 for the copied tool directory, including external tools."""
    paths = sorted(p for p in tool.rglob("*") if p.is_file() and p.name != "MANIFEST.sha256")
    extra = [
        tool / "../evidence/claude_audits/tools/verify_manifest.py",
        tool / "../evidence/claude_audits/tools/verify_state_chain.py",
        tool / "../qualification/reviews/capture_sp1_evidence.py",
    ]
    text = "".join(digest(p.read_bytes()) + "  " + str(p.relative_to(tool)) + "\n" for p in paths)
    for p in extra:
        rel = (
            "../qualification/reviews/" + p.name
            if p.name == "capture_sp1_evidence.py"
            else "../evidence/claude_audits/tools/" + p.name
        )
        if p.exists():
            text += digest(p.read_bytes()) + "  " + rel + "\n"
    (tool / "MANIFEST.sha256").write_text(text)


def create_test_fixture(
    temp_root: Path,
    tool_source: Optional[Path] = None,
    contract_source: Optional[Path] = None,
    programme_source: Optional[Path] = None,
) -> SyntheticFixture:
    """Generates a complete, self-contained synthetic workspace in temp_root.

    Zero external dependencies. Does not read /home or any external machine path.
    """
    temp_root = temp_root.resolve(strict=True)
    if tool_source is None:
        tool_source = _TOOL_ROOT

    workspace = temp_root / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    (workspace / "NewArc").mkdir(exist_ok=True)
    root = workspace / "NewArc/3m"
    root.mkdir(exist_ok=True)

    for rel in [
        "controls",
        "specs",
        "repos",
        "RWA",
        "RWA/start",
        "build",
        "upstream",
        "qualification",
        "qualification/reviews",
        "evidence",
        "evidence/state_updates",
        "evidence/claude_audits",
        "evidence/claude_audits/tools",
        "evidence/stagecheck",
    ]:
        (root / rel).mkdir(parents=True, exist_ok=True)

    tool = root / "stagecheck"
    if tool.exists():
        shutil.rmtree(tool)
    shutil.copytree(
        tool_source,
        tool,
        ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc", ".pytest_cache", ".stagecheck.lock"),
    )

    # Disable real commands / agents in test fixtures
    (tool / "config/commands.json").write_bytes(encode({"enabled": False, "product_grant": None, "commands": []}))
    fixture_agents = load(tool / "config/agents.json")
    fixture_agents.update(enabled=False, budget_usd=None, timeout_seconds=None)
    for item in fixture_agents["agents"]:
        item["model"] = None
    (tool / "config/agents.json").write_bytes(encode(fixture_agents))

    # Internalized synthetic verifier tools
    synthetic_verify_manifest = b"""#!/usr/bin/env python3
import sys
from pathlib import Path
import hashlib

def main():
    if len(sys.argv) >= 5:
        start_dir = Path(sys.argv[1])
        start_manifest = start_dir / "START_MANIFEST.md"
        if start_manifest.exists():
            h = hashlib.sha256(start_manifest.read_bytes()).hexdigest()
            if sys.argv[2] and h != sys.argv[2]:
                return 1
        arch_path = Path(sys.argv[3])
        if arch_path.exists():
            h_arch = hashlib.sha256(arch_path.read_bytes()).hexdigest()
            if sys.argv[4] and h_arch != sys.argv[4]:
                return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
"""

    synthetic_verify_state_chain = b"""#!/usr/bin/env python3
import sys

def main():
    return 0

if __name__ == "__main__":
    sys.exit(main())
"""

    synthetic_capture_sp1 = b"""#!/usr/bin/env python3
import sys

def main():
    return 0

if __name__ == "__main__":
    sys.exit(main())
"""

    (root / "evidence/claude_audits/tools/verify_manifest.py").write_bytes(synthetic_verify_manifest)
    (root / "evidence/claude_audits/tools/verify_state_chain.py").write_bytes(synthetic_verify_state_chain)
    (root / "qualification/reviews/capture_sp1_evidence.py").write_bytes(synthetic_capture_sp1)

    # State
    state = {
        k: None
        for k in [
            "schema_version",
            "programme",
            "architecture",
            "execution_plan",
            "authority",
            "evidence_root",
            "qualification_root",
            "note",
            "source_lock",
            "current_task",
        ]
    }
    state.update(status="SP1_NOT_STARTED", completed_tasks=[], evidence_references=[], open_prerequisites=[])
    protected = {
        k: v
        for k, v in state.items()
        if k
        not in [
            "status",
            "source_lock",
            "current_task",
            "completed_tasks",
            "evidence_references",
            "open_prerequisites",
        ]
    }
    protected_hash = digest(
        json.dumps(protected, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    )

    # Write controls and specs
    files = {
        "controls/DRWA_ACTIVE_STATE.json": encode(state),
        "controls/ACTIVE_STATE.json": encode({
            "schema_version": "1.0.0",
            "programme": "STAGECHECK-SYNTHETIC",
            "current_task": "task-01",
            "attempt": 1,
            "status": "IN_PROGRESS",
            "protected": protected,
            "execution_progress": {"current_step": "init", "tasks_completed": []},
        }),
        "controls/OWNER_GRANTS.md": b"# Fixture grants\nExpiry: end of SP1\nPermitted execution: selected fixture commands only.\n",
        "controls/FAILURE_PREVENTION.md": b"# Fixture register\n",
        "controls/EVIDENCE_ROOT.json": encode({"root": str(root / "evidence")}),
        "controls/QUALIFICATION_ROOT.json": encode({"root": str(root / "qualification")}),
        "controls/PRODUCT_REPOSITORIES.json": encode({
            "product_root": str(root / "build"),
            "untouched_upstream_root": str(root / "upstream"),
        }),
        "controls/DISPOSITIONS.json": encode([]),
        "RWA/start/RWA_Architecture_v4.2.8.md": b"# Fixture architecture\nSpecification value: accepted\n",
        "RWA/start/DRWA_Development_and_Decision_Plan.md": b"# Fixture plan\n",
        "specs/START_MANIFEST.md": b"# Start Manifest\n",
        "specs/TASK_PLAN.md": b"# Task Plan\n",
        "specs/ARCHITECTURE.md": b"# Architecture\n",
        "specs/TASK_PLAN.json": encode({"tasks": []}),
    }
    for rel, data in files.items():
        (root / rel).write_bytes(data)

    start = root / "RWA/start"
    (start / "START_MANIFEST.md").write_text(
        "# Fixture manifest\n"
        + "".join(
            f"| `{Path(name).name}` | fixture | `{digest(raw)}` |\n"
            for name, raw in files.items()
            if name.startswith("RWA/start/")
        )
    )

    # Compute manifest.sha256
    manifest(tool)
    stagecheck_manifest_hash = digest((tool / "MANIFEST.sha256").read_bytes())

    # Write STAGECHECK_ROOT.json
    (root / "controls/STAGECHECK_ROOT.json").write_bytes(
        encode({"root": str(tool), "manifest_sha256": stagecheck_manifest_hash})
    )

    # Generate synthetic contract
    arch_file = start / "RWA_Architecture_v4.2.8.md"
    arch_sha = digest(arch_file.read_bytes())
    contract_text = f"""# AGENTS.md Contract

**Active programme root:** `{root}`
**Controlling architecture:** `NewArc/3m/RWA/start/RWA_Architecture_v4.2.8.md`, SHA-256 `{arch_sha}`

| StageCheck tool | `{tool}/MANIFEST.sha256` | `{stagecheck_manifest_hash}` |
| Current-state pointer | `{root}/controls/DRWA_ACTIVE_STATE.json` | `{digest((root / "controls/DRWA_ACTIVE_STATE.json").read_bytes())}` |
| Owner authority and grants | `{root}/controls/OWNER_GRANTS.md` | `{digest((root / "controls/OWNER_GRANTS.md").read_bytes())}` |
| Failure prevention register | `{root}/controls/FAILURE_PREVENTION.md` | `{digest((root / "controls/FAILURE_PREVENTION.md").read_bytes())}` |
| Evidence root | `{root}/controls/EVIDENCE_ROOT.json` | `{digest((root / "controls/EVIDENCE_ROOT.json").read_bytes())}` |
| Product repositories | `{root}/controls/PRODUCT_REPOSITORIES.json` | `{digest((root / "controls/PRODUCT_REPOSITORIES.json").read_bytes())}` |
| Qualification tree (§11) | `{root}/controls/QUALIFICATION_ROOT.json` | `{digest((root / "controls/QUALIFICATION_ROOT.json").read_bytes())}` |

The current state is protected and must reproduce SHA-256 `{protected_hash}`.

Known excluded locations include:
- `RWA/previous/`

Historical citations
- None
"""
    contract = workspace / "contract.txt"
    contract.write_text(contract_text)
    (workspace / "AGENTS.md").write_text(contract_text)
    copy = workspace / "instruction_fixture.txt"
    copy.write_text(contract_text)

    paths = load(tool / "config/paths.json")
    paths["instruction_copies"] = [str(copy)]
    (tool / "config/paths.json").write_bytes(encode(paths))

    # Synthetic Git Repos
    repo = root / "build/product"
    head = _git_fixture(repo, {"go.mod": b"module fixture\n"})
    repos_product = root / "repos/product"
    _git_fixture(repos_product, {"README.md": b"# Synthetic product repo\n"})

    command(["git", "-C", str(repo), "read-tree", "HEAD"], repo)
    source = repo / "qual_fixture_test.go"
    source.write_text("package fixture\nfunc TestQualFixture(t *testing.T) {}\n")

    ev = root / "evidence"
    (ev / "EVIDENCE_MANIFEST.json").write_bytes(encode({"schema_version": "1.0.0", "entries": []}))
    record = ev / "record.json"
    record.write_text('{"scope":"fixture only"}\n')

    cite = {
        "type": "document",
        "path": str(start / "RWA_Architecture_v4.2.8.md"),
        "sha256": digest((start / "RWA_Architecture_v4.2.8.md").read_bytes()),
        "lines": [2, 2],
        "quote": "Specification value: accepted",
        "approved": True,
    }
    c = {
        "id": "C-001",
        "kind": "observation",
        "text": "Specification value: accepted",
        "scope": "fixture",
        "label": "SOURCE_PROVEN",
        "citations": [cite],
        "blast_radius": [],
    }
    claim_data = {
        "task_id": "fixture",
        "iteration": 1,
        "contract_sha256": digest(contract.read_bytes()),
        "record": str(record),
        "record_sha256": digest(record.read_bytes()),
        "claims": [c],
    }
    claim_path = ev / "claims.json"
    claim_path.write_bytes(encode(claim_data))

    report = ev / "report.md"
    report.write_text(
        "NOT DONE: fixture only\n"
        "Full Blast Radius Check: fixture source read\n"
        "Enforcement Self-Check: Enforcement is manual; fixture only\n\n"
        "Specification value: accepted\n"
    )

    run = {
        "task_id": "fixture",
        "iteration": 1,
        "tool_root": str(tool),
        "programme_root": str(root),
        "contract": str(contract),
        "repo": str(repo),
        "base": head,
        "checked_head": head,
        "claims": str(claim_path),
        "report": str(report),
        "depth": "docs",
        "changed_paths": [str(source)],
        "operation_records": [],
        "read_paths": [],
        "upstream": {},
        "run_path": str(ev / "run.json"),
    }
    (ev / "run.json").write_bytes(encode(run))

    # Re-manifest tool to include updated paths.json
    manifest(tool)
    new_stagecheck_hash = digest((tool / "MANIFEST.sha256").read_bytes())
    (root / "controls/STAGECHECK_ROOT.json").write_bytes(
        encode({"root": str(tool), "manifest_sha256": new_stagecheck_hash})
    )
    contract_text = contract_text.replace(stagecheck_manifest_hash, new_stagecheck_hash)
    contract.write_text(contract_text)
    (workspace / "AGENTS.md").write_text(contract_text)
    copy.write_text(contract_text)
    claim_data["contract_sha256"] = digest(contract.read_bytes())
    claim_path.write_bytes(encode(claim_data))

    return SyntheticFixture(run=run, data=claim_data, root=root, tool=tool, workspace=workspace)


@contextlib.contextmanager
def synthetic_workspace(prefix: str = "stagecheck-fixture-", tool_source: Optional[Path] = None):
    """Context manager for deterministic lifecycle synthetic workspace testing."""
    with tempfile.TemporaryDirectory(prefix=prefix) as temp_dir:
        temp_root = Path(temp_dir)
        fix = create_test_fixture(temp_root, tool_source=tool_source)
        yield fix
