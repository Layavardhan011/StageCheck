"""CLI Command Handlers for Specification Manifest Verification & Update (DEC-008 / FR-08).

Provides:
  stagecheck verify-manifest [--workspace <path>]
  stagecheck update-manifest [--workspace <path>]
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

from stagecheck.core.paths import find_workspace_root
from stagecheck.core.start_manifest import (
    SpecManifestError,
    update_spec_manifest,
    verify_spec_manifest,
)


def run_verify_manifest(workspace: Optional[str] = None) -> int:
    """Verify that files in specs/ match their digests in START_MANIFEST.md.

    Returns:
        0 if verified, 1 if tampered, missing, unregistered, or on error.
    """
    try:
        ws_root = Path(workspace).resolve() if workspace else find_workspace_root()
    except Exception as err:
        print(f"Error: Could not locate workspace root: {err}", file=sys.stderr)
        return 1

    try:
        res = verify_spec_manifest(ws_root)
        if res.get("valid", False):
            print("================================================================")
            print("          STAGECHECK SPECIFICATION MANIFEST VERIFICATION        ")
            print("================================================================")
            print(f"Workspace: {ws_root}")
            print(f"[OK] START_MANIFEST.md verified successfully.")
            for vf in res.get("verified", []):
                print(f"  ├── [MATCH] specs/{vf}")
            print("All specification baseline files match authoritative SHA-256 digests.")
            return 0
        else:
            print("================================================================", file=sys.stderr)
            print("    FAIL: STAGECHECK SPECIFICATION MANIFEST VERIFICATION FAILED ", file=sys.stderr)
            print("================================================================", file=sys.stderr)
            print(f"Workspace: {ws_root}", file=sys.stderr)
            if res.get("missing"):
                print("Missing specification deliverables:", file=sys.stderr)
                for mf in res["missing"]:
                    print(f"  ├── [MISSING] specs/{mf}", file=sys.stderr)
            if res.get("tampered"):
                print("Tampered specification deliverables (hash mismatch):", file=sys.stderr)
                for tf in res["tampered"]:
                    print(f"  ├── [TAMPERED] specs/{tf['file']}: expected {tf['expected'][:16]}..., actual {tf['actual'][:16]}...", file=sys.stderr)
            if res.get("unregistered"):
                print("Unregistered specification additions:", file=sys.stderr)
                for uf in res["unregistered"]:
                    print(f"  ├── [UNREGISTERED] specs/{uf}", file=sys.stderr)
            return 1

    except SpecManifestError as err:
        print(f"Specification manifest error: {err}", file=sys.stderr)
        return 1
    except Exception as err:
        print(f"Unexpected error during manifest verification: {err}", file=sys.stderr)
        return 1


def run_update_manifest(workspace: Optional[str] = None) -> int:
    """Explicitly recompute SHA-256 digests and update specs/START_MANIFEST.md.

    Returns:
        0 on success, 1 on error.
    """
    try:
        ws_root = Path(workspace).resolve() if workspace else find_workspace_root()
    except Exception as err:
        print(f"Error: Could not locate workspace root: {err}", file=sys.stderr)
        return 1

    try:
        manifest_path = update_spec_manifest(ws_root)
        print("================================================================")
        print("          STAGECHECK SPECIFICATION MANIFEST UPDATED             ")
        print("================================================================")
        print(f"Workspace: {ws_root}")
        print(f"[OK] Authoritative manifest rewritten at: {manifest_path.relative_to(ws_root)}")
        return 0
    except Exception as err:
        print(f"Failed to update specification manifest: {err}", file=sys.stderr)
        return 1

