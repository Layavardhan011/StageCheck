"""Authoritative manager for controls/ACTIVE_STATE.json and attempt state machine.

Ensures transactional updates, schema validation, defense-in-depth permission
elevation (0555 -> 0755 -> 0555), and automatic Merkle re-binding in AGENTS.md.
"""
import json
from pathlib import Path
from typing import Any, Dict, Union

from stagecheck.core.agents_md import write_agents_contract
from stagecheck.core.evidence import update_evidence_manifest
from stagecheck.core.permissions import _safe_chmod, controlled_write_transaction
from stagecheck.core.utils import load_json_file, pretty_json_dumps
from stagecheck.schemas.validator import validate_active_state


def get_active_state_path(workspace_root: Union[str, Path]) -> Path:
    """Returns absolute path to controls/ACTIVE_STATE.json."""
    return Path(workspace_root).resolve() / "controls" / "ACTIVE_STATE.json"


def load_active_state(workspace_root: Union[str, Path]) -> Dict[str, Any]:
    """Loads and returns current ACTIVE_STATE.json dictionary."""
    state_file = get_active_state_path(workspace_root)
    if not state_file.is_file():
        raise FileNotFoundError(f"ACTIVE_STATE.json not found at '{state_file}'")
    return load_json_file(state_file)


def save_active_state(
    workspace_root: Union[str, Path],
    state_data: Dict[str, Any],
    update_manifest: bool = True,
    update_contract: bool = True,
) -> None:
    """Saves ACTIVE_STATE.json under controlled write transaction and updates Merkle bindings."""
    root = Path(workspace_root).resolve()
    controls_dir = root / "controls"
    state_file = controls_dir / "ACTIVE_STATE.json"

    # Strict fail-closed schema validation (SEC-04 / SR-05)
    validate_active_state(state_data)

    from stagecheck.core.locking import acquire_runtime_lock, is_runtime_lock_held
    from stagecheck.core.paths import write_text_nofollow

    if is_runtime_lock_held(root):
        with controlled_write_transaction(controls_dir):
            write_text_nofollow(state_file, pretty_json_dumps(state_data), append=False, mode=0o644)
            _safe_chmod(state_file, 0o444)

            if update_contract:
                try:
                    write_agents_contract(root)
                except Exception:
                    pass

            if update_manifest:
                try:
                    update_evidence_manifest(root, [state_file])
                except Exception:
                    pass
    else:
        with acquire_runtime_lock(root):
            with controlled_write_transaction(controls_dir):
                write_text_nofollow(state_file, pretty_json_dumps(state_data), append=False, mode=0o644)
                _safe_chmod(state_file, 0o444)

                if update_contract:
                    try:
                        write_agents_contract(root)
                    except Exception:
                        pass

                if update_manifest:
                    try:
                        update_evidence_manifest(root, [state_file])
                    except Exception:
                        pass
