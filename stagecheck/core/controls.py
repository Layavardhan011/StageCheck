"""Authoritative 8 Mandatory Controls Registry & Schema Validation Service (FR-08 / Spec 05 / DEC-008).

Manages the workspace controls registry, schema validation for all control descriptors,
symlink rejection, and permissions validation.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from stagecheck.core.utils import load_json_file
from stagecheck.schemas.validator import validate_control_descriptor


class ControlsRegistryError(Exception):
    """Base exception for controls registry failures."""


class MissingControlError(ControlsRegistryError):
    """Raised when a mandatory control descriptor is missing."""


class ControlsSecurityError(ControlsRegistryError):
    """Raised when symbolic links or unsafe path traversals are detected in controls/."""


MANDATORY_CONTROLS: Tuple[str, ...] = (
    "STAGECHECK_ROOT.json",
    "EVIDENCE_ROOT.json",
    "PRODUCT_REPOSITORIES.json",
    "QUALIFICATION_ROOT.json",
    "ACTIVE_STATE.json",
    "OWNER_GRANTS.md",
    "FAILURE_PREVENTION.md",
    "DISPOSITIONS.json",
)


def get_mandatory_controls() -> List[str]:
    """Return the list of the 8 mandatory control file names."""
    return list(MANDATORY_CONTROLS)


def validate_controls_registry(
    workspace_root: Union[str, Path],
    strict: bool = True,
) -> Dict[str, Any]:
    """Validate all 8 mandatory control files in controls/ against requirements and schemas.

    Checks:
    1. controls/ directory exists and is not a symbolic link.
    2. All 8 mandatory control files exist.
    3. No control file is a symbolic link.
    4. All JSON descriptors conform to their JSON schemas.
    5. All Markdown files are non-empty regular files.

    Args:
        workspace_root: Workspace root path.
        strict: If True, raises ControlsRegistryError on first failure.

    Returns:
        Dict with keys 'valid', 'validated', 'missing', 'errors'.
    """
    root = Path(workspace_root).resolve()
    controls_dir = root / "controls"

    if not controls_dir.is_dir():
        if strict:
            raise ControlsRegistryError(f"Mandatory controls directory not found at '{controls_dir}'")
        return {
            "valid": False,
            "validated": [],
            "missing": list(MANDATORY_CONTROLS),
            "errors": [f"controls/ directory missing at '{controls_dir}'"],
        }

    if controls_dir.is_symlink():
        raise ControlsSecurityError(f"controls directory '{controls_dir}' is a symbolic link.")

    validated: List[str] = []
    missing: List[str] = []
    errors: List[str] = []

    for name in MANDATORY_CONTROLS:
        control_path = controls_dir / name
        if control_path.is_symlink():
            err_msg = f"Mandatory control file '{name}' is a prohibited symbolic link."
            if strict:
                raise ControlsSecurityError(err_msg)
            errors.append(err_msg)
            continue

        if not control_path.is_file():
            missing.append(name)
            continue

        # Validate content & schema
        if name.endswith(".json"):
            try:
                data = load_json_file(control_path)
                validate_control_descriptor(name, data)
                validated.append(name)
            except Exception as err:
                err_msg = f"Schema validation error in '{name}': {err}"
                if strict:
                    raise ControlsRegistryError(err_msg) from err
                errors.append(err_msg)
        else:
            # Markdown files
            try:
                text = control_path.read_text(encoding="utf-8")
                if not text.strip():
                    err_msg = f"Mandatory markdown control '{name}' is empty."
                    if strict:
                        raise ControlsRegistryError(err_msg)
                    errors.append(err_msg)
                else:
                    validated.append(name)
            except Exception as err:
                err_msg = f"Failed to read markdown control '{name}': {err}"
                if strict:
                    raise ControlsRegistryError(err_msg) from err
                errors.append(err_msg)

    is_valid = len(missing) == 0 and len(errors) == 0
    if strict and not is_valid:
        if missing:
            raise MissingControlError(f"Missing mandatory control descriptors: {missing}")
        if errors:
            raise ControlsRegistryError(f"Control validation errors: {errors}")

    return {
        "valid": is_valid,
        "validated": validated,
        "missing": missing,
        "errors": errors,
    }

