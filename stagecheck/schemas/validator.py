"""JSON Schema Validation Service for StageCheck Control Descriptors (P2-T2).

Validates PRODUCT_REPOSITORIES (Schema v2), ACTIVE_STATE, STAGECHECK_ROOT,
EVIDENCE_ROOT, QUALIFICATION_ROOT, and DISPOSITIONS.
"""

from __future__ import annotations

from typing import Any, Dict

from stagecheck.core.utils import (
    JSONParseError,
    SchemaValidationError,
    load_json_file,
    validate_schema,
)
from stagecheck.schemas import get_schema_path


def get_product_repositories_schema() -> Dict[str, Any]:
    """Load and return the PRODUCT_REPOSITORIES Schema v2."""
    schema_path = get_schema_path("product_repositories.schema.json")
    return load_json_file(schema_path)


def get_active_state_schema() -> Dict[str, Any]:
    """Load and return the ACTIVE_STATE Schema."""
    schema_path = get_schema_path("active_state.schema.json")
    return load_json_file(schema_path)


def get_control_descriptors_schema() -> Dict[str, Any]:
    """Load and return the multi-descriptor schemas."""
    schema_path = get_schema_path("control_descriptors.schema.json")
    return load_json_file(schema_path)


def validate_product_repositories(data: Dict[str, Any]) -> None:
    """Validate a PRODUCT_REPOSITORIES descriptor against Schema v2.

    Raises:
        SchemaValidationError: If data violates schema requirements.
    """
    schema = get_product_repositories_schema()
    validate_schema(data, schema)


def validate_active_state(data: Dict[str, Any]) -> None:
    """Validate an ACTIVE_STATE descriptor.

    Raises:
        SchemaValidationError: If data violates schema requirements.
    """
    schema = get_active_state_schema()
    validate_schema(data, schema)


def validate_control_descriptor(descriptor_name: str, data: Dict[str, Any]) -> None:
    """Validate an individual control descriptor by name.

    Supported descriptor names:
      - 'PRODUCT_REPOSITORIES.json'
      - 'ACTIVE_STATE.json'
      - 'STAGECHECK_ROOT.json'
      - 'EVIDENCE_ROOT.json'
      - 'QUALIFICATION_ROOT.json'
      - 'DISPOSITIONS.json'

    Raises:
        SchemaValidationError: If data violates schema requirements.
    """
    if descriptor_name == "PRODUCT_REPOSITORIES.json":
        validate_product_repositories(data)
        return

    if descriptor_name == "ACTIVE_STATE.json":
        validate_active_state(data)
        return

    defs = get_control_descriptors_schema().get("definitions", {})

    mapping = {
        "STAGECHECK_ROOT.json": "stagecheck_root",
        "EVIDENCE_ROOT.json": "evidence_root",
        "QUALIFICATION_ROOT.json": "qualification_root",
        "DISPOSITIONS.json": "dispositions",
    }

    if descriptor_name not in mapping:
        # Markdown descriptors (OWNER_GRANTS.md, FAILURE_PREVENTION.md) validated separately
        return

    schema_key = mapping[descriptor_name]
    schema = defs.get(schema_key)
    if not schema:
        raise SchemaValidationError(f"No schema definition found for: '{descriptor_name}'.")

    validate_schema(data, schema)

