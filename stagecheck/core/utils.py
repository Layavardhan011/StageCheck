"""StageCheck Core Utilities: Deterministic Hashing, RFC 8785 JCS, and Agent Slugs.

Provides canonical serialization, SHA-256 calculation, strict provider-neutral
agent slug validation, and robust JSON handling.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

# Provider-neutral slug regex: 3 to 64 chars, lowercase alphanumeric with internal hyphens
AGENT_SLUG_REGEX = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$")

# Forbidden path traversal and dangerous characters in identifiers
FORBIDDEN_IDENTIFIER_CHARS = {"/", "\\", ":", "\0", "..", "\n", "\r", "\t"}


class UtilityError(Exception):
    """Base exception for StageCheck core utilities."""


class AgentSlugError(UtilityError):
    """Raised when an agent slug violates provider-neutral standards."""


class SerializationError(UtilityError):
    """Raised when deterministic serialization fails."""


class JSONParseError(UtilityError):
    """Raised when parsing invalid or malformed JSON."""


class SchemaValidationError(UtilityError):
    """Raised when data fails schema validation rules."""


# ==========================================
# 1. PROVIDER-NEUTRAL AGENT SLUG VALIDATION
# ==========================================

def is_valid_agent_slug(slug: str) -> bool:
    """Check if a string matches the provider-neutral agent slug standard.

    Rules:
      - Length between 3 and 64 characters
      - Lowercase letters and numbers only, with optional internal hyphens
      - Cannot start or end with a hyphen
      - No slashes, colons, or vendor-specific namespaces (e.g. no 'claude/sonnet')
    """
    if not isinstance(slug, str):
        return False
    if any(char in slug for char in FORBIDDEN_IDENTIFIER_CHARS):
        return False
    return bool(AGENT_SLUG_REGEX.match(slug))


def validate_agent_slug(slug: str) -> str:
    """Validate and return a provider-neutral agent slug.

    Args:
        slug: The agent identifier string.

    Returns:
        The validated slug string.

    Raises:
        AgentSlugError: If the slug violates formatting or security rules.
    """
    if not isinstance(slug, str):
        raise AgentSlugError(f"Agent slug must be a string, got {type(slug).__name__}.")

    if not slug:
        raise AgentSlugError("Agent slug cannot be empty.")

    if any(char in slug for char in FORBIDDEN_IDENTIFIER_CHARS):
        raise AgentSlugError(
            f"Agent slug '{slug}' contains forbidden path-unsafe characters."
        )

    if not AGENT_SLUG_REGEX.match(slug):
        raise AgentSlugError(
            f"Invalid agent slug '{slug}'. Must be 3-64 lowercase alphanumeric "
            "characters with internal hyphens only (e.g. 'prompt-architect-1')."
        )

    return slug


# ==========================================
# 2. DETERMINISTIC SERIALIZATION & SHA-256
# ==========================================

def canonical_json_bytes(obj: Any) -> bytes:
    """Serialize object to bytes using RFC 8785 JSON Canonicalization Scheme (JCS).

    - Keys sorted recursively in lexicographical order
    - Minimal whitespace (no trailing spaces, separators=(',', ':'))
    - Strict UTF-8 encoding
    - NaN and Infinity disallowed
    """
    try:
        canonical_str = json.dumps(
            obj,
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        )
        return canonical_str.encode("utf-8")
    except (TypeError, ValueError) as err:
        raise SerializationError(f"Failed to canonically serialize object: {err}") from err


def canonical_json_dumps(obj: Any) -> str:
    """Serialize object to canonical RFC 8785 JSON string."""
    return canonical_json_bytes(obj).decode("utf-8")


def sha256_digest(data: Union[str, bytes]) -> str:
    """Compute the hexadecimal SHA-256 digest of string or bytes."""
    if isinstance(data, str):
        data_bytes = data.encode("utf-8")
    else:
        data_bytes = data
    return hashlib.sha256(data_bytes).hexdigest()


def sha256_canonical(obj: Any) -> str:
    """Compute deterministic SHA-256 digest over canonicalized RFC 8785 JSON."""
    return sha256_digest(canonical_json_bytes(obj))


def sha256_file(path: Union[str, Path]) -> str:
    """Compute the SHA-256 digest of a file in 64 KiB chunks."""
    file_path = Path(path)
    if not file_path.is_file():
        raise FileNotFoundError(f"File not found for SHA-256 calculation: {file_path}")

    hasher = hashlib.sha256()
    with open(file_path, "rb") as stream:
        while chunk := stream.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


# ==========================================
# 3. JSON PARSING & SCHEMA VALIDATION
# ==========================================

def load_json_file(path: Union[str, Path]) -> Any:
    """Load and parse JSON from a file with descriptive error handling."""
    file_path = Path(path)
    if not file_path.is_file():
        raise FileNotFoundError(f"JSON file does not exist: {file_path}")

    try:
        content = file_path.read_text(encoding="utf-8")
        return json.loads(content)
    except json.JSONDecodeError as err:
        raise JSONParseError(
            f"Malformed JSON in '{file_path}' at line {err.lineno}, col {err.colno}: {err.msg}"
        ) from err
    except UnicodeDecodeError as err:
        raise JSONParseError(f"UTF-8 decoding failed for '{file_path}': {err}") from err


def validate_schema(data: Any, schema: Dict[str, Any]) -> None:
    """Lightweight built-in JSON schema validator for core structures.

    Validates types, required object fields, pattern regexes, enums,
    minProperties, minItems, and additionalProperties.
    """
    if not isinstance(schema, dict):
        raise SchemaValidationError("Schema must be a dictionary.")

    expected_type = schema.get("type")
    if expected_type == "object":
        if not isinstance(data, dict):
            raise SchemaValidationError(f"Expected object, got {type(data).__name__}.")

        min_props = schema.get("minProperties")
        if min_props is not None and len(data) < min_props:
            raise SchemaValidationError(f"Object has {len(data)} properties, minimum required is {min_props}.")

        required = schema.get("required", [])
        for field in required:
            if field not in data:
                raise SchemaValidationError(f"Missing required property: '{field}'.")

        properties = schema.get("properties", {})
        additional_props = schema.get("additionalProperties")

        for key, val in data.items():
            if key in properties:
                validate_schema(val, properties[key])
            elif isinstance(additional_props, dict):
                validate_schema(val, additional_props)
            elif additional_props is False:
                raise SchemaValidationError(f"Unexpected additional property '{key}' not allowed by schema.")

    elif expected_type == "string":
        if not isinstance(data, str):
            raise SchemaValidationError(f"Expected string, got {type(data).__name__}.")
        pattern = schema.get("pattern")
        if pattern and not re.search(pattern, data):
            raise SchemaValidationError(
                f"String '{data}' does not match pattern '{pattern}'."
            )
        enum_values = schema.get("enum")
        if enum_values and data not in enum_values:
            raise SchemaValidationError(
                f"Value '{data}' not in allowed enum: {enum_values}."
            )

    elif expected_type == "integer":
        if not isinstance(data, int) or isinstance(data, bool):
            raise SchemaValidationError(f"Expected integer, got {type(data).__name__}.")
        minimum = schema.get("minimum")
        if minimum is not None and data < minimum:
            raise SchemaValidationError(f"Integer {data} is less than minimum {minimum}.")
        maximum = schema.get("maximum")
        if maximum is not None and data > maximum:
            raise SchemaValidationError(f"Integer {data} exceeds maximum {maximum}.")

    elif expected_type == "array":
        if not isinstance(data, list):
            raise SchemaValidationError(f"Expected array, got {type(data).__name__}.")
        min_items = schema.get("minItems")
        if min_items is not None and len(data) < min_items:
            raise SchemaValidationError(f"Array has {len(data)} items, minimum required is {min_items}.")
        items_schema = schema.get("items")
        if items_schema:
            for idx, item in enumerate(data):
                try:
                    validate_schema(item, items_schema)
                except SchemaValidationError as err:
                    raise SchemaValidationError(f"Array item at index {idx} invalid: {err}") from err

    elif expected_type == "boolean":
        if not isinstance(data, bool):
            raise SchemaValidationError(f"Expected boolean, got {type(data).__name__}.")


