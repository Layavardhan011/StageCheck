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


def pretty_json_dumps(obj: Any, indent: int = 2) -> str:
    """Serialize object to formatted, human-readable multi-line JSON with 2-space indentation.

    Requirements:
      1. Every JSON object uses multi-line formatting.
      2. Each key-value field appears on its own line.
      3. Nested objects and arrays are properly expanded and indented.
      4. Indentation is consistently 2 spaces.
      5. Preserves data structure, types, and values (ensure_ascii=False).
      6. Output always ends with a newline.
    """
    try:
        return json.dumps(obj, indent=indent, ensure_ascii=False, allow_nan=False) + "\n"
    except (TypeError, ValueError) as err:
        raise SerializationError(f"Failed to serialize object to formatted JSON: {err}") from err


def write_json_file(path: Union[str, Path], data: Any, indent: int = 2) -> None:
    """Write data to a file formatted as readable JSON with 2-space indentation and trailing newline."""
    file_path = Path(path)
    file_path.write_text(pretty_json_dumps(data, indent=indent), encoding="utf-8")


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

def _reject_duplicate_json_keys(pairs: List[tuple]) -> Dict[str, Any]:
    """Object pairs hook that rejects duplicate keys in JSON objects."""
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise JSONParseError(f"Duplicate JSON key '{key}' is not permitted.")
        result[key] = value
    return result


def _reject_nonfinite_json_constant(constant: str) -> Any:
    """Reject non-RFC-8259 JSON numeric constants (NaN, Infinity, -Infinity)."""
    raise JSONParseError(f"Non-standard JSON constant '{constant}' is not permitted.")


def strict_json_loads(content: str, source: str = "<memory>") -> Any:
    """Parse JSON string strictly per RFC 8259 (rejects duplicate keys and NaN/Infinity)."""
    try:
        return json.loads(
            content,
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_nonfinite_json_constant,
        )
    except JSONParseError:
        raise
    except json.JSONDecodeError as err:
        raise JSONParseError(
            f"Malformed JSON in '{source}' at line {err.lineno}, col {err.colno}: {err.msg}"
        ) from err


def load_json_file(path: Union[str, Path]) -> Any:
    """Load and parse JSON from a file with strict RFC 8259 enforcement."""
    file_path = Path(path)
    if not file_path.is_file():
        raise FileNotFoundError(f"JSON file does not exist: {file_path}")

    try:
        content = file_path.read_text(encoding="utf-8")
        return strict_json_loads(content, source=str(file_path))
    except UnicodeDecodeError as err:
        raise JSONParseError(f"UTF-8 decoding failed for '{file_path}': {err}") from err


def _matches_json_type(data: Any, type_name: str) -> bool:
    if type_name == "object":
        return isinstance(data, dict)
    if type_name == "array":
        return isinstance(data, list)
    if type_name == "string":
        return isinstance(data, str)
    if type_name == "integer":
        return isinstance(data, int) and not isinstance(data, bool)
    if type_name == "number":
        return isinstance(data, (int, float)) and not isinstance(data, bool)
    if type_name == "boolean":
        return isinstance(data, bool)
    if type_name == "null":
        return data is None
    raise SchemaValidationError(f"Unsupported schema type '{type_name}'.")


def validate_schema(data: Any, schema: Dict[str, Any]) -> None:
    """Strict built-in JSON schema validator for core structures.

    Validates types (including union lists and number), enum, const, oneOf, anyOf,
    required, minProperties, additionalProperties, minLength, maxLength, pattern,
    minimum, maximum, minItems, maxItems, and items.
    """
    if not isinstance(schema, dict):
        raise SchemaValidationError("Schema must be a dictionary.")

    if "const" in schema:
        if data != schema["const"] or type(data) is not type(schema["const"]):
            raise SchemaValidationError(f"Expected const value '{schema['const']}', got '{data}'.")

    if "enum" in schema:
        enum_values = schema["enum"]
        if not any(data == ev and type(data) is type(ev) for ev in enum_values):
            raise SchemaValidationError(
                f"Value '{data}' not in allowed enum: {enum_values}."
            )

    if "oneOf" in schema:
        matches = 0
        last_err = None
        for sub in schema["oneOf"]:
            try:
                validate_schema(data, sub)
                matches += 1
            except SchemaValidationError as err:
                last_err = err
        if matches != 1:
            raise SchemaValidationError(f"Expected exactly one matching schema in oneOf, matched {matches}: {last_err}")
        return

    if "anyOf" in schema:
        matched = False
        last_err = None
        for sub in schema["anyOf"]:
            try:
                validate_schema(data, sub)
                matched = True
                break
            except SchemaValidationError as err:
                last_err = err
        if not matched:
            raise SchemaValidationError(f"No schemas matched in anyOf: {last_err}")
        return

    expected_type = schema.get("type")
    if expected_type is not None:
        allowed_types = expected_type if isinstance(expected_type, list) else [expected_type]
        if not allowed_types or not any(_matches_json_type(data, t) for t in allowed_types):
            raise SchemaValidationError(
                f"Expected type {expected_type!r}, got {type(data).__name__}."
            )

    if isinstance(data, dict):
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

    elif isinstance(data, str):
        min_length = schema.get("minLength")
        if min_length is not None and len(data) < min_length:
            raise SchemaValidationError(
                f"String length {len(data)} is less than minLength {min_length}."
            )
        max_length = schema.get("maxLength")
        if max_length is not None and len(data) > max_length:
            raise SchemaValidationError(
                f"String length {len(data)} exceeds maxLength {max_length}."
            )
        pattern = schema.get("pattern")
        if pattern is not None:
            if not re.search(pattern, data) or (
                pattern.endswith("$") and not pattern.endswith(r"\$") and data.endswith("\n")
            ):
                raise SchemaValidationError(
                    f"String '{data}' does not match pattern '{pattern}'."
                )

    elif isinstance(data, (int, float)) and not isinstance(data, bool):
        minimum = schema.get("minimum")
        if minimum is not None and data < minimum:
            raise SchemaValidationError(f"Number {data} is less than minimum {minimum}.")
        maximum = schema.get("maximum")
        if maximum is not None and data > maximum:
            raise SchemaValidationError(f"Number {data} exceeds maximum {maximum}.")

    elif isinstance(data, list):
        min_items = schema.get("minItems")
        if min_items is not None and len(data) < min_items:
            raise SchemaValidationError(f"Array has {len(data)} items, minimum required is {min_items}.")
        max_items = schema.get("maxItems")
        if max_items is not None and len(data) > max_items:
            raise SchemaValidationError(f"Array has {len(data)} items, maximum allowed is {max_items}.")
        items_schema = schema.get("items")
        if items_schema:
            for idx, item in enumerate(data):
                try:
                    validate_schema(item, items_schema)
                except SchemaValidationError as err:
                    raise SchemaValidationError(f"Array item at index {idx} invalid: {err}") from err


