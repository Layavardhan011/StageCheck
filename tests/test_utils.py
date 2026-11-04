"""Unit Tests for Hashing, RFC 8785 Canonical JCS, and Agent Slugs (P1-T4)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from stagecheck.core.utils import (
    AgentSlugError,
    JSONParseError,
    SchemaValidationError,
    SerializationError,
    canonical_json_bytes,
    canonical_json_dumps,
    is_valid_agent_slug,
    load_json_file,
    sha256_canonical,
    sha256_digest,
    sha256_file,
    validate_agent_slug,
    validate_schema,
)


class TestUtils(unittest.TestCase):
    """Test suite for agent slugs, RFC 8785 canonical JSON, and schema utilities."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    # ==========================================
    # Agent Slug Tests
    # ==========================================

    def test_valid_agent_slugs(self) -> None:
        valid_slugs = [
            "agent-1",
            "prompt-architect",
            "code-implementer-2",
            "sonnet-specialist",
            "abc",
            "agent-0123456789-test",
        ]
        for slug in valid_slugs:
            with self.subTest(slug=slug):
                self.assertTrue(is_valid_agent_slug(slug))
                self.assertEqual(validate_agent_slug(slug), slug)

    def test_invalid_agent_slugs(self) -> None:
        invalid_slugs = [
            "",                        # empty
            "a",                       # too short (< 3)
            "ab",                      # too short (< 3)
            "A" * 65,                  # too long (> 64)
            "Agent-One",               # uppercase
            "-leading-hyphen",         # leading hyphen
            "trailing-hyphen-",        # trailing hyphen
            "claude/3.5-sonnet",       # path slash
            "gpt:4o",                  # colon
            "agent..traversal",        # path traversal
            "agent\0null",             # null byte
        ]
        for slug in invalid_slugs:
            with self.subTest(slug=slug):
                self.assertFalse(is_valid_agent_slug(slug))
                with self.assertRaises(AgentSlugError):
                    validate_agent_slug(slug)

    # ==========================================
    # RFC 8785 Canonical JSON & SHA-256 Tests
    # ==========================================

    def test_canonical_json_key_sorting(self) -> None:
        obj1 = {"z": 1, "a": {"d": 4, "c": 3}, "m": [3, 2, 1]}
        obj2 = {"m": [3, 2, 1], "a": {"c": 3, "d": 4}, "z": 1}

        # Canonical strings must be identical and sorted
        canon1 = canonical_json_dumps(obj1)
        canon2 = canonical_json_dumps(obj2)
        self.assertEqual(canon1, '{"a":{"c":3,"d":4},"m":[3,2,1],"z":1}')
        self.assertEqual(canon1, canon2)

        # Canonical SHA-256 must match
        self.assertEqual(sha256_canonical(obj1), sha256_canonical(obj2))

    def test_sha256_file_calculation(self) -> None:
        test_file = self.temp_path / "sample.txt"
        test_file.write_text("StageCheck Deterministic Integrity Test", encoding="utf-8")

        expected_digest = sha256_digest("StageCheck Deterministic Integrity Test")
        self.assertEqual(sha256_file(test_file), expected_digest)

    def test_sha256_file_missing_raises_error(self) -> None:
        with self.assertRaises(FileNotFoundError):
            sha256_file(self.temp_path / "nonexistent.file")

    # ==========================================
    # JSON Loading & Schema Validation Tests
    # ==========================================

    def test_load_json_file_success_and_malformed(self) -> None:
        valid_file = self.temp_path / "valid.json"
        valid_file.write_text('{"task_id": "task-101", "attempts": 1}', encoding="utf-8")
        loaded = load_json_file(valid_file)
        self.assertEqual(loaded["task_id"], "task-101")

        malformed_file = self.temp_path / "malformed.json"
        malformed_file.write_text('{"task_id": "incomplete', encoding="utf-8")
        with self.assertRaises(JSONParseError):
            load_json_file(malformed_file)

    def test_schema_validation_passes_valid_data(self) -> None:
        schema = {
            "type": "object",
            "required": ["task_id", "outcome", "attempts"],
            "properties": {
                "task_id": {"type": "string", "pattern": "^task-[0-9]+$"},
                "outcome": {"type": "string", "enum": ["PASSED", "FAILED"]},
                "attempts": {"type": "integer", "minimum": 1},
                "active": {"type": "boolean"},
            },
        }
        valid_data = {
            "task_id": "task-101",
            "outcome": "PASSED",
            "attempts": 2,
            "active": True,
        }
        # Should not raise
        validate_schema(valid_data, schema)

    def test_schema_validation_catches_missing_required(self) -> None:
        schema = {"type": "object", "required": ["task_id"]}
        with self.assertRaises(SchemaValidationError) as ctx:
            validate_schema({}, schema)
        self.assertIn("Missing required property", str(ctx.exception))

    def test_schema_validation_catches_enum_violation(self) -> None:
        schema = {
            "type": "object",
            "properties": {"outcome": {"type": "string", "enum": ["PASSED", "FAILED"]}},
        }
        with self.assertRaises(SchemaValidationError) as ctx:
            validate_schema({"outcome": "UNKNOWN"}, schema)
        self.assertIn("not in allowed enum", str(ctx.exception))

    def test_schema_validation_catches_pattern_violation(self) -> None:
        schema = {
            "type": "object",
            "properties": {"task_id": {"type": "string", "pattern": "^task-[0-9]+$"}},
        }
        with self.assertRaises(SchemaValidationError) as ctx:
            validate_schema({"task_id": "invalid-format"}, schema)
        self.assertIn("does not match pattern", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
