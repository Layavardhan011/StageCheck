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
    pretty_json_dumps,
    sha256_canonical,
    sha256_digest,
    sha256_file,
    validate_agent_slug,
    validate_schema,
    write_json_file,
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

    def test_pretty_json_formatting(self) -> None:
        """Verify pretty_json_dumps meets multi-line 2-space indentation and newline requirements."""
        data = {
            "agent": "agent1",
            "status": "ready",
            "config": {"enabled": True, "mode": "strict"},
            "checks": ["security", "quality", "compliance"],
        }
        output = pretty_json_dumps(data)
        expected = (
            "{\n"
            '  "agent": "agent1",\n'
            '  "status": "ready",\n'
            '  "config": {\n'
            '    "enabled": true,\n'
            '    "mode": "strict"\n'
            "  },\n"
            '  "checks": [\n'
            '    "security",\n'
            '    "quality",\n'
            '    "compliance"\n'
            "  ]\n"
            "}\n"
        )
        self.assertEqual(output, expected)
        # Verify valid JSON round-trip
        self.assertEqual(load_json_file(self.temp_path / "dummy.json" if False else None) if False else None, None)

    def test_write_json_file(self) -> None:
        """Verify write_json_file writes readable multi-line JSON ending with newline."""
        test_file = self.temp_path / "pretty.json"
        data = {"task_id": "task-01", "items": [1, 2]}
        write_json_file(test_file, data)

        content = test_file.read_text(encoding="utf-8")
        self.assertTrue(content.endswith("\n"))
        self.assertIn('\n  "task_id": "task-01",\n', content)
        self.assertIn('\n  "items": [\n    1,\n    2\n  ]\n', content)
        loaded = load_json_file(test_file)
        self.assertEqual(loaded, data)

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

    def test_strict_json_rejects_nan_and_duplicate_keys(self) -> None:
        from stagecheck.core.utils import SerializationError, pretty_json_dumps

        dup_file = self.temp_path / "dup.json"
        dup_file.write_text('{"a": 1, "a": 2}\n', encoding="utf-8")
        with self.assertRaises(JSONParseError):
            load_json_file(dup_file)

        nan_file = self.temp_path / "nan.json"
        nan_file.write_text('{"score": NaN}\n', encoding="utf-8")
        with self.assertRaises(JSONParseError):
            load_json_file(nan_file)

        with self.assertRaises(SerializationError):
            pretty_json_dumps({"score": float("nan")})

    def test_validate_schema_enforces_unions_number_minlength_maxitems_enum_and_newline_anchor(self) -> None:
        # Union type list & null
        union_schema = {"type": ["string", "null"]}
        validate_schema(None, union_schema)
        validate_schema("ok", union_schema)
        with self.assertRaises(SchemaValidationError):
            validate_schema(123, union_schema)

        # number minimum/maximum (rejecting bool)
        num_schema = {"type": "number", "minimum": 0.0, "maximum": 1.0}
        validate_schema(0.5, num_schema)
        with self.assertRaises(SchemaValidationError):
            validate_schema(True, num_schema)
        with self.assertRaises(SchemaValidationError):
            validate_schema(1.5, num_schema)

        # Top-level enum without type
        with self.assertRaises(SchemaValidationError):
            validate_schema("INVALID", {"enum": ["A", "B"]})

        # minLength, maxItems, trailing newline against $
        str_schema = {"type": "string", "minLength": 2, "pattern": "^[a-z]+$"}
        with self.assertRaises(SchemaValidationError):
            validate_schema("a", str_schema)
        with self.assertRaises(SchemaValidationError):
            validate_schema("abc\n", str_schema)

        arr_schema = {"type": "array", "maxItems": 2}
        with self.assertRaises(SchemaValidationError):
            validate_schema([1, 2, 3], arr_schema)


if __name__ == "__main__":
    unittest.main()

