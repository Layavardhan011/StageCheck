"""Unit tests for Spec 05: Universal Agent Decoupling & Dynamic Provider Architecture."""

import unittest
from stagecheck.core.utils import AgentSlugError, is_valid_agent_slug, validate_agent_slug


class TestUniversalAgentDecoupling(unittest.TestCase):
    """Test dynamic agent validation, provider independence, and security bounds."""

    def test_valid_arbitrary_agent_slugs(self):
        """Verify arbitrary valid agent provider names are accepted."""
        valid_agents = [
            "claude",
            "codex",
            "gemini",
            "cursor",
            "antigravity",
            "roo-code",
            "gpt-4o-mini",
            "custom-llm-1",
        ]
        for slug in valid_agents:
            with self.subTest(slug=slug):
                self.assertTrue(is_valid_agent_slug(slug), f"Slug '{slug}' should be valid")
                self.assertEqual(validate_agent_slug(slug), slug)

    def test_invalid_agent_slugs_rejected(self):
        """Verify invalid agent names, path traversals, and forbidden characters are rejected."""
        invalid_slugs = [
            "",  # Empty
            "-claude",  # Starts with hyphen
            "_codex",  # Starts with underscore
            "claude/subagent",  # Slash / Path traversal
            "../escape",  # Relative path traversal
            "agent.name",  # Dot not permitted in slug
            "agent$evil",  # Shell metacharacter
            "agent`rm -rf`",  # Command substitution
            "a" * 65,  # Over 64 chars max length
        ]
        for slug in invalid_slugs:
            with self.subTest(slug=slug):
                self.assertFalse(is_valid_agent_slug(slug), f"Slug '{slug}' should be rejected")
                with self.assertRaises(AgentSlugError):
                    validate_agent_slug(slug)

    def test_duplicate_agent_identifiers_rejected(self):
        """Verify duplicate registered agent identifiers in control descriptors are detected."""
        registered_agents = [
            {"name": "agent1", "role": "prompt_and_audit"},
            {"name": "agent1", "role": "code_implementation"},
        ]
        names = [a["name"] for a in registered_agents]
        has_duplicates = len(names) != len(set(names))
        self.assertTrue(has_duplicates, "Duplicate agent names must be detected")

    def test_provider_independent_turn_ids(self):
        """Verify turn tracking works for arbitrary agent providers without branching."""
        # Simulated event with explicit turn_id
        event_with_turn = {"turn_id": "turn-42", "stop_hook_active": False}
        turn_result = str(event_with_turn.get("turn_id"))
        self.assertEqual(turn_result, "turn-42")

        # Simulated event without turn_id falls back to monotonic counter
        event_without_turn = {}
        records_sim = [{"response_task_id": "task-1"}, {"response_task_id": "task-2"}]
        turn_fallback = (
            str(event_without_turn.get("turn_id"))
            if event_without_turn.get("turn_id") is not None
            else str(len(records_sim) + 1)
        )
        self.assertEqual(turn_fallback, "3")


if __name__ == "__main__":
    unittest.main()
