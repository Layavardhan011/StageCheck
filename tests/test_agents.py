"""Unit tests for Provider-Neutral Agent Registration & Evidence Routing (P3-T1)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from stagecheck.core.agents import (
    AgentRegistrationError,
    AgentRole,
    DuplicateAgentError,
    InvalidAgentSlugError,
    RegisteredAgent,
    SecurityPathEscapeError,
    load_registered_agents,
    normalize_turn_id,
    resolve_agent_response_dir,
    resolve_task_attempt_dir,
)


class TestAgentProtocol(unittest.TestCase):
    """Test suite covering provider-neutral agent registration, routing, and turn counting."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp_dir.name).resolve()
        (self.workspace / "evidence" / "tasks").mkdir(parents=True, exist_ok=True)
        (self.workspace / "evidence" / "responses").mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_arbitrary_valid_agent_slugs(self) -> None:
        """Verify arbitrary valid AI provider slugs succeed."""
        valid_slugs = [
            "claude",
            "codex",
            "gemini-flash-15",
            "cursor-ide",
            "antigravity",
            "deepseek-coder-v2",
            "agent-42",
            "Custom-Provider-1",
        ]
        for slug in valid_slugs:
            agent = RegisteredAgent(name=slug, role=AgentRole.DUAL_ROLE)
            self.assertEqual(agent.name, slug.lower())

    def test_invalid_agent_slugs_rejected_before_writes(self) -> None:
        """Verify invalid slugs (dots, slashes, traversal, special chars) are rejected."""
        invalid_slugs = [
            "claude/v1",
            "../escape",
            "gemini.pro",
            "bad space",
            "-leading-hyphen",
            "trailing-hyphen-",
            "_leading-underscore",
            "slug*",
            "tool;",
            "",
            "a" * 65,  # Exceeds 64 characters
        ]
        for slug in invalid_slugs:
            with self.assertRaises((InvalidAgentSlugError, ValueError)):
                RegisteredAgent(name=slug, role=AgentRole.DUAL_ROLE)

    def test_load_registered_agents_dual_mode(self) -> None:
        """Verify loading valid dual-agent configuration from active state."""
        state = {
            "registered_agents": [
                {
                    "name": "gemini-flash",
                    "role": "prompt_and_audit",
                    "instruction": "instructions/gemini.md",
                    "comment": "Audit agent",
                },
                {
                    "name": "claude-sonnet",
                    "role": "code_implementation",
                    "instruction": "instructions/claude.md",
                    "comment": "Coding agent",
                },
            ]
        }
        agents = load_registered_agents(state)
        self.assertEqual(len(agents), 2)
        self.assertEqual(agents[0].name, "gemini-flash")
        self.assertEqual(agents[0].role, AgentRole.PROMPT_AND_AUDIT)
        self.assertEqual(agents[1].name, "claude-sonnet")
        self.assertEqual(agents[1].role, AgentRole.CODE_IMPLEMENTATION)

    def test_load_registered_agents_single_agent_mode(self) -> None:
        """Verify loading valid single-agent configuration from protected active state."""
        state = {
            "protected": {
                "registered_agents": [
                    {
                        "name": "antigravity-unified",
                        "role": "dual_role",
                        "instruction": "instructions/antigravity.md",
                        "comment": "Unified prompt and coding agent",
                    }
                ]
            }
        }
        agents = load_registered_agents(state)
        self.assertEqual(len(agents), 1)
        self.assertEqual(agents[0].name, "antigravity-unified")
        self.assertEqual(agents[0].role, AgentRole.DUAL_ROLE)

    def test_load_registered_agents_rejects_duplicate_names(self) -> None:
        """Verify rejection when duplicate agent names are registered."""
        state = {
            "registered_agents": [
                {"name": "agent-one", "role": "prompt_and_audit"},
                {"name": "agent-one", "role": "code_implementation"},
            ]
        }
        with self.assertRaises(DuplicateAgentError):
            load_registered_agents(state)

    def test_load_registered_agents_rejects_missing_roles(self) -> None:
        """Verify rejection when dual-agent roles are incomplete."""
        state = {
            "registered_agents": [
                {"name": "agent-one", "role": "prompt_and_audit"}
            ]
        }
        with self.assertRaises(AgentRegistrationError):
            load_registered_agents(state)

    def test_resolve_task_attempt_dir_success_and_creation(self) -> None:
        """Verify safe task attempt path resolution and disk creation."""
        attempt_dir = resolve_task_attempt_dir(
            self.workspace,
            task_id="task-402",
            attempt=1,
            ensure_exists=True,
        )
        expected = self.workspace / "evidence" / "tasks" / "task-402" / "attempt_1"
        self.assertEqual(attempt_dir, expected)
        self.assertTrue(attempt_dir.is_dir())

    def test_resolve_task_attempt_dir_path_traversal_rejection(self) -> None:
        """Verify path traversal attempts in task_id are rejected before disk calls."""
        with self.assertRaises(ValueError):
            resolve_task_attempt_dir(self.workspace, task_id="../escape", attempt=1)

        with self.assertRaises(ValueError):
            resolve_task_attempt_dir(self.workspace, task_id="task/escape", attempt=1)

    def test_resolve_agent_response_dir_success_and_containment(self) -> None:
        """Verify resolving response evidence path per agent."""
        resp_dir = resolve_agent_response_dir(
            self.workspace,
            agent_slug="gemini-flash-15",
            ensure_exists=True,
        )
        expected = self.workspace / "evidence" / "responses" / "gemini-flash-15"
        self.assertEqual(resp_dir, expected)
        self.assertTrue(resp_dir.is_dir())

    def test_resolve_agent_response_dir_traversal_rejection(self) -> None:
        """Verify directory traversal in agent slug is rejected."""
        with self.assertRaises(InvalidAgentSlugError):
            resolve_agent_response_dir(self.workspace, agent_slug="../../root")

    def test_normalize_turn_id_explicit_turn(self) -> None:
        """Verify normalizing event containing explicit turn_id."""
        event_int = {"turn_id": 4}
        self.assertEqual(normalize_turn_id(event_int), "4")

        event_str = {"turn_id": "turn-7"}
        self.assertEqual(normalize_turn_id(event_str), "turn-7")

    def test_normalize_turn_id_fallback_counter(self) -> None:
        """Verify fallback auto-increment when turn_id is absent."""
        # Empty history
        self.assertEqual(normalize_turn_id({}), "1")

        # History with 2 distinct responses
        history = [
            {"response_task_id": "resp-01", "content": "alpha"},
            {"response_task_id": "resp-01", "content": "alpha-part2"},
            {"response_task_id": "resp-02", "content": "beta"},
        ]
        self.assertEqual(normalize_turn_id({}, history_records=history), "3")


if __name__ == "__main__":
    unittest.main()
