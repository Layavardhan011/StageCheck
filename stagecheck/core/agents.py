"""Provider-Neutral Agent Registration, Evidence Routing, and Turn Tracking (P3-T1).

Enforces universal agent decoupling, centralized slug validation, dynamic evidence
routing with strict path containment, and normalized turn tracking.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union

from stagecheck.core.paths import StageCheckPathError, is_path_contained, resolve_task_dir, safe_resolve
from stagecheck.core.utils import AgentSlugError, validate_agent_slug


class AgentRole(str, Enum):
    """Allowed governance roles for registered AI agents."""

    PROMPT_AND_AUDIT = "prompt_and_audit"
    CODE_IMPLEMENTATION = "code_implementation"
    DUAL_ROLE = "dual_role"


class AgentRegistrationError(Exception):
    """Raised when agent registration or validation fails."""


class InvalidAgentSlugError(AgentRegistrationError):
    """Raised when an agent slug contains illegal characters or escapes boundaries."""


class DuplicateAgentError(AgentRegistrationError):
    """Raised when duplicate agent names are encountered in the registry."""


class SecurityPathEscapeError(AgentRegistrationError):
    """Raised when an evidence route attempts path traversal outside evidence roots."""


@dataclass(frozen=True)
class RegisteredAgent:
    """Immutable representation of a registered governance agent."""

    name: str
    role: AgentRole
    instruction: Optional[str] = None
    comment: Optional[str] = None
    enabled: bool = True

    def __post_init__(self) -> None:
        # Validate slug at initialization time
        try:
            validated = validate_agent_slug(str(self.name).lower().strip())
        except (AgentSlugError, ValueError) as err:
            raise InvalidAgentSlugError(str(err)) from err

        if self.name != validated:
            object.__setattr__(self, "name", validated)


def parse_agent_definition(agent_data: Dict[str, Any]) -> RegisteredAgent:
    """Parse and validate a single agent configuration entry.

    Args:
        agent_data: Dictionary containing 'name', 'role', and optional metadata.

    Returns:
        Validated RegisteredAgent instance.
    """
    if not isinstance(agent_data, dict):
        raise AgentRegistrationError("Agent configuration entry must be a dictionary.")

    name = agent_data.get("name")
    if not name or not isinstance(name, str):
        raise AgentRegistrationError("Agent configuration missing valid 'name' string.")

    try:
        norm_name = validate_agent_slug(name.lower().strip())
    except (AgentSlugError, ValueError) as err:
        raise InvalidAgentSlugError(str(err)) from err

    role_str = agent_data.get("role")
    try:
        role = AgentRole(role_str)
    except (ValueError, TypeError) as err:
        raise AgentRegistrationError(
            f"Invalid role '{role_str}' for agent '{name}'. Allowed roles: "
            f"{[r.value for r in AgentRole]}"
        ) from err

    return RegisteredAgent(
        name=norm_name,
        role=role,
        instruction=agent_data.get("instruction"),
        comment=agent_data.get("comment"),
        enabled=bool(agent_data.get("enabled", True)),
    )


def load_registered_agents(active_state_data: Dict[str, Any]) -> List[RegisteredAgent]:
    """Extract and validate registered agents from ACTIVE_STATE descriptor.

    Reads from protected.registered_agents or top-level registered_agents.
    Validates unique slugs, role coverage, and active status.

    Args:
        active_state_data: Decoded ACTIVE_STATE.json dictionary.

    Returns:
        List of validated RegisteredAgent records.
    """
    raw_agents: Optional[List[Any]] = None

    # Check protected block first (spec-01 & spec-05)
    protected = active_state_data.get("protected")
    if isinstance(protected, dict) and "registered_agents" in protected:
        raw_agents = protected.get("registered_agents")
    elif "registered_agents" in active_state_data:
        raw_agents = active_state_data.get("registered_agents")

    if raw_agents is None:
        raise AgentRegistrationError(
            "ACTIVE_STATE descriptor contains no 'registered_agents' configuration."
        )

    if not isinstance(raw_agents, list) or len(raw_agents) == 0:
        raise AgentRegistrationError(
            "registered_agents must be a non-empty list of agent configurations."
        )

    registered: List[RegisteredAgent] = []
    seen_names: Set[str] = set()

    for item in raw_agents:
        agent = parse_agent_definition(item)
        if agent.name in seen_names:
            raise DuplicateAgentError(f"Duplicate agent name '{agent.name}' registered.")
        seen_names.add(agent.name)
        registered.append(agent)

    # Validate mode coverage
    has_dual_role = any(a.role == AgentRole.DUAL_ROLE and a.enabled for a in registered)
    has_prompt = any(a.role == AgentRole.PROMPT_AND_AUDIT and a.enabled for a in registered)
    has_code = any(a.role == AgentRole.CODE_IMPLEMENTATION and a.enabled for a in registered)

    if not has_dual_role and not (has_prompt and has_code):
        raise AgentRegistrationError(
            "Agent registry must define either a dual-role agent or both 'prompt_and_audit' "
            "and 'code_implementation' agents."
        )

    return registered


_TASK_ID_REGEX = re.compile(r"^[a-zA-Z0-9_-]+$")


def resolve_task_attempt_dir(
    workspace_root: Union[str, Path],
    task_id: str,
    attempt: int,
    ensure_exists: bool = False,
) -> Path:
    """Resolve and containment-check the evidence directory for a task attempt.

    Enforces path containment under <workspace_root>/evidence/tasks/.

    Args:
        workspace_root: Root workspace directory path.
        task_id: Unique task identifier (e.g. task-101).
        attempt: Attempt index (positive integer >= 1).
        ensure_exists: Whether to create the directory on disk.

    Returns:
        Resolved Path object.

    Raises:
        ValueError: If task_id or attempt are invalid.
        SecurityPathEscapeError: If the resolved path escapes the evidence tasks boundary.
    """
    if not isinstance(attempt, int) or attempt < 1:
        raise ValueError(f"Invalid attempt index {attempt}. Must be an integer >= 1.")

    root = Path(workspace_root).resolve()
    try:
        resolve_task_dir(root, task_id)
        target_dir = safe_resolve(f"evidence/tasks/{task_id}/attempt_{attempt}", root)
    except StageCheckPathError as err:
        raise SecurityPathEscapeError(
            f"Security violation: Task evidence path escapes boundary: {err}"
        ) from err

    if ensure_exists:
        target_dir.mkdir(parents=True, exist_ok=True)

    return target_dir


def resolve_agent_response_dir(
    workspace_root: Union[str, Path],
    agent_slug: str,
    ensure_exists: bool = False,
) -> Path:
    """Resolve and containment-check the evidence directory for an agent's responses.

    Enforces path containment under <workspace_root>/evidence/responses/.

    Args:
        workspace_root: Root workspace directory path.
        agent_slug: Arbitrary valid provider agent slug.
        ensure_exists: Whether to create the directory on disk.

    Returns:
        Resolved Path object.

    Raises:
        InvalidAgentSlugError: If agent_slug fails validation.
        SecurityPathEscapeError: If the resolved path escapes the evidence responses boundary.
    """
    try:
        norm_slug = validate_agent_slug(str(agent_slug).lower().strip())
    except (AgentSlugError, ValueError) as err:
        raise InvalidAgentSlugError(str(err)) from err

    root = Path(workspace_root).resolve()
    responses_root = (root / "evidence" / "responses").resolve()
    target_dir = (responses_root / norm_slug).resolve()

    if not is_path_contained(target_dir, responses_root):
        raise SecurityPathEscapeError(
            f"Security violation: Agent response path '{target_dir}' escapes '{responses_root}'."
        )

    if ensure_exists:
        target_dir.mkdir(parents=True, exist_ok=True)

    return target_dir


def normalize_turn_id(
    event: Dict[str, Any],
    history_records: Optional[List[Dict[str, Any]]] = None,
) -> str:
    """Normalize turn identifiers across arbitrary AI agent response events.

    Decouples turn counting from hardcoded agent names:
    - If event has 'turn_id', standardizes to string representation.
    - Otherwise, auto-increments based on unique response_task_ids in history_records.

    Args:
        event: Incoming agent hook/response event payload.
        history_records: Optional historical list of recorded responses for session.

    Returns:
        Normalized string turn identifier (e.g. '1', '2', '3').
    """
    if not isinstance(event, dict):
        raise ValueError("Event must be a dictionary.")

    turn = event.get("turn_id")
    if turn is not None:
        turn_str = str(turn).strip()
        if not turn_str:
            raise ValueError("Provided turn_id cannot be empty whitespace.")
        return turn_str

    if history_records:
        unique_tasks = {
            r.get("response_task_id")
            for r in history_records
            if isinstance(r, dict) and r.get("response_task_id")
        }
        return str(len(unique_tasks) + 1)

    return "1"
