"""StageCheck Verification Engine: Check Stages and Defect Data Structures (P4-T2)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


@dataclass
class Defect:
    """Represents a verification defect emitted by an audit stage."""

    defect_id: str
    message: str
    stage: str
    severity: str = "CRITICAL"
    blocking: bool = True
    repo: Optional[str] = None
    citation: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class StageResult:
    """Result of executing an individual verification stage."""

    stage_id: str
    status: str  # "CLEAR" or "FAIL"
    defects: List[Defect] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def is_clear(self) -> bool:
        return self.status == "CLEAR" and not any(d.blocking for d in self.defects)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stage_id": self.stage_id,
            "status": self.status,
            "defects": [d.to_dict() for d in self.defects],
            "errors": self.errors,
        }


@dataclass
class AuditContext:
    """Contextual state provided to each verification stage during audit."""

    workspace_root: Path
    task_id: str
    attempt: int
    touched_repos: List[str]
    all_registered_repos: List[str]
    claims: Dict[str, Any] = field(default_factory=dict)
    base_commits: Dict[str, str] = field(default_factory=dict)
    target_commits: Dict[str, str] = field(default_factory=dict)
    dispositions: List[Dict[str, Any]] = field(default_factory=list)
    declared_scope: Dict[str, Any] = field(default_factory=dict)
