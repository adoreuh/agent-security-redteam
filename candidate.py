"""
Candidate data models with parent-chain support for replay.

Official AttackCandidate: user_messages: tuple[str, ...] (replayable).
The evaluator replays the FULL message chain in a clean environment.
Parent state from snapshots is NOT preserved — only messages are.

CRITICAL: to_user_messages() must return the complete replayable chain.
For snapshot-based search, parent messages must be accumulated and
returned as part of user_messages.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass(frozen=True)
class Candidate:
    """Internal candidate with optional parent chain for replay."""

    candidate_id: str
    source_type: str
    prompt: str
    tags: Tuple[str, ...] = field(default_factory=tuple)
    metadata: Dict[str, Any] = field(default_factory=dict)
    depth: int = 0
    parent_id: Optional[str] = None
    parent_messages: Tuple[str, ...] = field(default_factory=tuple)
    """Messages from parent candidates that must be prepended for replay."""

    def to_user_messages(self) -> Tuple[str, ...]:
        """Return complete replayable message chain.

        Includes parent chain + current prompt.
        The evaluator replays this entire tuple in a clean environment.
        """
        return self.parent_messages + (self.prompt,)


@dataclass
class CandidateResult:
    candidate: Candidate
    score: float
    predicate_hits: List[str] = field(default_factory=list)
    trace_id: Optional[str] = None
    replayable: bool = False
    cell_signature: str = ""
    unique_cell: bool = False

    @property
    def official_predicate_hits(self) -> List[str]:
        from .config import OFFICIAL_PREDICATES
        return [h for h in self.predicate_hits if h in OFFICIAL_PREDICATES]

    @property
    def max_severity(self) -> int:
        from .config import PREDICATE_SEVERITY
        if not self.predicate_hits:
            return 0
        return max(
            getattr(PREDICATE_SEVERITY, h, 0) for h in self.predicate_hits
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "candidate_id": self.candidate.candidate_id,
            "score": self.score,
            "predicate_hits": self.predicate_hits,
            "trace_id": self.trace_id,
            "replayable": self.replayable,
            "cell_signature": self.cell_signature,
            "unique_cell": self.unique_cell,
            "max_severity": self.max_severity,
            "source_type": self.candidate.source_type,
            "depth": self.candidate.depth,
        }
