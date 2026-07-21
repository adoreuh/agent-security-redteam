"""
Agent Security Red Team Harness — aicomp-sdk 3.1.2 compatible.

IMPORTANT: Predicates, Cell signatures, and scoring in this package are
LOCAL APPROXIMATIONS for search guidance. The official evaluator recomputes
all predicates, Cells, and scores during replay of each AttackCandidate.

Quick start:
  >>> from agent_security_redteam import AttackAlgorithm
  >>> algo = AttackAlgorithm()
  >>> candidates = algo.run(env, config)

Local testing:
  python -m agent_security_redteam.main local --budget-s 60
  python -m agent_security_redteam.main validate

Official competition:
  aicomp test redteam attack.py --budget-s 60 --agent deterministic
  aicomp evaluate redteam attack.py --budget-s 1800 --agent deterministic --env gym
"""

from .attack import AttackAlgorithm
from .candidate import Candidate, CandidateResult
from .cell_signature import compute_cell_signature
from .config import SearchConfig, OFFICIAL_PREDICATES, RESEARCH_PREDICATES
from .dedupe import CellArchive, dedupe_candidates
from .search import GoExploreSearch, FrontierSearch, SearchResult
from .sdk_bridge import AttackCandidate, AttackRunConfig, AttackAlgorithmBase, FakeEnv

__all__ = [
    "AttackAlgorithm",
    "AttackAlgorithmBase",
    "AttackRunConfig",
    "AttackCandidate",
    "GoExploreSearch",
    "FrontierSearch",
    "SearchResult",
    "Candidate",
    "CandidateResult",
    "CellArchive",
    "SearchConfig",
    "FakeEnv",
    "compute_cell_signature",
    "dedupe_candidates",
    "OFFICIAL_PREDICATES",
    "RESEARCH_PREDICATES",
]
