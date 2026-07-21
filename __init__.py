"""
Agent Security Red Team Harness for aicomp-sdk 3.1.2.

Predicates, cell signatures, and scoring in this package are local
approximations for search guidance. The official evaluator recomputes all
predicates, cells, and scores during replay of each AttackCandidate.
"""

try:
    from .attack import AttackAlgorithm
    from .candidate import Candidate, CandidateResult
    from .cell_signature import compute_cell_signature
    from .config import OFFICIAL_PREDICATES, RESEARCH_PREDICATES, SearchConfig
    from .dedupe import CellArchive, dedupe_candidates
    from .sdk_bridge import AttackAlgorithmBase, AttackCandidate, AttackRunConfig, FakeEnv
    from .search import FrontierSearch, GoExploreSearch, SearchResult
except ImportError:
    from agent_security_redteam.attack import AttackAlgorithm
    from agent_security_redteam.candidate import Candidate, CandidateResult
    from agent_security_redteam.cell_signature import compute_cell_signature
    from agent_security_redteam.config import OFFICIAL_PREDICATES, RESEARCH_PREDICATES, SearchConfig
    from agent_security_redteam.dedupe import CellArchive, dedupe_candidates
    from agent_security_redteam.sdk_bridge import (
        AttackAlgorithmBase,
        AttackCandidate,
        AttackRunConfig,
        FakeEnv,
    )
    from agent_security_redteam.search import FrontierSearch, GoExploreSearch, SearchResult

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
