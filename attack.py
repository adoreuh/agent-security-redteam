"""
Official aicomp-sdk 3.1.2 competition entry point.

Contract:
  class AttackAlgorithm(AttackAlgorithmBase):
      def run(self, env, config: AttackRunConfig) -> list[AttackCandidate]

AttackRunConfig fields: time_budget_s, max_steps, max_tool_hops (ONLY)
AttackCandidate: user_messages, from_messages() (NO .validate())
EnvInteractionResult: dataclass with .tool_call_count, .refusal

CRITICAL: This module must work BOTH as a package member (development)
AND as a standalone file (submission). The development multi-module
version is here. For single-file Kaggle submission, use attack_submission.py.
"""

from __future__ import annotations

import time
from typing import List, Optional

from .candidate import Candidate as InternalCandidate
from .config import CONTRACT, SearchConfig
from .predicates import PredicateDetector
from .search import GoExploreSearch, SearchResult
from .sdk_bridge import (
    AttackAlgorithmBase,
    AttackCandidate,
    AttackRunConfig,
)
from .templates import build_candidates


class AttackAlgorithm(AttackAlgorithmBase):
    """Competition attack algorithm.

    Inherits from official AttackAlgorithmBase (or compatible stub).
    """

    def __init__(self, config: Optional[dict] = None) -> None:
        super().__init__(config)
        self._detector = PredicateDetector(use_official_sdk=True)

    def run(
        self,
        env,
        config: Optional[AttackRunConfig] = None,
    ) -> List[AttackCandidate]:
        """Execute attack search.

        Args:
            env: Official competition environment.
            config: AttackRunConfig(time_budget_s, max_steps, max_tool_hops).

        Returns:
            List of AttackCandidate for evaluator replay.
        """
        if config is None:
            config = AttackRunConfig()

        # Extract official budget fields (ONLY these exist on real config)
        time_budget_s = config.time_budget_s
        max_steps = config.max_steps
        max_tool_hops = config.max_tool_hops

        # Headroom: reserve 5% of time budget, capped at 5s
        headroom = min(5.0, time_budget_s * 0.05)

        # Internal search config
        search_config = SearchConfig(
            budget=max_steps,
            seed=getattr(env, "seed", 42),
            max_candidates=50,
            exit_headroom_seconds=headroom,
            validate_candidates=True,
            max_frontier_size=256,
            mutation_depth=3,
            mutations_per_candidate=4,
        )

        seed_candidates = build_candidates()
        search = GoExploreSearch(
            detector=self._detector,
            config=search_config,
        )
        result = search.search_with_env(
            env, seed_candidates,
            time_budget_s=time_budget_s,
            max_tool_hops=max_tool_hops,
        )

        return self._convert_to_official(result)

    @staticmethod
    def _convert_to_official(result: SearchResult) -> List[AttackCandidate]:
        """Convert internal findings to official AttackCandidate format.

        Does NOT call .validate() — real AttackCandidate has no such method.
        Enforces contract limits manually.
        """
        candidates: List[AttackCandidate] = []
        for finding in result.findings:
            msgs = finding.candidate.to_user_messages()
            # Enforce limits
            if len(msgs) > 32:
                msgs = msgs[:32]
            msgs = tuple(m[:2000] for m in msgs)
            candidates.append(AttackCandidate(user_messages=msgs))
            if len(candidates) >= 2000:
                break
        return candidates
