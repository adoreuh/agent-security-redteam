"""
Search engine tests.

Verify Go-Explore search, Cell dedup, budget management,
and deterministic reproducibility.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import pytest

from agent_security_redteam.search import GoExploreSearch
from agent_security_redteam.config import SearchConfig
from agent_security_redteam.dedupe import CellArchive, dedupe_candidates
from agent_security_redteam.cell_signature import compute_cell_signature, cell_novelty
from agent_security_redteam.templates import build_candidates


class TestGoExploreSearch:
    """Go-Explore search integration tests."""

    def test_search_returns_results(self) -> None:
        """Basic smoke test."""
        candidates = dedupe_candidates(build_candidates())
        config = SearchConfig(budget=50, seed=42)
        search = GoExploreSearch(config=config)
        result = search.search(candidates, budget=50)

        assert result.budget_used <= result.budget_total
        assert result.elapsed_seconds >= 0
        assert isinstance(result.findings, list)

    def test_deterministic_results(self) -> None:
        """Same seed + same input = same output."""
        candidates1 = dedupe_candidates(build_candidates())
        candidates2 = dedupe_candidates(build_candidates())

        config = SearchConfig(budget=50, seed=42)
        result1 = GoExploreSearch(config=config).search(candidates1, budget=50)
        result2 = GoExploreSearch(config=config).search(candidates2, budget=50)

        assert len(result1.findings) == len(result2.findings)
        for f1, f2 in zip(result1.findings, result2.findings):
            assert f1.candidate.candidate_id == f2.candidate.candidate_id
            assert f1.score == f2.score
            assert f1.predicate_hits == f2.predicate_hits

    def test_respects_budget(self) -> None:
        """Should not exceed budget."""
        candidates = dedupe_candidates(build_candidates())
        for budget in [10, 30, 50]:
            config = SearchConfig(budget=budget, seed=42, max_candidates=100)
            result = GoExploreSearch(config=config).search(candidates, budget=budget)
            assert result.budget_used <= budget, (
                f"Used {result.budget_used} > budget {budget}"
            )

    def test_respects_max_candidates(self) -> None:
        """Should not return more than max_candidates."""
        candidates = dedupe_candidates(build_candidates())
        for max_c in [5, 10]:
            config = SearchConfig(budget=100, seed=42, max_candidates=max_c)
            result = GoExploreSearch(config=config).search(candidates, budget=100)
            assert len(result.findings) <= max_c, (
                f"Got {len(result.findings)} > max {max_c}"
            )


class TestCellArchive:
    """Cell-based dedup and archive tests."""

    def test_new_cell_is_novel(self) -> None:
        archive = CellArchive()
        # We need a trace to test — use search result
        candidates = dedupe_candidates(build_candidates())
        config = SearchConfig(budget=10, seed=42)
        result = GoExploreSearch(config=config).search(candidates, budget=10)

        if result.traces:
            trace = result.traces[0]
            sig = compute_cell_signature(trace)
            is_new = archive.add(trace, score=1.0, depth=0)
            assert is_new, "First cell should be novel"

    def test_duplicate_cell_detected(self) -> None:
        archive = CellArchive()
        candidates = dedupe_candidates(build_candidates())
        config = SearchConfig(budget=10, seed=42)
        result = GoExploreSearch(config=config).search(candidates, budget=10)

        if result.traces:
            trace = result.traces[0]
            archive.add(trace, score=1.0, depth=0)
            is_new = archive.add(trace, score=1.0, depth=0)
            assert not is_new, "Same trace should not be novel"

    def test_archive_pruning(self) -> None:
        """Archive should prune when exceeding max_size."""
        archive = CellArchive(max_size=10, prune_threshold=5)

        # Add many cells — need traces
        candidates = dedupe_candidates(build_candidates())
        config = SearchConfig(budget=100, seed=42, max_candidates=100)
        result = GoExploreSearch(config=config).search(candidates, budget=100)

        for trace in result.traces:
            archive.add(trace, score=0.5, depth=0)

        assert archive.size <= 10, f"Archive should prune to max_size, got {archive.size}"
