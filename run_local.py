"""
Quick local runner for development and debugging.

Usage:
  python -m agent_security_redteam.run_local
  python -m agent_security_redteam.run_local --budget 100 --seed 123
  python -m agent_security_redteam.run_local --official  # Test official SDK path
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List

# Allow running as script
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent_security_redteam.attack import AttackAlgorithm
from agent_security_redteam.sdk_bridge import AttackRunConfig, FakeEnv
from agent_security_redteam.templates import build_candidates, build_focused_candidates
from agent_security_redteam.search import GoExploreSearch
from agent_security_redteam.config import SearchConfig
from agent_security_redteam.dedupe import dedupe_candidates


@dataclass
class DummyEnv:
    """Minimal env for quick smoke tests."""
    budget: int = 10
    seed: int = 42


def run_official_path(budget: int = 50, seed: int = 42) -> None:
    """Test the official SDK contract path."""
    print("=== Official SDK Contract Path ===")
    env = FakeEnv(seed=seed)
    config = AttackRunConfig(time_budget_s=float(budget) / 10.0)
    algo = AttackAlgorithm()
    candidates = algo.run(env, config)
    print(f"Returned {len(candidates)} AttackCandidate objects")
    for c in candidates[:5]:
        n_msgs = len(c.user_messages)
        n_chars = sum(len(m) for m in c.user_messages)
        ok = n_msgs <= 32 and all(len(m) <= 2000 for m in c.user_messages)
        print(f"  {n_msgs} msgs, {n_chars} chars: {'OK' if ok else 'LIMIT EXCEEDED'}")


def run_go_explore(budget: int = 200, seed: int = 42, verbose: bool = False) -> None:
    """Test the Go-Explore search path."""
    print("=== Go-Explore Search ===")
    candidates = dedupe_candidates(build_candidates())
    print(f"Seed candidates: {len(candidates)}")

    config = SearchConfig(budget=budget, seed=seed, verbose=verbose)
    search = GoExploreSearch(config=config)
    result = search.search(candidates, budget=budget)

    print(f"Findings: {len(result.findings)}")
    print(f"Budget used: {result.budget_used}/{result.budget_total}")
    print(f"Time: {result.elapsed_seconds:.2f}s")
    print(f"Unique cells: {result.unique_cells}")
    print(f"Archive size: {result.archive_summary.get('total_cells', 0)}")
    print(f"Exit graceful: {result.exit_graceful}")

    if result.findings:
        print(f"\nTop 5:")
        for f in result.findings[:5]:
            print(f"  {f.candidate.candidate_id}: score={f.score:.2f}, "
                  f"severity={f.max_severity}, "
                  f"hits={f.predicate_hits}, "
                  f"cell={'new' if f.unique_cell else 'dup'}, "
                  f"depth={f.candidate.depth}")


def run_threat_matrix() -> None:
    """Test all threat categories."""
    print("=== Threat Category Matrix ===")
    from agent_security_redteam.templates import ALL_TEMPLATE_FAMILIES

    for family in ALL_TEMPLATE_FAMILIES:
        candidates = build_focused_candidates(family.threat_category)
        config = SearchConfig(budget=50, seed=42)
        search = GoExploreSearch(config=config)
        result = search.search(candidates, budget=50)
        print(f"  {family.threat_category}: "
              f"{len(candidates)} seeds → {len(result.findings)} findings, "
              f"{result.unique_cells} cells")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Local red-team runner")
    parser.add_argument("--budget", type=int, default=200, help="Interaction budget")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--official", action="store_true", help="Test official SDK path")
    parser.add_argument("--matrix", action="store_true", help="Run threat matrix")
    args = parser.parse_args()

    if args.official:
        run_official_path(budget=args.budget, seed=args.seed)
    elif args.matrix:
        run_threat_matrix()
    else:
        run_go_explore(budget=args.budget, seed=args.seed, verbose=args.verbose)
        print()
        run_official_path(budget=min(args.budget, 50), seed=args.seed)
