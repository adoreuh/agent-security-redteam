"""
CLI entry point for local experimentation.

Commands:
  python -m agent_security_redteam.main local --budget-s 60
  python -m agent_security_redteam.main validate
  python -m agent_security_redteam.main focused --category prompt_injection

Note: Official competition commands use aicomp CLI:
  aicomp test redteam attack.py --budget-s 60 --agent deterministic
  aicomp evaluate redteam attack.py --budget-s 1800 --agent deterministic --env gym
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

from .attack import AttackAlgorithm
from .config import SearchConfig
from .dedupe import dedupe_candidates
from .report import generate_experiment_report, summarize_findings, write_report
from .search import GoExploreSearch
from .sdk_bridge import FakeEnv, validate_attack_class
from .templates import build_candidates, build_focused_candidates


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Agent Security Red-Team Harness (local development)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m agent_security_redteam.main local --budget-s 120
  python -m agent_security_redteam.main validate
  python -m agent_security_redteam.main focused --category cross_modal --budget-s 60

Official competition:
  aicomp test redteam attack.py --budget-s 60 --agent deterministic
  aicomp evaluate redteam attack.py --budget-s 1800 --agent deterministic --env gym
        """,
    )
    subparsers = parser.add_subparsers(dest="command", help="Command")

    # local
    lp = subparsers.add_parser("local", help="Run local search")
    lp.add_argument("--budget-s", type=float, default=120.0, help="Time budget (seconds)")
    lp.add_argument("--seed", type=int, default=42)
    lp.add_argument("--max-candidates", type=int, default=50)
    lp.add_argument("--verbose", action="store_true")
    lp.add_argument("--output", type=str, default="outputs")

    # validate
    subparsers.add_parser("validate", help="Validate SDK contract")

    # focused
    fp = subparsers.add_parser("focused", help="Focused threat category search")
    fp.add_argument("--category", type=str, required=True,
        choices=["prompt_injection", "tool_output_poisoning", "memory_poisoning",
                 "intent_hijacking", "objective_drifting", "cross_modal"])
    fp.add_argument("--budget-s", type=float, default=60.0)
    fp.add_argument("--seed", type=int, default=42)
    fp.add_argument("--verbose", action="store_true")
    fp.add_argument("--output", type=str, default="outputs")

    args = parser.parse_args()

    if args.command == "validate":
        _cmd_validate()
    elif args.command == "focused":
        _cmd_focused(args.category, int(args.budget_s * 10), args.seed, args.verbose, args.output)
    elif args.command == "local":
        _cmd_local(int(args.budget_s * 10), args.seed, args.max_candidates, args.verbose, args.output)
    else:
        _cmd_local(200, 42, 50, False, "outputs")


def _cmd_local(budget: int, seed: int, max_candidates: int, verbose: bool, output_dir: str) -> None:
    print(f"=== Agent Security Red-Team: Local Search ===")
    print(f"Budget: {budget}, Seed: {seed}")

    candidates = dedupe_candidates(build_candidates())
    print(f"Seed candidates: {len(candidates)}")

    config = SearchConfig(budget=budget, seed=seed, max_candidates=max_candidates, verbose=verbose)
    result = GoExploreSearch(config=config).search(candidates, budget=budget)

    print(f"\nFindings: {len(result.findings)}")
    print(f"Budget: {result.budget_used}/{result.budget_total}")
    print(f"Time: {result.elapsed_seconds:.2f}s")
    print(f"Unique cells: {result.unique_cells}")

    if result.findings:
        print(f"\nTop 5:")
        for f in result.findings[:5]:
            print(f"  {f.candidate.candidate_id}: score={f.score:.4f}, hits={f.predicate_hits}")

    out_path = Path(output_dir)
    paths = write_report(result, out_path)
    print(f"\nReports: {out_path}")

    exp_report = generate_experiment_report(result, title="Local Red-Team Run", seed=seed)
    (out_path / "experiment_report.md").write_text(exp_report, encoding="utf-8")


def _cmd_focused(category: str, budget: int, seed: int, verbose: bool, output_dir: str) -> None:
    print(f"=== Focused: {category} ===")
    candidates = build_focused_candidates(category)
    print(f"Seeds: {len(candidates)}")

    config = SearchConfig(budget=budget, seed=seed, verbose=verbose)
    result = GoExploreSearch(config=config).search(candidates, budget=budget)

    print(f"Findings: {len(result.findings)}, Unique cells: {result.unique_cells}")
    for f in result.findings[:10]:
        print(f"  {f.candidate.candidate_id}: score={f.score:.4f}, hits={f.predicate_hits}")

    out_path = Path(output_dir) / f"focused_{category}"
    write_report(result, out_path)


def _cmd_validate() -> None:
    """Validate attack module against SDK contract."""
    print("=== SDK Contract Validation ===")

    # Static check
    result = validate_attack_class()
    print(f"Module: attack.py")
    print(f"Valid: {result['valid']}")
    print(f"Inherits AttackAlgorithmBase: {result.get('inherits_base', '?')}")
    print(f"Has run() method: {result['has_run_method']}")
    print(f"Signature: {result['run_signature']}")

    if result["violations"]:
        print(f"Violations:")
        for v in result["violations"]:
            print(f"  - {v}")
    else:
        print("No violations found.")

    # Runtime inheritance check
    try:
        from .attack import AttackAlgorithm as AA
        from .sdk_bridge import AttackAlgorithmBase
        is_subclass = issubclass(AA, AttackAlgorithmBase)
        print(f"\nRuntime issubclass check: {'PASS' if is_subclass else 'FAIL'}")
    except Exception as e:
        print(f"\nRuntime check error: {e}")

    # Smoke test
    print("\n--- Smoke Test ---")
    try:
        env = FakeEnv(seed=42)
        algo = AttackAlgorithm()
        candidates = algo.run(env)
        print(f"OK: {len(candidates)} candidates")
        for c in candidates[:3]:
            n_msgs = len(c.user_messages)
            n_chars = sum(len(m) for m in c.user_messages)
            ok = n_msgs <= 32 and all(len(m) <= 2000 for m in c.user_messages)
            print(f"  {n_msgs} msgs, {n_chars} chars: {'OK' if ok else 'LIMIT EXCEEDED'}")
    except Exception as e:
        print(f"FAILED: {e}")
        sys.exit(1)

    print("\nNote: Run 'aicomp validate redteam attack.py' for official validation.")


if __name__ == "__main__":
    main()
