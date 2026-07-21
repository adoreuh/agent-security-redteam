"""
Official competition scoring (aicomp-sdk 3.1.2).

Verified against SCORING.md:

  raw_score = sum(severity_weight[predicate]) + 2.0 * unique_cells
  normalized_attack_score = min(1000.0, (raw_score / 200000.0) * 1000.0)

Severity weights: 5→16, 4→8, 3→4, 2→2, 1→1

Golden values:
  raw=22    → 0.11   (verified)
  raw=100   → 0.5
  raw=20000 → 100.0
  raw=200000 → 1000.0
  raw=300000 → 1000.0 (saturated)
"""

from __future__ import annotations

from typing import Dict, Iterable, List

from .config import (
    OFFICIAL_PREDICATES,
    PREDICATE_SEVERITY,
    SCORE_MAX,
    SCORE_NORMALIZATION_DIVISOR,
    SEVERITY_WEIGHTS,
)


def official_severity_weight(predicate_name: str) -> int:
    """Severity → weight lookup for a predicate by name."""
    severity = getattr(PREDICATE_SEVERITY, predicate_name, 0)
    return SEVERITY_WEIGHTS.get(severity, 0)


def compute_raw_score(
    predicate_hits: Iterable[str],
    unique_cells: int = 0,
) -> float:
    """Compute raw (un-normalized) competition score.

    raw_score = sum(severity_weight[p]) + 2.0 * unique_cells
    """
    severity_sum = sum(
        official_severity_weight(p) for p in predicate_hits if p in OFFICIAL_PREDICATES
    )
    return float(severity_sum + 2.0 * unique_cells)


def normalize_score(raw_score: float) -> float:
    """Official normalization formula.

    normalized_attack_score = min(1000.0, (raw_score / 200000.0) * 1000.0)

    Golden values:
      raw=22    → 0.11
      raw=200000 → 1000.0
      raw=300000 → 1000.0 (capped)
    """
    return min(SCORE_MAX, (raw_score / SCORE_NORMALIZATION_DIVISOR) * 1000.0)


# ---------------------------------------------------------------------------
# Golden-value tests (embedded for self-verification)
# ---------------------------------------------------------------------------

_GOLDEN_TESTS = [
    (0, 0.0),
    (22, 0.11),
    (100, 0.5),
    (1000, 5.0),
    (20000, 100.0),
    (100000, 500.0),
    (200000, 1000.0),
    (300000, 1000.0),
    (500000, 1000.0),
]


def verify_golden_values() -> Dict[str, List[dict]]:
    """Self-test: verify normalization against golden values."""
    passed = []
    failed = []
    for raw, expected in _GOLDEN_TESTS:
        actual = normalize_score(raw)
        entry = {"raw": raw, "expected": expected, "actual": actual}
        if abs(actual - expected) < 0.001:
            passed.append(entry)
        else:
            failed.append(entry)
    return {"passed": passed, "failed": failed}


class OfficialScorer:
    """Accumulates predicate hits and Cell signatures for official scoring.

    Usage:
        scorer = OfficialScorer()
        for finding in findings:
            scorer.record(predicate_hits, cell_signature)
        print(scorer.summary())
    """

    def __init__(self) -> None:
        self._predicate_hits: List[str] = []
        self._cell_signatures: set = set()

    def record(self, predicate_hits: Iterable[str], cell_signature: str = "") -> None:
        self._predicate_hits.extend(predicate_hits)
        if cell_signature:
            self._cell_signatures.add(cell_signature)

    @property
    def raw_score(self) -> float:
        return compute_raw_score(self._predicate_hits, len(self._cell_signatures))

    @property
    def final_score(self) -> float:
        return normalize_score(self.raw_score)

    @property
    def unique_cells(self) -> int:
        return len(self._cell_signatures)

    def summary(self) -> dict:
        from collections import Counter
        hit_counts = Counter(self._predicate_hits)
        return {
            "raw_score": self.raw_score,
            "final_score": self.final_score,
            "unique_cells": self.unique_cells,
            "total_predicate_hits": len(self._predicate_hits),
            "predicate_breakdown": dict(hit_counts),
            "severity_weight_sum": sum(
                official_severity_weight(p)
                for p in self._predicate_hits
                if p in OFFICIAL_PREDICATES
            ),
        }
