"""
Cell-based deduplication for agent security traces.

Official Cell: composite of tool sequences, side effects, scope, source,
success/failure, secret access, egress, sensitive tools, parameter signatures,
output summaries, user intent, and guardrail blocks.

This module replaces the old (source_type, prompt, tags, trust_level)
dedup with Cell-signature-based dedup that matches the competition evaluator.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set, Tuple

from .candidate import Candidate
from .cell_signature import cell_novelty, compute_cell_signature
from .trace import Trace


# ---------------------------------------------------------------------------
# Legacy dedup (kept for backward compatibility during transition)
# ---------------------------------------------------------------------------

class LegacyDedupeIndex:
    """Old dedup: (source_type, prompt, tags, trust_level).

    Still useful for seed candidate dedup before traces are generated.
    """

    def __init__(self) -> None:
        self._seen: Set[Tuple[str, str, Tuple[str, ...], str]] = set()

    def add(self, candidate: Candidate) -> bool:
        trust_level = str(candidate.metadata.get("trust_level", "unknown"))
        key = (candidate.source_type, candidate.prompt, candidate.tags, trust_level)
        if key in self._seen:
            return False
        self._seen.add(key)
        return True


def dedupe_candidates(candidates: Iterable[Candidate]) -> List[Candidate]:
    """Deduplicate seed candidates using legacy index."""
    index = LegacyDedupeIndex()
    kept: List[Candidate] = []
    for c in candidates:
        if index.add(c):
            kept.append(c)
    return kept


# ---------------------------------------------------------------------------
# Cell-based dedup (official approach)
# ---------------------------------------------------------------------------


@dataclass
class CellArchive:
    """Archive of visited Cells with novelty tracking.

    Used for Go-Explore search: maintains a set of seen Cell signatures
    and tracks how many times each Cell was visited, its best score,
    and its discovery depth.
    """

    max_size: int = 5000
    prune_threshold: int = 4000

    _signatures: Set[str] = field(default_factory=set)
    _cell_data: Dict[str, dict] = field(default_factory=dict)

    def add(self, trace: Trace, score: float, depth: int = 0) -> bool:
        """Add a trace's Cell to the archive.

        Returns True if this is a new Cell (novel), False if duplicate.
        """
        sig = compute_cell_signature(trace)
        is_new = sig not in self._signatures

        if is_new:
            self._signatures.add(sig)
            self._cell_data[sig] = {
                "score": score,
                "depth": depth,
                "visits": 1,
                "trace_id": trace.trace_id,
                "candidate_id": trace.candidate_id,
            }

            # Prune if over threshold
            if len(self._signatures) > self.max_size:
                self._prune()
        else:
            # Update existing cell data
            if sig in self._cell_data:
                self._cell_data[sig]["visits"] += 1
                if score > self._cell_data[sig]["score"]:
                    self._cell_data[sig]["score"] = score

        return is_new

    def contains(self, trace: Trace) -> bool:
        """Check if trace's Cell is already in the archive."""
        return compute_cell_signature(trace) in self._signatures

    def novelty(self, trace: Trace) -> float:
        """Compute novelty (0-1) of a trace relative to archive."""
        sig = compute_cell_signature(trace)
        return cell_novelty(sig, self._signatures)

    def is_novel(self, trace: Trace, threshold: float = 0.3) -> bool:
        """Check if trace is sufficiently novel."""
        return self.novelty(trace) >= threshold

    @property
    def size(self) -> int:
        return len(self._signatures)

    @property
    def signatures(self) -> Set[str]:
        return set(self._signatures)

    def get_cell_data(self, sig: str) -> Optional[dict]:
        return self._cell_data.get(sig)

    def best_cells(self, n: int = 10) -> List[dict]:
        """Return top N cells by score."""
        sorted_cells = sorted(
            self._cell_data.values(),
            key=lambda d: d.get("score", 0),
            reverse=True,
        )
        return sorted_cells[:n]

    def _prune(self) -> None:
        """Prune least-valuable cells to stay under max_size.

        Removes cells with lowest score and fewest visits first.
        """
        if len(self._signatures) <= self.prune_threshold:
            return

        # Sort by (score descending, visits descending)
        sorted_cells = sorted(
            self._cell_data.items(),
            key=lambda kv: (kv[1].get("score", 0), kv[1].get("visits", 0)),
            reverse=True,
        )

        keep_count = self.prune_threshold
        to_remove = sorted_cells[keep_count:]

        for sig, _ in to_remove:
            self._signatures.discard(sig)
            self._cell_data.pop(sig, None)

    def summary(self) -> dict:
        """Return archive statistics."""
        if not self._cell_data:
            return {"total_cells": 0, "avg_score": 0.0, "avg_visits": 0.0}

        scores = [d["score"] for d in self._cell_data.values()]
        visits = [d["visits"] for d in self._cell_data.values()]
        return {
            "total_cells": len(self._signatures),
            "avg_score": sum(scores) / len(scores),
            "max_score": max(scores),
            "avg_visits": sum(visits) / len(visits),
            "total_visits": sum(visits),
        }
