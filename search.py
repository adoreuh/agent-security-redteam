"""
Go-Explore search engine — official env contract.

Official env:
  env.reset() -> None
  env.interact(msg: str, max_tool_hops: int = 8) -> EnvInteractionResult (DATACLASS)
  env.export_trace_dict() -> dict (keys: tool_events, egress, user_messages, ...)
  env.snapshot() -> Any
  env.restore(snapshot: Any) -> None

EnvInteractionResult has: .tool_call_count, .refusal (NOT .get()).
Tool events are in export_trace_dict()['tool_events'], NOT in interact response.
"""

from __future__ import annotations

import time
import traceback
from dataclasses import dataclass, field
from heapq import heappop, heappush
from typing import Any, Dict, List, Optional, Tuple

from .candidate import Candidate, CandidateResult
from .cell_signature import compute_cell_signature
from .config import CONTRACT, SearchConfig
from .dedupe import CellArchive, dedupe_candidates
from .mutation import Mutator
from .predicates import PredicateDetector, predicate_names
from .scoring import compute_raw_score, normalize_score
from .trace import Trace, TraceStep, ToolCall


@dataclass(order=True)
class _FrontierEntry:
    priority: float
    candidate: Candidate = field(compare=False)
    parent_messages: Tuple[str, ...] = field(compare=False, default_factory=tuple)
    snapshot_id: Any = field(compare=False, default=None)
    depth: int = field(compare=False, default=0)


@dataclass
class SearchResult:
    traces: List[Trace] = field(default_factory=list)
    findings: List[CandidateResult] = field(default_factory=list)
    archive_summary: Dict[str, Any] = field(default_factory=dict)
    budget_used: int = 0
    budget_total: int = 0
    elapsed_seconds: float = 0.0
    unique_cells: int = 0
    exit_graceful: bool = True
    errors: List[str] = field(default_factory=list)


class GoExploreSearch:
    """Go-Explore with budget awareness."""

    def __init__(
        self,
        detector: Optional[PredicateDetector] = None,
        mutator: Optional[Mutator] = None,
        config: Optional[SearchConfig] = None,
    ) -> None:
        self.detector = detector or PredicateDetector()
        self.mutator = mutator or Mutator()
        self.config = config or SearchConfig()

    # ------------------------------------------------------------------
    # search_with_env
    # ------------------------------------------------------------------

    def search_with_env(
        self,
        env,
        candidates: List[Candidate],
        time_budget_s: float = 300.0,
        max_tool_hops: int = 8,
    ) -> SearchResult:
        """Execute search using real competition env.

        Args:
            time_budget_s: from AttackRunConfig.time_budget_s
            max_tool_hops: from AttackRunConfig.max_tool_hops
        """
        start_time = time.monotonic()
        max_steps = self.config.budget
        headroom = self.config.exit_headroom_seconds

        archive = CellArchive(
            max_size=self.config.archive_max_size,
            prune_threshold=self.config.archive_prune_threshold,
        )
        frontier: List[_FrontierEntry] = []
        findings: List[CandidateResult] = []
        traces: List[Trace] = []
        errors: List[str] = []
        steps_used = 0
        cell_count = 0

        for c in dedupe_candidates(candidates):
            heappush(frontier, _FrontierEntry(
                priority=self._compute_priority(c, novelty=1.0),
                candidate=c, depth=0,
            ))

        exit_graceful = True

        while frontier and steps_used < max_steps:
            elapsed = time.monotonic() - start_time
            if elapsed > time_budget_s - headroom:
                exit_graceful = elapsed < time_budget_s
                break

            entry = heappop(frontier)

            if self.config.validate_candidates:
                if self._validate_candidate(entry.candidate):
                    continue

            # Restore or reset (EnvSnapshot is opaque; int is FakeEnv)
            if entry.snapshot_id is not None:
                try:
                    env.restore(entry.snapshot_id)
                except Exception:
                    try:
                        env.reset()
                    except Exception:
                        pass
            else:
                try:
                    env.reset()
                except Exception:
                    pass

            # Execute — interact() returns EnvInteractionResult (dataclass)
            try:
                trace, steps_used = self._execute_candidate(
                    env, entry.candidate, entry.parent_messages,
                    steps_used, max_steps, max_tool_hops,
                )
            except Exception as e:
                errors.append(f"{entry.candidate.candidate_id}: {e}")
                continue

            if trace is None:
                continue

            traces.append(trace)

            # Evaluate predicates (local approximation)
            predicate_hits = self.detector.evaluate(trace)
            hit_names = predicate_names(predicate_hits)
            official_hits = [h.name for h in predicate_hits if h.is_official]

            # Cell and novelty
            cell_sig = compute_cell_signature(trace)
            is_novel = archive.add(trace, score=0.0, depth=entry.depth)
            if is_novel:
                cell_count += 1

            # Score this finding individually (NOT cumulative cell count)
            raw = compute_raw_score(official_hits, unique_cells=1 if is_novel else 0)
            score = normalize_score(raw)

            result = CandidateResult(
                candidate=entry.candidate,
                score=score,
                predicate_hits=hit_names,
                trace_id=trace.trace_id,
                replayable=len(official_hits) > 0,
                cell_signature=cell_sig,
                unique_cell=is_novel,
            )

            if result.replayable:
                findings.append(result)

            # Mutate and expand
            if (is_novel or result.replayable) and entry.depth < self.config.mutation_depth:
                if len(frontier) < self.config.max_frontier_size:
                    try:
                        snap_id = env.snapshot()
                    except Exception:
                        snap_id = None

                    # Build parent message chain for replay
                    full_chain = entry.parent_messages + entry.candidate.to_user_messages()

                    mutations = self.mutator.expand(
                        entry.candidate, trace=trace,
                        max_variants=self.config.mutations_per_candidate,
                    )
                    for mutated in mutations:
                        novelty = archive.novelty(trace)
                        heappush(frontier, _FrontierEntry(
                            priority=self._compute_priority(mutated, novelty=novelty),
                            candidate=mutated,
                            parent_messages=full_chain,
                            snapshot_id=snap_id,
                            depth=entry.depth + 1,
                        ))

            # Cap frontier
            while len(frontier) > self.config.max_frontier_size:
                frontier.sort(key=lambda e: e.priority, reverse=True)
                frontier.pop()

        findings.sort(key=lambda r: r.score, reverse=True)
        if len(findings) > self.config.max_candidates:
            findings = findings[:self.config.max_candidates]

        return SearchResult(
            traces=traces, findings=findings,
            archive_summary=archive.summary(),
            budget_used=steps_used, budget_total=max_steps,
            elapsed_seconds=time.monotonic() - start_time,
            unique_cells=cell_count,
            exit_graceful=exit_graceful,
            errors=errors,
        )

    # ------------------------------------------------------------------
    # Local search
    # ------------------------------------------------------------------

    def search(self, candidates: List[Candidate], budget: int = 50) -> SearchResult:
        from .sdk_bridge import FakeEnv
        env = FakeEnv(seed=self.config.seed)
        return self.search_with_env(
            env, candidates,
            time_budget_s=float(budget) * 10.0,
            max_tool_hops=8,
        )

    # ------------------------------------------------------------------
    # Candidate execution
    # ------------------------------------------------------------------

    def _execute_candidate(
        self,
        env,
        candidate: Candidate,
        parent_messages: Tuple[str, ...],
        steps_used: int,
        max_steps: int,
        max_tool_hops: int,
    ) -> Tuple[Optional[Trace], int]:
        """Execute a candidate via env.interact().

        interact() returns EnvInteractionResult dataclass.
        Tool events come from export_trace_dict(), not the response.
        """
        user_messages = candidate.to_user_messages()

        # If candidate has parent chain, prepend parent messages
        if parent_messages:
            user_messages = parent_messages + user_messages

        if len(user_messages) > 32:
            return None, steps_used
        for m in user_messages:
            if len(m) > 2000:
                return None, steps_used

        trace = Trace(
            trace_id=f"trace::{candidate.candidate_id}",
            candidate_id=candidate.candidate_id,
        )

        # Interact — one call per message
        for i, msg in enumerate(user_messages):
            if steps_used >= max_steps:
                break

            # Call env.interact(msg, max_tool_hops=max_tool_hops)
            # Returns EnvInteractionResult dataclass
            try:
                _ = env.interact(msg, max_tool_hops=max_tool_hops)
            except Exception:
                return None, steps_used
            steps_used += 1

        # Get actual tool events from export_trace_dict()
        try:
            trace_dict = env.export_trace_dict()
        except Exception:
            return None, steps_used

        # Parse official trace structure into local Trace
        tool_events = trace_dict.get("tool_events", [])
        egress_events = trace_dict.get("egress", [])

        for i, msg in enumerate(user_messages):
            # Map tool_events to this step (simple: one step = one message)
            step_tools = []
            if i < len(tool_events):
                tc = tool_events[i]
                step_tools.append(ToolCall(
                    name=tc.get("name", "unknown"),
                    args=tc.get("args", {}),
                    result=tc.get("result"),
                ))

            step = TraceStep(
                step_index=i,
                input_text=msg,
                output_text="",
                tool_calls=step_tools,
                source_type=candidate.source_type if i >= len(parent_messages) else "user",
                trusted=False,
                trust_level=str(candidate.metadata.get("trust_level", "untrusted")),
                source_chain=(candidate.source_type,),
                notes={
                    "guardrail_blocked": False,
                    "family": candidate.metadata.get("family"),
                    "egress": bool(egress_events),
                },
            )
            trace.add_step(step)

        if not trace.steps:
            return None, steps_used

        return trace, steps_used

    # ------------------------------------------------------------------
    # Priority
    # ------------------------------------------------------------------

    def _compute_priority(self, candidate: Candidate, novelty: float = 1.0) -> float:
        severity_map = {
            "prompt_injection": 5, "tool_output_poisoning": 4,
            "memory_poisoning": 4, "intent_hijacking": 5,
            "objective_drifting": 3, "cross_modal": 4,
        }
        sev = severity_map.get(candidate.metadata.get("threat_category", "unknown"), 2)
        return -(novelty * self.config.novelty_bonus_weight + sev * self.config.severity_weight_exponent)

    def _validate_candidate(self, candidate: Candidate) -> List[str]:
        v: List[str] = []
        msgs = candidate.to_user_messages()
        if len(msgs) > 32:
            v.append(f"messages={len(msgs)} > 32")
        for i, m in enumerate(msgs):
            if len(m) > 2000:
                v.append(f"msg[{i}] length={len(m)} > 2000")
        return v


FrontierSearch = GoExploreSearch
