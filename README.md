# Agent Security Red Team Harness

This folder contains a defensive research harness for analyzing multi-step tool-using agent failures in a deterministic, replayable setting.

## Goals

- Model attack paths as replayable traces
- Track trust boundaries across multiple steps
- Detect high-risk predicate patterns
- Support search over candidate traces with diversity and deduplication
- Produce outputs that are useful for defense evaluation and benchmark analysis

## Modules

- `candidate.py` - structured candidate representation
- `trace.py` - trace and step data models
- `predicates.py` - heuristic detectors for risky transitions
- `templates.py` - safe, non-deployable template families for evaluation
- `mutation.py` - trace-guided mutation helpers
- `search.py` - frontier-based exploration loop
- `dedupe.py` - unique-cell style deduplication utilities
- `report.py` - summary generation helpers
- `main.py` - minimal entry point for local experimentation

## Notes

The implementation is intentionally oriented toward security research and replayable benchmarking, not real-world misuse.
