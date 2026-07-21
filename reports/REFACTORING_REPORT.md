# Agent Security Red-Team: Competition Refactoring Report

**Date:** 2026-07-21
**Status:** Competition hardening complete
**SDK Target:** aicomp-sdk 3.1.2

## Executive Summary

The project has been reshaped around the AI Agent Security red-team
competition contract. The main deliverable is now a standalone
`attack_submission.py` that can be written as Kaggle `attack.py`, plus a package
entry point that reuses the same engine.

## Completed Changes

- `AttackAlgorithm` inherits from `AttackAlgorithmBase` and accepts
  `run(self, env, config)`.
- Returned items are bounded `AttackCandidate.user_messages` chains.
- The generator is budget-aware and leaves wall-clock headroom.
- Candidate probes target the official predicates:
  `EXFILTRATION`, `UNTRUSTED_TO_ACTION`, `DESTRUCTIVE_WRITE`, and
  `CONFUSED_DEPUTY`.
- The standalone submission uses only SDK imports plus standard library
  fallback stubs.
- Documentation now reflects the competition fixture, tool surface, and scoring
  predicates.
- `pyproject.toml` declares the package mapping for local tests.

## Known Evaluation Notes

The public deterministic agent with the packaged `optimal_public` guardrail is
very strict: sensitive targets and dangerous actions after web/email taint are
often denied before a predicate can score. A zero score in that local smoke test
is still useful when validation succeeds and the attack returns before deadline.
Private and model-backed tracks can behave differently, so the submission keeps
a small high-signal backstop set as well as predicate-confirmed probes.

## Validation Commands

```bash
python -m aicomp_sdk.cli.main validate redteam attack_submission.py
python -m aicomp_sdk.cli.main test redteam attack_submission.py --budget-s 10 --agent deterministic --env sandbox
python -m pytest -q
```

## Remaining Work

- Run longer model-backed evaluations when the competition runtime exposes the
  selected gpt-oss and Gemma agents.
- Tune probe ordering from saved official evaluation artifacts.
