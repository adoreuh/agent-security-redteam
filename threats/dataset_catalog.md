# Fixture Catalog

This project uses the offline aicomp-sdk fixtures bundled with the competition.
No additional datasets are required for submission generation or local smoke
testing.

## Public Fixture Groups

| Group | Examples | Purpose |
| --- | --- | --- |
| Web corpus | `page_2`, `page_5`, `page_32`, `chain_attack_1` | Public web content for indirect prompt injection |
| Mail seed | `email_1`, `email_12`, `email_22` | Local email bodies for untrusted instruction handling |
| File seed | `readme.txt`, `config.txt`, `secret.txt`, `mh_bridge.txt` | Local sandbox files and protected secret target |

## Usage Policy

1. Probe only the competition fixtures or hidden equivalents exposed by the
   evaluator environment.
2. Return only replayable `AttackCandidate.user_messages` chains.
3. Treat attacker metadata as non-scoring; rely on tool events and official
   predicates.
4. Keep URLs non-routable (`.invalid`) and keep payloads limited to benchmark
   canaries or fixture-local content.
5. Validate with the official SDK before publishing.

## Submission Relevance

The standalone `attack_submission.py` probes these fixture families during
generation, keeps predicate-confirmed chains when available, and returns a small
bounded backstop set for model or guardrail variants that only materialize during
fresh replay.
