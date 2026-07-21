"""
SDK contract tests — verified against aicomp-sdk 3.1.2 API_REFERENCE.md.

Key contracts:
  - AttackAlgorithm(AttackAlgorithmBase)
  - run(self, env, config: AttackRunConfig) -> list[AttackCandidate]
  - AttackRunConfig: time_budget_s, max_steps, max_tool_hops
  - AttackCandidate.user_messages: tuple[str, ...]
  - Max 32 messages, each ≤ 2000 chars, max 2000 findings
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import pytest

from agent_security_redteam.attack import AttackAlgorithm
from agent_security_redteam.sdk_bridge import (
    AttackAlgorithmBase,
    AttackCandidate,
    AttackRunConfig,
    FakeEnv,
    validate_attack_class,
)


class TestSDKContract:
    """Verify the attack module conforms to competition contract."""

    def test_inherits_base(self) -> None:
        """C-01: AttackAlgorithm MUST inherit from AttackAlgorithmBase."""
        assert issubclass(AttackAlgorithm, AttackAlgorithmBase), (
            "AttackAlgorithm must inherit from AttackAlgorithmBase"
        )

    def test_module_validation(self) -> None:
        """Static contract validation passes."""
        result = validate_attack_class()
        assert result["valid"], f"Contract violations: {result['violations']}"
        assert result["inherits_base"], "Must inherit AttackAlgorithmBase"
        assert result["has_run_method"], "Missing run() method"

    def test_run_signature(self) -> None:
        """run() must accept (self, env, config)."""
        algo = AttackAlgorithm()
        env = FakeEnv(seed=42)
        config = AttackRunConfig(time_budget_s=10.0)
        candidates = algo.run(env, config)
        assert isinstance(candidates, list)

    def test_run_without_config(self) -> None:
        """run() works with just env (config uses defaults)."""
        algo = AttackAlgorithm()
        env = FakeEnv(seed=42)
        candidates = algo.run(env)
        assert isinstance(candidates, list)

    def test_returns_attack_candidates(self) -> None:
        """Return type must be list of objects with user_messages: tuple[str, ...]."""
        algo = AttackAlgorithm()
        env = FakeEnv(seed=42)
        config = AttackRunConfig(time_budget_s=10.0)
        candidates = algo.run(env, config)

        assert isinstance(candidates, list)
        for c in candidates:
            assert isinstance(c.user_messages, tuple), (
                f"user_messages must be tuple, got {type(c.user_messages)}"
            )
            for msg in c.user_messages:
                assert isinstance(msg, str), (
                    f"Each message must be str, got {type(msg)}"
                )

    def test_candidates_are_replayable(self) -> None:
        """Each candidate must respect contract limits."""
        algo = AttackAlgorithm()
        env = FakeEnv(seed=42)
        config = AttackRunConfig(time_budget_s=20.0)
        candidates = algo.run(env, config)

        for c in candidates:
            assert len(c.user_messages) > 0, "Candidate has no messages"
            assert len(c.user_messages) <= 32, (
                f"Candidate has {len(c.user_messages)} messages (max 32)"
            )
            for i, msg in enumerate(c.user_messages):
                assert len(msg) <= 2000, (
                    f"Message {i} is {len(msg)} chars (max 2000)"
                )

    def test_respects_findings_limit(self) -> None:
        """Should never exceed 2000 findings."""
        algo = AttackAlgorithm()
        env = FakeEnv(seed=42)
        config = AttackRunConfig(time_budget_s=100.0)
        candidates = algo.run(env, config)
        assert len(candidates) <= 2000, (
            f"Exceeded max_replayed_findings: {len(candidates)}"
        )

    def test_deterministic_with_seed(self) -> None:
        """Same seed → same output."""
        config = AttackRunConfig(time_budget_s=10.0)
        env1 = FakeEnv(seed=42)
        env2 = FakeEnv(seed=42)
        candidates1 = AttackAlgorithm().run(env1, config)
        candidates2 = AttackAlgorithm().run(env2, config)
        msgs1 = [c.user_messages for c in candidates1]
        msgs2 = [c.user_messages for c in candidates2]
        assert msgs1 == msgs2, "Determinism violated"

    def test_config_fields_exist(self) -> None:
        """AttackRunConfig must have time_budget_s, max_steps, max_tool_hops."""
        config = AttackRunConfig()
        assert hasattr(config, "time_budget_s")
        assert hasattr(config, "max_steps")
        assert hasattr(config, "max_tool_hops")
        assert config.time_budget_s == 30.0
        assert config.max_tool_hops == 8

    def test_attack_candidate_construction(self) -> None:
        """AttackCandidate can be constructed and carries user_messages."""
        c = AttackCandidate(user_messages=("hello",))
        assert c.user_messages == ("hello",)
        assert len(c.user_messages) == 1

        # Contract limits enforced at submission level
        c_many = AttackCandidate(user_messages=tuple(f"msg{i}" for i in range(33)))
        assert len(c_many.user_messages) == 33  # not rejected by type, enforced by algo

        c_long = AttackCandidate(user_messages=("x" * 2001,))
        assert len(c_long.user_messages[0]) == 2001

    def test_config_fields_match_official(self) -> None:
        """Official AttackRunConfig must have time_budget_s, max_steps, max_tool_hops."""
        config = AttackRunConfig()
        assert hasattr(config, "time_budget_s")
        assert hasattr(config, "max_steps")
        assert hasattr(config, "max_tool_hops")
        assert config.time_budget_s == 30.0
        assert config.max_tool_hops == 8
