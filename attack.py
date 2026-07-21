"""Package entry point for the AI Agent Security red-team submission.

The Kaggle notebook writes ``attack_submission.py`` as a standalone
``/kaggle/working/attack.py``. This module keeps local package imports and tests
on the same implementation while inheriting from the local SDK bridge type.
"""

from __future__ import annotations

from typing import Any, Mapping

from .attack_submission import run_attack
from .sdk_bridge import AttackAlgorithmBase, AttackCandidate, AttackRunConfig


class AttackAlgorithm(AttackAlgorithmBase):
    """Competition attack algorithm using the shared standalone engine."""

    def __init__(self, config: Mapping[str, Any] | None = None) -> None:
        super().__init__(config)
        self.config = dict(config or {})

    def run(
        self,
        env: Any,
        config: AttackRunConfig | None = None,
    ) -> list[AttackCandidate]:
        return run_attack(env, config or AttackRunConfig(), AttackCandidate, self.config)
