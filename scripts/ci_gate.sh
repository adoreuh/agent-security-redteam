#!/usr/bin/env bash
set -euo pipefail

# CI gate for agent_security_redteam
# Run before every commit: bash scripts/ci_gate.sh

echo "=== 1. Python syntax check ==="
python -m compileall -q attack_submission.py attack.py

echo "=== 2. Standalone import check ==="
python -c "
import importlib.util
spec = importlib.util.spec_from_file_location('attack_submission', 'attack_submission.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
assert hasattr(mod, 'AttackAlgorithm')
assert issubclass(mod.AttackAlgorithm, mod.AttackAlgorithmBase)
"

echo "=== 3. Unit tests ==="
python -m pytest tests/ -v

echo "=== 4. SDK contract validation ==="
PYTHONIOENCODING=utf-8 aicomp validate redteam attack_submission.py

echo "=== 5. SDK smoke test ==="
PYTHONIOENCODING=utf-8 aicomp test redteam attack_submission.py --budget-s 10 --agent deterministic

echo ""
echo "=== ALL GATES PASSED ==="
