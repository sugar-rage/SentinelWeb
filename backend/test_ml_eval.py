"""
SentinelWeb ML Evaluation and Generalization Test Runner.

Executes unseen evaluation benchmarks to verify ML model generalization,
resilience against false positives, and latency.
"""

import sys
from pathlib import Path

# Ensure UTF-8 output on Windows
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from scripts.evaluate_ml_models import run_evaluation


def test_ml_evaluation():
    print("=" * 60)
    print("RUNNING SENTINELWEB ML EVALUATION TEST SUITE")
    print("=" * 60)
    success = run_evaluation()
    assert success, "ML Evaluation test suite did not meet accuracy threshold (>=90%)"
    print("\nALL ML EVALUATION TESTS COMPLETED SUCCESSFULLY!")


if __name__ == "__main__":
    try:
        test_ml_evaluation()
    except AssertionError as e:
        print(f"FAILED: {e}", file=sys.stderr)
        sys.exit(1)
