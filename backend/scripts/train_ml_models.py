"""
CLI Script to execute reproducible training of all SentinelWeb ML attack detection models.

Usage:
    python scripts/train_ml_models.py
    python scripts/train_ml_models.py --datasets-dir ../datasets --models-dir app/ml/models --reports-dir ml_reports
"""

import argparse
import os
import sys
from pathlib import Path

# Ensure UTF-8 output on Windows
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")

# Ensure backend root is in sys.path
SCRIPT_DIR = Path(__file__).resolve().parent
BACKEND_DIR = SCRIPT_DIR.parent
WORKSPACE_DIR = BACKEND_DIR.parent

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.ml.train_models import train_all_models


def find_datasets_dir(custom_path: str | None = None) -> Path:
    """Resolve datasets directory across multiple standard workspace locations."""
    if custom_path:
        p = Path(custom_path).resolve()
        if p.exists():
            return p

    candidates = [
        WORKSPACE_DIR / "datasets",
        BACKEND_DIR / "datasets",
        Path.cwd() / "datasets",
        Path.cwd().parent / "datasets",
    ]
    for c in candidates:
        if c.exists() and (c / "sql_injection").exists():
            return c.resolve()

    # Default fallback
    return (WORKSPACE_DIR / "datasets").resolve()


def main():
    parser = argparse.ArgumentParser(
        description="SentinelWeb AI/ML Training Pipeline for Web Attack Detection."
    )
    parser.add_argument(
        "--datasets-dir",
        type=str,
        default=None,
        help="Path to datasets directory (containing sql_injection, xss, prompt_injection)",
    )
    parser.add_argument(
        "--models-dir",
        type=str,
        default=str(BACKEND_DIR / "app" / "ml" / "models"),
        help="Path where trained .joblib model files should be stored",
    )
    parser.add_argument(
        "--reports-dir",
        type=str,
        default=str(BACKEND_DIR / "ml_reports"),
        help="Path where evaluation JSON reports should be stored",
    )

    args = parser.parse_args()

    datasets_dir = find_datasets_dir(args.datasets_dir)
    models_dir = Path(args.models_dir).resolve()
    reports_dir = Path(args.reports_dir).resolve()

    print("=" * 65)
    print("STARTING SENTINELWEB ML TRAINING PIPELINE")
    print("=" * 65)
    print(f"Resolved Datasets Dir: {datasets_dir}")
    print(f"Resolved Models Dir:   {models_dir}")
    print(f"Resolved Reports Dir:  {reports_dir}")
    print()

    if not datasets_dir.exists():
        print(f"ERROR: Datasets directory does not exist: {datasets_dir}", file=sys.stderr)
        sys.exit(1)

    summary = train_all_models(
        datasets_dir=datasets_dir,
        models_dir=models_dir,
        reports_dir=reports_dir,
    )

    print("\n--- FINAL TRAINING PIPELINE SUMMARY ---")
    for model_key in ["sqli_model", "xss_model", "prompt_injection_model"]:
        if model_key in summary.get("models", {}):
            m = summary["models"][model_key]
            metrics = m.get("metrics", {})
            cm = m.get("confusion_matrix", {})
            print(f"\nModel: {m.get('model_name')} [{m.get('attack_category')}]")
            print(f"  Accuracy:  {metrics.get('accuracy', 0)*100:.2f}%")
            print(f"  Precision: {metrics.get('precision', 0)*100:.2f}%")
            print(f"  Recall:    {metrics.get('recall', 0)*100:.2f}%")
            print(f"  F1-Score:  {metrics.get('f1_score', 0)*100:.2f}%")
            print(f"  ROC-AUC:   {metrics.get('roc_auc', 0):.4f}")
            print(f"  Confusion Matrix: TN={cm.get('true_negatives')}, FP={cm.get('false_positives')}, FN={cm.get('false_negatives')}, TP={cm.get('true_positives')}")

    print("\nPipeline execution successfully finished.")


if __name__ == "__main__":
    main()
