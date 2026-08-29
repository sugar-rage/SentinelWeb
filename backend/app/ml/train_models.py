"""
Training and evaluation pipeline for SentinelWeb ML detection models.

Trains three independent binary classification pipelines:
  1. SQL Injection Model (SQLi vs Benign)
  2. XSS Model (XSS vs Benign)
  3. Prompt Injection Model (Prompt Injection vs Benign)

Features:
  - Deduplication before splitting (prevents train-test leakage)
  - Stratified 80/20 train/test splitting (random_state=42)
  - Vectorizer fitted strictly on training partition
  - Calibrated probability estimates
  - Comprehensive metrics (Accuracy, Precision, Recall, F1, Confusion Matrix)
  - Joblib artifact serialization and JSON report generation
"""

import csv
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Tuple

import joblib
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

from app.ml.preprocessing import (
    clean_text,
    build_sqli_pipeline,
    build_xss_pipeline,
    build_prompt_injection_pipeline,
)


def load_and_clean_sqli_dataset(file_path: Path) -> Tuple[List[str], List[int], Dict[str, Any]]:
    """
    Load and clean the SQL Injection CSV dataset.
    
    Columns: Query, Label
    Mapping: 0 -> Benign, 1 -> SQL Injection
    """
    if not file_path.exists():
        raise FileNotFoundError(f"SQL Injection dataset not found at {file_path}")

    raw_count = 0
    null_count = 0
    malformed_count = 0
    texts: List[str] = []
    labels: List[int] = []

    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.reader(f)
        header = next(reader, None)
        
        q_idx = 0
        l_idx = 1
        if header:
            clean_header = [h.strip().lstrip('\ufeff') for h in header]
            if "Query" in clean_header:
                q_idx = clean_header.index("Query")
            if "Label" in clean_header:
                l_idx = clean_header.index("Label")

        for row in reader:
            raw_count += 1
            if len(row) <= max(q_idx, l_idx):
                malformed_count += 1
                continue
            query = clean_text(row[q_idx])
            lbl_raw = clean_text(row[l_idx])
            
            if not query or lbl_raw not in ("0", "1"):
                null_count += 1
                continue
            
            texts.append(query)
            labels.append(int(lbl_raw))

    # Deduplicate payloads
    seen = set()
    dedup_texts: List[str] = []
    dedup_labels: List[int] = []
    for text, label in zip(texts, labels):
        if text not in seen:
            seen.add(text)
            dedup_texts.append(text)
            dedup_labels.append(label)

    duplicate_count = len(texts) - len(dedup_texts)
    benign_count = dedup_labels.count(0)
    malicious_count = dedup_labels.count(1)

    stats = {
        "dataset_name": "SQL Injection",
        "file_name": file_path.name,
        "raw_count": raw_count,
        "malformed_count": malformed_count,
        "null_or_invalid_count": null_count,
        "duplicate_count": duplicate_count,
        "cleaned_count": len(dedup_texts),
        "class_distribution": {
            "0 (Benign)": benign_count,
            "1 (SQL Injection)": malicious_count,
        },
    }
    return dedup_texts, dedup_labels, stats


def load_and_clean_xss_dataset(file_path: Path) -> Tuple[List[str], List[int], Dict[str, Any]]:
    """
    Load and clean the XSS CSV dataset.
    
    Header structure: ['', 'Sentence', 'Label']
    Mapping: 0 -> Benign, 1 -> XSS
    """
    if not file_path.exists():
        raise FileNotFoundError(f"XSS dataset not found at {file_path}")

    raw_count = 0
    null_count = 0
    malformed_count = 0
    texts: List[str] = []
    labels: List[int] = []

    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.reader(f)
        header = next(reader, None)
        
        sent_idx = 1
        lbl_idx = 2
        if header:
            clean_header = [h.strip().lstrip('\ufeff').lower() for h in header]
            if "sentence" in clean_header:
                sent_idx = clean_header.index("sentence")
            if "label" in clean_header:
                lbl_idx = clean_header.index("label")

        for row in reader:
            raw_count += 1
            if len(row) <= max(sent_idx, lbl_idx):
                malformed_count += 1
                continue
            sentence = clean_text(row[sent_idx])
            lbl_raw = clean_text(row[lbl_idx])
            
            if not sentence or lbl_raw not in ("0", "1"):
                null_count += 1
                continue
            
            texts.append(sentence)
            labels.append(int(lbl_raw))

    # Deduplicate payloads
    seen = set()
    dedup_texts: List[str] = []
    dedup_labels: List[int] = []
    for text, label in zip(texts, labels):
        if text not in seen:
            seen.add(text)
            dedup_texts.append(text)
            dedup_labels.append(label)

    duplicate_count = len(texts) - len(dedup_texts)
    benign_count = dedup_labels.count(0)
    malicious_count = dedup_labels.count(1)

    stats = {
        "dataset_name": "XSS",
        "file_name": file_path.name,
        "raw_count": raw_count,
        "malformed_count": malformed_count,
        "null_or_invalid_count": null_count,
        "duplicate_count": duplicate_count,
        "cleaned_count": len(dedup_texts),
        "class_distribution": {
            "0 (Benign)": benign_count,
            "1 (XSS)": malicious_count,
        },
    }
    return dedup_texts, dedup_labels, stats


def load_and_clean_prompt_injection_dataset(file_path: Path) -> Tuple[List[str], List[int], Dict[str, Any]]:
    """
    Load and clean the Prompt Injection JSONL dataset.
    
    Fields: id, prompt, label ("benign"/"malicious"), attack_type, context, response
    Mapping: 'benign' -> 0, 'malicious' -> 1
    """
    if not file_path.exists():
        raise FileNotFoundError(f"Prompt Injection dataset not found at {file_path}")

    raw_count = 0
    null_count = 0
    malformed_count = 0
    texts: List[str] = []
    labels: List[int] = []
    categories: Dict[str, int] = {}

    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if not line.strip():
                continue
            raw_count += 1
            try:
                data = json.loads(line)
            except Exception:
                malformed_count += 1
                continue
            
            prompt = clean_text(data.get("prompt"))
            lbl_raw = clean_text(data.get("label")).lower()
            category = clean_text(data.get("attack_type", data.get("category", "none")))
            
            if not prompt or lbl_raw not in ("benign", "malicious"):
                null_count += 1
                continue
            
            categories[category] = categories.get(category, 0) + 1
            lbl_val = 1 if lbl_raw == "malicious" else 0
            texts.append(prompt)
            labels.append(lbl_val)

    # Deduplicate prompts
    seen = set()
    dedup_texts: List[str] = []
    dedup_labels: List[int] = []
    for text, label in zip(texts, labels):
        if text not in seen:
            seen.add(text)
            dedup_texts.append(text)
            dedup_labels.append(label)

    duplicate_count = len(texts) - len(dedup_texts)
    benign_count = dedup_labels.count(0)
    malicious_count = dedup_labels.count(1)

    stats = {
        "dataset_name": "Prompt Injection",
        "file_name": file_path.name,
        "raw_count": raw_count,
        "malformed_count": malformed_count,
        "null_or_invalid_count": null_count,
        "duplicate_count": duplicate_count,
        "cleaned_count": len(dedup_texts),
        "class_distribution": {
            "0 (Benign)": benign_count,
            "1 (Prompt Injection)": malicious_count,
        },
        "attack_categories": categories,
    }
    return dedup_texts, dedup_labels, stats


def train_and_evaluate_model(
    model_name: str,
    attack_category: str,
    texts: List[str],
    labels: List[int],
    pipeline_builder: Callable[[], Pipeline],
    model_save_path: Path,
    reports_dir: Path,
) -> Dict[str, Any]:
    """
    Train, evaluate, serialize, and save reports for an attack category classifier.
    """
    print(f"\n{'=' * 60}")
    print(f"Training: {model_name} ({attack_category})")
    print(f"{'=' * 60}")

    # Stratified Train/Test Split (80% Train, 20% Test)
    X_train, X_test, y_train, y_test = train_test_split(
        texts,
        labels,
        test_size=0.20,
        random_state=42,
        stratify=labels,
    )

    print(f"Train samples: {len(X_train)} (Benign: {y_train.count(0)}, Malicious: {y_train.count(1)})")
    print(f"Test samples:  {len(X_test)}  (Benign: {y_test.count(0)}, Malicious: {y_test.count(1)})")

    # Construct and Fit Pipeline ONLY on X_train
    start_time = time.time()
    pipeline = pipeline_builder()
    pipeline.fit(X_train, y_train)
    train_duration = time.time() - start_time
    print(f"Training completed in {train_duration:.2f} seconds.")

    # Evaluate on Unseen Test Partition
    y_pred = pipeline.predict(X_test)
    y_proba = pipeline.predict_proba(X_test)[:, 1]

    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, zero_division=0))
    rec = float(recall_score(y_test, y_pred, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, zero_division=0))
    
    try:
        roc_auc = float(roc_auc_score(y_test, y_proba))
    except Exception:
        roc_auc = 0.0

    cm = confusion_matrix(y_test, y_pred).tolist()
    # Format: [[TN, FP], [FN, TP]]
    tn, fp, fn, tp = cm[0][0], cm[0][1], cm[1][0], cm[1][1]

    print("\nEvaluation Metrics on Test Partition:")
    print(f"  Accuracy:  {acc * 100:.2f}%")
    print(f"  Precision: {prec * 100:.2f}%")
    print(f"  Recall:    {rec * 100:.2f}%")
    print(f"  F1-Score:  {f1 * 100:.2f}%")
    print(f"  ROC-AUC:   {roc_auc:.4f}")
    print(f"  Confusion Matrix: TN={tn}, FP={fp}, FN={fn}, TP={tp}")
    print("\nDetailed Classification Report:")
    report_dict = classification_report(y_test, y_pred, target_names=["Benign (0)", f"{attack_category} (1)"], output_dict=True)
    print(classification_report(y_test, y_pred, target_names=["Benign (0)", f"{attack_category} (1)"], digits=4))

    # Serialize Pipeline to disk
    model_save_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, model_save_path)
    file_size_kb = model_save_path.stat().st_size / 1024
    print(f"Model saved to: {model_save_path} ({file_size_kb:.1f} KB)")

    # Prepare and Save Detailed Report
    report_data = {
        "model_name": model_name,
        "attack_category": attack_category,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "train_samples": len(X_train),
        "test_samples": len(X_test),
        "training_duration_seconds": round(train_duration, 3),
        "model_file": str(model_save_path.name),
        "model_size_kb": round(file_size_kb, 2),
        "metrics": {
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "roc_auc": round(roc_auc, 4),
        },
        "confusion_matrix": {
            "true_negatives": tn,
            "false_positives": fp,
            "false_negatives": fn,
            "true_positives": tp,
            "raw_matrix": cm,
        },
        "classification_report": report_dict,
    }

    reports_dir.mkdir(parents=True, exist_ok=True)
    report_file = reports_dir / f"{model_name.lower().replace(' ', '_')}_report.json"
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)
    print(f"Report saved to: {report_file}")

    return report_data


def train_all_models(
    datasets_dir: Path,
    models_dir: Path,
    reports_dir: Path,
) -> Dict[str, Any]:
    """
    Execute end-to-end training and evaluation for all 3 attack models.
    """
    print(f"{'=' * 65}")
    print("SentinelWeb AI/ML Security Training Pipeline")
    print(f"{'=' * 65}")
    print(f"Datasets Path: {datasets_dir}")
    print(f"Models Path:   {models_dir}")
    print(f"Reports Path:  {reports_dir}")

    total_start = time.time()
    summary_results: Dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "datasets_dir": str(datasets_dir),
        "models_dir": str(models_dir),
        "reports_dir": str(reports_dir),
        "models": {},
    }

    # 1. SQL Injection Model
    sqli_path = datasets_dir / "sql_injection" / "Modified_SQL_Dataset.csv"
    sqli_texts, sqli_labels, sqli_stats = load_and_clean_sqli_dataset(sqli_path)
    summary_results["models"]["sqli_dataset_stats"] = sqli_stats
    sqli_report = train_and_evaluate_model(
        model_name="sqli_model",
        attack_category="SQL Injection",
        texts=sqli_texts,
        labels=sqli_labels,
        pipeline_builder=build_sqli_pipeline,
        model_save_path=models_dir / "sqli_model.joblib",
        reports_dir=reports_dir,
    )
    summary_results["models"]["sqli_model"] = sqli_report

    # 2. XSS Model
    xss_path = datasets_dir / "xss" / "XSS_dataset.csv"
    xss_texts, xss_labels, xss_stats = load_and_clean_xss_dataset(xss_path)
    summary_results["models"]["xss_dataset_stats"] = xss_stats
    xss_report = train_and_evaluate_model(
        model_name="xss_model",
        attack_category="XSS",
        texts=xss_texts,
        labels=xss_labels,
        pipeline_builder=build_xss_pipeline,
        model_save_path=models_dir / "xss_model.joblib",
        reports_dir=reports_dir,
    )
    summary_results["models"]["xss_model"] = xss_report

    # 3. Prompt Injection Model
    pi_path = datasets_dir / "prompt_injection" / "Prompt_INJECTION_And_Benign_DATASET.jsonl"
    pi_texts, pi_labels, pi_stats = load_and_clean_prompt_injection_dataset(pi_path)
    summary_results["models"]["prompt_injection_dataset_stats"] = pi_stats
    pi_report = train_and_evaluate_model(
        model_name="prompt_injection_model",
        attack_category="Prompt Injection",
        texts=pi_texts,
        labels=pi_labels,
        pipeline_builder=build_prompt_injection_pipeline,
        model_save_path=models_dir / "prompt_injection_model.joblib",
        reports_dir=reports_dir,
    )
    summary_results["models"]["prompt_injection_model"] = pi_report

    total_duration = time.time() - total_start
    summary_results["total_pipeline_duration_seconds"] = round(total_duration, 2)

    # Save models metadata
    metadata = {
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "models": {
            "sqli": {
                "file": "sqli_model.joblib",
                "attack_type": "SQL Injection",
                "accuracy": sqli_report["metrics"]["accuracy"],
                "f1_score": sqli_report["metrics"]["f1_score"],
            },
            "xss": {
                "file": "xss_model.joblib",
                "attack_type": "XSS",
                "accuracy": xss_report["metrics"]["accuracy"],
                "f1_score": xss_report["metrics"]["f1_score"],
            },
            "prompt_injection": {
                "file": "prompt_injection_model.joblib",
                "attack_type": "Prompt Injection",
                "accuracy": pi_report["metrics"]["accuracy"],
                "f1_score": pi_report["metrics"]["f1_score"],
            },
        },
    }
    with open(models_dir / "metadata.json", "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    # Save consolidated summary
    with open(reports_dir / "training_summary.json", "w", encoding="utf-8") as f:
        json.dump(summary_results, f, indent=2)

    print(f"\n{'=' * 65}")
    print(f"TRAINING PIPELINE COMPLETE (Total time: {total_duration:.2f}s)")
    print(f"Summary saved to: {reports_dir / 'training_summary.json'}")
    print(f"{'=' * 65}")

    return summary_results
