"""
Safe text preprocessing and pipeline constructors for SentinelWeb ML models.

SECURITY PRINCIPLE:
Every payload is treated strictly as plain text. No code execution, eval,
or dangerous string parsing is performed.
"""

import unicodedata
from typing import Optional
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from sklearn.linear_model import LogisticRegression


def clean_text(text: Optional[str]) -> str:
    """
    Safely sanitize and normalize input text for ML feature extraction.

    - Handles None/null gracefully.
    - Normalizes Unicode to NFKC.
    - Preserves case and special security tokens (e.g. quotes, brackets, hyphens, tags).
    """
    if text is None:
        return ""
    if not isinstance(text, str):
        text = str(text)
    
    # Safe unicode normalization
    normalized = unicodedata.normalize("NFKC", text)
    return normalized.strip()


def build_sqli_pipeline() -> Pipeline:
    """
    Create the scikit-learn Pipeline for SQL Injection detection.
    
    Uses character word-boundary n-grams (2-4) to capture SQL keywords, operators,
    tautologies, comments, and hex sequences.
    """
    vectorizer = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(2, 4),
        max_features=25000,
        sublinear_tf=True,
        lowercase=True,
    )
    base_clf = LinearSVC(C=1.0, random_state=42, max_iter=2000)
    calibrated_clf = CalibratedClassifierCV(estimator=base_clf, cv=5)
    
    return Pipeline([
        ("tfidf", vectorizer),
        ("clf", calibrated_clf),
    ])


def build_xss_pipeline() -> Pipeline:
    """
    Create the scikit-learn Pipeline for Cross-Site Scripting (XSS) detection.
    
    Uses character word-boundary n-grams (2-4) to capture HTML tags, event handlers,
    DOM sinks, and obfuscated JavaScript calls.
    """
    vectorizer = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(2, 4),
        max_features=25000,
        sublinear_tf=True,
        lowercase=True,
    )
    base_clf = LinearSVC(C=1.0, random_state=42, max_iter=2000)
    calibrated_clf = CalibratedClassifierCV(estimator=base_clf, cv=5)
    
    return Pipeline([
        ("tfidf", vectorizer),
        ("clf", calibrated_clf),
    ])


def build_prompt_injection_pipeline() -> Pipeline:
    """
    Create the scikit-learn Pipeline for Prompt Injection detection.
    
    Uses word n-grams (1-2) with sublinear TF to capture override directives,
    jailbreak triggers, role hijacking, and delimiter attacks while cleanly distinguishing
    benign questions.
    """
    vectorizer = TfidfVectorizer(
        analyzer="word",
        ngram_range=(1, 2),
        max_features=10000,
        sublinear_tf=True,
        lowercase=True,
    )
    base_clf = LinearSVC(C=1.0, random_state=42, max_iter=2000)
    calibrated_clf = CalibratedClassifierCV(estimator=base_clf, cv=5)
    
    return Pipeline([
        ("tfidf", vectorizer),
        ("clf", calibrated_clf),
    ])
