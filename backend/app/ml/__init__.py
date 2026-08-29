"""
SentinelWeb AI/ML Security Module.

Provides machine learning models, inference engines, preprocessing pipelines,
and training orchestration for SQL Injection, XSS, and Prompt Injection detection.
"""

from app.ml.predictor import ml_predictor, MLPredictionResult

__all__ = ["ml_predictor", "MLPredictionResult"]
