"""
Inference engine and runtime predictor for SentinelWeb ML models.

Features:
  - Singleton pattern for fast thread-safe inference without reloading/retraining.
  - Returns class probabilities and confidence scores for SQLi, XSS, and Prompt Injection.
  - Graceful fallback: If models are unavailable or corrupt, logs a warning and returns
    a safe result without crashing the application.
"""

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional, Tuple

import joblib

from app.ml.preprocessing import clean_text

logger = logging.getLogger("sentinelweb.ml")


@dataclass
class MLPredictionResult:
    """Outcome of ML inference across all attack models."""
    is_available: bool = False
    is_attack: bool = False
    predicted_class: Optional[str] = None
    confidence: float = 0.0
    probabilities: Dict[str, float] = field(default_factory=dict)
    error: Optional[str] = None


class MLPredictor:
    """
    Manages loading and runtime inference for attack classifiers.
    """

    def __init__(self, models_dir: Optional[Path] = None):
        if models_dir is None:
            self.models_dir = Path(__file__).resolve().parent / "models"
        else:
            self.models_dir = Path(models_dir)

        self.sqli_pipeline = None
        self.xss_pipeline = None
        self.prompt_injection_pipeline = None
        self.is_loaded = False
        self._load_error = None

    def load_models(self) -> bool:
        """
        Load serialized model artifacts from disk.
        Returns True if all models loaded successfully, False otherwise.
        """
        try:
            sqli_path = self.models_dir / "sqli_model.joblib"
            xss_path = self.models_dir / "xss_model.joblib"
            pi_path = self.models_dir / "prompt_injection_model.joblib"

            missing = []
            for name, path in [("sqli", sqli_path), ("xss", xss_path), ("prompt_injection", pi_path)]:
                if not path.exists():
                    missing.append(f"{name} ({path.name})")

            if missing:
                self._load_error = f"Missing model artifacts: {', '.join(missing)}"
                self.is_loaded = False
                logger.warning(
                    f"ML models unavailable — using rule-based fallback. Details: {self._load_error}"
                )
                return False

            self.sqli_pipeline = joblib.load(sqli_path)
            self.xss_pipeline = joblib.load(xss_path)
            self.prompt_injection_pipeline = joblib.load(pi_path)
            self.is_loaded = True
            self._load_error = None
            logger.info("ML models loaded successfully (SQLi, XSS, Prompt Injection).")
            return True

        except Exception as e:
            self._load_error = str(e)
            self.is_loaded = False
            logger.warning(
                f"ML models failed to load — using rule-based fallback. Error: {e}",
                exc_info=True,
            )
            return False

    def predict(self, payload: str) -> MLPredictionResult:
        """
        Predict attack probabilities for a given payload across SQLi, XSS, and Prompt Injection.

        Returns:
            MLPredictionResult with predicted attack class, probabilities,
            and confidence score. If models are unavailable, returns is_available=False.
        """
        if not self.is_loaded:
            # Attempt load once
            if not self.load_models():
                return MLPredictionResult(
                    is_available=False,
                    error=self._load_error or "ML models not loaded",
                )

        cleaned = clean_text(payload)
        if not cleaned or len(cleaned) < 2:
            return MLPredictionResult(
                is_available=True,
                is_attack=False,
                predicted_class=None,
                confidence=0.0,
                probabilities={"SQL Injection": 0.0, "XSS": 0.0, "Prompt Injection": 0.0},
            )

        try:
            # 1. SQL Injection inference
            sqli_vec = self.sqli_pipeline.named_steps["tfidf"].transform([cleaned])
            if sqli_vec.nnz > 0:
                prob_sqli = float(self.sqli_pipeline.named_steps["clf"].predict_proba(sqli_vec)[0][1])
            else:
                prob_sqli = 0.0

            # 2. XSS inference
            xss_vec = self.xss_pipeline.named_steps["tfidf"].transform([cleaned])
            if xss_vec.nnz > 0:
                prob_xss = float(self.xss_pipeline.named_steps["clf"].predict_proba(xss_vec)[0][1])
            else:
                prob_xss = 0.0

            # 3. Prompt Injection inference
            pi_vec = self.prompt_injection_pipeline.named_steps["tfidf"].transform([cleaned])
            if pi_vec.nnz > 0:
                prob_pi = float(self.prompt_injection_pipeline.named_steps["clf"].predict_proba(pi_vec)[0][1])
            else:
                prob_pi = 0.0

            probabilities = {
                "SQL Injection": round(prob_sqli, 4),
                "XSS": round(prob_xss, 4),
                "Prompt Injection": round(prob_pi, 4),
            }

            # Threshold for considering any individual model as flagging an attack
            threshold = 0.60
            is_sqli = prob_sqli >= threshold
            is_xss = prob_xss >= threshold
            is_pi = prob_pi >= threshold

            if not (is_sqli or is_xss or is_pi):
                # No model crossed the minimum attack threshold -> Benign
                return MLPredictionResult(
                    is_available=True,
                    is_attack=False,
                    predicted_class=None,
                    confidence=round(max(prob_sqli, prob_xss, prob_pi), 4),
                    probabilities=probabilities,
                )

            # Targeted attack resolution
            if is_sqli and prob_sqli >= prob_xss and prob_sqli >= 0.75:
                top_class, top_prob = "SQL Injection", prob_sqli
            elif is_xss and prob_xss >= prob_sqli and prob_xss >= 0.75:
                top_class, top_prob = "XSS", prob_xss
            elif is_pi and prob_pi >= 0.70 and prob_sqli < 0.75 and prob_xss < 0.75:
                top_class, top_prob = "Prompt Injection", prob_pi
            else:
                # Argmax over active candidate categories
                active = []
                if is_sqli: active.append(("SQL Injection", prob_sqli))
                if is_xss: active.append(("XSS", prob_xss))
                if is_pi: active.append(("Prompt Injection", prob_pi))
                top_class, top_prob = max(active, key=lambda x: x[1])

            return MLPredictionResult(
                is_available=True,
                is_attack=True,
                predicted_class=top_class,
                confidence=round(top_prob, 4),
                probabilities=probabilities,
            )

        except Exception as e:
            logger.error(f"Error during ML prediction: {e}", exc_info=True)
            return MLPredictionResult(
                is_available=False,
                error=str(e),
            )


# Global singleton instance
ml_predictor = MLPredictor()
