"""
Detection service — AI/ML Hybrid Detection Engine.

Orchestrates:
  1. Primary Rule-based Detection Engine (Regex & Syntax Indicators)
  2. AI/ML Classifier Predictor (SQLi, XSS, Prompt Injection Models)
  3. Hybrid Decision & Risk Calculation (Rule-authority + ML generalization)
  4. Database Persistence (AttackLog)
  5. API Response Serialization (ScanResponse)

Security & Governance Rules:
  - Rule-based detection remains authoritative: A confirmed rule-based attack
    (confidence >= 0.70) is NEVER downgraded by ML.
  - High-confidence ML predictions (confidence >= 0.85) can identify obfuscated/novel
    attacks with no rule match, triggering blocks according to RISK_BLOCK_THRESHOLD=80.
  - Weak rule matches are reinforced synergistically when ML strongly agrees.
  - Low-confidence ML predictions (< 0.60) without rule matches are safely allowed.
  - If ML models are unavailable/fail, the system falls back safely to pure rule-based detection.
"""

import logging
from typing import Optional, List
from sqlalchemy.orm import Session

from app.security.detection_engine import detection_engine
from app.ml.predictor import ml_predictor
from app.services.risk_service import calculate_risk_score, get_risk_level, should_block
from app.schemas.detection import DetectionResult, ScanResponse
from app.database.models.attack_log import AttackLog
from app.utils.helpers import utc_now

logger = logging.getLogger("sentinelweb.detection")

_SEVERITY_MAP = [
    (0.85, "Critical"),
    (0.70, "High"),
    (0.50, "Medium"),
    (0.30, "Low"),
    (0.00, "Info"),
]

_DEFAULT_MITIGATIONS: dict[str, str] = {
    "SQL Injection": (
        "Use parameterized queries (prepared statements). "
        "Validate and sanitize all user inputs. "
        "Apply the principle of least privilege to database accounts."
    ),
    "XSS": (
        "Encode all user-supplied output (HTML entity encoding). "
        "Use Content-Security-Policy headers. "
        "Sanitize inputs using a library like DOMPurify on the client side."
    ),
    "Prompt Injection": (
        "Never pass raw user input directly to LLM system prompts. "
        "Use input/output filtering and sandwich defense patterns. "
        "Implement role-based prompt isolation."
    ),
}


def _get_severity(confidence: float) -> str:
    """Determine human-readable severity level from numeric confidence."""
    for threshold, level in _SEVERITY_MAP:
        if confidence >= threshold:
            return level
    return "Info"


def scan_payload(
    payload: str,
    ip_address: str,
    db: Session,
) -> ScanResponse:
    """
    Full Hybrid Scan Pipeline:
      Rule Scan ──► ML Inference ──► Hybrid Arbitration ──► Risk Scoring ──► Log ──► Response
    """
    # 1. Primary rule-based scan
    rule_match = detection_engine.scan(payload)

    # 2. ML inference (safe with internal fallback)
    try:
        ml_result = ml_predictor.predict(payload)
    except Exception as e:
        logger.warning(f"ML Predictor exception: {e} — falling back to rule-based only.", exc_info=True)
        ml_result = None

    rule_detected = rule_match is not None
    rule_conf = rule_match.confidence if rule_match else 0.0
    rule_type = rule_match.attack_type if rule_match else None

    ml_available = ml_result.is_available if ml_result else False
    ml_detected = ml_result.is_attack if ml_result else False
    ml_conf = ml_result.confidence if ml_result else 0.0
    ml_type = ml_result.predicted_class if ml_result else None

    # 3. Hybrid decision arbitration
    matched_patterns: List[str] = []
    
    # Case A: Confirmed High-Confidence Rule Attack (rule_conf >= 0.70)
    if rule_detected and rule_conf >= 0.70:
        attack_detected = True
        attack_type = rule_type
        severity = rule_match.severity
        mitigation = rule_match.mitigation
        matched_patterns = list(rule_match.matched_patterns)

        # Check if ML also detected and confirmed
        if ml_available and ml_detected and (ml_type == rule_type or ml_conf >= 0.85):
            detection_method = "hybrid"
            confidence = round(max(rule_conf, ml_conf), 2)
            explanation = (
                f"{rule_match.explanation} Confirmed by AI/ML classifier "
                f"({ml_conf * 100:.1f}% confidence)."
            )
        else:
            detection_method = "rule_based"
            confidence = round(rule_conf, 2)
            explanation = rule_match.explanation

        risk_score = calculate_risk_score(confidence, attack_type)
        risk_level = get_risk_level(risk_score)
        action = "blocked" if should_block(risk_score) else "allowed"

    # Case B: Weak Rule Match (0 < rule_conf < 0.70)
    elif rule_detected and rule_conf < 0.70:
        matched_patterns = list(rule_match.matched_patterns)
        
        if ml_available and ml_detected and ml_conf >= 0.85:
            # ML strongly reinforces weak rule match
            attack_detected = True
            attack_type = rule_type if rule_type == ml_type else (ml_type or rule_type)
            detection_method = "hybrid"
            confidence = round(min(0.95, rule_conf * 0.3 + ml_conf * 0.7), 2)
            severity = _get_severity(confidence)
            explanation = (
                f"{rule_match.explanation} Strongly reinforced by AI/ML classifier "
                f"({ml_conf * 100:.1f}% confidence)."
            )
            mitigation = rule_match.mitigation
            risk_score = calculate_risk_score(confidence, attack_type)
            risk_level = get_risk_level(risk_score)
            action = "blocked" if should_block(risk_score) else "allowed"
        else:
            # ML does not reinforce; preserve rule detector outcome
            attack_detected = True
            attack_type = rule_type
            detection_method = "rule_based"
            confidence = round(rule_conf, 2)
            severity = rule_match.severity
            explanation = rule_match.explanation
            mitigation = rule_match.mitigation
            risk_score = calculate_risk_score(confidence, attack_type)
            risk_level = get_risk_level(risk_score)
            action = "blocked" if should_block(risk_score) else "allowed"

    # Case C: No Rule Match (rule_match is None)
    else:
        if ml_available and ml_detected and ml_conf >= 0.85:
            # High-confidence ML detection of novel / obfuscated attack
            attack_detected = True
            attack_type = ml_type
            detection_method = "ml"
            confidence = round(ml_conf, 2)
            severity = _get_severity(confidence)
            risk_score = calculate_risk_score(confidence, attack_type)
            risk_level = get_risk_level(risk_score)
            action = "blocked" if should_block(risk_score) else "allowed"
            explanation = (
                f"AI/ML detection model identified high-confidence {attack_type} pattern "
                f"({ml_conf * 100:.1f}% confidence)."
            )
            mitigation = _DEFAULT_MITIGATIONS.get(
                attack_type, "Sanitize and validate all user inputs."
            )
            matched_patterns = [f"ml_{attack_type.lower().replace(' ', '_')}"]

        elif ml_available and ml_detected and ml_conf >= 0.60:
            # Moderate ML detection (suspicious, but under blocking threshold)
            attack_detected = True
            attack_type = ml_type
            detection_method = "ml"
            confidence = round(ml_conf, 2)
            severity = "Medium"
            # Dampened risk score below blocking threshold (e.g. 50-65)
            risk_score = min(calculate_risk_score(confidence * 0.70, attack_type), 65)
            risk_level = get_risk_level(risk_score)
            action = "allowed"  # Monitored without blocking
            explanation = (
                f"AI/ML model flagged suspicious {attack_type} pattern "
                f"({ml_conf * 100:.1f}% confidence). Monitored without blocking."
            )
            mitigation = _DEFAULT_MITIGATIONS.get(
                attack_type, "Sanitize and validate all user inputs."
            )
            matched_patterns = [f"ml_suspicious_{attack_type.lower().replace(' ', '_')}"]

        else:
            # Clean / Benign Payload
            attack_detected = False
            attack_type = None
            confidence = 0.0
            severity = None
            risk_score = 0
            risk_level = "Safe"
            detection_method = "hybrid" if ml_available else "rule_based"
            action = "allowed"
            explanation = None
            mitigation = None
            matched_patterns = []

    # Build Pydantic DetectionResult
    result = DetectionResult(
        attack_detected=attack_detected,
        attack_type=attack_type,
        confidence=confidence,
        severity=severity,
        risk_score=risk_score,
        risk_level=risk_level,
        explanation=explanation,
        mitigation=mitigation,
        detection_method=detection_method,
        ml_confidence=round(ml_conf, 4) if ml_available and ml_conf > 0 else None,
        rule_confidence=round(rule_conf, 4) if rule_detected else None,
        matched_patterns=matched_patterns if matched_patterns else None,
    )

    # 4. Persist to PostgreSQL attack_logs
    log = AttackLog(
        timestamp=utc_now(),
        ip_address=ip_address,
        raw_payload=payload,
        attack_detected=result.attack_detected,
        attack_type=result.attack_type,
        confidence=result.confidence,
        severity=result.severity,
        risk_score=result.risk_score,
        risk_level=result.risk_level,
        explanation=result.explanation,
        mitigation=result.mitigation,
        detection_method=result.detection_method,
        action=action,
    )
    db.add(log)
    db.commit()

    return ScanResponse(payload=payload, result=result, action=action)
