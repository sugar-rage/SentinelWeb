"""
Detection service — glue between the detection engine, risk analysis,
and the Pydantic response schemas.

The route calls this service; this service calls the engine + risk
module and returns a fully populated ScanResponse.
"""

from sqlalchemy.orm import Session

from app.security.detection_engine import detection_engine
from app.services.risk_service import calculate_risk_score, get_risk_level, should_block
from app.schemas.detection import DetectionResult, ScanResponse
from app.database.models.attack_log import AttackLog
from app.utils.helpers import utc_now


def scan_payload(
    payload: str,
    ip_address: str,
    db: Session,
) -> ScanResponse:
    """
    Full scan pipeline: detect → score → log → respond.

    1. Run the payload through the detection engine.
    2. Calculate the risk score.
    3. Persist the result in attack_logs.
    4. Return the ScanResponse.
    """
    match = detection_engine.scan(payload)

    if match is None:
        # No attack detected
        result = DetectionResult(
            attack_detected=False,
            confidence=0.0,
            risk_score=0,
            risk_level="Safe",
            detection_method="rule_based",
        )
        action = "allowed"
    else:
        risk_score = calculate_risk_score(match.confidence, match.attack_type)
        risk_level = get_risk_level(risk_score)
        action = "blocked" if should_block(risk_score) else "allowed"

        result = DetectionResult(
            attack_detected=True,
            attack_type=match.attack_type,
            confidence=match.confidence,
            severity=match.severity,
            risk_score=risk_score,
            risk_level=risk_level,
            explanation=match.explanation,
            mitigation=match.mitigation,
            detection_method="rule_based",
        )

    # Persist to database
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
