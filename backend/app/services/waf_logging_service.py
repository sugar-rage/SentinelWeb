"""Transactional persistence for WAF policy decisions and per-vector evidence."""

import json

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.database.models.attack_log import AttackLog
from app.database.models.waf_event import WAFEvent
from app.utils.helpers import utc_now
from app.utils.redaction import is_sensitive_component, safe_payload_evidence
from app.waf.policy import WAFDecision


def record_waf_event(
    db: Session,
    *,
    correlation_id: str,
    source_ip: str,
    method: str,
    path: str,
    action: str,
    decision: WAFDecision | None = None,
    upstream_status: int | None = None,
    error_code: str | None = None,
) -> WAFEvent:
    """Persist the WAF outcome and all findings without credential/header storage."""
    decision = decision or WAFDecision([], 0, "Safe", 0.0, False)
    event = WAFEvent(
        timestamp=utc_now(),
        correlation_id=correlation_id,
        source_ip=source_ip[:45],
        method=method[:10],
        path=path[:500],
        attack_types=json.dumps(decision.attack_types, separators=(",", ":")) or None,
        confidence=decision.confidence,
        base_risk_score=decision.base_risk_score if decision.base_risk_score is not None else decision.risk_score,
        adaptive_factors=json.dumps(decision.adaptive_factors, separators=(",", ":")) if decision.adaptive_factors else None,
        risk_score=decision.risk_score,
        risk_level=decision.risk_level,
        action=action,
        upstream_status=upstream_status,
        error_code=error_code,
    )
    try:
        db.add(event)
        db.flush()
        attack_action = "blocked" if action == "blocked" else "allowed"
        for finding in decision.findings:
            evidence, digest, truncated = safe_payload_evidence(
                finding.value, settings.ATTACK_PAYLOAD_EVIDENCE_CHARS
            )
            if is_sensitive_component(finding.component):
                evidence = "[REDACTED]"
                truncated = False
            result = finding.result
            db.add(AttackLog(
                timestamp=utc_now(),
                correlation_id=correlation_id,
                waf_event_id=event.id,
                request_component=finding.component[:255],
                ip_address=source_ip[:45],
                raw_payload=evidence,
                payload_sha256=digest,
                payload_truncated=truncated,
                attack_detected=True,
                attack_type=result.attack_type,
                confidence=result.confidence,
                severity=result.severity,
                risk_score=result.risk_score,
                risk_level=result.risk_level,
                explanation=result.explanation,
                mitigation=result.mitigation,
                detection_method=result.detection_method,
                action=attack_action,
            ))
        db.commit()
        return event
    except SQLAlchemyError:
        db.rollback()
        raise
