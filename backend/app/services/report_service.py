"""
Report service — queries attack logs and builds SecurityReport objects.
"""

import logging
from datetime import date, datetime, time, timezone
from sqlalchemy.orm import Session
from sqlalchemy import String, case, cast, func
from sqlalchemy.exc import SQLAlchemyError
from fastapi import HTTPException, status

from app.database.models.attack_log import AttackLog
from app.schemas.report import ReportEntry, SecurityReport, WAFReportEntry
from app.database.models.waf_event import WAFEvent
from app.core.config import settings
from app.utils.helpers import utc_now

logger = logging.getLogger("sentinelweb.reports")


def generate_report(
    db: Session,
    start_date: date | None = None,
    end_date: date | None = None,
) -> SecurityReport:
    """
    Build a SecurityReport from attack_logs within a date range.

    Args:
        db:         Active DB session.
        start_date: Validated ISO calendar date. Defaults to all time.
        end_date:   Validated ISO calendar date. Defaults to now.

    Returns:
        A populated SecurityReport Pydantic model.
    """
    attack_filters = []
    waf_filters = []

    if start_date:
        start_dt = datetime.combine(start_date, time.min, tzinfo=timezone.utc)
        attack_filters.append(AttackLog.timestamp >= start_dt)
        waf_filters.append(WAFEvent.timestamp >= start_dt)

    if end_date:
        end_dt = datetime.combine(end_date, time.max, tzinfo=timezone.utc)
        attack_filters.append(AttackLog.timestamp <= end_dt)
        waf_filters.append(WAFEvent.timestamp <= end_dt)

    try:
        attack_query = db.query(AttackLog).filter(*attack_filters)
        waf_query = db.query(WAFEvent).filter(*waf_filters)
        total_events = attack_query.count()
        attack_findings = attack_query.filter(AttackLog.attack_detected.is_(True)).count()
        scanner_findings = attack_query.filter(
            AttackLog.attack_detected.is_(True), AttackLog.waf_event_id.is_(None)
        ).count()
        logs = attack_query.order_by(AttackLog.timestamp.desc()).limit(settings.REPORT_MAX_ENTRIES).all()
        waf_request_count = waf_query.count()
        waf_logs = waf_query.order_by(WAFEvent.timestamp.desc()).limit(settings.REPORT_MAX_ENTRIES).all()

        decision_key = case(
            (AttackLog.request_id.is_not(None), func.concat("request:", cast(AttackLog.request_id, String))),
            (AttackLog.correlation_id.is_not(None), func.concat("correlation:", AttackLog.correlation_id)),
            else_=func.concat("legacy:", cast(AttackLog.id, String)),
        )
        scanner = (
            db.query(
                decision_key.label("decision_key"),
                func.max(case((AttackLog.action == "blocked", 1), else_=0)).label("blocked"),
            )
            .filter(*attack_filters, AttackLog.waf_event_id.is_(None))
            .group_by(decision_key)
            .subquery()
        )
        scanner_total = db.query(func.count()).select_from(scanner).scalar() or 0
        scanner_blocked = db.query(func.count()).select_from(scanner).filter(scanner.c.blocked == 1).scalar() or 0
        waf_blocked = waf_query.filter(WAFEvent.action == "blocked").count()
        waf_allowed = waf_query.filter(WAFEvent.action == "allowed").count()
    except SQLAlchemyError:
        db.rollback()
        logger.exception("Failed to generate security report")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to generate security report",
        )

    entries = [
        ReportEntry(
            id=log.id,
            timestamp=log.timestamp,
            attack_type=log.attack_type,
            confidence=log.confidence,
            severity=log.severity,
            risk_score=log.risk_score,
            risk_level=log.risk_level,
            explanation=log.explanation,
            mitigation=log.mitigation,
            raw_payload=log.raw_payload,
            action=log.action,
            correlation_id=log.correlation_id,
            request_id=log.request_id,
            waf_event_id=log.waf_event_id,
            request_component=log.request_component,
            source="waf" if log.waf_event_id else "scanner",
            detection_method=log.detection_method,
        )
        for log in logs
    ]

    waf_entries = [
        WAFReportEntry(
            id=event.id,
            timestamp=event.timestamp,
            correlation_id=event.correlation_id,
            request_id=event.request_id,
            method=event.method,
            path=event.path,
            risk_score=event.risk_score,
            risk_level=event.risk_level,
            action=event.action,
            upstream_status=event.upstream_status,
        )
        for event in waf_logs
    ]

    return SecurityReport(
        generated_at=utc_now(),
        total_events=total_events,
        attacks_found=attack_findings,
        blocked_count=scanner_blocked + waf_blocked,
        allowed_count=(scanner_total - scanner_blocked) + waf_allowed,
        entries=entries,
        scanner_findings=scanner_findings,
        attack_findings=attack_findings,
        waf_request_count=waf_request_count,
        waf_blocked_requests=waf_blocked,
        waf_allowed_requests=waf_allowed,
        waf_events=waf_entries,
        truncated=total_events > len(entries) or waf_request_count > len(waf_entries),
    )
