"""
Report service — queries attack logs and builds SecurityReport objects.
"""

from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database.models.attack_log import AttackLog
from app.schemas.report import ReportEntry, SecurityReport
from app.utils.helpers import utc_now


def generate_report(
    db: Session,
    start_date: str | None = None,
    end_date: str | None = None,
) -> SecurityReport:
    """
    Build a SecurityReport from attack_logs within a date range.

    Args:
        db:         Active DB session.
        start_date: ISO date string (YYYY-MM-DD).  Defaults to all time.
        end_date:   ISO date string (YYYY-MM-DD).  Defaults to now.

    Returns:
        A populated SecurityReport Pydantic model.
    """
    query = db.query(AttackLog)

    if start_date:
        start_dt = datetime.strptime(start_date, "%Y-%m-%d")
        query = query.filter(AttackLog.timestamp >= start_dt)

    if end_date:
        end_dt = datetime.strptime(end_date, "%Y-%m-%d")
        # Include the full end day
        end_dt = end_dt.replace(hour=23, minute=59, second=59)
        query = query.filter(AttackLog.timestamp <= end_dt)

    logs = query.order_by(AttackLog.timestamp.desc()).all()

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
        )
        for log in logs
    ]

    attacks = [e for e in entries if e.attack_type is not None]
    blocked = [e for e in entries if e.action == "blocked"]
    allowed = [e for e in entries if e.action == "allowed"]

    return SecurityReport(
        generated_at=utc_now(),
        total_events=len(entries),
        attacks_found=len(attacks),
        blocked_count=len(blocked),
        allowed_count=len(allowed),
        entries=entries,
    )
