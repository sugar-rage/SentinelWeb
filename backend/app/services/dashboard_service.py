"""
Dashboard service — aggregation queries for the dashboard API.

Every function receives a db session and returns plain data or
Pydantic models.  No HTTP or FastAPI imports at this layer.
"""

import logging
from functools import wraps

from fastapi import HTTPException, status
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from sqlalchemy import Date, Integer, String, case, cast, func
from datetime import datetime, timedelta

from app.database.models.attack_log import AttackLog
from app.database.models.request_log import RequestLog
from app.database.models.waf_event import WAFEvent
from app.schemas.dashboard import (
    DashboardStats,
    AttackDistributionItem,
    DailyAttackCount,
    RiskDistributionItem,
)

logger = logging.getLogger("sentinelweb.dashboard")


def _scanner_decisions(db: Session):
    """One row per non-WAF scanner HTTP request, regardless of batch findings."""
    decision_key = case(
        (AttackLog.request_id.is_not(None), func.concat("request:", cast(AttackLog.request_id, String))),
        (AttackLog.correlation_id.is_not(None), func.concat("correlation:", AttackLog.correlation_id)),
        else_=func.concat("legacy:", cast(AttackLog.id, String)),
    )
    return (
        db.query(
            decision_key.label("decision_key"),
            func.max(case((AttackLog.action == "blocked", 1), else_=0)).label("blocked"),
            func.max(AttackLog.risk_score).label("risk_score"),
        )
        .filter(AttackLog.waf_event_id.is_(None))
        .group_by(decision_key)
        .subquery()
    )


def _handle_database_failure(operation):
    @wraps(operation)
    def wrapped(db: Session, *args, **kwargs):
        try:
            return operation(db, *args, **kwargs)
        except SQLAlchemyError:
            db.rollback()
            logger.exception("Database failure during %s", operation.__name__)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Dashboard data is temporarily unavailable",
            )
    return wrapped


@_handle_database_failure
def get_dashboard_stats(db: Session) -> DashboardStats:
    """Return the high-level overview numbers."""
    total_scans = db.query(func.count(AttackLog.id)).scalar() or 0
    attacks_detected = (
        db.query(func.count(AttackLog.id))
        .filter(AttackLog.attack_detected == True)
        .scalar()
    ) or 0
    scanner = _scanner_decisions(db)
    scanner_total = db.query(func.count()).select_from(scanner).scalar() or 0
    scanner_blocked = db.query(func.count()).select_from(scanner).filter(scanner.c.blocked == 1).scalar() or 0
    scanner_allowed = scanner_total - scanner_blocked
    waf_blocked = db.query(func.count(WAFEvent.id)).filter(WAFEvent.action == "blocked").scalar() or 0
    waf_allowed = db.query(func.count(WAFEvent.id)).filter(WAFEvent.action == "allowed").scalar() or 0
    blocked = scanner_blocked + waf_blocked
    allowed = scanner_allowed + waf_allowed
    total_http_requests = db.query(func.count(RequestLog.id)).scalar() or 0
    total_security_requests = scanner_total + (db.query(func.count(WAFEvent.id)).scalar() or 0)

    # Top attack type
    top_row = (
        db.query(AttackLog.attack_type, func.count(AttackLog.id).label("cnt"))
        .filter(AttackLog.attack_detected == True)
        .group_by(AttackLog.attack_type)
        .order_by(func.count(AttackLog.id).desc())
        .first()
    )
    top_attack = top_row[0] if top_row else None

    return DashboardStats(
        total_scans=total_scans,
        attacks_detected=attacks_detected,
        blocked_requests=blocked,
        allowed_requests=allowed,
        top_attack_type=top_attack,
        total_http_requests=total_http_requests,
        total_security_requests=total_security_requests,
        total_attack_findings=attacks_detected,
    )


@_handle_database_failure
def get_attack_distribution(db: Session) -> list[AttackDistributionItem]:
    """Return the count and percentage of each attack type."""
    rows = (
        db.query(AttackLog.attack_type, func.count(AttackLog.id).label("cnt"))
        .filter(AttackLog.attack_detected == True)
        .group_by(AttackLog.attack_type)
        .order_by(func.count(AttackLog.id).desc())
        .all()
    )

    total = sum(r.cnt for r in rows) if rows else 1
    return [
        AttackDistributionItem(
            attack_type=r.attack_type or "Unknown",
            count=r.cnt,
            percentage=round(r.cnt / total * 100, 1),
        )
        for r in rows
    ]


@_handle_database_failure
def get_daily_attack_counts(db: Session, days: int = 30) -> list[DailyAttackCount]:
    """Return attack counts per day for the last *days* days."""
    since = datetime.utcnow() - timedelta(days=days)

    rows = (
        db.query(
            cast(AttackLog.timestamp, Date).label("day"),
            func.count(AttackLog.id).label("cnt"),
        )
        .filter(AttackLog.attack_detected == True)
        .filter(AttackLog.timestamp >= since)
        .group_by(cast(AttackLog.timestamp, Date))
        .order_by(cast(AttackLog.timestamp, Date))
        .all()
    )

    return [
        DailyAttackCount(date=str(r.day), count=r.cnt)
        for r in rows
    ]


@_handle_database_failure
def get_weekly_attack_counts(db: Session, weeks: int = 12) -> list[DailyAttackCount]:
    """Return attack counts per week for the last *weeks* weeks."""
    since = datetime.utcnow() - timedelta(weeks=weeks)

    rows = (
        db.query(
            cast(AttackLog.timestamp, Date).label("day"),
            func.count(AttackLog.id).label("cnt"),
        )
        .filter(AttackLog.attack_detected == True)
        .filter(AttackLog.timestamp >= since)
        .group_by(cast(AttackLog.timestamp, Date))
        .order_by(cast(AttackLog.timestamp, Date))
        .all()
    )

    # Aggregate daily rows into weekly buckets
    weekly: dict[str, int] = {}
    for r in rows:
        # ISO week label
        d = datetime.strptime(str(r.day), "%Y-%m-%d")
        week_label = f"{d.isocalendar()[0]}-W{d.isocalendar()[1]:02d}"
        weekly[week_label] = weekly.get(week_label, 0) + r.cnt

    return [
        DailyAttackCount(date=week, count=cnt)
        for week, cnt in weekly.items()
    ]


@_handle_database_failure
def get_total_requests(db: Session) -> int:
    """Total HTTP requests logged by middleware."""
    return db.query(func.count(RequestLog.id)).scalar() or 0


@_handle_database_failure
def get_risk_distribution(db: Session) -> list[RiskDistributionItem]:
    """Aggregate risk bands once per WAF/scanner request, never per finding."""
    counts: dict[str, int] = {}
    for level, count in db.query(WAFEvent.risk_level, func.count(WAFEvent.id)).group_by(WAFEvent.risk_level):
        counts[level] = counts.get(level, 0) + count

    scanner = _scanner_decisions(db)
    risk_band = case(
        (scanner.c.risk_score >= 81, "Critical"),
        (scanner.c.risk_score >= 61, "High"),
        (scanner.c.risk_score >= 41, "Medium"),
        (scanner.c.risk_score >= 21, "Low"),
        else_="Safe",
    )
    for level, count in db.query(risk_band.label("risk_level"), func.count()).select_from(scanner).group_by(risk_band):
        counts[level] = counts.get(level, 0) + count
    order = {"Safe": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    return [
        RiskDistributionItem(risk_level=level, count=count)
        for level, count in sorted(counts.items(), key=lambda item: order.get(item[0], 99))
    ]
