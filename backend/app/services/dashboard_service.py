"""
Dashboard service — aggregation queries for the dashboard API.

Every function receives a db session and returns plain data or
Pydantic models.  No HTTP or FastAPI imports at this layer.
"""

from sqlalchemy.orm import Session
from sqlalchemy import func, cast, Date
from datetime import datetime, timedelta

from app.database.models.attack_log import AttackLog
from app.database.models.request_log import RequestLog
from app.schemas.dashboard import (
    DashboardStats,
    AttackDistributionItem,
    DailyAttackCount,
)


def get_dashboard_stats(db: Session) -> DashboardStats:
    """Return the high-level overview numbers."""
    total_scans = db.query(func.count(AttackLog.id)).scalar() or 0
    attacks_detected = (
        db.query(func.count(AttackLog.id))
        .filter(AttackLog.attack_detected == True)
        .scalar()
    ) or 0
    blocked = (
        db.query(func.count(AttackLog.id))
        .filter(AttackLog.action == "blocked")
        .scalar()
    ) or 0
    allowed = (
        db.query(func.count(AttackLog.id))
        .filter(AttackLog.action == "allowed")
        .scalar()
    ) or 0

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
    )


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


def get_total_requests(db: Session) -> int:
    """Total HTTP requests logged by middleware."""
    return db.query(func.count(RequestLog.id)).scalar() or 0
