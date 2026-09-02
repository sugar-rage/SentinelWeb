"""
Dashboard routes — statistics endpoints for the frontend dashboard.

GET /api/dashboard/stats                — overview numbers.
GET /api/dashboard/attack-distribution  — attack type breakdown.
GET /api/dashboard/attack-frequency     — daily attack counts.
GET /api/dashboard/weekly-frequency     — weekly attack counts.
GET /api/dashboard/top-attack-type      — single most common attack.
GET /api/dashboard/total-requests       — total HTTP requests logged.
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from typing import List

from app.database.database import get_db
from app.schemas.dashboard import DashboardStats, AttackDistributionItem, DailyAttackCount, RiskDistributionItem
from app.services.dashboard_service import (
    get_dashboard_stats,
    get_attack_distribution,
    get_daily_attack_counts,
    get_weekly_attack_counts,
    get_total_requests,
    get_risk_distribution,
)
from app.auth.dependencies import require_permission
from app.database.models.administrator import Administrator

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])
require_analytics = require_permission("view_analytics")


@router.get("/stats", response_model=DashboardStats)
def stats(
    db: Session = Depends(get_db),
    admin: Administrator = Depends(require_analytics),
):
    """High-level overview: totals, blocked, allowed, top attack. Requires admin."""
    return get_dashboard_stats(db)


@router.get("/attack-distribution", response_model=List[AttackDistributionItem])
def attack_distribution(
    db: Session = Depends(get_db),
    admin: Administrator = Depends(require_analytics),
):
    """Breakdown of attack counts by type. Requires admin."""
    return get_attack_distribution(db)


@router.get("/attack-frequency", response_model=List[DailyAttackCount])
def attack_frequency(
    days: int = Query(default=30, ge=1, le=365),
    db: Session = Depends(get_db),
    admin: Administrator = Depends(require_analytics),
):
    """Daily attack counts for the last N days. Requires admin."""
    return get_daily_attack_counts(db, days=days)


@router.get("/weekly-frequency", response_model=List[DailyAttackCount])
def weekly_frequency(
    weeks: int = Query(default=12, ge=1, le=52),
    db: Session = Depends(get_db),
    admin: Administrator = Depends(require_analytics),
):
    """Weekly attack counts for the last N weeks. Requires admin."""
    return get_weekly_attack_counts(db, weeks=weeks)


@router.get("/top-attack-type")
def top_attack_type(
    db: Session = Depends(get_db),
    admin: Administrator = Depends(require_analytics),
):
    """Return the single most common attack type. Requires admin."""
    data = get_dashboard_stats(db)
    return {"top_attack_type": data.top_attack_type}


@router.get("/total-requests")
def total_requests(
    db: Session = Depends(get_db),
    admin: Administrator = Depends(require_analytics),
):
    """Total HTTP requests logged by the middleware. Requires admin."""
    count = get_total_requests(db)
    return {"total_requests": count}


@router.get("/risk-distribution", response_model=List[RiskDistributionItem])
def risk_distribution(
    db: Session = Depends(get_db),
    admin: Administrator = Depends(require_analytics),
):
    """Request-level risk distribution for scanner and WAF decisions."""
    return get_risk_distribution(db)
