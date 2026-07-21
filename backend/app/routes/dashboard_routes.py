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
from app.schemas.dashboard import DashboardStats, AttackDistributionItem, DailyAttackCount
from app.services.dashboard_service import (
    get_dashboard_stats,
    get_attack_distribution,
    get_daily_attack_counts,
    get_weekly_attack_counts,
    get_total_requests,
)

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])


@router.get("/stats", response_model=DashboardStats)
def stats(db: Session = Depends(get_db)):
    """High-level overview: totals, blocked, allowed, top attack."""
    return get_dashboard_stats(db)


@router.get("/attack-distribution", response_model=List[AttackDistributionItem])
def attack_distribution(db: Session = Depends(get_db)):
    """Breakdown of attack counts by type."""
    return get_attack_distribution(db)


@router.get("/attack-frequency", response_model=List[DailyAttackCount])
def attack_frequency(
    days: int = Query(default=30, ge=1, le=365),
    db: Session = Depends(get_db),
):
    """Daily attack counts for the last N days."""
    return get_daily_attack_counts(db, days=days)


@router.get("/weekly-frequency", response_model=List[DailyAttackCount])
def weekly_frequency(
    weeks: int = Query(default=12, ge=1, le=52),
    db: Session = Depends(get_db),
):
    """Weekly attack counts for the last N weeks."""
    return get_weekly_attack_counts(db, weeks=weeks)


@router.get("/top-attack-type")
def top_attack_type(db: Session = Depends(get_db)):
    """Return the single most common attack type."""
    data = get_dashboard_stats(db)
    return {"top_attack_type": data.top_attack_type}


@router.get("/total-requests")
def total_requests(db: Session = Depends(get_db)):
    """Total HTTP requests logged by the middleware."""
    count = get_total_requests(db)
    return {"total_requests": count}
