"""
Pydantic schemas for the dashboard statistics endpoints.
"""

from pydantic import BaseModel
from typing import List


class DashboardStats(BaseModel):
    """High-level overview numbers for the dashboard."""
    total_scans: int
    attacks_detected: int
    blocked_requests: int
    allowed_requests: int
    top_attack_type: str | None = None


class AttackDistributionItem(BaseModel):
    """One row in the attack type distribution."""
    attack_type: str
    count: int
    percentage: float


class DailyAttackCount(BaseModel):
    """Attack count for a single day."""
    date: str     # ISO format YYYY-MM-DD
    count: int
