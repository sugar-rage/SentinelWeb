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
    total_http_requests: int = 0
    total_security_requests: int = 0
    total_attack_findings: int = 0


class AttackDistributionItem(BaseModel):
    """One row in the attack type distribution."""
    attack_type: str
    count: int
    percentage: float


class DailyAttackCount(BaseModel):
    """Attack count for a single day."""
    date: str     # ISO format YYYY-MM-DD
    count: int


class RiskDistributionItem(BaseModel):
    """Request-level count for one risk band."""
    risk_level: str
    count: int
