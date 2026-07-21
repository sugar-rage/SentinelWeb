"""
Pydantic schemas for security report generation.
"""

from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime


class ReportEntry(BaseModel):
    """One attack event inside a security report."""
    id: int
    timestamp: datetime
    attack_type: str | None
    confidence: float
    severity: str | None
    risk_score: int
    risk_level: str
    explanation: str | None
    mitigation: str | None
    raw_payload: str
    action: str


class SecurityReport(BaseModel):
    """Full security report for a date range."""
    generated_at: datetime
    total_events: int
    attacks_found: int
    blocked_count: int
    allowed_count: int
    entries: List[ReportEntry]


class ReportRequest(BaseModel):
    """Request body for POST /api/reports/generate."""
    start_date: Optional[str] = None  # ISO format YYYY-MM-DD
    end_date: Optional[str] = None    # ISO format YYYY-MM-DD
