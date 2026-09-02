"""
Pydantic schemas for security report generation.
"""

from pydantic import BaseModel, Field, model_validator
from typing import List, Optional
from datetime import date, datetime


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
    correlation_id: str | None = None
    request_id: int | None = None
    waf_event_id: int | None = None
    request_component: str | None = None
    source: str = "scanner"
    detection_method: str | None = None


class WAFReportEntry(BaseModel):
    id: int
    timestamp: datetime
    correlation_id: str
    request_id: int | None
    method: str
    path: str
    risk_score: int
    risk_level: str
    action: str
    upstream_status: int | None


class SecurityReport(BaseModel):
    """Full security report for a date range."""
    generated_at: datetime
    total_events: int
    attacks_found: int
    blocked_count: int
    allowed_count: int
    entries: List[ReportEntry]
    scanner_findings: int = 0
    attack_findings: int = 0
    waf_request_count: int = 0
    waf_blocked_requests: int = 0
    waf_allowed_requests: int = 0
    waf_events: List[WAFReportEntry] = Field(default_factory=list)
    truncated: bool = False


class ReportRequest(BaseModel):
    """Request body for POST /api/reports/generate."""
    start_date: Optional[date] = None
    end_date: Optional[date] = None

    @model_validator(mode="after")
    def validate_date_range(self) -> "ReportRequest":
        if self.start_date and self.end_date and self.start_date > self.end_date:
            raise ValueError("start_date must be on or before end_date")
        return self
