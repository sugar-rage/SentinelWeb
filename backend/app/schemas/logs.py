"""Bounded, credential-free schemas for security history APIs."""

from datetime import datetime
from typing import Generic, TypeVar

from pydantic import BaseModel

T = TypeVar("T")


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int
    page: int
    page_size: int
    pages: int


class RequestLogItem(BaseModel):
    id: int
    timestamp: datetime
    correlation_id: str | None
    ip_address: str
    method: str
    path: str
    status_code: int | None
    process_time: float | None
    session_id: int | None


class AttackLogItem(BaseModel):
    id: int
    timestamp: datetime
    correlation_id: str | None
    request_id: int | None
    session_id: int | None
    waf_event_id: int | None
    request_component: str | None
    attack_type: str | None
    confidence: float
    severity: str | None
    risk_score: int
    risk_level: str
    detection_method: str | None
    action: str
    payload_sha256: str | None
    payload_truncated: bool


class SessionLogItem(BaseModel):
    id: int
    user_id: int
    ip_address: str
    user_agent: str | None
    session_start: datetime
    expires_at: datetime
    last_seen_at: datetime
    session_end: datetime | None
    session_status: str
    duration_seconds: int
    request_count: int
    attack_count: int
    blocked_count: int
    average_risk: float
    max_risk: int
    last_activity: datetime


class WAFEventItem(BaseModel):
    id: int
    timestamp: datetime
    correlation_id: str
    request_id: int | None
    source_ip: str
    method: str
    path: str
    attack_types: list[str]
    confidence: float
    base_risk_score: int
    adaptive_factors: dict[str, int] | None
    risk_score: int
    risk_level: str
    action: str
    upstream_status: int | None
    error_code: str | None


class SecurityAuditItem(BaseModel):
    id: int
    timestamp: datetime
    event_type: str
    outcome: str
    user_id: int | None
    session_id: int | None
    correlation_id: str | None
    ip_address: str | None
    details: str | None
