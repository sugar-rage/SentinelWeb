"""SRS-required paginated request, attack, session, and WAF history APIs."""

from datetime import datetime

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.auth.dependencies import require_permission
from app.database.database import get_db
from app.database.models.administrator import Administrator
from app.schemas.logs import AttackLogItem, Page, RequestLogItem, SecurityAuditItem, SessionLogItem, WAFEventItem
from app.services.log_query_service import list_attack_logs, list_request_logs, list_security_audit_events, list_sessions, list_waf_events

router = APIRouter(tags=["Security History"])
view_security = require_permission("view_security_events")
manage_sessions = require_permission("manage_sessions")


@router.get("/api/requests", response_model=Page[RequestLogItem])
def requests(
    page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=100),
    start: datetime | None = None, end: datetime | None = None,
    method: str | None = Query(None, max_length=10), status_code: int | None = Query(None, ge=100, le=599),
    db: Session = Depends(get_db), _: Administrator = Depends(view_security),
):
    return list_request_logs(db, page=page, page_size=page_size, start=start, end=end, method=method, status_code=status_code)


@router.get("/api/attacks", response_model=Page[AttackLogItem])
def attacks(
    page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=100),
    start: datetime | None = None, end: datetime | None = None,
    attack_type: str | None = Query(None, max_length=50), action: str | None = Query(None, pattern="^(allowed|blocked)$"),
    db: Session = Depends(get_db), _: Administrator = Depends(view_security),
):
    return list_attack_logs(db, page=page, page_size=page_size, start=start, end=end, attack_type=attack_type, action=action)


@router.get("/api/sessions", response_model=Page[SessionLogItem])
def sessions(
    page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=100),
    start: datetime | None = None, end: datetime | None = None,
    status: str | None = Query(None, pattern="^(active|logged_out|revoked|expired)$"), user_id: int | None = Query(None, ge=1),
    db: Session = Depends(get_db), _: Administrator = Depends(manage_sessions),
):
    return list_sessions(db, page=page, page_size=page_size, start=start, end=end, status=status, user_id=user_id)


@router.get("/api/waf/events", response_model=Page[WAFEventItem])
def waf_events(
    page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=100),
    start: datetime | None = None, end: datetime | None = None,
    action: str | None = Query(None, pattern="^(allowed|blocked|rejected|error)$"),
    risk_level: str | None = Query(None, pattern="^(Safe|Low|Medium|High|Critical)$"),
    db: Session = Depends(get_db), _: Administrator = Depends(view_security),
):
    return list_waf_events(db, page=page, page_size=page_size, start=start, end=end, action=action, risk_level=risk_level)


@router.get("/api/security/events", response_model=Page[SecurityAuditItem])
def security_events(
    page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=100),
    start: datetime | None = None, end: datetime | None = None,
    event_type: str | None = Query(None, max_length=64),
    outcome: str | None = Query(None, pattern="^(success|failure|denied)$"),
    db: Session = Depends(get_db), _: Administrator = Depends(view_security),
):
    return list_security_audit_events(
        db, page=page, page_size=page_size, start=start, end=end,
        event_type=event_type, outcome=outcome,
    )
