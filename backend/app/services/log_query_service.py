"""Paginated security-history queries with bounded result sets."""

import json
import math
from datetime import datetime

from sqlalchemy import case, func
from sqlalchemy.orm import Query, Session

from app.database.models.attack_log import AttackLog
from app.database.models.request_log import RequestLog
from app.database.models.session_log import SessionLog
from app.database.models.waf_event import WAFEvent
from app.database.models.security_audit_log import SecurityAuditLog
from app.schemas.logs import (
    AttackLogItem,
    Page,
    RequestLogItem,
    SessionLogItem,
    WAFEventItem,
    SecurityAuditItem,
)


def _page(query: Query, *, page: int, page_size: int):
    total = query.order_by(None).count()
    rows = query.offset((page - 1) * page_size).limit(page_size).all()
    return rows, total, math.ceil(total / page_size) if total else 0


def list_request_logs(
    db: Session, *, page: int, page_size: int, start: datetime | None,
    end: datetime | None, method: str | None, status_code: int | None,
) -> Page[RequestLogItem]:
    query = db.query(RequestLog)
    if start: query = query.filter(RequestLog.timestamp >= start)
    if end: query = query.filter(RequestLog.timestamp <= end)
    if method: query = query.filter(RequestLog.method == method.upper())
    if status_code is not None: query = query.filter(RequestLog.status_code == status_code)
    rows, total, pages = _page(query.order_by(RequestLog.timestamp.desc()), page=page, page_size=page_size)
    return Page(
        items=[RequestLogItem(**{field: getattr(row, field) for field in RequestLogItem.model_fields}) for row in rows],
        total=total, page=page, page_size=page_size, pages=pages,
    )


def list_attack_logs(
    db: Session, *, page: int, page_size: int, start: datetime | None,
    end: datetime | None, attack_type: str | None, action: str | None,
) -> Page[AttackLogItem]:
    query = db.query(AttackLog)
    if start: query = query.filter(AttackLog.timestamp >= start)
    if end: query = query.filter(AttackLog.timestamp <= end)
    if attack_type: query = query.filter(AttackLog.attack_type == attack_type)
    if action: query = query.filter(AttackLog.action == action)
    rows, total, pages = _page(query.order_by(AttackLog.timestamp.desc()), page=page, page_size=page_size)
    return Page(
        items=[AttackLogItem(**{field: getattr(row, field) for field in AttackLogItem.model_fields}) for row in rows],
        total=total, page=page, page_size=page_size, pages=pages,
    )


def list_sessions(
    db: Session, *, page: int, page_size: int, start: datetime | None,
    end: datetime | None, status: str | None, user_id: int | None,
) -> Page[SessionLogItem]:
    query = db.query(SessionLog)
    if start: query = query.filter(SessionLog.session_start >= start)
    if end: query = query.filter(SessionLog.session_start <= end)
    if status: query = query.filter(SessionLog.session_status == status)
    if user_id is not None: query = query.filter(SessionLog.user_id == user_id)
    rows, total, pages = _page(query.order_by(SessionLog.session_start.desc()), page=page, page_size=page_size)
    session_ids = [row.id for row in rows]
    request_metrics = {}
    attack_metrics = {}
    if session_ids:
        request_metrics = {
            session_id: (count, last_activity)
            for session_id, count, last_activity in (
                db.query(RequestLog.session_id, func.count(RequestLog.id), func.max(RequestLog.timestamp))
                .filter(RequestLog.session_id.in_(session_ids))
                .group_by(RequestLog.session_id)
                .all()
            )
        }
        attack_metrics = {
            session_id: (attack_count, blocked_count, average_risk, max_risk, last_activity)
            for session_id, attack_count, blocked_count, average_risk, max_risk, last_activity in (
                db.query(
                    AttackLog.session_id,
                    func.count(AttackLog.id).filter(AttackLog.attack_detected.is_(True)),
                    func.sum(case((AttackLog.action == "blocked", 1), else_=0)),
                    func.avg(AttackLog.risk_score),
                    func.max(AttackLog.risk_score),
                    func.max(AttackLog.timestamp),
                )
                .filter(AttackLog.session_id.in_(session_ids))
                .group_by(AttackLog.session_id)
                .all()
            )
        }
    items = []
    for row in rows:
        request_count, request_activity = request_metrics.get(row.id, (0, None))
        attack_count, blocked_count, average_risk, max_risk, attack_activity = attack_metrics.get(
            row.id, (0, 0, 0, 0, None)
        )
        last_activity = max(
            value for value in (row.last_seen_at, request_activity, attack_activity) if value is not None
        )
        effective_end = row.session_end or last_activity
        duration_seconds = max(0, int((effective_end - row.session_start).total_seconds()))
        items.append(SessionLogItem(
            id=row.id,
            user_id=row.user_id,
            ip_address=row.ip_address,
            user_agent=row.user_agent,
            session_start=row.session_start,
            expires_at=row.expires_at,
            last_seen_at=row.last_seen_at,
            session_end=row.session_end,
            session_status=row.session_status,
            duration_seconds=duration_seconds,
            request_count=int(request_count or 0),
            attack_count=int(attack_count or 0),
            blocked_count=int(blocked_count or 0),
            average_risk=round(float(average_risk or 0), 2),
            max_risk=int(max_risk or 0),
            last_activity=last_activity,
        ))
    return Page(
        items=items,
        total=total, page=page, page_size=page_size, pages=pages,
    )


def list_waf_events(
    db: Session, *, page: int, page_size: int, start: datetime | None,
    end: datetime | None, action: str | None, risk_level: str | None,
) -> Page[WAFEventItem]:
    query = db.query(WAFEvent)
    if start: query = query.filter(WAFEvent.timestamp >= start)
    if end: query = query.filter(WAFEvent.timestamp <= end)
    if action: query = query.filter(WAFEvent.action == action)
    if risk_level: query = query.filter(WAFEvent.risk_level == risk_level)
    rows, total, pages = _page(query.order_by(WAFEvent.timestamp.desc()), page=page, page_size=page_size)
    items = []
    for row in rows:
        values = {field: getattr(row, field) for field in WAFEventItem.model_fields if field not in {"attack_types", "adaptive_factors"}}
        values["attack_types"] = json.loads(row.attack_types or "[]")
        values["adaptive_factors"] = json.loads(row.adaptive_factors) if row.adaptive_factors else None
        items.append(WAFEventItem(**values))
    return Page(items=items, total=total, page=page, page_size=page_size, pages=pages)


def list_security_audit_events(
    db: Session, *, page: int, page_size: int, start: datetime | None,
    end: datetime | None, event_type: str | None, outcome: str | None,
) -> Page[SecurityAuditItem]:
    query = db.query(SecurityAuditLog)
    if start: query = query.filter(SecurityAuditLog.timestamp >= start)
    if end: query = query.filter(SecurityAuditLog.timestamp <= end)
    if event_type: query = query.filter(SecurityAuditLog.event_type == event_type)
    if outcome: query = query.filter(SecurityAuditLog.outcome == outcome)
    rows, total, pages = _page(query.order_by(SecurityAuditLog.timestamp.desc()), page=page, page_size=page_size)
    return Page(
        items=[SecurityAuditItem(**{field: getattr(row, field) for field in SecurityAuditItem.model_fields}) for row in rows],
        total=total, page=page, page_size=page_size, pages=pages,
    )
