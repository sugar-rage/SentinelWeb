"""Structured privileged/security event auditing without sensitive values."""

import json
import logging
from typing import Any

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.database.models.security_audit_log import SecurityAuditLog
from app.utils.helpers import utc_now

logger = logging.getLogger("sentinelweb.security_audit")


def add_security_event(
    db: Session,
    *,
    event_type: str,
    outcome: str,
    user_id: int | None = None,
    session_id: int | None = None,
    correlation_id: str | None = None,
    ip_address: str | None = None,
    details: dict[str, Any] | None = None,
) -> SecurityAuditLog:
    """Stage a sanitized event in the caller's transaction."""
    event = SecurityAuditLog(
        timestamp=utc_now(),
        event_type=event_type,
        outcome=outcome,
        user_id=user_id,
        session_id=session_id,
        correlation_id=correlation_id,
        ip_address=ip_address,
        details=json.dumps(details, separators=(",", ":"), sort_keys=True) if details else None,
    )
    db.add(event)
    return event


def record_security_event(db: Session, **kwargs) -> None:
    """Persist one event, rolling back and surfacing audit-store failures."""
    try:
        add_security_event(db, **kwargs)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        logger.exception("Failed to persist security audit event %s", kwargs.get("event_type"))
        raise
