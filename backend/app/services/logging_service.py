"""
Logging service — persists HTTP request metadata to request_logs.

Called by the request_logger middleware on every inbound request.
"""

import logging

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from app.database.models.request_log import RequestLog
from app.database.models.attack_log import AttackLog
from app.database.models.waf_event import WAFEvent
from app.utils.helpers import utc_now

logger = logging.getLogger("sentinelweb.audit")


def log_request(
    db: Session,
    correlation_id: str,
    session_id: int | None,
    ip_address: str,
    method: str,
    path: str,
    status_code: int,
    process_time: float,
) -> None:
    """
    Insert one row into the request_logs table.

    Rolls back and re-raises database errors so the caller can record a
    server-side audit failure without corrupting the active session.
    """
    entry = RequestLog(
        timestamp=utc_now(),
        correlation_id=correlation_id,
        session_id=session_id,
        ip_address=ip_address[:45],
        method=method[:10],
        path=path[:500],
        status_code=status_code,
        process_time=process_time,
    )
    try:
        db.add(entry)
        db.flush()
        db.query(AttackLog).filter(
            AttackLog.correlation_id == correlation_id,
            AttackLog.request_id.is_(None),
        ).update({AttackLog.request_id: entry.id}, synchronize_session=False)
        db.query(WAFEvent).filter(
            WAFEvent.correlation_id == correlation_id,
            WAFEvent.request_id.is_(None),
        ).update({WAFEvent.request_id: entry.id}, synchronize_session=False)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        logger.exception("Failed to persist HTTP request audit record")
        raise
