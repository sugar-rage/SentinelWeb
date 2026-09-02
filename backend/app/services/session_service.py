"""Session creation, validation, and revocation helpers."""

from datetime import timedelta
from uuid import uuid4

from sqlalchemy.orm import Session

from app.auth.jwt_handler import hash_token_identifier, new_token_identifier
from app.core.config import settings
from app.database.models.session_log import SessionLog
from app.utils.helpers import utc_now


def create_session(db: Session, *, user_id: int, ip_address: str, user_agent: str | None) -> tuple[SessionLog, str]:
    token_identifier = new_token_identifier()
    now = utc_now()
    session = SessionLog(
        user_id=user_id,
        session_identifier=uuid4().hex,
        token_jti_hash=hash_token_identifier(token_identifier),
        ip_address=ip_address,
        user_agent=(user_agent or "")[:255] or None,
        session_start=now,
        expires_at=now + timedelta(minutes=settings.JWT_EXPIRY_MINUTES),
        last_seen_at=now,
        session_status="active",
    )
    db.add(session)
    db.flush()
    return session, token_identifier


def terminate_session(session: SessionLog, status: str = "logged_out") -> None:
    session.session_status = status
    session.session_end = utc_now()


def find_active_session(db: Session, *, session_identifier: str, token_identifier: str) -> SessionLog | None:
    session = (
        db.query(SessionLog)
        .filter(
            SessionLog.session_identifier == session_identifier,
            SessionLog.token_jti_hash == hash_token_identifier(token_identifier),
        )
        .first()
    )
    if session is None or session.session_status != "active":
        return None
    now = utc_now()
    expires_at = session.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=now.tzinfo)
    if expires_at <= now:
        terminate_session(session, status="expired")
        db.commit()
        return None
    if (now - session.last_seen_at.replace(tzinfo=session.last_seen_at.tzinfo or now.tzinfo)).total_seconds() >= 60:
        session.last_seen_at = now
        db.commit()
    return session
