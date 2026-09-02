from sqlalchemy import func
from sqlalchemy.exc import SQLAlchemyError
from datetime import timedelta
from uuid import uuid4

from app.database.models.attack_log import AttackLog
from app.database.models.request_log import RequestLog
from app.database.models.session_log import SessionLog
from app.services.logging_service import log_request
from app.auth.jwt_handler import hash_token_identifier
from app.auth.password import hash_password
from app.database.models.administrator import Administrator
from app.utils.helpers import utc_now
from tests.conftest import auth_headers


def test_scan_and_request_middleware_persist_to_isolated_database(client, user_token, db_session_factory):
    response = client.post(
        "/api/scan",
        json={"payload": "1' OR '1'='1' --"},
        headers=auth_headers(user_token),
    )
    assert response.status_code == 200

    session = db_session_factory()
    try:
        assert session.query(func.count(AttackLog.id)).scalar() == 1
        assert session.query(func.count(RequestLog.id)).scalar() >= 1
        request_log = session.query(RequestLog).first()
        assert request_log.path == "/api/auth/register" or request_log.path == "/api/scan"
        assert request_log.status_code in {200, 201}
    finally:
        session.close()


def test_session_log_relationship_is_persisted(db):
    user = Administrator(username="relationship", email="relationship@example.com", password_hash=hash_password("UserSecure123!"), role="user")
    db.add(user)
    db.flush()
    token_id = uuid4().hex
    session_log = SessionLog(
        user_id=user.id,
        session_identifier=uuid4().hex,
        token_jti_hash=hash_token_identifier(token_id),
        ip_address="127.0.0.1",
        expires_at=utc_now() + timedelta(hours=1),
        session_status="active",
    )
    db.add(session_log)
    db.flush()
    db.add(
        RequestLog(
            ip_address="127.0.0.1",
            method="GET",
            path="/health",
            status_code=200,
            process_time=0.01,
            session_id=session_log.id,
        )
    )
    db.commit()
    assert db.query(SessionLog).one().requests[0].path == "/health"


def test_logging_failure_rolls_back_and_is_not_silent(db, monkeypatch):
    def fail_commit():
        raise SQLAlchemyError("database unavailable")

    monkeypatch.setattr(db, "commit", fail_commit)
    try:
        log_request(
            db,
            correlation_id=str(uuid4()),
            session_id=None,
            ip_address="127.0.0.1",
            method="GET",
            path="/health",
            status_code=200,
            process_time=0.01,
        )
    except SQLAlchemyError:
        pass
    else:
        raise AssertionError("logging failure must be propagated to middleware")
    assert db.query(RequestLog).count() == 0
