from datetime import timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import inspect, text
from sqlalchemy.exc import IntegrityError

from app.database.models.attack_log import AttackLog
from app.database.models.request_log import RequestLog
from app.database.models.security_audit_log import SecurityAuditLog
from app.database.models.session_log import SessionLog
from app.database.models.administrator import Administrator
from scripts import bootstrap_admin
from app.routes import dashboard_routes
from app.utils.helpers import utc_now
from tests.conftest import auth_headers, register


def test_alembic_migration_reached_head(test_engine):
    config = Config(str(Path(__file__).resolve().parents[1] / "alembic.ini"))
    expected_head = ScriptDirectory.from_config(config).get_current_head()
    with test_engine.connect() as connection:
        assert connection.execute(text("SELECT version_num FROM alembic_version")).scalar() == expected_head


def test_correlation_id_is_generated_and_valid_uuid(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert str(UUID(response.headers["X-Request-ID"])) == response.headers["X-Request-ID"]


def test_valid_correlation_id_is_preserved(client):
    correlation_id = str(uuid4())
    response = client.get("/health", headers={"X-Request-ID": correlation_id})
    assert response.headers["X-Request-ID"] == correlation_id


def test_scan_links_session_request_and_attack(client, user_token, db_session_factory):
    correlation_id = str(uuid4())
    response = client.post(
        "/api/scan",
        json={"payload": "1' OR '1'='1' --"},
        headers={**auth_headers(user_token), "X-Request-ID": correlation_id},
    )
    assert response.status_code == 200
    db = db_session_factory()
    try:
        request_log = db.query(RequestLog).filter(RequestLog.correlation_id == correlation_id).one()
        attack = db.query(AttackLog).filter(AttackLog.correlation_id == correlation_id).one()
        assert request_log.session_id is not None
        assert attack.session_id == request_log.session_id
        assert attack.request_id == request_log.id
        assert len(attack.payload_sha256) == 64
    finally:
        db.close()


def test_foreign_key_integrity_rejects_unknown_user(db):
    db.add(
        SessionLog(
            user_id=999999,
            session_identifier=uuid4().hex,
            token_jti_hash=uuid4().hex + uuid4().hex,
            ip_address="127.0.0.1",
            session_start=utc_now(),
            expires_at=utc_now() + timedelta(hours=1),
            last_seen_at=utc_now(),
            session_status="active",
        )
    )
    with pytest.raises(IntegrityError):
        db.commit()
    db.rollback()


def test_security_events_cover_account_login_admin_and_denial(client, admin_token, user_token, db_session_factory):
    assert client.get("/api/dashboard/stats", headers=auth_headers(user_token)).status_code == 403
    assert client.post("/api/reports/generate", json={}, headers=auth_headers(admin_token)).status_code == 200
    db = db_session_factory()
    try:
        event_types = {row[0] for row in db.query(SecurityAuditLog.event_type).all()}
        assert {"account_created", "login_success", "admin_login", "authorization_failure", "admin_access", "admin_report_generated"} <= event_types
    finally:
        db.close()


def test_password_token_and_authorization_header_never_enter_logs(client, caplog):
    password = "NeverLogThis123!"
    register_response = client.post(
        "/api/auth/register",
        json={"username": "nolog", "email": "nolog@example.com", "password": password},
    )
    assert register_response.status_code == 201
    login = client.post("/api/auth/login", json={"username": "nolog", "password": password})
    token = login.json()["access_token"]
    client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    captured = caplog.text
    assert password not in captured
    assert token not in captured
    assert f"Bearer {token}" not in captured


def test_attack_evidence_redacts_secrets_and_is_bounded(client, user_token, db_session_factory):
    payload = "password=SuperSecret123! " + ("A" * 5000)
    response = client.post("/api/scan", json={"payload": payload}, headers=auth_headers(user_token))
    assert response.status_code == 200
    db = db_session_factory()
    try:
        attack = db.query(AttackLog).one()
        assert "SuperSecret123!" not in attack.raw_payload
        assert "[REDACTED]" in attack.raw_payload
        assert len(attack.raw_payload) <= 4096
        assert attack.payload_truncated is True
    finally:
        db.close()


def test_admin_bootstrap_is_secret_gated_and_one_time(db_session_factory, monkeypatch):
    bootstrap_secret = "B" * 32
    monkeypatch.setattr(bootstrap_admin.settings, "ADMIN_BOOTSTRAP_SECRET", bootstrap_secret)
    monkeypatch.setattr(bootstrap_admin, "SessionLocal", db_session_factory)
    monkeypatch.setattr(
        bootstrap_admin.sys,
        "argv",
        ["bootstrap_admin.py", "--username", "initialadmin", "--email", "initialadmin@example.com"],
    )
    answers = iter([bootstrap_secret, "AdminSecure123!", "AdminSecure123!"])
    monkeypatch.setattr(bootstrap_admin.getpass, "getpass", lambda _prompt: next(answers))
    assert bootstrap_admin.main() == 0

    db = db_session_factory()
    try:
        admin = db.query(Administrator).filter(Administrator.username == "initialadmin").one()
        assert admin.role == "admin"
        assert db.query(SecurityAuditLog).filter(SecurityAuditLog.event_type == "admin_bootstrap").count() == 1
    finally:
        db.close()

    second_answers = iter([bootstrap_secret, "AdminSecure123!", "AdminSecure123!"])
    monkeypatch.setattr(bootstrap_admin.getpass, "getpass", lambda _prompt: next(second_answers))
    assert bootstrap_admin.main() == 5


def test_unhandled_exception_returns_generic_correlated_500_and_is_logged(
    client, admin_token, db_session_factory, monkeypatch
):
    def fail_dashboard(_db):
        raise RuntimeError("internal secret diagnostic")

    monkeypatch.setattr(dashboard_routes, "get_dashboard_stats", fail_dashboard)
    correlation_id = str(uuid4())
    response = client.get(
        "/api/dashboard/stats",
        headers={**auth_headers(admin_token), "X-Request-ID": correlation_id},
    )
    assert response.status_code == 500
    assert response.headers["X-Request-ID"] == correlation_id
    assert response.json() == {"detail": "Internal server error", "request_id": correlation_id}
    assert "internal secret diagnostic" not in response.text

    db = db_session_factory()
    try:
        request_log = db.query(RequestLog).filter(RequestLog.correlation_id == correlation_id).one()
        assert request_log.status_code == 500
    finally:
        db.close()
