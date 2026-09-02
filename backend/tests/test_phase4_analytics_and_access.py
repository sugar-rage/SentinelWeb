"""Request-level analytics, corrected reports, history APIs, and role permissions."""

from datetime import date
from uuid import uuid4

from app.auth.password import hash_password
from app.database.models import Administrator, AttackLog, RequestLog, WAFEvent
from app.reports.report_generator import build_security_report
from app.services.dashboard_service import get_dashboard_stats, get_risk_distribution
from app.services.report_service import generate_report
from app.utils.helpers import utc_now
from tests.conftest import auth_headers, login


def _multi_vector_request(db_session_factory):
    db = db_session_factory()
    try:
        correlation_id = str(uuid4())
        request = RequestLog(
            timestamp=utc_now(), correlation_id=correlation_id, ip_address="127.0.0.1",
            method="GET", path="/waf/search", status_code=403, process_time=0.01,
        )
        db.add(request)
        db.flush()
        event = WAFEvent(
            timestamp=utc_now(), correlation_id=correlation_id, request_id=request.id,
            source_ip="127.0.0.1", method="GET", path="/search",
            attack_types='["SQL Injection","XSS"]', confidence=1.0,
            base_risk_score=95, adaptive_factors='{"frequency":0}',
            risk_score=95, risk_level="Critical", action="blocked",
        )
        db.add(event)
        db.flush()
        for attack_type, component in (("SQL Injection", "query.q"), ("XSS", "query.q")):
            db.add(AttackLog(
                timestamp=utc_now(), correlation_id=correlation_id, request_id=request.id,
                waf_event_id=event.id, request_component=component, ip_address="127.0.0.1",
                raw_payload="redacted", attack_detected=True, attack_type=attack_type,
                confidence=1.0, severity="Critical", risk_score=95,
                risk_level="Critical", detection_method="hybrid", action="blocked",
            ))
        db.commit()
    finally:
        db.close()


def _role_token(client, db_session_factory, role: str, suffix: str) -> str:
    db = db_session_factory()
    try:
        db.add(Administrator(
            username=f"{role}{suffix}", email=f"{role}{suffix}@example.com",
            password_hash=hash_password("RoleSecure123!"), role=role,
        ))
        db.commit()
    finally:
        db.close()
    return login(client, username=f"{role}{suffix}", password="RoleSecure123!")


def test_multi_vector_is_one_blocked_request_and_two_findings(db_session_factory):
    _multi_vector_request(db_session_factory)
    db = db_session_factory()
    try:
        stats = get_dashboard_stats(db)
        assert stats.blocked_requests == 1
        assert stats.total_attack_findings == stats.attacks_detected == 2
        assert stats.total_http_requests == 1
        assert sum(item.count for item in get_risk_distribution(db)) == 1
        report = generate_report(db)
        assert report.blocked_count == 1
        assert report.attack_findings == 2
        assert report.waf_request_count == report.waf_blocked_requests == 1
        assert {entry.source for entry in report.entries} == {"waf"}
        assert report.entries[0].correlation_id is not None
    finally:
        db.close()


def test_report_wrapper_accepts_date_objects(db_session_factory):
    _multi_vector_request(db_session_factory)
    db = db_session_factory()
    try:
        today = utc_now().date()
        report = build_security_report(db, start_date=today, end_date=today)
        assert report.waf_request_count == 1
    finally:
        db.close()


def test_security_analyst_permissions_and_session_boundary(client, db_session_factory):
    _multi_vector_request(db_session_factory)
    token = _role_token(client, db_session_factory, "security_analyst", "one")
    headers = auth_headers(token)
    assert client.get("/api/dashboard/stats", headers=headers).status_code == 200
    assert client.get("/api/reports/latest", headers=headers).status_code == 403
    assert client.get("/api/requests?page_size=1", headers=headers).status_code == 200
    attacks = client.get("/api/attacks?page_size=1", headers=headers)
    assert attacks.status_code == 200
    assert "raw_payload" not in attacks.json()["items"][0]
    assert client.get("/api/waf/events?page_size=1", headers=headers).status_code == 200
    assert client.get("/api/security/events?page_size=1", headers=headers).status_code == 200
    assert client.get("/api/sessions?page_size=1", headers=headers).status_code == 403


def test_developer_has_scan_but_not_privileged_analytics(client, db_session_factory):
    token = _role_token(client, db_session_factory, "developer", "one")
    headers = auth_headers(token)
    assert client.post("/api/scan", json={"payload": "hello"}, headers=headers).status_code == 200
    assert client.get("/api/dashboard/stats", headers=headers).status_code == 403
    assert client.get("/api/attacks", headers=headers).status_code == 403


def test_admin_paginated_sessions_and_bounds(client, admin_token):
    headers = auth_headers(admin_token)
    response = client.get("/api/sessions?page=1&page_size=1&status=active", headers=headers)
    assert response.status_code == 200
    body = response.json()
    assert body["page_size"] == 1 and len(body["items"]) <= 1
    if body["items"]:
        assert "token_jti_hash" not in body["items"][0]
        assert "session_identifier" not in body["items"][0]
    assert client.get("/api/sessions?page_size=101", headers=headers).status_code == 422


def test_history_apis_require_authentication(client):
    for path in ("/api/requests", "/api/attacks", "/api/sessions", "/api/waf/events", "/api/security/events"):
        assert client.get(path).status_code == 401


def test_public_registration_cannot_create_new_privileged_roles(client):
    response = client.post("/api/auth/register", json={
        "username": "analystrequest", "email": "analystrequest@example.com",
        "password": "UserSecure123!", "role": "security_analyst",
    })
    assert response.status_code == 201
    assert response.json()["role"] == "user"


def test_only_admin_can_assign_privileged_roles(client, admin_token, db_session_factory):
    created = client.post("/api/auth/register", json={
        "username": "rolecandidate", "email": "rolecandidate@example.com",
        "password": "UserSecure123!",
    }).json()
    analyst = _role_token(client, db_session_factory, "security_analyst", "assign")
    path = f"/api/auth/users/{created['id']}/role"
    assert client.patch(path, json={"role": "developer"}, headers=auth_headers(analyst)).status_code == 403
    changed = client.patch(path, json={"role": "developer"}, headers=auth_headers(admin_token))
    assert changed.status_code == 200
    assert changed.json()["role"] == "developer"
