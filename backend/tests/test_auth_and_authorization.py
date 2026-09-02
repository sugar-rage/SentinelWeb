from datetime import datetime, timedelta, timezone

from jose import jwt

from app.core.config import settings
from app.database.models.session_log import SessionLog
from tests.conftest import auth_headers, register


def test_public_registration_forces_user_role(client):
    response = client.post(
        "/api/auth/register",
        json={
            "username": "rolecheck",
            "email": "rolecheck@example.com",
            "password": "UserSecure123!",
            "role": "admin",
        },
    )
    assert response.status_code == 201
    assert response.json()["role"] == "user"


def test_authentication_and_current_user(client, user_token):
    response = client.get("/api/auth/me", headers=auth_headers(user_token))
    assert response.status_code == 200
    assert response.json()["username"] == "user1"


def test_security_boundaries(client, user_token, admin_token):
    assert client.post("/api/scan", json={"payload": "hello"}).status_code == 401
    assert client.get("/api/dashboard/stats").status_code == 401
    assert client.post("/api/reports/generate", json={}).status_code == 401

    assert client.post("/api/scan", json={"payload": "hello"}, headers=auth_headers(user_token)).status_code == 200
    assert client.get("/api/dashboard/stats", headers=auth_headers(user_token)).status_code == 403
    assert client.post("/api/reports/generate", json={}, headers=auth_headers(user_token)).status_code == 403

    assert client.get("/api/dashboard/stats", headers=auth_headers(admin_token)).status_code == 200
    assert client.post("/api/reports/generate", json={}, headers=auth_headers(admin_token)).status_code == 200


def test_tampered_and_expired_tokens_are_rejected(client, user_token):
    assert client.post("/api/scan", json={"payload": "hello"}, headers=auth_headers("tampered.jwt.token")).status_code == 401

    expired = jwt.encode(
        {"sub": "1", "role": "user", "exp": datetime.now(timezone.utc) - timedelta(minutes=1)},
        settings.JWT_SECRET,
        algorithm=settings.JWT_ALGORITHM,
    )
    assert client.post("/api/scan", json={"payload": "hello"}, headers=auth_headers(expired)).status_code == 401


def test_login_creates_session_and_logout_revokes_token(client, db_session_factory):
    register(client, username="sessionuser", email="sessionuser@example.com")
    login_response = client.post(
        "/api/auth/login",
        json={"username": "sessionuser", "password": "UserSecure123!"},
    )
    assert login_response.status_code == 200
    token = login_response.json()["access_token"]
    session = db_session_factory()
    try:
        stored = session.query(SessionLog).one()
        assert stored.session_status == "active"
        assert stored.token_jti_hash not in token
    finally:
        session.close()

    logout = client.post("/api/auth/logout", headers=auth_headers(token))
    assert logout.status_code == 200
    assert client.get("/api/auth/me", headers=auth_headers(token)).status_code == 401

    session = db_session_factory()
    try:
        stored = session.query(SessionLog).one()
        assert stored.session_status == "logged_out"
        assert stored.session_end is not None
    finally:
        session.close()


def test_repeated_failed_logins_are_rate_limited(client):
    register(client, username="limited", email="limited@example.com")
    for _ in range(settings.AUTH_RATE_LIMIT_ATTEMPTS):
        response = client.post(
            "/api/auth/login",
            json={"username": "limited", "password": "wrong-password"},
        )
        assert response.status_code == 401
    limited = client.post(
        "/api/auth/login",
        json={"username": "limited", "password": "wrong-password"},
    )
    assert limited.status_code == 429
    assert int(limited.headers["Retry-After"]) > 0


def test_password_policy_returns_validation_error(client):
    response = client.post(
        "/api/auth/register",
        json={"username": "weakpass", "email": "weakpass@example.com", "password": "password"},
    )
    assert response.status_code == 422
    assert "password" in response.text.lower()
