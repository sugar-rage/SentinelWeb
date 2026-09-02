from datetime import datetime

from app.database.models.attack_log import AttackLog
from tests.conftest import auth_headers


def _insert_event(db_session_factory, timestamp: datetime) -> None:
    session = db_session_factory()
    try:
        session.add(
            AttackLog(
                timestamp=timestamp,
                ip_address="127.0.0.1",
                raw_payload="payload",
                attack_detected=True,
                attack_type="SQL Injection",
                confidence=0.95,
                severity="Critical",
                risk_score=90,
                risk_level="Critical",
                action="blocked",
            )
        )
        session.commit()
    finally:
        session.close()


def test_valid_and_same_day_report_ranges(client, admin_token, db_session_factory):
    _insert_event(db_session_factory, datetime(2026, 8, 29, 12, 0, 0))
    headers = auth_headers(admin_token)
    valid = client.post(
        "/api/reports/generate",
        json={"start_date": "2026-08-29", "end_date": "2026-08-29"},
        headers=headers,
    )
    assert valid.status_code == 200
    assert valid.json()["total_events"] == 1


def test_invalid_and_inverted_report_dates_return_validation_errors(client, admin_token):
    headers = auth_headers(admin_token)
    invalid = client.post("/api/reports/generate", json={"start_date": "not-a-date"}, headers=headers)
    assert invalid.status_code == 422

    inverted = client.post(
        "/api/reports/generate",
        json={"start_date": "2026-08-30", "end_date": "2026-08-29"},
        headers=headers,
    )
    assert inverted.status_code == 422
    assert "start_date must be on or before end_date" in inverted.text


def test_report_boundary_date_is_inclusive(client, admin_token, db_session_factory):
    _insert_event(db_session_factory, datetime(2026, 8, 29, 23, 59, 59, 999999))
    response = client.post(
        "/api/reports/generate",
        json={"start_date": "2026-08-29", "end_date": "2026-08-29"},
        headers=auth_headers(admin_token),
    )
    assert response.status_code == 200
    assert response.json()["total_events"] == 1
