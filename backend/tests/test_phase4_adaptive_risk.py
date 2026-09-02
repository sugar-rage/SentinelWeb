"""Deterministic history, identity isolation, decay, and threshold tests."""

from datetime import timedelta
from uuid import uuid4

import pytest

from app.database.models import Administrator, AttackLog, SessionLog, WAFEvent
from app.services.adaptive_risk_service import calculate_adaptive_risk
from app.services.risk_service import should_block
from app.utils.helpers import utc_now


def _session(db, username: str) -> SessionLog:
    now = utc_now()
    user = Administrator(username=username, email=f"{username}@example.com", password_hash="unused", role="user")
    db.add(user)
    db.flush()
    session = SessionLog(
        user_id=user.id, session_identifier=uuid4().hex,
        token_jti_hash=uuid4().hex + uuid4().hex, ip_address="127.0.0.1",
        session_start=now, expires_at=now + timedelta(hours=1), last_seen_at=now,
        session_status="active",
    )
    db.add(session)
    db.flush()
    return session


def _history(
    db, *, now, attack_type="SQL Injection", count=1, ip="10.0.0.1",
    session_id=None, endpoint="/login", age_minutes=1,
):
    for index in range(count):
        timestamp = now - timedelta(minutes=age_minutes, seconds=index)
        event = WAFEvent(
            timestamp=timestamp, correlation_id=str(uuid4()), source_ip=ip,
            method="GET", path=endpoint, attack_types=f'["{attack_type}"]',
            confidence=0.9, base_risk_score=86, risk_score=86,
            risk_level="Critical", action="blocked",
        )
        db.add(event)
        db.flush()
        db.add(AttackLog(
            timestamp=timestamp, correlation_id=event.correlation_id,
            session_id=session_id, waf_event_id=event.id, ip_address=ip,
            raw_payload="redacted", attack_detected=True, attack_type=attack_type,
            confidence=0.9, severity="Critical", risk_score=86,
            risk_level="Critical", detection_method="hybrid", action="blocked",
        ))
    db.commit()


def _risk(db, *, now, base=70, attack=True, attack_type="SQL Injection", ip="10.0.0.1", session_id=None, endpoint="/login"):
    return calculate_adaptive_risk(
        db, base_score=base, attack_detected=attack, attack_type=attack_type,
        source_ip=ip, session_id=session_id, endpoint=endpoint, now=now,
    )


def test_isolated_benign_request_stays_safe_even_after_attack_history(db):
    now = utc_now()
    _history(db, now=now, count=5)
    result = _risk(db, now=now, base=0, attack=False, attack_type=None)
    assert result.adaptive_score == 0
    assert sum(result.factors.values()) == 0


def test_isolated_sqli_keeps_base_risk_without_history(db):
    result = _risk(db, now=utc_now(), base=86)
    assert result.adaptive_score == result.base_score == 86


@pytest.mark.parametrize("attack_type", ["SQL Injection", "XSS", "Prompt Injection"])
def test_repeated_attack_type_increases_risk(db, attack_type):
    now = utc_now()
    _history(db, now=now, attack_type=attack_type, count=2)
    result = _risk(db, now=now, base=65, attack_type=attack_type)
    assert result.adaptive_score > 65
    assert result.factors["repetition"] > 0


def test_increasing_frequency_increases_risk(db):
    now = utc_now()
    _history(db, now=now, count=1, ip="10.0.0.1")
    _history(db, now=now, count=4, ip="10.0.0.2")
    low = _risk(db, now=now, base=60, ip="10.0.0.1")
    high = _risk(db, now=now, base=60, ip="10.0.0.2")
    assert high.adaptive_score > low.adaptive_score


def test_old_activity_decays_out_of_window(db):
    now = utc_now()
    _history(db, now=now, count=3, age_minutes=16)
    result = _risk(db, now=now, base=60)
    assert result.adaptive_score == 60
    assert result.history_events == 0


def test_different_sessions_do_not_share_history(db):
    now = utc_now()
    first = _session(db, "sessionone")
    second = _session(db, "sessiontwo")
    db.commit()
    _history(db, now=now, count=3, session_id=first.id)
    assert _risk(db, now=now, base=60, session_id=first.id).adaptive_score > 60
    assert _risk(db, now=now, base=60, session_id=second.id).adaptive_score == 60


def test_different_sources_do_not_share_history(db):
    now = utc_now()
    _history(db, now=now, count=3, ip="10.0.0.1")
    assert _risk(db, now=now, base=60, ip="10.0.0.2").adaptive_score == 60


def test_same_endpoint_and_behavior_diversity_are_bounded_factors(db):
    now = utc_now()
    _history(db, now=now, attack_type="SQL Injection", endpoint="/login")
    _history(db, now=now, attack_type="XSS", endpoint="/login")
    result = _risk(db, now=now, base=60, endpoint="/login")
    assert result.factors["same_endpoint"] > 0
    assert result.factors["behavior_diversity"] == 5


def test_risk_is_clamped_to_valid_range(db):
    now = utc_now()
    _history(db, now=now, count=20)
    assert _risk(db, now=now, base=99).adaptive_score == 100
    assert _risk(db, now=now, base=-50, attack=False, attack_type=None).adaptive_score == 0


def test_threshold_80_remains_enforced(db):
    now = utc_now()
    assert should_block(_risk(db, now=now, base=79).adaptive_score) is False
    assert should_block(_risk(db, now=now, base=80).adaptive_score) is True


def test_multi_vector_history_counts_as_one_request(db):
    now = utc_now()
    _history(db, now=now, attack_type="SQL Injection", count=1)
    event = db.query(WAFEvent).one()
    db.add(AttackLog(
        timestamp=event.timestamp, correlation_id=event.correlation_id,
        waf_event_id=event.id, ip_address=event.source_ip, raw_payload="redacted",
        attack_detected=True, attack_type="XSS", confidence=0.9,
        severity="Critical", risk_score=86, risk_level="Critical",
        detection_method="hybrid", action="blocked",
    ))
    db.commit()
    result = _risk(db, now=now, base=60)
    assert result.history_events == 1
    assert result.factors["frequency"] <= 2
