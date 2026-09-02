"""Transparent time-decayed adaptive risk calculation.

Formula for a detected current request::

    adaptive = base
             + min(9,  3 * decayed same-type attempts)
             + min(10, 2 * decayed recent attack frequency)
             + min(8,  2 * decayed recent blocked requests)
             + min(6,  2 * decayed attacks on the same endpoint)
             + 5 when recent behavior spans multiple attack types

Each historical event has linear decay ``1 - age/window`` and events outside the
configured window contribute nothing. Benign current traffic receives no history
bonus, preventing prior attacks from turning ordinary requests malicious.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from app.core.config import settings
from app.database.models.attack_log import AttackLog
from app.database.models.request_log import RequestLog
from app.database.models.waf_event import WAFEvent
from app.services.risk_service import get_risk_level
from app.utils.helpers import utc_now


@dataclass(frozen=True)
class AdaptiveRiskResult:
    base_score: int
    adaptive_score: int
    risk_level: str
    factors: dict[str, int]
    history_events: int


def calculate_adaptive_risk(
    db: Session,
    *,
    base_score: int,
    attack_detected: bool,
    attack_type: str | None,
    source_ip: str,
    session_id: int | None = None,
    endpoint: str | None = None,
    now: datetime | None = None,
) -> AdaptiveRiskResult:
    """Apply bounded, identity-scoped, linearly decayed history bonuses."""
    base_score = max(0, min(int(base_score), 100))
    empty_factors = {
        "repetition": 0,
        "frequency": 0,
        "recent_blocks": 0,
        "same_endpoint": 0,
        "behavior_diversity": 0,
    }
    if not attack_detected or not attack_type:
        return AdaptiveRiskResult(base_score, base_score, get_risk_level(base_score), empty_factors, 0)

    now = now or utc_now()
    window = timedelta(minutes=settings.ADAPTIVE_RISK_WINDOW_MINUTES)
    cutoff = now - window
    query = (
        db.query(AttackLog, WAFEvent.path.label("waf_path"), RequestLog.path.label("request_path"))
        .outerjoin(WAFEvent, AttackLog.waf_event_id == WAFEvent.id)
        .outerjoin(RequestLog, AttackLog.request_id == RequestLog.id)
        .filter(
            AttackLog.attack_detected.is_(True),
            AttackLog.timestamp >= cutoff,
            AttackLog.timestamp < now,
        )
    )
    if session_id is not None:
        query = query.filter(AttackLog.session_id == session_id)
    else:
        query = query.filter(AttackLog.session_id.is_(None), AttackLog.ip_address == source_ip)

    rows = (
        query.order_by(AttackLog.timestamp.desc())
        .limit(settings.ADAPTIVE_RISK_MAX_HISTORY)
        .all()
    )
    grouped: dict[str, dict] = {}
    window_seconds = max(window.total_seconds(), 1.0)
    for log, waf_path, request_path in rows:
        timestamp = log.timestamp
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=now.tzinfo)
        decay = max(0.0, 1.0 - ((now - timestamp).total_seconds() / window_seconds))
        key = (
            f"waf:{log.waf_event_id}" if log.waf_event_id is not None
            else f"request:{log.request_id}" if log.request_id is not None
            else f"correlation:{log.correlation_id}" if log.correlation_id
            else f"legacy:{log.id}"
        )
        group = grouped.setdefault(key, {
            "decay": decay,
            "types": set(),
            "blocked": False,
            "endpoint": waf_path or request_path,
        })
        group["decay"] = max(group["decay"], decay)
        if log.attack_type:
            group["types"].add(log.attack_type)
        group["blocked"] = group["blocked"] or log.action == "blocked"

    same_type = frequency = blocked = same_endpoint = 0.0
    recent_types: set[str] = set()
    for group in grouped.values():
        decay = group["decay"]
        frequency += decay
        if attack_type in group["types"]:
            same_type += decay
        if group["blocked"]:
            blocked += decay
        if endpoint and group["endpoint"] == endpoint:
            same_endpoint += decay
        recent_types.update(group["types"])

    factors = {
        "repetition": min(9, int(round(3 * same_type))),
        "frequency": min(10, int(round(2 * frequency))),
        "recent_blocks": min(8, int(round(2 * blocked))),
        "same_endpoint": min(6, int(round(2 * same_endpoint))),
        "behavior_diversity": 5 if len(recent_types) >= 2 else 0,
    }
    adaptive_score = max(0, min(100, base_score + sum(factors.values())))
    return AdaptiveRiskResult(
        base_score=base_score,
        adaptive_score=adaptive_score,
        risk_level=get_risk_level(adaptive_score),
        factors=factors,
        history_events=len(grouped),
    )
