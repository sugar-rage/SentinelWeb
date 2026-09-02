"""
AttackLog model — stores every detected (or scanned) attack event.

Each row represents one /scan call with its detection results,
confidence, risk score, and the action taken (blocked / allowed).
This table powers the dashboard stats and report generation.
"""

from sqlalchemy import CheckConstraint, Column, Integer, String, DateTime, Float, Text, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from app.database.database import Base
from app.utils.helpers import utc_now


class AttackLog(Base):
    __tablename__ = "attack_logs"
    __table_args__ = (
        CheckConstraint("action IN ('allowed', 'blocked')", name="ck_attack_logs_action"),
        CheckConstraint("risk_score >= 0 AND risk_score <= 100", name="ck_attack_logs_risk_score"),
    )

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)
    correlation_id = Column(String(36), nullable=True, index=True)
    request_id = Column(Integer, ForeignKey("request_logs.id", ondelete="SET NULL"), nullable=True, index=True)
    session_id = Column(Integer, ForeignKey("session_logs.id", ondelete="SET NULL"), nullable=True, index=True)
    waf_event_id = Column(Integer, ForeignKey("waf_events.id", ondelete="SET NULL"), nullable=True, index=True)
    request_component = Column(String(255), nullable=True)
    ip_address = Column(String(45), nullable=True)
    raw_payload = Column(Text, nullable=False)
    payload_sha256 = Column(String(64), nullable=True)
    payload_truncated = Column(Boolean, default=False, nullable=False)

    # Detection results
    attack_detected = Column(Boolean, default=False, index=True)
    attack_type = Column(String(50), nullable=True, index=True)
    confidence = Column(Float, default=0.0)
    severity = Column(String(20), nullable=True)
    risk_score = Column(Integer, default=0)
    risk_level = Column(String(20), default="Safe")
    explanation = Column(Text, nullable=True)
    mitigation = Column(Text, nullable=True)
    detection_method = Column(String(50), default="rule_based")

    # Action taken on the request
    action = Column(String(20), default="allowed", nullable=False, index=True)

    request = relationship("RequestLog", back_populates="attacks")
    session = relationship("SessionLog", back_populates="attacks")
    waf_event = relationship("WAFEvent", back_populates="attacks")
