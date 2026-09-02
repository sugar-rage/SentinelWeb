"""One auditable policy/forwarding outcome for every request handled by the WAF."""

from sqlalchemy import CheckConstraint, Column, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from app.database.database import Base
from app.utils.helpers import utc_now


class WAFEvent(Base):
    __tablename__ = "waf_events"
    __table_args__ = (
        CheckConstraint("action IN ('allowed', 'blocked', 'rejected', 'error')", name="ck_waf_events_action"),
        CheckConstraint("risk_score >= 0 AND risk_score <= 100", name="ck_waf_events_risk_score"),
    )

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)
    correlation_id = Column(String(36), nullable=False, index=True)
    request_id = Column(Integer, ForeignKey("request_logs.id", ondelete="SET NULL"), nullable=True, index=True)
    source_ip = Column(String(45), nullable=False)
    method = Column(String(10), nullable=False)
    path = Column(String(500), nullable=False)
    attack_types = Column(Text, nullable=True)
    confidence = Column(Float, default=0.0, nullable=False)
    base_risk_score = Column(Integer, default=0, nullable=False)
    adaptive_factors = Column(Text, nullable=True)
    risk_score = Column(Integer, default=0, nullable=False)
    risk_level = Column(String(20), default="Safe", nullable=False)
    action = Column(String(20), nullable=False, index=True)
    upstream_status = Column(Integer, nullable=True)
    error_code = Column(String(64), nullable=True)

    request = relationship("RequestLog", back_populates="waf_events")
    attacks = relationship("AttackLog", back_populates="waf_event", passive_deletes=True)
