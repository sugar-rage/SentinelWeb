"""Security-relevant audit events without credentials, tokens, or raw payloads."""

from sqlalchemy import CheckConstraint, Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from app.database.database import Base
from app.utils.helpers import utc_now


class SecurityAuditLog(Base):
    __tablename__ = "security_audit_logs"
    __table_args__ = (
        CheckConstraint("outcome IN ('success', 'failure', 'denied')", name="ck_security_audit_outcome"),
    )

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)
    event_type = Column(String(64), nullable=False, index=True)
    outcome = Column(String(16), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("administrators.id", ondelete="SET NULL"), nullable=True, index=True)
    session_id = Column(Integer, ForeignKey("session_logs.id", ondelete="SET NULL"), nullable=True, index=True)
    correlation_id = Column(String(36), nullable=True, index=True)
    ip_address = Column(String(45), nullable=True)
    details = Column(Text, nullable=True)

    user = relationship("Administrator", back_populates="security_events")
    session = relationship("SessionLog", back_populates="security_events")
