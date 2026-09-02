from sqlalchemy import CheckConstraint, Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from app.database.database import Base
from app.utils.helpers import utc_now

class SessionLog(Base):
    __tablename__ = "session_logs"
    __table_args__ = (
        CheckConstraint(
            "session_status IN ('active', 'logged_out', 'revoked', 'expired')",
            name="ck_session_logs_status",
        ),
    )

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("administrators.id", ondelete="RESTRICT"), nullable=False, index=True)
    session_identifier = Column(String(64), unique=True, nullable=False, index=True)
    token_jti_hash = Column(String(64), unique=True, nullable=False, index=True)
    ip_address = Column(String(45), nullable=False)
    user_agent = Column(String(255), nullable=True)
    session_start = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    last_seen_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    session_end = Column(DateTime(timezone=True), nullable=True)
    session_status = Column(String(20), default="active", nullable=False, index=True)

    user = relationship("Administrator", back_populates="sessions")
    requests = relationship("RequestLog", back_populates="session", passive_deletes=True)
    attacks = relationship("AttackLog", back_populates="session", passive_deletes=True)
    security_events = relationship("SecurityAuditLog", back_populates="session", passive_deletes=True)
