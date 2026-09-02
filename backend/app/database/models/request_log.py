"""
RequestLog model — stores every HTTP request hitting the backend.

Fields cover the request basics (IP, method, path) plus detection
results so the dashboard can query blocked vs allowed requests.
"""

from sqlalchemy import Column, Integer, String, DateTime, Float, ForeignKey
from sqlalchemy.orm import relationship
from app.database.database import Base
from app.utils.helpers import utc_now


class RequestLog(Base):
    __tablename__ = "request_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)
    correlation_id = Column(String(36), nullable=True, index=True)
    ip_address = Column(String(45), nullable=False)
    method = Column(String(10), nullable=False)
    path = Column(String(500), nullable=False)
    status_code = Column(Integer)
    process_time = Column(Float)

    # Foreign key to session_logs (optional)
    session_id = Column(Integer, ForeignKey("session_logs.id", ondelete="SET NULL"), nullable=True, index=True)
    session = relationship("SessionLog", back_populates="requests")
    attacks = relationship("AttackLog", back_populates="request", passive_deletes=True)
    waf_events = relationship("WAFEvent", back_populates="request", passive_deletes=True)
