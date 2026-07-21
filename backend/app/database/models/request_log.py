"""
RequestLog model — stores every HTTP request hitting the backend.

Fields cover the request basics (IP, method, path) plus detection
results so the dashboard can query blocked vs allowed requests.
"""

from sqlalchemy import Column, Integer, String, DateTime, Float, Boolean, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.database.database import Base
from datetime import datetime


class RequestLog(Base):
    __tablename__ = "request_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    ip_address = Column(String(45), nullable=False)
    method = Column(String(10), nullable=False)
    path = Column(String(500), nullable=False)
    status_code = Column(Integer)
    process_time = Column(Float)

    # Foreign key to session_logs (optional)
    session_id = Column(Integer, ForeignKey("session_logs.id"), nullable=True)
    session = relationship("SessionLog", back_populates="requests")