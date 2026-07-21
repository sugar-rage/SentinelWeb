"""
AttackLog model — stores every detected (or scanned) attack event.

Each row represents one /scan call with its detection results,
confidence, risk score, and the action taken (blocked / allowed).
This table powers the dashboard stats and report generation.
"""

from sqlalchemy import Column, Integer, String, DateTime, Float, Text, Boolean
from app.database.database import Base
from datetime import datetime


class AttackLog(Base):
    __tablename__ = "attack_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    ip_address = Column(String(45), nullable=True)
    raw_payload = Column(Text, nullable=False)

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
    action = Column(String(20), default="allowed")  # "blocked" or "allowed"
