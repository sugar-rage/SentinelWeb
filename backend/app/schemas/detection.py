"""
Pydantic schemas for the attack detection / scan endpoints.

ScanRequest  — what the client sends.
DetectionResult — the internal detection outcome.
ScanResponse — what the API returns.
"""

from pydantic import BaseModel
from typing import Optional


class ScanRequest(BaseModel):
    """Payload submitted by the client for scanning."""
    payload: str


class DetectionResult(BaseModel):
    """Result produced by the detection engine."""
    attack_detected: bool = False
    attack_type: Optional[str] = None
    confidence: float = 0.0
    severity: Optional[str] = None
    risk_score: int = 0
    risk_level: str = "Safe"
    explanation: Optional[str] = None
    mitigation: Optional[str] = None
    detection_method: Optional[str] = None


class ScanResponse(BaseModel):
    """Full response returned by POST /api/scan."""
    payload: str
    result: DetectionResult
    action: str  # "blocked" or "allowed"
