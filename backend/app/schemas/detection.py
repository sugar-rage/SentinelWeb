"""
Pydantic schemas for the attack detection / scan endpoints.

ScanRequest     — what the client sends.
DetectionResult — the internal hybrid detection outcome.
ScanResponse    — what the API returns.
"""

from typing import List, Optional
from pydantic import BaseModel


class ScanRequest(BaseModel):
    """Payload submitted by the client for scanning."""
    payload: str


class DetectionResult(BaseModel):
    """Result produced by the hybrid detection engine."""
    attack_detected: bool = False
    attack_type: Optional[str] = None
    confidence: float = 0.0
    severity: Optional[str] = None
    risk_score: int = 0
    risk_level: str = "Safe"
    explanation: Optional[str] = None
    mitigation: Optional[str] = None
    detection_method: Optional[str] = None

    # Optional backward-compatible metadata
    ml_confidence: Optional[float] = None
    rule_confidence: Optional[float] = None
    matched_patterns: Optional[List[str]] = None


class ScanResponse(BaseModel):
    """Full response returned by POST /api/scan."""
    payload: str
    result: DetectionResult
    action: str  # "blocked" or "allowed"
