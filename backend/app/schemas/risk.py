"""
Pydantic schemas for risk analysis.
"""

from pydantic import BaseModel


class RiskAssessment(BaseModel):
    """Risk analysis result attached to every scan."""
    risk_score: int       # 0-100
    risk_level: str       # Safe / Low / Medium / High / Critical
    should_block: bool    # True when score >= threshold
