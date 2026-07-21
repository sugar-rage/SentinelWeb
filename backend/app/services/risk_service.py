"""
Risk analysis service.

Converts a detection confidence + attack type into a risk score (0-100)
and a human-readable risk level.

Risk Level Mapping:
    0-20   → Safe
    21-40  → Low
    41-60  → Medium
    61-80  → High
    81-100 → Critical
"""

from app.core.config import settings

# Attack-type severity weights (how dangerous is this class of attack?)
_TYPE_WEIGHTS: dict[str, float] = {
    "SQL Injection": 0.95,
    "XSS": 0.85,
    "Prompt Injection": 0.75,
}

# Risk level boundaries
_RISK_LEVELS: list[tuple[int, str]] = [
    (81, "Critical"),
    (61, "High"),
    (41, "Medium"),
    (21, "Low"),
    (0,  "Safe"),
]


def calculate_risk_score(confidence: float, attack_type: str) -> int:
    """
    Compute a risk score from 0 to 100.

    Formula: score = confidence × type_weight × 100
    Clamped to [0, 100].

    Args:
        confidence:  Detection confidence (0.0 – 1.0).
        attack_type: The detected attack category.

    Returns:
        Integer risk score.
    """
    weight = _TYPE_WEIGHTS.get(attack_type, 0.70)
    raw = confidence * weight * 100
    return max(0, min(int(raw), 100))


def get_risk_level(score: int) -> str:
    """Map a numeric risk score to a human-readable level."""
    for threshold, level in _RISK_LEVELS:
        if score >= threshold:
            return level
    return "Safe"


def should_block(score: int) -> bool:
    """Return True if the score meets or exceeds the blocking threshold."""
    return score >= settings.RISK_BLOCK_THRESHOLD
