"""
Abstract base class for all attack detectors.

Every detector (SQLi, XSS, Prompt Injection) inherits from this
and implements the `detect` method.  The detection engine iterates
over all registered detectors and picks the highest-confidence match.

Design pattern: Strategy Pattern — each detector encapsulates one
detection algorithm behind a common interface.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class DetectionMatch:
    """
    Data class returned by a detector when a pattern is found.

    Attributes:
        attack_type:      Category name (sql_injection, xss, prompt_injection).
        confidence:       0.0 – 1.0 representing detection certainty.
        severity:         Info / Low / Medium / High / Critical.
        explanation:      Human-readable reason why the payload was flagged.
        mitigation:       Recommended fix or countermeasure.
        matched_patterns: List of regex/rule labels that fired.
    """
    attack_type: str
    confidence: float
    severity: str
    explanation: str
    mitigation: str
    matched_patterns: list[str] = field(default_factory=list)


class BaseDetector(ABC):
    """
    Interface that every attack detector must implement.

    Subclasses must define:
        name         — a short identifier (e.g. "sqli").
        detect(payload) — analyse the payload and return a match or None.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Short identifier for this detector."""
        ...

    @abstractmethod
    def detect(self, payload: str) -> Optional[DetectionMatch]:
        """
        Analyse *payload* for a specific attack type.

        Returns:
            A DetectionMatch if an attack is found, else None.
        """
        ...
