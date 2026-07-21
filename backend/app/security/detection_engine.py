"""
Detection Engine — orchestrates all registered detectors.

Runs the payload through every detector in sequence and returns
the result with the highest confidence.  Designed as a singleton
so detectors are instantiated once at import time.

Open/Closed Principle: to add a new detector, create a new class
inheriting BaseDetector and register it in _DETECTORS below.
"""

from typing import Optional
from app.security.detectors.base_detector import BaseDetector, DetectionMatch
from app.security.detectors.sqli_detector import SQLInjectionDetector
from app.security.detectors.xss_detector import XSSDetector
from app.security.detectors.prompt_injection_detector import PromptInjectionDetector

# ────────────────────────────────────────────────────────────────
# Registered detectors — add new ones here
# ────────────────────────────────────────────────────────────────
_DETECTORS: list[BaseDetector] = [
    SQLInjectionDetector(),
    XSSDetector(),
    PromptInjectionDetector(),
]


class DetectionEngine:
    """
    Facade that runs all detectors and picks the best match.

    Usage:
        engine = DetectionEngine()
        result = engine.scan("1' OR '1'='1")
    """

    def __init__(self, detectors: list[BaseDetector] | None = None):
        self.detectors = detectors or _DETECTORS

    def scan(self, payload: str) -> Optional[DetectionMatch]:
        """
        Run *payload* through every registered detector.

        Returns the DetectionMatch with the highest confidence,
        or None if no attack is detected.
        """
        best: Optional[DetectionMatch] = None

        for detector in self.detectors:
            match = detector.detect(payload)
            if match is not None:
                if best is None or match.confidence > best.confidence:
                    best = match

        return best

    def scan_all(self, payload: str) -> list[DetectionMatch]:
        """
        Run *payload* through every detector and return ALL matches.

        Useful for reports that need to show every type of attack
        found in a single payload.
        """
        results: list[DetectionMatch] = []
        for detector in self.detectors:
            match = detector.detect(payload)
            if match is not None:
                results.append(match)
        return results


# Module-level singleton for convenience
detection_engine = DetectionEngine()
