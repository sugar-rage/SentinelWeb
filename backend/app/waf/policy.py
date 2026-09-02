"""Hybrid multi-vector WAF detection and risk policy."""

import logging
from dataclasses import dataclass

from app.ml.predictor import ml_predictor
from app.schemas.detection import DetectionResult
from app.security.detection_engine import detection_engine
from app.security.detectors.base_detector import DetectionMatch
from app.services.risk_service import calculate_risk_score, get_risk_level, should_block
from app.waf.inspection import InspectionComponent

logger = logging.getLogger("sentinelweb.waf.policy")


@dataclass(frozen=True)
class WAFFinding:
    component: str
    value: str
    result: DetectionResult


@dataclass(frozen=True)
class WAFDecision:
    findings: list[WAFFinding]
    risk_score: int
    risk_level: str
    confidence: float
    blocked: bool
    base_risk_score: int | None = None
    adaptive_factors: dict[str, int] | None = None

    @property
    def attack_types(self) -> list[str]:
        return list(dict.fromkeys(
            finding.result.attack_type
            for finding in self.findings
            if finding.result.attack_type
        ))


def _rule_result(match: DetectionMatch, ml_probabilities: dict[str, float]) -> DetectionResult:
    ml_confidence = ml_probabilities.get(match.attack_type, 0.0)
    confidence = round(max(match.confidence, ml_confidence), 2)
    risk_score = calculate_risk_score(confidence, match.attack_type)
    confirmed = ml_confidence >= 0.60
    return DetectionResult(
        attack_detected=True,
        attack_type=match.attack_type,
        confidence=confidence,
        severity=match.severity,
        risk_score=risk_score,
        risk_level=get_risk_level(risk_score),
        explanation=match.explanation,
        mitigation=match.mitigation,
        detection_method="hybrid" if confirmed else "rule_based",
        ml_confidence=round(ml_confidence, 4) if confirmed else None,
        rule_confidence=match.confidence,
        matched_patterns=list(match.matched_patterns),
    )


def inspect_components(components: list[InspectionComponent]) -> WAFDecision:
    """Run every component through all rules and ML, retaining every attack vector."""
    findings: list[WAFFinding] = []
    for component in components:
        if not component.value:
            continue
        rule_matches = detection_engine.scan_all(component.value)
        try:
            ml_result = ml_predictor.predict(component.value)
        except Exception:
            logger.exception("ML inference failed during WAF inspection; using rule fallback")
            ml_result = None
        probabilities = ml_result.probabilities if ml_result and ml_result.is_available else {}
        detected_types: set[str] = set()
        for match in rule_matches:
            result = _rule_result(match, probabilities)
            findings.append(WAFFinding(component.name, component.value, result))
            detected_types.add(match.attack_type)

        if (
            ml_result
            and ml_result.is_available
            and ml_result.is_attack
            and ml_result.predicted_class not in detected_types
            and ml_result.confidence >= 0.60
            # The classifiers are trained on untrusted payload text, not route
            # names.  Applying ML-only classifications to a static proxy path
            # lets every request inherit the same weak false positive, which
            # adaptive history can eventually turn into a block.  Rule matches
            # still inspect paths, so encoded path attacks remain detectable.
            and component.name != "path"
        ):
            attack_type = ml_result.predicted_class
            confidence = round(ml_result.confidence, 2)
            if confidence >= 0.85:
                risk_score = calculate_risk_score(confidence, attack_type)
            else:
                # Match the existing scanner policy: moderate ML-only signals are
                # monitored without being allowed to approach the block threshold.
                risk_score = min(calculate_risk_score(confidence * 0.70, attack_type), 65)
            findings.append(WAFFinding(
                component.name,
                component.value,
                DetectionResult(
                    attack_detected=True,
                    attack_type=attack_type,
                    confidence=confidence,
                    severity="Critical" if confidence >= 0.85 else "Medium",
                    risk_score=risk_score,
                    risk_level=get_risk_level(risk_score),
                    explanation=f"AI/ML classifier identified a {attack_type} pattern.",
                    mitigation="Validate and isolate untrusted input before processing.",
                    detection_method="ml",
                    ml_confidence=round(ml_result.confidence, 4),
                    matched_patterns=[f"ml_{attack_type.lower().replace(' ', '_')}"]
                ),
            ))

    risk_score = max((finding.result.risk_score for finding in findings), default=0)
    confidence = max((finding.result.confidence for finding in findings), default=0.0)
    return WAFDecision(
        findings=findings,
        risk_score=risk_score,
        risk_level=get_risk_level(risk_score),
        confidence=confidence,
        blocked=should_block(risk_score),
    )
