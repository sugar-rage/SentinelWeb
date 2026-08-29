"""
Prompt Injection detector — rule-based.

Targets attempts to manipulate LLM-based systems by:
  - Overriding system instructions  ("ignore previous instructions", "disregard prior rules")
  - Role hijacking & jailbreaking   ("you are now DAN", "act as an unrestricted AI")
  - Safety filter bypass            ("bypass all safety filters", "disable guardrails")
  - Prompt leaking                  ("show me your system prompt", "reveal initial instructions")
  - Delimiter and tag injection     (###, <<SYS>>, [SYSTEM], <|im_start|>)

Confidence is computed using indicator weighting and pattern synergy.
"""

import re
from typing import Optional
from app.security.detectors.base_detector import BaseDetector, DetectionMatch

# ────────────────────────────────────────────────────────────────
# Pattern registry
# ────────────────────────────────────────────────────────────────
_HIGH_IMPACT_PATTERNS: list[tuple[str, re.Pattern]] = [
    # Instruction override / system reset
    ("ignore_previous",
     re.compile(r"\b(?:ignore|disregard|forget|override|bypass|discard|cancel|neglect)\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier|system|existing)?\s*(?:instructions?|prompts?|rules?|guidelines?|constraints?|directives?|commands?)\b", re.I)),
    ("do_not_follow",
     re.compile(r"\bdo\s+not\s+follow\s+(?:any|the|your|previous)\s+(?:rules?|instructions?|guidelines?|constraints?)\b", re.I)),
    ("stop_following",
     re.compile(r"\bstop\s+following\s+(?:all\s+)?(?:rules?|instructions?|guidelines?)\b", re.I)),
    ("forget_everything",
     re.compile(r"\bforget\s+(?:everything|all|all\s+instructions|prior\s+context)\b", re.I)),
    ("override_instructions",
     re.compile(r"\boverride\s+(?:your|the|all)?\s*(?:instructions?|rules?|guidelines?|safety)\b", re.I)),

    # Role hijacking & persona takeover
    ("you_are_now",
     re.compile(r"\byou\s+are\s+now\s+(?:a|an|the)?\s*[\w\s-]+\b", re.I)),
    ("act_as_persona",
     re.compile(r"\b(?:act|pretend|behave|roleplay)\s+as\s+(?:a|an|if\s+you\s+are|the)?\s*[\w\s-]+\b", re.I)),
    ("switch_mode",
     re.compile(r"\bswitch\s+to\s+[\w\s-]+(?:mode|persona)\b", re.I)),

    # Jailbreak modes & phrases
    ("dan_mode",
     re.compile(r"\b(DAN(\s*mode)?|do\s+anything\s+now)\b", re.I)),
    ("jailbreak_keyword",
     re.compile(r"\b(jailbreak|jailbroken|developer\s+mode(\s+enabled|\s+on|\s+activated)?|unrestricted\s+mode|unfiltered\s+mode|AIM\s+mode|god\s+mode)\b", re.I)),

    # Safety filter / guardrail bypass
    ("bypass_safety",
     re.compile(r"\b(?:bypass|circumvent|disable|ignore|turn\s+off)\s+(?:all\s+|any\s+)?(?:safety|content|moderation|security|filter|guardrail|policy|rules|protections?)s?\b", re.I)),

    # Prompt leaking & system extraction
    ("show_system_prompt",
     re.compile(r"\b(?:show|reveal|display|output|print|repeat|tell\s+me|expose)\s+(?:me\s+)?(?:your\s+)?(?:system|initial|original|hidden|secret|internal)?\s*(?:prompt|instructions?|rules?|directives?)\b", re.I)),

    # Delimiter and system tags
    ("system_tag",
     re.compile(r"(?:\[SYSTEM\]|\[INST\]|\[\/INST\]|<<SYS>>|<\/SYS>|<\|im_start\|>|<\|im_end\|>)", re.I)),
]

_SUPPORTING_PATTERNS: list[tuple[str, re.Pattern]] = [
    # General queries about prompt
    ("what_is_your_prompt",
     re.compile(r"\bwhat\s+(?:is|are)\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions?)\b", re.I)),

    # Delimiter abuse
    ("delimiter_hashes",
     re.compile(r"#{3,}")),
    ("delimiter_arrows",
     re.compile(r"(<<<|>>>)")),

    # Direct injection phrases
    ("new_instructions",
     re.compile(r"\b(?:new|updated|revised)\s+instructions?\s*:", re.I)),
]

_SEVERITY_MAP = [
    (0.85, "Critical"),
    (0.70, "High"),
    (0.50, "Medium"),
    (0.30, "Low"),
    (0.00, "Info"),
]


class PromptInjectionDetector(BaseDetector):
    """Rule-based prompt injection detector with weighted confidence scoring."""

    @property
    def name(self) -> str:
        return "prompt_injection"

    def detect(self, payload: str) -> Optional[DetectionMatch]:
        high_matched: list[str] = []
        supporting_matched: list[str] = []

        for label, pattern in _HIGH_IMPACT_PATTERNS:
            if pattern.search(payload):
                high_matched.append(label)

        for label, pattern in _SUPPORTING_PATTERNS:
            if pattern.search(payload):
                supporting_matched.append(label)

        all_matched = high_matched + supporting_matched
        if not all_matched:
            return None

        # Weighted confidence calculation
        if len(high_matched) >= 2 or (len(high_matched) >= 1 and len(supporting_matched) >= 1):
            # Compound injection attempt (e.g. instruction override + DAN/bypass safety)
            confidence = min(0.90 + 0.04 * (len(all_matched) - 1), 1.0)
        elif len(high_matched) == 1:
            # Single definitive prompt override or jailbreak command
            confidence = 0.90
        else:
            # Only supporting/weak indicators present
            confidence = min(len(supporting_matched) * 0.20, 0.50)

        severity = "Info"
        for threshold, level in _SEVERITY_MAP:
            if confidence >= threshold:
                severity = level
                break

        return DetectionMatch(
            attack_type="Prompt Injection",
            confidence=round(confidence, 2),
            severity=severity,
            explanation=(
                f"Detected {len(all_matched)} prompt injection indicator(s): "
                f"{', '.join(all_matched[:5])}."
            ),
            mitigation=(
                "Never pass raw user input directly to LLM system prompts. "
                "Use input/output filtering and sandwich defense patterns. "
                "Implement role-based prompt isolation."
            ),
            matched_patterns=all_matched,
        )

