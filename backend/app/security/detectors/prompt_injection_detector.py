"""
Prompt Injection detector — rule-based.

Targets attempts to manipulate LLM-based systems by:
  - Overriding system instructions  ("ignore previous instructions")
  - Role hijacking                  ("you are now", "act as")
  - Jailbreak phrases               ("DAN mode", "developer mode")
  - Prompt leaking                  ("show me your system prompt")
  - Instruction smuggling           ("do not follow any rules")
  - Delimiter abuse                 (###, <<<, >>>)

Useful for protecting AI-integrated APIs where user input is
forwarded to an LLM backend.
"""

import re
from typing import Optional
from app.security.detectors.base_detector import BaseDetector, DetectionMatch

# ────────────────────────────────────────────────────────────────
# Pattern registry
# ────────────────────────────────────────────────────────────────
_PATTERNS: list[tuple[str, re.Pattern]] = [
    # Instruction override
    ("ignore_previous",
     re.compile(r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?)", re.I)),
    ("disregard_instructions",
     re.compile(r"disregard\s+(all\s+)?(previous|prior|above)?\s*(instructions?|prompts?|rules?)", re.I)),
    ("forget_everything",
     re.compile(r"forget\s+(everything|all|previous)", re.I)),
    ("do_not_follow",
     re.compile(r"do\s+not\s+follow\s+(any|the|your)\s+(rules?|instructions?|guidelines?)", re.I)),
    ("override_instructions",
     re.compile(r"override\s+(your|the|all)?\s*(instructions?|rules?|guidelines?)", re.I)),

    # Role hijacking
    ("you_are_now",
     re.compile(r"you\s+are\s+now\s+(a|an|the)?\s*\w+", re.I)),
    ("act_as",
     re.compile(r"act\s+as\s+(a|an|if)?\s*", re.I)),
    ("pretend_to_be",
     re.compile(r"pretend\s+(to\s+be|you\s+are)", re.I)),
    ("roleplay_as",
     re.compile(r"roleplay\s+as\b", re.I)),

    # Jailbreak keywords
    ("dan_mode",
     re.compile(r"\bDAN\s*(mode)?\b")),
    ("developer_mode",
     re.compile(r"developer\s+mode\s+(enabled|on|activated)", re.I)),
    ("jailbreak",
     re.compile(r"\bjailbreak\b", re.I)),
    ("unrestricted_mode",
     re.compile(r"(unrestricted|unfiltered|uncensored)\s+mode", re.I)),

    # Prompt leaking
    ("show_system_prompt",
     re.compile(r"(show|reveal|display|output|print|repeat)\s+(me\s+)?(your\s+)?(system|initial|original)\s*(prompt|instructions?)", re.I)),
    ("what_is_your_prompt",
     re.compile(r"what\s+(is|are)\s+(your|the)\s+(system\s+)?(prompt|instructions?)", re.I)),

    # Delimiter abuse
    ("delimiter_hashes",
     re.compile(r"#{3,}")),
    ("delimiter_arrows",
     re.compile(r"(<<<|>>>)")),
    ("system_tag",
     re.compile(r"\[SYSTEM\]|\[INST\]|\[/INST\]", re.I)),

    # Direct injection phrases
    ("new_instructions",
     re.compile(r"(new|updated|revised)\s+instructions?\s*:", re.I)),
    ("bypass_safety",
     re.compile(r"bypass\s+(safety|content|moderation|filter)", re.I)),
]

_SEVERITY_MAP = [
    (0.9, "Critical"),
    (0.7, "High"),
    (0.5, "Medium"),
    (0.3, "Low"),
    (0.0, "Info"),
]


class PromptInjectionDetector(BaseDetector):
    """Rule-based prompt injection detector."""

    @property
    def name(self) -> str:
        return "prompt_injection"

    def detect(self, payload: str) -> Optional[DetectionMatch]:
        matched: list[str] = []
        for label, pattern in _PATTERNS:
            if pattern.search(payload):
                matched.append(label)

        if not matched:
            return None

        confidence = min(len(matched) / 3.0, 1.0)

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
                f"Detected {len(matched)} prompt injection indicator(s): "
                f"{', '.join(matched[:5])}."
            ),
            mitigation=(
                "Never pass raw user input directly to LLM system prompts. "
                "Use input/output filtering and sandwich defense patterns. "
                "Implement role-based prompt isolation."
            ),
            matched_patterns=matched,
        )
