"""
Cross-Site Scripting (XSS) detector — rule-based.

Covers:
  - Script tags                  (<script>, </script>)
  - Event handler attributes     (onerror=, onload=, onclick=, …)
  - JavaScript URI scheme        (javascript:)
  - DOM manipulation             (document.cookie, document.write)
  - Dangerous functions          (eval, alert, prompt, confirm)
  - SVG / iframe / img injection (<img onerror=, <svg onload=, <iframe src=)
  - CSS expression               (expression(), url('javascript:'))
  - Data URI with script         (data:text/html)
  - Encoded payloads             (&#x, %3Cscript)

Confidence is computed using indicator weighting and pattern synergy.
"""

import re
from typing import Optional
from app.security.detectors.base_detector import BaseDetector, DetectionMatch

# ────────────────────────────────────────────────────────────────
# Pattern registry
# ────────────────────────────────────────────────────────────────
_HIGH_IMPACT_PATTERNS: list[tuple[str, re.Pattern]] = [
    # Script tags
    ("script_open",          re.compile(r"<\s*script\b", re.I)),
    ("script_close",         re.compile(r"<\s*/\s*script\s*>", re.I)),

    # JavaScript URI
    ("javascript_uri",       re.compile(r"javascript\s*:", re.I)),

    # Element injection with event handler
    ("tag_with_event",       re.compile(r"<\s*(img|svg|iframe|embed|object|body|input|audio|video|style|link|details)\b[^>]*\bon\w+\s*=", re.I)),

    # DOM access & dangerous sinks
    ("document_cookie",      re.compile(r"document\s*\.\s*cookie", re.I)),
    ("document_write",       re.compile(r"document\s*\.\s*(write|writeln)", re.I)),
    ("document_location",    re.compile(r"(document|window)\s*\.\s*location", re.I)),

    # Dangerous JS execution functions
    ("eval_call",            re.compile(r"\beval\s*\(", re.I)),
    ("alert_call",           re.compile(r"\balert\s*\(", re.I)),
    ("prompt_call",          re.compile(r"\bprompt\s*\(", re.I)),
    ("confirm_call",         re.compile(r"\bconfirm\s*\(", re.I)),
    ("settimeout_call",      re.compile(r"\b(setTimeout|setInterval)\s*\(", re.I)),
]

_SUPPORTING_PATTERNS: list[tuple[str, re.Pattern]] = [
    # Event handlers (isolated attribute)
    ("on_error",             re.compile(r"\bon\s*error\s*=", re.I)),
    ("on_load",              re.compile(r"\bon\s*load\s*=", re.I)),
    ("on_click",             re.compile(r"\bon\s*click\s*=", re.I)),
    ("on_mouseover",         re.compile(r"\bon\s*mouseover\s*=", re.I)),
    ("on_focus",             re.compile(r"\bon\s*focus\s*=", re.I)),
    ("on_input",             re.compile(r"\bon\s*input\s*=", re.I)),

    # DOM manipulation
    ("inner_html",           re.compile(r"\.innerHTML\s*=", re.I)),

    # Standalone HTML tags
    ("svg_tag",              re.compile(r"<\s*svg\b", re.I)),
    ("iframe_tag",           re.compile(r"<\s*iframe\b", re.I)),

    # Encoding / obfuscation
    ("html_entity_hex",      re.compile(r"&#x[0-9a-fA-F]+;?")),
    ("url_encoded_script",   re.compile(r"%3[Cc]\s*script", re.I)),
    ("data_uri",             re.compile(r"data\s*:\s*text/html", re.I)),

    # CSS expressions
    ("css_expression",       re.compile(r"expression\s*\(", re.I)),
]

_SEVERITY_MAP = [
    (0.85, "Critical"),
    (0.70, "High"),
    (0.50, "Medium"),
    (0.30, "Low"),
    (0.00, "Info"),
]


class XSSDetector(BaseDetector):
    """Rule-based Cross-Site Scripting detector with weighted confidence scoring."""

    @property
    def name(self) -> str:
        return "xss"

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
            # Compound XSS payload (e.g. <script>alert(1)</script> or <img src=x onerror=alert(1)>)
            confidence = min(0.88 + 0.04 * (len(all_matched) - 1), 1.0)
        elif len(high_matched) == 1:
            # Single high-confidence XSS structure
            confidence = 0.88
        else:
            # Only supporting/isolated indicators
            confidence = min(len(supporting_matched) * 0.20, 0.50)

        severity = "Info"
        for threshold, level in _SEVERITY_MAP:
            if confidence >= threshold:
                severity = level
                break

        return DetectionMatch(
            attack_type="XSS",
            confidence=round(confidence, 2),
            severity=severity,
            explanation=(
                f"Detected {len(all_matched)} XSS indicator(s): "
                f"{', '.join(all_matched[:5])}."
            ),
            mitigation=(
                "Encode all user-supplied output (HTML entity encoding). "
                "Use Content-Security-Policy headers. "
                "Sanitize inputs using a library like DOMPurify on the client side."
            ),
            matched_patterns=all_matched,
        )

