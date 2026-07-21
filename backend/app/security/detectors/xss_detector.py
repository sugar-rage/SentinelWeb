"""
Cross-Site Scripting (XSS) detector — rule-based.

Covers:
  - Script tags                  (<script>, </script>)
  - Event handler attributes     (onerror=, onload=, onclick=, …)
  - JavaScript URI scheme        (javascript:)
  - DOM manipulation             (document.cookie, document.write)
  - Dangerous functions          (eval, alert, prompt, confirm)
  - SVG / iframe injection       (<svg onload, <iframe src)
  - CSS expression               (expression(), url('javascript:'))
  - Data URI with script         (data:text/html)
  - Encoded payloads             (&#x, %3Cscript)

Confidence is proportional to the number of distinct patterns matched.
"""

import re
from typing import Optional
from app.security.detectors.base_detector import BaseDetector, DetectionMatch

# ────────────────────────────────────────────────────────────────
# Pattern registry
# ────────────────────────────────────────────────────────────────
_PATTERNS: list[tuple[str, re.Pattern]] = [
    # Script tags
    ("script_open",      re.compile(r"<\s*script", re.I)),
    ("script_close",     re.compile(r"<\s*/\s*script\s*>", re.I)),

    # Event handlers (on*)
    ("on_error",         re.compile(r"\bon\s*error\s*=", re.I)),
    ("on_load",          re.compile(r"\bon\s*load\s*=", re.I)),
    ("on_click",         re.compile(r"\bon\s*click\s*=", re.I)),
    ("on_mouseover",     re.compile(r"\bon\s*mouseover\s*=", re.I)),
    ("on_focus",         re.compile(r"\bon\s*focus\s*=", re.I)),
    ("on_input",         re.compile(r"\bon\s*input\s*=", re.I)),

    # JavaScript URI
    ("javascript_uri",   re.compile(r"javascript\s*:", re.I)),

    # DOM access
    ("document_cookie",  re.compile(r"document\s*\.\s*cookie", re.I)),
    ("document_write",   re.compile(r"document\s*\.\s*write", re.I)),
    ("document_location",re.compile(r"document\s*\.\s*location", re.I)),
    ("window_location",  re.compile(r"window\s*\.\s*location", re.I)),
    ("inner_html",       re.compile(r"\.innerHTML\s*=", re.I)),

    # Dangerous JS functions
    ("eval_call",        re.compile(r"\beval\s*\(", re.I)),
    ("alert_call",       re.compile(r"\balert\s*\(", re.I)),
    ("prompt_call",      re.compile(r"\bprompt\s*\(", re.I)),
    ("confirm_call",     re.compile(r"\bconfirm\s*\(", re.I)),
    ("settimeout_call",  re.compile(r"\bsetTimeout\s*\(", re.I)),

    # Element injection
    ("img_tag",          re.compile(r"<\s*img\b[^>]+\bon\w+\s*=", re.I)),
    ("svg_tag",          re.compile(r"<\s*svg\b", re.I)),
    ("iframe_tag",       re.compile(r"<\s*iframe\b", re.I)),
    ("embed_tag",        re.compile(r"<\s*embed\b", re.I)),
    ("object_tag",       re.compile(r"<\s*object\b", re.I)),

    # Encoding / obfuscation
    ("html_entity_hex",  re.compile(r"&#x[0-9a-fA-F]+;?")),
    ("url_encoded",      re.compile(r"%3[Cc]\s*script", re.I)),
    ("data_uri",         re.compile(r"data\s*:\s*text/html", re.I)),

    # CSS expressions
    ("css_expression",   re.compile(r"expression\s*\(", re.I)),
]

_SEVERITY_MAP = [
    (0.9, "Critical"),
    (0.7, "High"),
    (0.5, "Medium"),
    (0.3, "Low"),
    (0.0, "Info"),
]


class XSSDetector(BaseDetector):
    """Rule-based Cross-Site Scripting detector."""

    @property
    def name(self) -> str:
        return "xss"

    def detect(self, payload: str) -> Optional[DetectionMatch]:
        matched: list[str] = []
        for label, pattern in _PATTERNS:
            if pattern.search(payload):
                matched.append(label)

        if not matched:
            return None

        confidence = min(len(matched) / 4.0, 1.0)

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
                f"Detected {len(matched)} XSS indicator(s): "
                f"{', '.join(matched[:5])}."
            ),
            mitigation=(
                "Encode all user-supplied output (HTML entity encoding). "
                "Use Content-Security-Policy headers. "
                "Sanitize inputs using a library like DOMPurify on the client side."
            ),
            matched_patterns=matched,
        )
