"""Bounded security evidence representation and secret redaction."""

import hashlib
import re

_SENSITIVE_PATTERNS = (
    re.compile(r"(?i)(password|passwd|pwd|token|secret|authorization)\s*[:=]\s*([^\s,;&]+)"),
    re.compile(r"(?i)bearer\s+[a-z0-9._~+\-/]+=*"),
)
_SENSITIVE_FIELD_NAMES = {"password", "passwd", "pwd", "token", "secret", "authorization"}


def is_sensitive_component(name: str) -> bool:
    """Identify normalized request fields whose value must never be retained."""
    normalized = re.sub(r"\[\d+\]", "", name.lower())
    return any(segment in _SENSITIVE_FIELD_NAMES for segment in normalized.split("."))


def safe_payload_evidence(payload: str, max_chars: int) -> tuple[str, str, bool]:
    """Return a redacted bounded excerpt, full-content SHA-256, and truncation flag."""
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    redacted = payload
    for pattern in _SENSITIVE_PATTERNS:
        if pattern.pattern.lower().startswith("(?i)bearer"):
            redacted = pattern.sub("Bearer [REDACTED]", redacted)
        else:
            redacted = pattern.sub(lambda match: f"{match.group(1)}=[REDACTED]", redacted)
    truncated = len(redacted) > max_chars
    return redacted[:max_chars], digest, truncated
