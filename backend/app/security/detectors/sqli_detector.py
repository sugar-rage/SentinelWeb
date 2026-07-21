"""
SQL Injection detector — rule-based.

Uses a curated set of regex patterns covering:
  - Classic tautologies          (OR 1=1, OR 'a'='a')
  - UNION-based injection        (UNION SELECT)
  - Stacked queries              (; DROP TABLE)
  - Comment-based bypass         (--, /*, #)
  - Blind / time-based injection (WAITFOR DELAY, SLEEP, BENCHMARK)
  - Schema enumeration           (information_schema, sysobjects)
  - String manipulation          (CHAR(), CONCAT(), 0x hex literals)

Confidence is proportional to the number of distinct patterns matched.
"""

import re
from typing import Optional
from app.security.detectors.base_detector import BaseDetector, DetectionMatch

# ────────────────────────────────────────────────────────────────
# Pattern registry: (label, compiled regex)
# ────────────────────────────────────────────────────────────────
_PATTERNS: list[tuple[str, re.Pattern]] = [
    # Tautologies
    ("tautology_or_1=1",      re.compile(r"\bor\s+1\s*=\s*1", re.I)),
    ("tautology_or_true",     re.compile(r"\bor\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?", re.I)),
    ("tautology_always_true", re.compile(r"\bor\s+true\b", re.I)),

    # UNION injection
    ("union_select",   re.compile(r"\bunion\s+(all\s+)?select\b", re.I)),

    # Stacked queries / destructive
    ("drop_statement", re.compile(r"\bdrop\s+(table|database|column)\b", re.I)),
    ("delete_from",    re.compile(r"\bdelete\s+from\b", re.I)),
    ("insert_into",    re.compile(r"\binsert\s+into\b", re.I)),
    ("update_set",     re.compile(r"\bupdate\s+\w+\s+set\b", re.I)),
    ("alter_table",    re.compile(r"\balter\s+table\b", re.I)),

    # Comment / terminator abuse
    ("sql_comment_dash",  re.compile(r"--\s")),
    ("sql_comment_hash",  re.compile(r"#\s")),
    ("sql_comment_block", re.compile(r"/\*.*?\*/", re.S)),
    ("semicolon_chain",   re.compile(r";\s*(select|drop|insert|update|delete|exec)\b", re.I)),

    # Blind / time-based
    ("waitfor_delay",  re.compile(r"\bwaitfor\s+delay\b", re.I)),
    ("sleep_function", re.compile(r"\bsleep\s*\(", re.I)),
    ("benchmark_func", re.compile(r"\bbenchmark\s*\(", re.I)),

    # Schema enumeration
    ("info_schema",    re.compile(r"\binformation_schema\b", re.I)),
    ("sysobjects",     re.compile(r"\bsysobjects\b", re.I)),
    ("sys_tables",     re.compile(r"\bsys\.\w+", re.I)),

    # String tricks
    ("char_function",  re.compile(r"\bchar\s*\(", re.I)),
    ("concat_func",    re.compile(r"\bconcat\s*\(", re.I)),
    ("hex_literal",    re.compile(r"0x[0-9a-fA-F]{4,}")),

    # Common probing
    ("single_quote",   re.compile(r"'+\s*(or|and|union|select)", re.I)),
    ("exec_xp",        re.compile(r"\bexec\s+(xp_|sp_)", re.I)),
]

# Severity bands by confidence
_SEVERITY_MAP = [
    (0.9, "Critical"),
    (0.7, "High"),
    (0.5, "Medium"),
    (0.3, "Low"),
    (0.0, "Info"),
]


class SQLInjectionDetector(BaseDetector):
    """Rule-based SQL injection detector."""

    @property
    def name(self) -> str:
        return "sqli"

    def detect(self, payload: str) -> Optional[DetectionMatch]:
        matched: list[str] = []
        for label, pattern in _PATTERNS:
            if pattern.search(payload):
                matched.append(label)

        if not matched:
            return None

        # Confidence scales with the fraction of patterns triggered
        confidence = min(len(matched) / 5.0, 1.0)

        # Map confidence to a severity label
        severity = "Info"
        for threshold, level in _SEVERITY_MAP:
            if confidence >= threshold:
                severity = level
                break

        return DetectionMatch(
            attack_type="SQL Injection",
            confidence=round(confidence, 2),
            severity=severity,
            explanation=(
                f"Detected {len(matched)} SQL injection indicator(s): "
                f"{', '.join(matched[:5])}."
            ),
            mitigation=(
                "Use parameterized queries (prepared statements). "
                "Validate and sanitize all user inputs. "
                "Apply the principle of least privilege to database accounts."
            ),
            matched_patterns=matched,
        )
