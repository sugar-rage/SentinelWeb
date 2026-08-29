"""
SQL Injection detector — rule-based.

Uses a curated set of regex patterns covering:
  - Classic tautologies          (OR 1=1, OR 'a'='a', OR ''='')
  - UNION-based injection        (UNION SELECT, UNION ALL SELECT)
  - Stacked queries              (; DROP TABLE, ; EXEC)
  - Comment-based bypass         (--, /*, #)
  - Blind / time-based injection (WAITFOR DELAY, SLEEP, BENCHMARK, PG_SLEEP)
  - Schema enumeration           (information_schema, sysobjects)
  - Authentication bypass        (admin' --, ' OR 1=1 --)
  - String manipulation          (CHAR(), CONCAT(), 0x hex literals)

Confidence is computed using indicator weighting and pattern synergy.
"""

import re
from typing import Optional
from app.security.detectors.base_detector import BaseDetector, DetectionMatch

# ────────────────────────────────────────────────────────────────
# Pattern registry: (label, compiled regex, is_high_impact)
# ────────────────────────────────────────────────────────────────
_HIGH_IMPACT_PATTERNS: list[tuple[str, re.Pattern]] = [
    # Tautologies
    ("tautology_or_1=1",      re.compile(r"\b(or|and)\s+['\"]?1['\"]?\s*=\s*['\"]?1['\"]?", re.I)),
    ("tautology_or_true",     re.compile(r"\b(or|and)\s+['\"]?([a-zA-Z0-9_]+)['\"]?\s*=\s*['\"]?\2['\"]?", re.I)),
    ("tautology_empty_str",   re.compile(r"\b(or|and)\s+['\"]{2}\s*=\s*['\"]{2}", re.I)),
    ("tautology_always_true", re.compile(r"\b(or|and)\s+(true|1\s*=\s*1)\b", re.I)),

    # UNION injection
    ("union_select",          re.compile(r"\bunion\s+(all\s+)?select\b", re.I)),

    # Authentication bypass combos
    ("auth_bypass_admin",     re.compile(r"(\badmin|\broot|\buser)'\s*(?:--|#|/\*|or\b)", re.I)),
    ("quote_tautology_combo", re.compile(r"'\s*(or|and)\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?\s*(?:--|#|/\*)?", re.I)),

    # Stacked queries / destructive
    ("drop_statement",        re.compile(r"\bdrop\s+(table|database|column|schema|view)\b", re.I)),
    ("delete_from",           re.compile(r"\bdelete\s+from\b", re.I)),
    ("insert_into",           re.compile(r"\binsert\s+into\b", re.I)),
    ("update_set",            re.compile(r"\bupdate\s+\w+\s+set\b", re.I)),
    ("alter_table",           re.compile(r"\balter\s+table\b", re.I)),
    ("truncate_table",        re.compile(r"\btruncate\s+table\b", re.I)),

    # Stacked execution
    ("semicolon_chain",       re.compile(r";\s*(select|drop|insert|update|delete|exec|alter|truncate)\b", re.I)),

    # Blind / time-based
    ("waitfor_delay",         re.compile(r"\bwaitfor\s+delay\b", re.I)),
    ("sleep_function",        re.compile(r"\b(sleep|pg_sleep)\s*\(", re.I)),
    ("benchmark_func",        re.compile(r"\bbenchmark\s*\(", re.I)),
    ("extractvalue_inject",   re.compile(r"\bextractvalue\s*\(", re.I)),

    # Schema enumeration
    ("info_schema",           re.compile(r"\binformation_schema\b", re.I)),
    ("sysobjects",            re.compile(r"\b(sysobjects|syscolumns|all_tables)\b", re.I)),
    ("sys_tables",            re.compile(r"\bsys\.\w+", re.I)),
    ("db_fingerprint",        re.compile(r"\b(version|user|current_user|database|schema)\s*\(\s*\)", re.I)),
]

_SUPPORTING_PATTERNS: list[tuple[str, re.Pattern]] = [
    # Comment / terminator abuse
    ("sql_comment_dash",      re.compile(r"--(?:[\s\r\n]|$)")),
    ("sql_comment_hash",      re.compile(r"#(?:[\s\r\n]|$)")),
    ("sql_comment_block",     re.compile(r"/\*.*?\*/", re.S)),

    # String & encoding tricks
    ("char_function",         re.compile(r"\b(char|concat|chr)\s*\(", re.I)),
    ("concat_func",           re.compile(r"\bconcat\s*\(", re.I)),
    ("hex_literal",           re.compile(r"0x[0-9a-fA-F]{4,}")),

    # Common probing & quote breakout
    ("single_quote_op",       re.compile(r"['\"]+\s*(or|and|union|select|having|group\s+by|order\s+by)\b", re.I)),
    ("exec_xp",               re.compile(r"\bexec\s+(xp_|sp_)", re.I)),
]

# Severity bands by confidence
_SEVERITY_MAP = [
    (0.85, "Critical"),
    (0.70, "High"),
    (0.50, "Medium"),
    (0.30, "Low"),
    (0.00, "Info"),
]


class SQLInjectionDetector(BaseDetector):
    """Rule-based SQL injection detector with weighted confidence scoring."""

    @property
    def name(self) -> str:
        return "sqli"

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
            # Compound lethal attack (e.g. Tautology + UNION SELECT or Tautology + Comment)
            confidence = min(0.90 + 0.04 * (len(all_matched) - 1), 1.0)
        elif len(high_matched) == 1:
            # Single definitive SQL injection structure
            confidence = 0.90
        else:
            # Only supporting/weak indicators present (e.g., isolated comments or single quotes)
            confidence = min(len(supporting_matched) * 0.20, 0.50)

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
                f"Detected {len(all_matched)} SQL injection indicator(s): "
                f"{', '.join(all_matched[:5])}."
            ),
            mitigation=(
                "Use parameterized queries (prepared statements). "
                "Validate and sanitize all user inputs. "
                "Apply the principle of least privilege to database accounts."
            ),
            matched_patterns=all_matched,
        )

