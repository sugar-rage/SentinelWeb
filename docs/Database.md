# Database Design

## 1. Overview

SentinelWeb uses PostgreSQL through SQLAlchemy. Alembic is the authoritative schema
manager; production databases must be upgraded with `python -m alembic upgrade head`
and are not created with `Base.metadata.create_all()`.

The current schema contains six tables:

- `administrators`
- `session_logs`
- `request_logs`
- `waf_events`
- `attack_logs`
- `security_audit_logs`

All event timestamps are timezone-aware. Frequently filtered timestamps,
correlation IDs, relationships, roles, event types, outcomes, and actions are indexed.

## 2. Tables

### 2.1 `administrators`

Stores local accounts used by the protected API and dashboard.

| Column | Purpose |
|---|---|
| `id` | Integer primary key |
| `username` | Unique login name |
| `email` | Unique email address |
| `password_hash` | bcrypt password hash; plaintext is never stored |
| `role` | `user`, `developer`, `security_analyst`, or `admin` |

### 2.2 `session_logs`

Stores revocable server-side JWT sessions. It contains `id`, `user_id`, a unique
random `session_identifier`, a unique SHA-256 `token_jti_hash`, client IP and bounded
user agent, `session_start`, `expires_at`, `last_seen_at`, optional `session_end`, and
`session_status`. Status is constrained to `active`, `logged_out`, `revoked`, or
`expired`. The raw JWT and raw JTI are never stored.

### 2.3 `request_logs`

Stores request metadata only: `id`, timestamp, optional correlation ID, client IP,
HTTP method, path, status code, processing time, and optional session relationship.
Headers, cookies, bearer tokens, and request bodies are not stored.

### 2.4 `waf_events`

Stores one prevention decision per intercepted WAF request: correlation and request
links, source IP, method, path, detected attack types, confidence, base and adaptive
risk data, final risk level/action, upstream status, and safe error code. Actions are
constrained to `allowed`, `blocked`, `rejected`, or `error` and risk is constrained to
0-100.

### 2.5 `attack_logs`

Stores scanner and per-vector WAF findings. Fields include request/session/WAF links,
correlation ID, responsible request component, client IP, redacted and bounded payload
evidence, a SHA-256 digest of the complete payload, truncation flag, attack type,
confidence, severity, base/adaptive/final risk data, explanation, mitigation,
detection method, and action. Action and risk values are database-constrained.

### 2.6 `security_audit_logs`

Stores authentication, authorization, privileged-operation, and bootstrap evidence:
event type, outcome, optional user/session/correlation/IP links, and sanitized JSON
details. Outcomes are constrained to `success`, `failure`, or `denied`.

## 3. Relationships and deletion behavior

- One administrator has many sessions; an administrator with sessions is protected by
  a restrictive foreign key.
- A session may be associated with many request, attack, and audit records.
- A request may be linked to a WAF event and multiple per-vector attack findings.
- A WAF event may be linked to multiple attack findings.
- Historical event relationships use nullable `SET NULL` foreign keys so deleting a
  related operational row does not erase security evidence.

## 4. Data boundaries

- PostgreSQL is the SentinelWeb system of record. The intentionally vulnerable testbed
  uses a separate local SQLite database and never shares SentinelWeb credentials.
- Reports and history endpoints use bounded, paginated queries.
- Sensitive authentication material and HTTP headers/bodies are excluded from request
  and audit records; stored attack evidence is redacted, truncated, and hashed.
- Schema correctness is checked with `alembic current` and `alembic check`.
