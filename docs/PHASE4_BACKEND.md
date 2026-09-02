# Phase 4 backend correctness, adaptive risk, and analytics

## Adaptive risk formula

Adaptive history is applied only when the current request is detected as an attack.
Benign current traffic receives no history bonus.

Within the default 15-minute window, each prior event receives linear decay:

```text
decay = max(0, 1 - event_age / window)
```

The final request risk is:

```text
base risk
+ min(9,  3 × decayed same-type attempts)
+ min(10, 2 × decayed recent attack frequency)
+ min(8,  2 × decayed recent blocked requests)
+ min(6,  2 × decayed attacks against the same endpoint)
+ 5 when recent behavior contains multiple attack types
= adaptive risk, clamped to 0–100
```

Authenticated history is scoped to the server-side session. Public WAF history is
scoped to source IP. Different sessions and sources do not share history. Queries are
bounded by `ADAPTIVE_RISK_MAX_HISTORY` (default 200). The blocking threshold remains 80.

## Request-level analytics

Dashboard and report request decisions are grouped once per WAF event or scanner HTTP
request. A multi-vector WAF request can create multiple attack findings but counts as
one blocked request. `/api/dashboard/stats` preserves its previous fields and adds:

- `total_http_requests`
- `total_security_requests`
- `total_attack_findings`

`GET /api/dashboard/risk-distribution` is also request-level. Attack distribution
remains finding-level by design.

Reports retain JSON entries and now include scanner/WAF source, request/correlation IDs,
WAF request counts, finding counts, request-level allowed/blocked counts, and WAF events.
Returned evidence is still redacted. Report entries are capped by `REPORT_MAX_ENTRIES`;
the response sets `truncated=true` when the date range exceeds the cap.

## Roles and permissions

| Role | Permissions |
|---|---|
| user | authenticated scanning |
| developer | scanning and limited diagnostics |
| security_analyst | scanning, security history, analytics |
| admin | all analyst permissions plus user/session administration and diagnostics |

Public registration always creates `user`. Only an administrator with `manage_users`
may call `PATCH /api/auth/users/{user_id}/role`.

## Paginated history APIs

All endpoints require authentication, enforce a maximum page size of 100, and omit
passwords, JWTs, token hashes, session identifiers, and raw attack payloads.

- `GET /api/requests`
- `GET /api/attacks`
- `GET /api/sessions` (admin only)
- `GET /api/waf/events`
- `GET /api/security/events`

Reports remain administrator-only.

Date and type/action/status filters are available where appropriate.

## Isolated verification

`python test_e2e.py` derives `sentinelweb_test` (or uses `TEST_DATABASE_URL`), rejects
database names without `test`, migrates the schema, starts a private backend on port
8010, runs the original 36 checks, terminates it, and drops all generated tables.
It does not use or clean the development database.
