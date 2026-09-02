# API Design

## 1. Overview

SentinelWeb follows a RESTful API architecture. All communication between the frontend, backend, Hybrid Detection Engine, Adaptive Risk Engine, Dashboard, and PostgreSQL database is performed through HTTP APIs.

The API is responsible for:

- Receiving incoming HTTP requests
- Passing requests to the Hybrid Detection Engine
- Calculating adaptive risk scores
- Logging requests and attacks
- Providing dashboard statistics
- Managing administrator authentication
- Generating security reports

---

# 2. API Workflow

Client

↓

POST /api/scan

↓

FastAPI Controller

↓

Hybrid Detection Engine

↓

Adaptive Risk Engine

↓

Database Service

↓

PostgreSQL

↓

Response

↓

Client

---

# 3. Endpoints

## 3.1 Analyze Request

### Endpoint

POST /api/scan

### Purpose

Analyzes an incoming request for SQL Injection, XSS, and Prompt Injection attacks.

Stores request information, calculates the adaptive risk score, and returns the final decision.

`POST /api/scan/batch` applies the same pipeline to at most 100 payloads.

### Request Body

```json
{
    "payload": "' OR 1=1 --"
}
```

### Response

```json
{
    "payload": "' OR 1=1 --",
    "result": {
        "attack_detected": true,
        "attack_type": "SQL Injection",
        "confidence": 0.97,
        "risk_score": 95,
        "risk_level": "Critical"
    },
    "action": "blocked"
}
```

---

## 3.2 Get Request Logs

### Endpoint

GET /api/requests

### Purpose

Returns all HTTP request logs stored in the system.

The result is paginated (`page`, `page_size`) and requires the
`view_security_events` permission.

---

## 3.3 Get Attack Logs

### Endpoint

GET /api/attacks

### Purpose

Returns all detected malicious requests.

The result is paginated and requires the `view_security_events` permission.

---

## 3.4 Get Session Logs

### Endpoint

GET /api/sessions

### Purpose

Returns all user session information including API calls, duration, and session risk.

The administrator-only paginated response includes persisted request/attack/blocked counts, duration,
average and maximum risk, last activity, expiry, and session status. It excludes
the session identifier and JWT digest.

Report exports are available to administrators through:

- `POST /api/reports/export/csv`
- `POST /api/reports/export/pdf`

Both accept the same optional `start_date` and `end_date` body as JSON report
generation and reuse the same bounded report query.

---

## 3.5 Dashboard Summary

### Endpoint

GET /api/dashboard/stats

### Purpose

Returns summarized statistics for the SentinelWeb dashboard.

### Example Response

```json
{
    "total_requests": 1520,
    "blocked_requests": 48,
    "sqli_attacks": 19,
    "xss_attacks": 17,
    "prompt_injection_attacks": 12,
    "active_sessions": 21,
    "high_risk_sessions": 4
}
```

---

## 3.6 Generate Security Report

### Endpoint

GET /api/reports/latest

### Purpose

Generates an all-time security report. `POST /api/reports/generate` accepts optional
`start_date` and `end_date` values for bounded date-range reports. All report endpoints
require the administrator role.

---

## 3.7 Administrator Login

### Endpoint

POST /api/auth/login

### Purpose

Authenticates a registered local user.

The endpoint authenticates any registered local role (`user`, `developer`,
`security_analyst`, or `admin`) and creates a revocable server-side session.

### Request

```json
{
    "username": "admin",
    "password": "********"
}
```

---

## 3.8 Administrator Logout

### Endpoint

POST /api/auth/logout

### Purpose

Terminates the current authenticated user's session.

Logout terminates the current authenticated user's server-side session and immediately
invalidates that JWT.

---

## 3.9 Registration, identity, and role management

- `POST /api/auth/register` creates only an unprivileged `user` account.
- `GET /api/auth/me` returns the current authenticated user's public profile.
- `PATCH /api/auth/users/{user_id}/role` is administrator-only and assigns one of
  `user`, `developer`, `security_analyst`, or `admin`.
- The initial administrator is provisioned with `scripts/bootstrap_admin.py`; there
  is no public administrator-registration endpoint.

## 3.10 WAF and security history

- `GET /api/waf/health` exposes fixed-upstream WAF health without disclosing secrets.
- `GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD /waf/{path}` is the fixed-destination
  interception path.
- `GET /api/waf/events` and `GET /api/security/events` provide permission-protected,
  paginated prevention and audit history.

---

# 4. HTTP Status Codes

| Code | Meaning |
|-------|---------|
| 200 | Request Successful |
| 201 | Resource Created |
| 400 | Bad Request |
| 401 | Unauthorized |
| 403 | Forbidden |
| 404 | Resource Not Found |
| 413 | Request Body Too Large |
| 414 | URI Too Long |
| 422 | Validation Error |
| 429 | Rate Limit Exceeded |
| 431 | Request Header Fields Too Large |
| 500 | Internal Server Error |
| 502 | Upstream Unavailable or Unsafe Response |
| 504 | Upstream Timeout |

---

# 5. Module Interaction

Frontend

↓

FastAPI API

↓

Hybrid Detection Engine

↓

Adaptive Risk Engine

↓

Database Service

↓

PostgreSQL

↓

Response

---

# 6. Security

The API implements:

- Password hashing for all local accounts
- Input validation
- SQL parameterized queries
- Request logging
- Session management
- Role-based access control (`user`, `developer`, `security_analyst`, and `admin`)

---
# API Ownership

| API | Module Responsible |
|------|--------------------|
| /api/scan | Hybrid Detection Engine |
| /api/requests | Request Logging Module |
| /api/attacks | Attack Logging Module |
| /api/sessions | Session Management Module |
| /api/dashboard/* | Dashboard Module |
| /api/reports/* | Reporting Module |
| /api/auth/* | Authentication Module |
| /waf/* | Fixed-upstream WAF Module |

---

# 7. Future APIs (Version 2)

The following APIs are reserved for future development:

- POST /api/model/retrain
- GET /api/threat-intelligence
- POST /api/settings
- GET /api/model/statistics
