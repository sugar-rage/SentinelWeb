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

POST /api/requests/analyze

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

POST /api/requests/analyze

### Purpose

Analyzes an incoming request for SQL Injection, XSS, and Prompt Injection attacks.

Stores request information, calculates the adaptive risk score, and returns the final decision.

### Request Body

```json
{
    "ip_address": "192.168.1.5",
    "endpoint": "/login",
    "method": "POST",
    "headers": {},
    "payload": "' OR 1=1 --"
}
```

### Response

```json
{
    "request_id": 27,
    "attack_detected": true,
    "attack_type": "SQL Injection",
    "confidence_score": 0.97,
    "risk_score": 95,
    "decision": "Blocked"
}
```

---

## 3.2 Get Request Logs

### Endpoint

GET /api/requests

### Purpose

Returns all HTTP request logs stored in the system.

---

## 3.3 Get Attack Logs

### Endpoint

GET /api/attacks

### Purpose

Returns all detected malicious requests.

---

## 3.4 Get Session Logs

### Endpoint

GET /api/sessions

### Purpose

Returns all user session information including API calls, duration, and session risk.

---

## 3.5 Dashboard Summary

### Endpoint

GET /api/dashboard

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

GET /api/reports

### Purpose

Generates a security report containing attack statistics, request summaries, and risk analysis.

---

## 3.7 Administrator Login

### Endpoint

POST /api/auth/login

### Purpose

Authenticates an administrator or security analyst.

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

Terminates the administrator session.

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
| 500 | Internal Server Error |

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

The API will implement:

- Password hashing for administrator accounts
- Input validation
- SQL parameterized queries
- Request logging
- Session management
- Role-based access control (Administrator and Security Analyst)

---
# API Ownership

| API | Module Responsible |
|------|--------------------|
| /api/requests/analyze | Hybrid Detection Engine |
| /api/requests | Request Logging Module |
| /api/attacks | Attack Logging Module |
| /api/sessions | Session Management Module |
| /api/dashboard | Dashboard Module |
| /api/reports | Reporting Module |
| /api/auth/* | Authentication Module |

---

# 7. Future APIs (Version 2)

The following APIs are reserved for future development:

- POST /api/model/retrain
- GET /api/threat-intelligence
- POST /api/settings
- GET /api/model/statistics