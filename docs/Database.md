# Database Design

## 1. Overview

SentinelWeb uses PostgreSQL as its primary relational database for storing request logs, attack logs, administrator information, and session data. The database is designed using normalization principles to minimize redundancy while maintaining efficient relationships between different entities.

---

# 2. Entity Relationship Overview

administrators

        │

session_logs

        │
        │
request_logs

        │
        │
attack_logs

---

# 3. Tables

## 3.1 administrators

Purpose:

Stores users authorized to access and manage the SentinelWeb dashboard.

| Column | Type | Description |
|---------|------|-------------|
| id | SERIAL | Primary Key |
| username | VARCHAR | Administrator username |
| email | VARCHAR | Email address |
| password_hash | TEXT | Encrypted password |
| role | VARCHAR | Administrator / Security Analyst |

---

## 3.2 session_logs

Purpose:

Stores information about every user session. It is used for adaptive risk analysis and session-level analytics.

| Column | Type | Description |
|---------|------|-------------|
| session_id | SERIAL | Primary Key |
| user_id | INTEGER (Nullable) | Logged-in user if available |
| ip_address | VARCHAR | Client IP |
| session_start | TIMESTAMP | Session start |
| session_end | TIMESTAMP | Session end |
| session_duration | INTEGER | Duration in seconds |
| total_api_calls | INTEGER | Total requests made |
| blocked_requests | INTEGER | Number of blocked requests |
| successful_requests | INTEGER | Number of allowed requests |
| average_risk_score | DECIMAL | Average session risk |
| max_risk_score | INTEGER | Highest observed risk |
| session_status | VARCHAR | Active / Expired / Blocked |

---

## 3.3 request_logs

Purpose:

Stores every HTTP request received by SentinelWeb.

| Column | Type | Description |
|---------|------|-------------|
| id | SERIAL | Primary Key |
| session_id | INTEGER | Foreign Key → session_logs |
| timestamp | TIMESTAMP | Request timestamp |
| ip_address | VARCHAR | Client IP |
| endpoint | VARCHAR | Requested endpoint |
| http_method | VARCHAR | GET / POST / PUT / DELETE |
| payload | TEXT | Request body |
| headers | JSONB | HTTP headers |
| request_size | INTEGER | Request size (bytes) |
| processing_time | FLOAT | Processing time (ms) |
| request_status | VARCHAR | Allowed / Blocked |

---

## 3.4 attack_logs

Purpose:

Stores information only for malicious requests detected by SentinelWeb.

| Column | Type | Description |
|---------|------|-------------|
| attack_id | SERIAL | Primary Key |
| request_id | INTEGER | Foreign Key → request_logs |
| attack_type | VARCHAR | SQLi / XSS / Prompt Injection |
| confidence_score | DECIMAL | Detection confidence |
| risk_score | INTEGER | Final adaptive risk score |
| detection_reason | TEXT | Why the attack was detected |
| action_taken | VARCHAR | Allowed / Blocked |

---

# 4. Relationships

One session can contain many requests.

One request can generate zero or one attack record.

One administrator can manage many sessions and reports.

---

# 5. Design Decisions

- Every request is stored in `request_logs`.
- Only malicious requests are stored in `attack_logs`.
- Session-level statistics are stored separately in `session_logs` to avoid duplicate data.
- PostgreSQL JSONB is used to store request headers because HTTP headers can vary between requests.
- Foreign keys are used to maintain referential integrity and reduce data redundancy.

---

# 6. Future Expansion

The database can be extended by adding tables such as:

- blocked_ips
- model_predictions
- threat_intelligence
- audit_logs

These tables are intentionally excluded from Version 1 to keep the project focused and achievable within the project timeline.