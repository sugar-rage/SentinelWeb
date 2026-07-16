## Work flow

Client Request
        |
        V
Hybrid Detection Engine
        |
        V
Adaptive Risk Engine
        |
        V
Decision Engine
    |       |
    V       V
    Allow   Block
    |       |
    V       V
    Target  Attack log
    Website
    |       |
    ---------
        |
        V
        Dashboard & reports

---

# Core Modules

### 3.1 Hybrid Detection Engine

Purpose:
Inspect every incoming request and detect possible attacks.

Submodules:

- SQL Injection Detector
- Cross-Site Scripting Detector
- Prompt Injection Detector

Input:

HTTP Request

Output:

Attack Type

Confidence Score

Detection Reason

---

### 3.2 Adaptive Risk Engine

Purpose:

Calculate the overall threat level of a request.

Factors:

- Attack Severity
- Detection Confidence
- Previous Attempts
- Repeated Requests
- Attack Frequency

Output:

Risk Score (0–100)

Risk Level

Low

Medium

High

Critical

---

### 3.3 Decision Engine

Purpose:

Determine whether the request should be

- Allowed
- Blocked
- Logged

Output:

Final Decision

---

### 3.4 Logging Module

Purpose:

Store every detected attack.

Stores

- Timestamp
- IP Address
- Request
- Attack Type
- Risk Score
- Decision

---

### 3.5 Dashboard

Purpose:

Provide administrators with a visual overview.

Displays

- Total Requests
- Blocked Requests
- SQLi Attacks
- XSS Attacks
- Prompt Injection Attacks
- Risk Distribution
- Recent Logs

---

### 3.6 Vulnerable Test Website

Purpose:

Generate realistic attacks for testing SentinelWeb.

Contains

- Login
- Search
- Contact
- Chatbot
- Admin

---
