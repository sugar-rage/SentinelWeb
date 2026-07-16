## 1. Objective

Build an AI powered web security framework.

## 2. Scope

## Features

- SQL injection Detection
- XSS (Cross-site Scripting Detection)
- Prompt Injection Detection
- Hybrid Detection Engine (Rule-based + ML)
- Adaptive risk scoring
- Security Dashboard
- Security Reports
- Request Blocking
- Vulnerable Test Website

## OUT OF SCOPE

- Distributed deployment
- Cloud scalability
- DDoS mitigation
- Malware detection
- Authentication systems
- Production WAF replacement

---

## 3. Attacks

- SQL Injection (SQLi)
- XSS (Cross-Site Scripting)
- Prompt injection

---

## 4. System Modules

### 4.1 Interceptor

Captures every incoming HTTP request before it reaches the target application.

---

### 4.2 Detection Engine

Analyzes requests using both rule-based techniques and machine learning models.

Submodules:

- SQLi Detector
- XSS Detector
- Prompt Injection Detector

---

### 4.3 Hybrid Decision Engine

Combines rule-based confidence and machine learning confidence to determine whether a request is malicious.

---

### 4.4 Adaptive Risk Engine

Calculates a dynamic risk score based on attack severity, attack frequency, repeated attempts, and behavioral patterns.

---

### 4.5 Logging System

Stores attack logs, request history, and system events for future analysis.

---

### 4.6 Dashboard

Displays attack statistics, threat summaries, risk levels, logs, and security reports.

---

### 4.7 Vulnerable Test Website

A deliberately vulnerable web application used to simulate cyber attacks and evaluate SentinelWeb.

---


## 5. USER ROLES

Adminstrator

Security Analyst

Developer

## 6. Technology Stack

Backend

- FastAPI

Frontend

- React

Machine Learning

- Scikit-learn

Database

- PostgreSQL


Version Control

- Git
- GitHub

---

## 7. Success Criteria

The project will be considered successful if it:

- Detects SQL Injection attacks.
- Detects Cross-Site Scripting attacks.
- Detects Prompt Injection attacks.
- Assigns adaptive risk scores.
- Blocks malicious requests.
- Stores attack logs.
- Generates security reports.
- Displays attack statistics through a dashboard.
