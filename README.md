
# Security Log Analysis & Threat Detection

A Python-based security monitoring pipeline that analyzes 1,500
synthetic authentication events, identifies potential brute-force
attacks, and generates structured security alerts.

## Tech Stack

Python | CSV | pytest | GitHub Actions

## Features

- Generates 1,500 reproducible synthetic authentication events
- Simulates repeated failed login attempts against an admin account
- Detects 5 or more failed logins from one IP within 5 minutes
- Uses sliding time windows to identify suspicious activity
- Generates CSV security alerts with HIGH severity classifications
- Includes 5 automated tests for detection accuracy
- Runs tests automatically through GitHub Actions CI

## Pipeline Architecture

Authentication Logs (CSV)
        |
        v
Chronological Event Processing
        |
        v
Sliding-Window Threat Detection
        |
        v
Security Alert Classification
        |
        v
CSV Security Alert Report

## Getting Started

Requires Python 3.9+.

Clone the repository:

    git clone https://github.com/Rith-Ven/security-log-threat-detection.git
    cd security-log-threat-detection

Generate authentication logs:

    python3 generate_logs.py

Run threat detection:

    python3 detect_threats.py

Run automated tests:

    python3 -m pip install pytest
    python3 -m pytest -q

## Project Structure

    security-log-threat-detection/
    ├── .github/workflows/tests.yml
    ├── data/auth_logs.csv
    ├── reports/security_alerts.csv
    ├── tests/test_detection.py
    ├── generate_logs.py
    ├── detect_threats.py
    ├── README.md
    └── .gitignore

## Security Considerations

All authentication events are synthetic, and IP addresses use
reserved documentation ranges.

Detection thresholds are illustrative and may produce false
positives in real-world environments. This project is a
rule-based security monitoring prototype, not a production SIEM.
