## VULNEXIS

Quantum Cryptography Risk Scanner

VULNEXIS is a cybersecurity tool that identifies quantum-vulnerable cryptography and prioritizes risks before they become critical.

## Run it

```bash
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py                                          # http://127.0.0.1:5000
```

Optional environment variables: `PORT`, `HOST`, `QSHIELD_DB` (SQLite path), `FLASK_DEBUG=1`.

## Key Features

Static Scanning: Detects cryptographic usage in source code and configuration files.

Live TLS Scanning: Analyzes cryptographic algorithms used by authorized network endpoints.

Quantum Risk Analysis: Evaluates exposure to future quantum computing threats.

Smart Risk Scoring: Calculates risk scores using vulnerability, data sensitivity, confidentiality lifetime, and exposure.

Risk Prioritization: Ranks findings by severity and remediation urgency.

Migration Guidance: Recommends suitable post-quantum cryptographic alternatives.

PDF Reports: Generates detailed security findings and remediation plans.

## Tech Stack

Frontend: HTML, CSS, JavaScript

Backend: Python, Flask

Security: OpenSSL, TLS Analysis

Reporting: PDF Security Reports

## How It Works

Upload source code or enter an authorized network endpoint.

Detect cryptographic algorithms and configurations.

Analyze quantum vulnerabilities and security risks.

Calculate risk scores and prioritize findings.

Recommend migration strategies and generate reports.

## Mission

Discover. Assess. Prioritize. Migrate.

Prepare today's security infrastructure for a quantum-safe future.

## Disclaimer

For authorized security assessments and educational purposes only.
