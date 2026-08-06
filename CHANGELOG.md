# Changelog

Condensed history of the original 6-phase build (June 2026), replacing the
individual `PHASE1_COMPLETE.md`–`PHASE6_COMPLETE.md` status logs.

## Phase 6 — AI Analyst
- OpenAI-powered attacker analysis and automated threat reports
- Natural-language alert summaries and executive summary generation
- Report export to `reports/`, AI Analysis dashboard page

## Phase 5 — Correlation Engine
- Attack campaign detection (4 campaign types)
- Behavioral correlation engine and attack-chain detection
- Similar-attacker identification, threat hunting dashboard page, IOC search

## Phase 4 — Dashboard
- Streamlit multi-page application
- Real-time attack feed with auto-refresh, interactive world map
- Attacker intelligence profiles, analytics charts, alert management, CSV export

## Phase 3 — Threat Intelligence
- IP geolocation enrichment (ip-api.com)
- AbuseIPDB reputation checks
- Weighted threat scoring (0–100, 18 factors), IOC detection, threat verdict classification

## Phase 2 — Login Trap & Detection
- FTP, Telnet, and HTTP honeypot services alongside SSH
- Credential capture, brute-force detection (9 rules), multi-service attack correlation

## Phase 1 — Foundation
- Raw TCP socket-based SSH honeypot, SQLite schema, connection logging
- Multithreaded connection handling, structured logging

## Unreleased — Cleanup & Hardening Pass
- Removed ~20 duplicated status/report markdown files; consolidated docs into `README.md` + `docs/`
- Removed unused dependencies (`fastapi`, `uvicorn`, `langchain`, `langchain-openai`); bumped stale pins
- Moved utility scripts to `scripts/`, test scripts to `tests/`
- Switched password hashing from raw PBKDF2 to bcrypt; added dashboard login lockout
- Moved the API-key vault's encryption key from a plaintext on-disk file to an environment variable
- Removed the plaintext default-credentials file and the login page's credential display
- Enforced the per-IP connection cap on honeypot listeners
- Parameterized the one remaining f-string-built SQL query
- Added `LICENSE`, project-level `CLAUDE.md`
