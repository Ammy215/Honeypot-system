# HoneyShield Honeypot — Project Instructions

## What this is
A multi-protocol network honeypot (SSH/FTP/HTTP/Telnet) with threat-intel enrichment, detection/correlation, an AI report generator, and a Streamlit SOC dashboard. Single-operator security tool — see `README.md` for the full feature list and `docs/HOW_IT_WORKS.md` for the architecture walkthrough.

## Stack
- Python 3.13 (raw `socket`/`threading`, no async framework) — no Django/Flask/FastAPI
- SQLite via hand-written SQL (`database/db.py`, pooled `database/db_production.py` variant) — no ORM
- Streamlit + Plotly for the dashboard (`dashboard/`)
- OpenAI SDK directly (no LangChain) for the AI analyst (`honeypot/ai/`)
- `bcrypt` for password hashing, `cryptography.Fernet` for the API-key vault

## Directory layout
- `honeypot/` — `core/` (base service + server orchestrator), `services/` (SSH/FTP/HTTP/Telnet), `detectors/` (brute-force, correlation, campaigns), `intelligence/` (geolocation, AbuseIPDB, threat scoring), `alerting/`, `ai/`
- `database/` — schema, migrations, connection managers, `queries/`
- `dashboard/` — Streamlit app, `login.py`, `pages/` (numbered, one file per page)
- `auth/` — RBAC (admin/analyst/viewer), bcrypt hashing, session + lockout state
- `security/` — encrypted API key vault, audit logging
- `scripts/` — operational one-off scripts (security checks, setup wizard, DB verification) — not imported by the app, run directly
- `tests/` — integration-style smoke tests, run directly (`python tests/test_phase2.py`); not yet pytest-based
- `docs/` — deployment guide, API key setup guide, DB inspection guide, architecture explainer
- `data/`, `logs/`, `reports/` — runtime-generated, gitignored (dirs kept via `.gitkeep`)

## Running it
```bash
python -m venv .venv && .venv/Scripts/activate   # or source .venv/bin/activate on Linux/macOS
pip install -r requirements.txt
cp .env.example .env   # fill in ABUSEIPDB_API_KEY / OPENAI_API_KEY / API_KEY_ENCRYPTION_SECRET
python main.py                       # starts the honeypot listeners
streamlit run dashboard/app.py       # starts the dashboard (localhost:8501)
```
First run creates a default `admin` account and prints its one-time password to the console — it is never written to disk. Note the password immediately; there is no other way to retrieve it.

## Testing
No pytest suite yet (tracked as a follow-up phase). Current tests are standalone scripts under `tests/` — run each directly, e.g. `python tests/test_phase2.py`. `tests/test_complete_system.py` is a static environment/config health check, not a live integration test.

## Config surface
All runtime config lives in `config.py`, populated from `.env` (see `.env.example` for the full list). Ports, detection thresholds, and feature flags (`ENABLE_AUTHENTICATION`, `ENABLE_RATE_LIMITING`, `USE_PRODUCTION_DB`, etc.) are all there — check it before adding a new hardcoded constant elsewhere.

## Conventions / things to know
- Honeypot services intentionally accept raw untrusted attacker input (usernames, passwords, HTTP requests) — always log/store it via parameterized queries (`?` placeholders), never string-interpolated SQL.
- `security/api_key_manager.py` sources its Fernet encryption key from `API_KEY_ENCRYPTION_SECRET` in the environment; it only falls back to a local `security/.master_key` file for dev convenience. Never commit that file or the key value.
- `auth/users.json`, `auth/sessions.json`, `security/api_keys.enc`, `security/.master_key` are all gitignored runtime state — regenerated on first run, never checked in.
- SMTP (2525) and RDP (3389) honeypot services are defined in `config.py` but intentionally disabled — not a bug, a deliberate scope decision.
