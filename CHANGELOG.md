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

## 2026-08-13 — Option A: Constrained PaaS Deployment
- Pivoted deployment from a self-hosted VPS to a free, no-card PaaS (Koyeb) running the HTTP honeypot only; SSH/FTP/Telnet stay built and tested but undeployed — see README "Future Work"
- Added forwarded-header client IP resolution (`honeypot/core/client_ip.py`): the trusted entry is counted from the right, since proxies append and a naive first-entry read would trust an attacker-forged `X-Forwarded-For`; the raw header is stored alongside the resolved IP as evidence
- Added `$PORT` binding for the platform-injected port, `ENABLED_SERVICES` to gate which listeners start, and `IGNORE_UNFORWARDED_CONNECTIONS` to filter platform health-check probes out of captured data
- Hardened the production database: least-privilege grants (`SELECT`/`INSERT`/`UPDATE` only, no DDL), Row Level Security on all 9 tables as defense-in-depth behind those grants, and closed Supabase's default REST API exposure (`anon`/`authenticated` revoked from the schema) — verified with a real anon key returning `permission denied`, not data
- Split database access into three roles instead of one shared credential: `honeyshield_app` (the internet-facing honeypot process, no access to `admin_users`), `honeyshield_dashboard` (local-only, scoped to exactly what dashboard pages read/write), and the DB owner (admin/migration tasks only) — so a compromise of the deployed process can't reach admin credentials or destroy captured data
- Rotated production AbuseIPDB and Gemini API keys, separate from dev, both live-verified; left AlienVault OTX out of production deliberately, since it issues one account-wide key with no per-project scoping, and keeping it dev-only avoids widening that credential's blast radius to other, unrelated projects
- Added a pre-commit hook blocking key-shaped strings in staged commits, plus GitHub secret scanning and push protection as the non-bypassable server-side backstop
- Pushed the full repository history to GitHub for the first time

## 2026-08-14 — Hosting Pivot: Koyeb → Render
- Discovered Koyeb's free Starter tier closed to new signups following its acquisition by Mistral AI (Feb 2026); Koyeb's own docs now state a credit card is required for new-account verification, which fails the project's no-card constraint regardless of never being charged
- Researched Render as the replacement against Render's own primary docs rather than aggregator summaries, learning directly from the Koyeb miss: confirmed no stated card requirement (one unverified conflicting report noted, not dismissed), 750 free instance-hours/month, TCP health checks by default (unlike Koyeb, which defaulted to HTTP and needed a manual override), and that Render does not auto-inject `$PORT` — the opposite of Koyeb, requiring it to be set explicitly
- Flagged as genuinely unverified rather than assumed: Render's `X-Forwarded-For` hop count. Anecdotal evidence (a Render community thread, not official docs) suggests two appending proxy hops, not Koyeb's one — `docs/RENDER.md` starts with `TRUSTED_PROXY_HOPS=2` as a best guess and requires live confirmation before trusting captured IPs, with an explicit instruction to watch for a payment prompt at both account signup and instance-type selection before proceeding
- Renamed `docs/KOYEB.md` to `docs/RENDER.md` and rewrote it for the new platform; updated cross-references in `database/grants_dashboard.sql` and `docs/SECRETS.md`. This entry is additive — the prior Koyeb-pivot entry above is left as accurate history, not rewritten
