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

## 2026-08-22 — OTX enrichment restored in production
- Created a **dedicated AlienVault OTX account** for this project, resolving the constraint that previously kept OTX out of production. OTX issues one key per account, so the old key was shared with unrelated projects and deploying it would have widened its blast radius past this honeypot — the only remedy OTX's model allows is a separate account, not a second key
- `OTX_API_KEY` is now set in production, restoring pulse-match enrichment and the `otx_pulse_match` scoring factor (weight 15 of 100), which previously could never fire there
- The old shared key was deliberately left in place on the original account rather than regenerated — regenerating would have silently invalidated it for every other project using it
- Verified live before deploying, through the app's own `async_otx.py` client: `/user/me` authenticates, and pulse lookups returned real counts (50, 26 and 5) across three known-flagged IPs
- Updated `docs/SECRETS.md` §2 and `docs/RENDER.md` §4, which both documented the exclusion; fixed two stale `docs/KOYEB.md` references in `.env` left over from the hosting pivot

## 2026-08-14 — Hosting Pivot: Koyeb → Render
- Discovered Koyeb's free Starter tier closed to new signups following its acquisition by Mistral AI (Feb 2026); Koyeb's own docs now state a credit card is required for new-account verification, which fails the project's no-card constraint regardless of never being charged
- Researched Render as the replacement against Render's own primary docs rather than aggregator summaries, learning directly from the Koyeb miss: confirmed no stated card requirement (one unverified conflicting report noted, not dismissed), 750 free instance-hours/month, TCP health checks by default (unlike Koyeb, which defaulted to HTTP and needed a manual override), and that Render does not auto-inject `$PORT` — the opposite of Koyeb, requiring it to be set explicitly
- Flagged as genuinely unverified rather than assumed: Render's `X-Forwarded-For` hop count. Anecdotal evidence (a Render community thread, not official docs) suggests two appending proxy hops, not Koyeb's one — `docs/RENDER.md` starts with `TRUSTED_PROXY_HOPS=2` as a best guess and requires live confirmation before trusting captured IPs, with an explicit instruction to watch for a payment prompt at both account signup and instance-type selection before proceeding
- Renamed `docs/KOYEB.md` to `docs/RENDER.md` and rewrote it for the new platform; updated cross-references in `database/grants_dashboard.sql` and `docs/SECRETS.md`. This entry is additive — the prior Koyeb-pivot entry above is left as accurate history, not rewritten

## 2026-09-05 — Live deployment: proxy hops confirmed, noise filtered, dashboard fixed
- **`TRUSTED_PROXY_HOPS` was wrong in production and is now confirmed correct.** The documented starting value of `2` was a guess taken from a community thread; §5 against the live service showed a three-segment chain (`client, Cloudflare edge, Render internal LB` — Render fronts with Cloudflare). At `2`, both plain and spoofed requests resolved to the Cloudflare edge: the safe direction, never the attacker's forged value, but data that collapsed every attacker onto one address. At `3`, verified across two controlled requests and multiple organic hits, the real client resolves correctly and an injected `X-Forwarded-For: 1.2.3.4` is stored only as evidence in `forwarded_for_raw`
- Enabled `IGNORE_UNFORWARDED_CONNECTIONS` **after** §5 passed, not before — the platform health check was arriving ~14×/minute and had been recorded as an attacker with a rising threat score. It now writes to `filtered_connections` instead, and `honeyshield_dashboard` gained `SELECT` (plus a matching RLS policy) on that table so filtered volume is visible from the Live Feed rather than needing a script
- Deleted data captured under the wrong hop count: 4 connections resolved to Cloudflare edge addresses, their 4 attacker rows and 1 login attempt, plus 423 health-check rows and 3 infrastructure "attacker" rows. Rows were identified by recomputing what `hops=3` would resolve from each row's own stored header and deleting only mismatches — not by pattern-matching IPs — with a dry run and abort guards first
- Rotated both credentials exposed during deployment: the dashboard admin password (which had been printed into a chat transcript) and the `honeyshield_app` database password (visible unmasked in a screenshot). The admin rotation moved to `scripts/rotate_admin_password.py`, which reads the new password with `getpass` and never prints it, so the plaintext stays in the operator's terminal
- **Fixed a dashboard bug that made every page unusable against PostgreSQL.** Each call site used `asyncio.run()`, which closes its event loop; asyncpg pools bind to their creating loop, so the pool built at login was unusable by every later query. The login page masked it by only calling `db.connect()` and rendering a form. `dashboard/async_bridge.py` now owns one loop per process. Two further bugs surfaced while testing: asyncpg decoding `INET` as `ipaddress` objects (rejected by both Plotly and pyarrow, crashing Analytics), and a missing SQLite `row_factory`
- Added `tests/test_dashboard_pages.py` — renders all 8 pages via `AppTest`, checks the auth gate on each, and pins the cross-loop failure mode directly. The absence of exactly this test is why the loop bug shipped: every query worked in isolation, but nothing ever ran a page the way Streamlit does

## 2026-09-06 — AI analyst retries transient Gemini failures
- Gemini's free tier sheds load with `503 UNAVAILABLE` ("high demand… try again later"). `generate_attacker_report()` caught that and gave up immediately, so a routine, self-correcting condition became a failed report with the provider's raw JSON payload rendered in the dashboard
- It now retries **transient conditions only** — 503/`UNAVAILABLE`, 429/`RESOURCE_EXHAUSTED`, 500/`INTERNAL`, 504/`DEADLINE_EXCEEDED` and transport timeouts — on a 2s/6s/15s backoff. Genuine errors (rejected API key, safety block, malformed request) still fail on the first attempt: they fail identically every time, so retrying only burns quota and delays the message the operator needs
- When retries are exhausted the operator sees "Gemini is busy — retried 3 times over ~23s… try again in a minute" instead of `503 UNAVAILABLE. {'error': {'code': 503, …}}`. The underlying cause is preserved in a `detail` field for logs rather than discarded
- **The test suite had been hiding this.** `generate_with_retry()` in `tests/test_ai_analyst.py` did the retrying *itself*, with a comment arguing 503s were "an API condition, not a defect in this code" — half true, and the wrong half was load-bearing: the workaround sat on the test side of the boundary, so the suite stayed green while the product failed in exactly the way the helper was compensating for. Retry now lives in the product, and the tests assert the product performs it — attempt counts, the transient/permanent split, and that the message is not a JSON dump
- Verified as a genuine regression guard, not just newly-green: with `_is_transient` forced to `False` (reproducing the old no-retry path) four of the new assertions fail, including the raw-JSON-dump check. Suite grew 25 → 44 checks
