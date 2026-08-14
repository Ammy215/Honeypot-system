# Render Deployment — HTTP Honeypot (Option A)

Deploys the **HTTP honeypot only**, to Render's free web service tier, with
PostgreSQL on Supabase and the dashboard kept local. See the README's *Future
Work* section for why only one service is deployed.

**Region: Ohio (US-East)** — deliberately not Frankfurt. This database stores
captured credentials, which are real third-party personal data; an EU region puts
that more squarely inside GDPR for no benefit here.

**Why not Koyeb:** Koyeb's free Starter tier closed to new signups after its
acquisition by Mistral AI (Feb 2026) — its own docs now state a credit card is
required for new-account verification, even though never charged. That fails the
no-card constraint outright, so this plan moved to Render instead. Everything
below was researched against Render's own primary docs where possible, following
the same discipline that should have been applied to Koyeb from the start.

---

## What Render's free tier actually gives you

| Property | Reality | Source confidence |
|---|---|---|
| Cost | Free, ongoing — not a time-limited trial | Render's own docs (`/docs/free`) |
| Credit card | **Not stated as required** in Render's own docs — unlike Koyeb, which now explicitly says it is. One unverified user report claims otherwise | Primary docs + one conflicting anecdote — **confirm live, see §0 below** |
| Resources | 512 MB RAM, 0.1 vCPU | Render's own docs |
| **Sleep** | Spins down after **15 minutes** without inbound traffic | Render's own docs |
| Wake time | ~1 minute (slower than Koyeb's 1–5s — a real regression, accepted as the cost of Koyeb no longer being viable) | Render's own docs |
| Monthly hour limit | 750 free instance-hours/workspace; suspends until next month if exhausted. A honeypot's idle-heavy traffic should stay well under this | Render's own docs |
| Regions | Oregon, Ohio, Frankfurt, Singapore confirmed; one source also listed Virginia — **unconfirmed which are actually free-tier-eligible**, check at service-creation time | Docs + search, inconsistent on the 5th region |
| Deploys | Git-based | Render's own docs |
| Health checks | **Default to TCP socket probes** — HTTP path checks are opt-in, not default | Render's own docs |

**On the sleep behaviour:** slower than Koyeb's wake time, but this is the accepted
trade-off given Koyeb is no longer viable at all. Most scanner HTTP clients use
timeouts well above 1 minute, but expect to miss more fast-timeout probes than the
original Koyeb plan would have caught.

---

## 0. Before anything else — confirm the card question live

This is the step that burned the Koyeb plan, so it gets done first and explicitly,
not assumed from docs. **Watch for a payment-info prompt at two separate points,
not just one:**

1. **Account signup itself.**
2. **Instance-type / plan selection**, when creating the web service — a platform
   can let you sign up free and still gate a specific instance type behind a card.

If a card prompt appears at either point: **stop before entering anything, and
report back** — do not proceed on the assumption it's harmless "just for
verification," since that was exactly Koyeb's framing too.

- [ ] Signed up — no card prompt.
- [ ] Reached instance-type selection — no card prompt.

## 1. Prerequisites (already done, nothing to repeat)

- [x] Supabase project created, schema applied, `database/grants_production.sql`
      and `database/rls_policies.sql` run.
- [x] Production API keys generated, separate from dev
      ([docs/SECRETS.md](SECRETS.md)).
- [x] Repo pushed to GitHub, push protection enabled.
- [x] `database/grants_dashboard.sql` applied for local dashboard access.

## 2. Database setup (already done — reference only)

Covered in §0 of the git history for this pivot; not repeated here. See
[database/grants_production.sql](../database/grants_production.sql) and
[database/rls_policies.sql](../database/rls_policies.sql) if this is ever run
against a fresh Supabase project from scratch.

## 3. Create the Render web service

1. Sign up at render.com — watch for the card prompt per §0.
2. **New → Web Service** → connect GitHub → select `Ammy215/Honeypot-system`,
   branch `main`.
3. **Region: Ohio.** Confirm it's actually offered under the free instance type at
   this step — the docs didn't confirm free-tier region restrictions the way
   Koyeb's did.
4. **Instance type: Free.** Watch for the card prompt here specifically, per §0.
5. **Runtime: Python 3.** Render auto-detects `requirements.txt`.
6. **Start Command:** type `python main.py` explicitly into the dashboard field.
   Don't rely on the `Procfile` being auto-read — Render's own service-creation
   docs describe Start Command as a required dashboard field and don't mention
   `Procfile` as an alternative, unlike Koyeb's buildpack flow. The `Procfile`
   stays in the repo regardless; it's harmless if unused and still documents
   intent.
7. **Health check:** leave at the default (TCP). Render's default health check
   type is TCP-based, unlike Koyeb where an HTTP default would have needed
   manually switching away from it. If you do see an HTTP path option and it's
   enabled, don't point it at `/` — the honeypot deliberately 404s unknown paths.
   Point it at `/admin` instead, which returns 200.
8. Don't deploy yet — set environment variables first (§4).

## 4. Environment variables

Render → your service → **Environment**. Mark secrets appropriately (Render
supports marking values as secret/hidden in the dashboard).

| Variable | Value | Why |
|---|---|---|
| `PORT` | `10000` | **Opposite of Koyeb.** Render does not auto-inject a port — you must set one yourself. `config.py`'s `HTTP_PORT = int(os.getenv("PORT") or ...)` already handles this with no code change; `10000` matches Render's own default expectation |
| `DATABASE_URL` | `honeyshield_app`'s pooler connection string | Least-privilege role, **not** the owner or dashboard role |
| `DB_SSL_MODE` | `require` | asyncpg would otherwise accept an unencrypted connection |
| `SKIP_SCHEMA_INIT` | `true` | The app role can't run `CREATE TABLE` |
| `ENABLED_SERVICES` | `HTTP` | Free PaaS routes HTTP only |
| `TRUST_PROXY_HEADERS` | `true` | Without this every attacker records as Render's edge |
| `TRUSTED_PROXY_HOPS` | `2` (starting value — **see §5, this needs live confirmation**) | Anecdotal evidence (a Render community thread, not official docs) suggests Render's proxy chain appends twice — an edge layer, then an internal reverse proxy — unlike Koyeb's single hop. If §5 shows the real IP one position further left than expected, this is why |
| `FORWARDED_IP_HEADER` | `x-forwarded-for` | Render's reverse proxy appends to this without stripping attacker-supplied values first — confirmed via Render's own community forum, consistent with our anti-spoofing design |
| `IGNORE_UNFORWARDED_CONNECTIONS` | `false` | **Leave false until §5 passes** |
| `ABUSEIPDB_API_KEY` | production key | Rotated, honeypot-only |
| `GEMINI_API_KEY` | production key | Rotated, honeypot-only, live-verified |
| `GEMINI_MODEL` | `gemini-flash-latest` | |

`PYTHONIOENCODING=utf-8` is **not needed** on Render the way it was flagged for
Koyeb — worth setting anyway as a harmless safeguard against the same non-ASCII
banner crash under a piped/non-UTF-8 log context, but hasn't been confirmed as
necessary here specifically.

**`OTX_API_KEY` is deliberately left unset here**, same reasoning as the Koyeb
plan: AlienVault OTX issues one account-wide key, shared with other projects, so
deploying it anywhere third-party would widen its blast radius. See
[docs/SECRETS.md](SECRETS.md).

## 5. Deploy, then verify the forwarded header — this is the critical step

More important here than it was for Koyeb, because the hop count itself is
unverified (§ above), not just the header name.

```bash
curl https://<your-app>.onrender.com/admin
curl -X POST -d "username=verify&password=test" https://<your-app>.onrender.com/admin
```

Then in Supabase:

```sql
SELECT ip_address, forwarded_for_raw, connected_at
FROM connections ORDER BY connected_at DESC LIMIT 5;
```

- `ip_address` must be **your own public IP**.
- `forwarded_for_raw` must be populated, and — check this carefully — count how
  many comma-separated entries it has. If `ip_address` is NOT your real IP:
  - If it looks like it landed on the *second-to-last* entry when it should be
    last (or vice versa), adjust `TRUSTED_PROXY_HOPS` between `1` and `2` and
    redeploy, then re-test.
  - If `forwarded_for_raw` is `NULL` entirely, Render may use a different header
    name than `x-forwarded-for` — check the raw request some other way (e.g. a
    temporary debug log of all headers) and update `FORWARDED_IP_HEADER`.

Then the anti-spoofing check, same as before:

```bash
curl -H "X-Forwarded-For: 1.2.3.4" https://<your-app>.onrender.com/admin
```

Stored `ip_address` must still be **your** real IP, with `1.2.3.4` appearing only
inside `forwarded_for_raw`.

**Do not flip `IGNORE_UNFORWARDED_CONNECTIONS` to `true` until this entire section
passes with the correct hop count confirmed.**

## 6. Connect the local dashboard

Unchanged from the Koyeb plan — the dashboard is never deployed, runs locally
against Supabase using the `honeyshield_dashboard` role from
[database/grants_dashboard.sql](../database/grants_dashboard.sql):

```bash
# in your local .env
DATABASE_URL=postgresql://honeyshield_dashboard.<project-ref>:<pw>@<pooler-host>:5432/postgres
DB_SSL_MODE=require
SKIP_SCHEMA_INIT=true

streamlit run dashboard/app.py
```

## 7. Live validation window (24–48 h)

- [ ] Leave it running untouched.
- [ ] Check for real scanner activity:
      ```sql
      SELECT ip_address, service, connected_at FROM connections
      WHERE ip_address NOT IN ('<your own IP>')
      ORDER BY connected_at DESC LIMIT 50;
      ```
- [ ] Confirm the pipeline end to end on real IPs: connection captured →
      geolocation/AbuseIPDB/OTX enrichment populated → threat score and verdict set
      → alerts fired where warranted.
- [ ] Note time-to-first-unsolicited-connection.

**Calibrate expectations:** a PaaS hostname is not IP-addressable, so mass IPv4
scanners never reach it. Expect **dozens of hits per 48 h, not thousands**, mostly
from Certificate Transparency log harvesters and hostname-based path scanning. A
sparse table here is the expected result, not a broken pipeline.

## 8. Known limitations

- **Slower cold start than the original Koyeb plan** (~1 min vs. 1–5 s) — expect
  more missed fast-timeout scanner probes.
- **Background enrichment is killed on sleep** — `spawn_background` tasks don't
  survive a spin-down, so some attackers land un-enriched. Re-run
  `enrich_captured_attackers` periodically from your machine to backfill.
- **The Supabase Postgres endpoint is publicly reachable** and cannot be
  firewalled on the free tier — IP allowlisting is a paid Supabase feature. The
  controls that apply are the strong unique password, enforced TLS, and least
  privilege.
- **Supabase free projects pause after ~7 days of inactivity.** Honeypot writes
  normally prevent this, but a fully quiet week could pause the database.
- **Only HTTP runs**, so `multi_service` detection and its scoring weight cannot
  fire.
- **`TRUSTED_PROXY_HOPS` starts as a best guess (2), not a confirmed fact** —
  unlike the Koyeb plan where the single-hop model was fairly confidently
  correct. §5 must actually pass before trusting captured IPs at all.

## Deferred until after §7 succeeds

A lightweight `GET /_health` endpoint (200 immediately, no logging/enrichment,
invisible in `attackers`/`connections`) for an external uptime monitor. Decided,
not built — build only once real validation-window data shows it's actually
needed, not speculatively.
