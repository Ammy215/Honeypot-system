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
| `TRUSTED_PROXY_HOPS` | `3` — **confirmed live 2026-09-05**, not a guess | The pre-deployment guess of `2` was wrong. §5 against the real service showed a three-segment chain: `client, Cloudflare edge, Render internal LB` (Render fronts with Cloudflare — `Server: cloudflare` and `CF-RAY` are on every response). At `2` both plain and spoofed requests resolved to the Cloudflare edge IP — the safe direction, never the attacker's forged value, but useless data that collapsed every attacker onto one address. Confirmed correct at `3` across two controlled requests and multiple organic hits |
| `FORWARDED_IP_HEADER` | `x-forwarded-for` | Render's reverse proxy appends to this without stripping attacker-supplied values first — confirmed via Render's own community forum, consistent with our anti-spoofing design |
| `IGNORE_UNFORWARDED_CONNECTIONS` | `true` — set 2026-09-05, **only after §5 passed** | Start at `false` on a fresh deployment and keep it there until §5 confirms the hop count; flipping early hides the very traffic you need to diagnose it. Once live it diverted ~14 health-check probes/minute that were otherwise being recorded as a real attacker. Filtered connections aren't dropped silently — they go to `filtered_connections`, not `attackers`/`connections`, so filtered traffic stays visible and distinguishable from genuinely low traffic during §7 |
| `ABUSEIPDB_API_KEY` | production key | Rotated, honeypot-only |
| `GEMINI_API_KEY` | production key | Rotated, honeypot-only, live-verified |
| `GEMINI_MODEL` | `gemini-flash-latest` | |
| `OTX_API_KEY` | production key | On a **dedicated OTX account** created for this project — see below |

`PYTHONIOENCODING=utf-8` is **not needed** on Render the way it was flagged for
Koyeb — worth setting anyway as a harmless safeguard against the same non-ASCII
banner crash under a piped/non-UTF-8 log context, but hasn't been confirmed as
necessary here specifically.

**`OTX_API_KEY` is now included** — reversing the earlier decision to omit it.

The original exclusion was never about OTX being unimportant. It was that OTX
issues exactly one API key per account, and the key in use was already shared with
other, unrelated projects; putting it into a third-party platform's env store would
have widened its blast radius well past this deployment.

That specific problem is now gone. The key configured here belongs to a **separate
AlienVault OTX account created solely for this project**, so it is project-scoped
in the only way OTX permits — a dedicated account rather than a per-project key.
A leak of this credential exposes this honeypot's OTX access and nothing else,
which is the same containment property `ABUSEIPDB_API_KEY` and `GEMINI_API_KEY`
already have.

Including it restores OTX pulse-match enrichment in production, and with it the
`otx_pulse_match` scoring factor (weight 15 of 100) that would otherwise never
fire. Verified live against this key before deploying: `/user/me` authenticates,
and pulse lookups return real counts (50, 26 and 5 pulses on three known-flagged
IPs). See [docs/SECRETS.md](SECRETS.md) §2.

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
  - The resolved entry is counted from the **right**, so the index is
    `len(entries) - TRUSTED_PROXY_HOPS`. On this deployment the chain is
    `client, Cloudflare edge, Render internal LB` — three entries, so `3`
    selects the leftmost, which is the real client. If the stored IP is one
    position off, adjust `TRUSTED_PROXY_HOPS` (values of `1`–`3` are plausible
    depending on how Render routes) and redeploy, then re-test.
  - A spoofed request adds one entry on the left, making four; the same
    `hops=3` then correctly selects the second entry — still the real client,
    never the forged one. If a forged value is ever stored, the hop count is
    too high: stop and fix it before trusting any captured data.
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

> **Outcome on this deployment (2026-09-05).** §5 initially *failed*: at
> `TRUSTED_PROXY_HOPS=2` both the plain and the spoofed request resolved to the
> Cloudflare edge, not the real client. Raising it to `3` and re-running gave the
> real client IP in both cases, with the forged `1.2.3.4` present only inside
> `forwarded_for_raw`. Any pre-fix rows are wrong data and were deleted rather
> than kept — an attacker row holding a Cloudflare address is worse than no row,
> because it looks legitimate.

## 6. Connect the local dashboard

Unchanged from the Koyeb plan — the dashboard is never deployed, runs locally
against Supabase using the `honeyshield_dashboard` role from
[database/grants_dashboard.sql](../database/grants_dashboard.sql):

```bash
# in your local .env
DATABASE_URL=postgresql://honeyshield_dashboard.<project-ref>:<pw>@<pooler-host>:5432/postgres
DB_SSL_MODE=require
SKIP_SCHEMA_INIT=true
HONEYPOT_PUBLIC_URL=https://<your-app>.onrender.com   # Sensor health probes <this>/_health

python run_dashboard.py        # or: streamlit run dashboard/app.py
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
- [ ] Check `filtered_connections` alongside `connections` — this is what tells
      "genuinely low traffic" apart from "traffic getting filtered," which would
      otherwise look identical from outside once `IGNORE_UNFORWARDED_CONNECTIONS`
      is on:
      ```sql
      SELECT peer_ip, method, path, filtered_at FROM filtered_connections
      ORDER BY filtered_at DESC LIMIT 50;
      ```
      Expect this to be dominated by one or two `peer_ip` values hitting
      repeatedly with no `path` (or the same one or two paths) — that's the
      platform's own health checker. A `peer_ip` that only shows up once, or a
      `path` unrelated to a health check, is worth a second look: it may be real
      traffic that's being incorrectly filtered rather than genuine noise.

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
- **`TRUSTED_PROXY_HOPS` was a guess, and the guess was wrong.** The documented
  starting value of `2` produced Cloudflare edge IPs, not attackers; `3` is the
  confirmed-correct value (§4, §5). Kept here rather than quietly corrected,
  because the lesson generalises: a hop count copied from a community thread is
  a hypothesis, and §5 is what turns it into a fact. Re-run §5 after any change
  to how Render fronts the service.
- **Render's free tier sleeps after ~15 minutes idle.** Observed live: a ~16.6
  minute gap in probes while asleep. Traffic arriving during sleep triggers a
  cold start (~1 min) and the very first request may be lost, so a quiet stretch
  in the data is not automatically evidence of no attacker activity.

## 9. Keeping the service awake — `GET /_health` and an uptime monitor

Built ahead of its original schedule, and the reason is worth recording. This
was deferred until after a successful §7 window, on the principle of not
building speculatively. The first real look at the data inverted that: over 72
hours the service had recorded traffic in only **six one-hour buckets**, in
two-hour bursts separated by 12–24 hours of complete silence — no attacker
traffic *and no platform health checks either*, which is the tell, since those
are constant while the instance is awake. Measured cold-start cost was **32.9s
to first byte, against 0.49s once warm**. The instance was asleep for the large
majority of the window, so the window was not measuring what it claimed to. The
endpoint stopped being polish and became the blocker.

**What it does.** `GET /_health` (path configurable via `HEALTH_CHECK_PATH`)
returns `200 ok` and writes nothing anywhere. The check sits *above* both
recording branches in `handle_connection`, which is the load-bearing detail: an
external monitor arrives through the load balancer **with** a forwarding header
and would otherwise be written to `connections` as an attacker, while Render's
internal checker arrives **without** one and would be written to
`filtered_connections`. Only a check preceding both is invisible to capture.

**What it deliberately does not do.** It matches the path *exactly* and only for
`GET`/`HEAD`. Decoy paths match by prefix so `/admin/config.php` is still
captured; the same rule here would let `/_health/../wp-login.php`, `/_healthz`
or a credential `POST` to `/_health` escape logging. Everything that is not
precisely this path and method falls through to full normal capture — the
failure direction is always "log it", never "drop it". Covered by
`tests/test_health_endpoint.py` (29 checks), which asserts the negative: after
27 pings, every capture table holds exactly the row count it started with.

### 9a. Repoint Render's own health check

Render's internal checker was pointed at **`/admin` — a decoy path** — firing
roughly every 5 seconds. That alone generated the ~2,500 rows in
`filtered_connections`. In the Render dashboard: **Settings → Health Check Path
→ `/_health`**. This does not keep the service awake (internal checks don't
count as inbound traffic) but it stops the self-inflicted noise.

### 9b. UptimeRobot — the part that actually keeps it awake

Free, no card required. **Point it at `/_health` and never at a decoy path** —
a monitor on `/admin` would manufacture an attacker row every 5 minutes and
poison the dataset the honeypot exists to collect.

1. Sign up at <https://uptimerobot.com> (free tier: 50 monitors, 5-minute
   interval — comfortably under Render's ~15-minute sleep threshold).
2. **+ New monitor**
   - Monitor type: **HTTP(s)**
   - Friendly name: `HoneyShield keepalive`
   - URL: `https://honeypot-system-9j9a.onrender.com/_health`
   - Monitoring interval: **5 minutes**
3. Leave alerting on if you want to know when the service dies; it is otherwise
   harmless.
4. Verify after ~15 minutes: the monitor shows 200s, and
   `SELECT count(*) FROM connections WHERE connected_at > now() - interval '15 min'`
   returns **0**. Both must be true — a green monitor with rows appearing means
   it is pointed at the wrong path.

Note the tradeoff being accepted, stated honestly: this is one path on the host
that is not a trap, and a `GET` of it is genuinely invisible — that is the
feature, and it necessarily means an attacker who happens to request `/_health`
leaves no row either. What that costs is small (a bland `200 ok`, carrying the
same `Apache/2.4.41` header as every other response, revealing nothing) and it
is bounded: any *variation* — `POST /_health`, `/_healthz`, `/_health/sub` — is
captured in full, so the blind spot is exactly one method-and-path pair and
cannot be widened into a general logging bypass.
