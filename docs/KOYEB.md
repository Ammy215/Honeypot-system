# Koyeb Deployment — HTTP Honeypot (Option A)

Deploys the **HTTP honeypot only**, to Koyeb's free instance, with PostgreSQL on
Supabase and the dashboard kept local. See the README's *Future Work* section for
why only one service is deployed.

**Region: Washington, D.C.** — deliberately not Frankfurt. This database stores
captured credentials, which are real third-party personal data; an EU region puts
that more squarely inside GDPR for no benefit here.

---

## What Koyeb's free tier actually gives you

Verified against Koyeb's own documentation, not third-party summaries:

| Property | Reality |
|---|---|
| Cost | Free, no expiry |
| Credit card | Usually not required — Koyeb prompts for one only if it can't otherwise verify you're human. Not guaranteed |
| Resources | 512 MB RAM, 0.1 vCPU, 2 GB SSD, one web service |
| **Sleep** | **Scales to zero after 1 hour without traffic. Cannot be disabled on the free instance** |
| Wake time | 1–5 s cold start (Deep Sleep) |
| Deploys | Git-based only |
| Persistent volumes | **Not available** — this is why Postgres is mandatory, not optional |
| Regions | Washington D.C. · Frankfurt · Singapore |

**On the sleep behaviour:** a honeypot's traffic is idle-heavy, so the instance will
be asleep most of the time. Most scanners use HTTP timeouts well above 5 s, so the
1–5 s wake usually still serves the request — but expect to miss occasional probes
from fast-timeout scanners. This is the accepted trade-off of the free tier, and it
is still far better than Render's ~50 s cold start.

**Note:** Koyeb was acquired by Mistral AI in February 2026. The free-tier commitment
is stated as unchanged, but that is now a post-acquisition promise.

---

## 1. Prerequisites

- [ ] Supabase project created, schema applied, and
      `database/grants_production.sql` run — see §2.
- [ ] Production API keys generated, separate from your dev keys
      ([docs/SECRETS.md](SECRETS.md)).
- [ ] Repo pushed to GitHub (Koyeb's free tier deploys from git).
- [ ] GitHub push protection enabled (Settings → Advanced Security).

## 2. Database setup (do this before deploying)

In the Supabase SQL editor, as the project owner:

1. Run [database/schema_postgres.sql](../database/schema_postgres.sql) — creates all
   tables and indexes.
2. Edit [database/grants_production.sql](../database/grants_production.sql), replacing
   `REPLACE_ME_WITH_A_GENERATED_PASSWORD` with a freshly generated password, then
   run it. This creates the least-privilege `honeyshield_app` role **and** closes
   Supabase's REST API exposure.
3. Run the two verification queries at the bottom of that file. The
   `anon`/`authenticated` query **must return zero rows** — otherwise captured
   credentials are readable over the public REST endpoint.
4. Confirm externally:

   ```bash
   curl "https://<project>.supabase.co/rest/v1/login_attempts?select=*" \
        -H "apikey: <anon-key>"
   ```

   Expect a permission error. Any row data returned means step 2 did not apply.

## 3. Create the Koyeb service

1. Sign up at koyeb.com (GitHub OAuth is the smoothest path).
2. **Create Web Service** → **GitHub** → select `Ammy215/Honeypot-system`, branch `main`.
3. **Region:** Washington, D.C.
4. **Instance:** Free.
5. **Builder:** Buildpack. Koyeb detects `requirements.txt` and uses the `Procfile`
   (`web: python main.py`). No Dockerfile needed.
6. **Health check:** set to **TCP** on the exposed port.

   > Not HTTP. An HTTP health check on `/` would fail — the honeypot deliberately
   > returns **404** for unknown paths, which is the whole point of the decoy. If you
   > prefer an HTTP check, point it at `/admin`, which returns 200.

## 4. Environment variables

Set these in Koyeb → Service → Settings → Environment variables. Mark every key and
the database URL as **Secret**, not plain text.

| Variable | Value | Why |
|---|---|---|
| `DATABASE_URL` | `postgresql://honeyshield_app:<pw>@<host>:5432/postgres` | Least-privilege role, **not** the owner |
| `DB_SSL_MODE` | `require` | asyncpg would otherwise accept an unencrypted connection |
| `SKIP_SCHEMA_INIT` | `true` | The app role can't run `CREATE TABLE` |
| `ENABLED_SERVICES` | `HTTP` | Free PaaS routes HTTP only |
| `TRUST_PROXY_HEADERS` | `true` | Without this every attacker records as the load balancer |
| `TRUSTED_PROXY_HOPS` | `1` | Bare Koyeb load balancer, one appending hop |
| `FORWARDED_IP_HEADER` | `x-forwarded-for` | Confirm against §6 before relying on it |
| `IGNORE_UNFORWARDED_CONNECTIONS` | `true` | Drops health-check noise. **Set this only after §6 confirms real traffic carries the header** |
| `PYTHONIOENCODING` | `utf-8` | Container logs are a pipe; the banner glyphs crash startup under a C/POSIX locale. Must be a real env var — `.env` is read too late |
| `ABUSEIPDB_API_KEY` | production key | Rotated, honeypot-only — see docs/SECRETS.md |
| `GEMINI_API_KEY` | production key | Rotated, honeypot-only, live-verified |
| `GEMINI_MODEL` | `gemini-flash-latest` | |

`PORT` is injected by Koyeb automatically — do **not** set it.

**`OTX_API_KEY` is deliberately left unset here.** Unlike AbuseIPDB and Gemini, AlienVault
OTX issues exactly one API key per account — there's no way to generate a second,
honeypot-only key. The existing key is already shared with other, unrelated projects,
so putting it in Koyeb's env store would widen its blast radius beyond this deployment:
a Koyeb compromise would then expose a credential that also protects those other
projects, not just this one.

The app already handles this cleanly — `honeypot/intelligence/async_otx.py` gates every
call behind `_has_api_key()`, tested since Phase 3. With no key, OTX pulse-match
enrichment (one of 14 scoring factors, weight 15/100) just doesn't populate; nothing
crashes or degrades elsewhere. AbuseIPDB and Gemini enrichment are unaffected.

## 5. Deploy

Push to `main`, or hit Deploy in the Koyeb console. Watch the build logs for:

```
Database ready (postgres)
Starting services:
  • HTTP on port <injected>
  Not started (ENABLED_SERVICES): SSH, FTP, TELNET — built and tested, gated for this deployment
```

`Database ready (postgres)` is the line that matters — `(sqlite)` means
`DATABASE_URL` didn't reach the process, and the data would be written to a
filesystem that disappears on the next sleep.

## 6. Verify the forwarded header before trusting it (important)

This has to be confirmed against the live platform, not assumed. Hit the service and
check what actually lands in the database:

```bash
curl https://<your-app>.koyeb.app/admin
curl -X POST -d "username=verify&password=test" https://<your-app>.koyeb.app/admin
```

Then, from the Supabase SQL editor:

```sql
SELECT ip_address, forwarded_for_raw, connected_at
FROM connections ORDER BY connected_at DESC LIMIT 5;
```

- `ip_address` should be **your own public IP**, not a Koyeb-internal address.
- `forwarded_for_raw` should be populated.

If `forwarded_for_raw` is NULL but the connection was real, Koyeb uses a different
header name — find it and set `FORWARDED_IP_HEADER` accordingly. **Do not enable
`IGNORE_UNFORWARDED_CONNECTIONS` until this check passes**, or real traffic will be
silently discarded along with the health checks.

Then confirm the spoofing defence works end to end:

```bash
curl -H "X-Forwarded-For: 1.2.3.4" https://<your-app>.koyeb.app/admin
```

The stored `ip_address` must still be **your** IP, with `1.2.3.4` appearing only
inside `forwarded_for_raw`.

## 7. Connect the local dashboard

The dashboard is never deployed. Run it locally against the same database:

```bash
# in your local .env
DATABASE_URL=postgresql://honeyshield_app:<pw>@<host>:5432/postgres
DB_SSL_MODE=require
SKIP_SCHEMA_INIT=true

streamlit run dashboard/app.py
```

This is strictly safer than the original Cloudflare Tunnel plan — the dashboard has
no public surface at all.

> The dashboard needs `INSERT` on `ai_reports` and `UPDATE` on `alerts`
> (acknowledgement), both of which `honeyshield_app` already has. It also needs
> `admin_users` for login — which that role is deliberately denied. Either run the
> dashboard under the owner credential locally, or grant a separate dashboard role
> access to `admin_users` only.

## 8. Live validation window (24–48 h)

- [ ] Leave it running untouched.
- [ ] Check for real scanner activity:
      ```sql
      SELECT ip_address, service, connected_at FROM connections
      WHERE ip_address NOT IN ('<your own IP>')
      ORDER BY connected_at DESC LIMIT 50;
      ```
- [ ] Confirm the pipeline end to end on real IPs: connection captured →
      geolocation/AbuseIPDB/OTX enrichment populated → threat score and verdict set →
      alerts fired where warranted.
- [ ] Note time-to-first-unsolicited-connection.

**Calibrate expectations:** a PaaS hostname is not IP-addressable, so mass IPv4
scanners never reach it. Expect **dozens of hits per 48 h, not thousands**, arriving
mostly from Certificate Transparency log harvesters and hostname-based path scanning.
A sparse table here is the expected result, not a broken pipeline.

## 9. Known limitations

- **Scale-to-zero** costs the occasional probe from fast-timeout scanners.
- **Background enrichment is killed on sleep.** `spawn_background` tasks don't
  survive the instance scaling down, so some attackers land un-enriched. Re-run
  `enrich_captured_attackers` periodically from your machine to backfill.
- **The Supabase Postgres endpoint is publicly reachable** and cannot be firewalled
  on the free tier — IP allowlisting is a paid feature. The controls that apply are
  the strong unique password, enforced TLS, and least privilege.
- **Supabase free projects pause after ~7 days of inactivity.** Honeypot writes
  normally prevent this, but a fully quiet week could pause the database.
- **Only HTTP runs**, so `multi_service` detection and its scoring weight cannot fire.
