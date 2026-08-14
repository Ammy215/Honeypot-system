# Secrets & Data Exposure

Goal: **a leaked key should be harmless, not merely unlikely.** Prevention is one
layer; the others are blast-radius reduction and fast rotation.

---

## 1. Current state (verified)

| Check | Result |
|---|---|
| `.env` gitignored | Yes — `.gitignore` line 2 |
| `.env` ever committed | No — no `.env` blob exists in any commit |
| Key-shaped strings anywhere in git history | None — all commits scanned for `AIza…`, `sk-…`, 64/80-char hex |
| `security/.master_key`, `security/api_keys.enc` gitignored | Yes |
| Pre-commit secret hook | Added — `.githooks/pre-commit` |

The only history match for "key" was `docs/GET_API_KEYS_GUIDE.md`, which documents
how to obtain keys and contains none.

Re-run the history scan at any time:

```bash
git grep -aIE "(AIza[0-9A-Za-z_-]{20,}|sk-[A-Za-z0-9]{20,}|[a-f0-9]{80})" $(git rev-list --all)
```

---

## 2. Separate production and development keys

Generate a **second, independent key for each service** and use it only in
production. Never share one key across both — except OTX, which structurally can't
do this (see below).

| Service | Dev | Production | Status |
|---|---|---|---|
| AbuseIPDB | old key retired | new key | ✅ rotated 2026-08-13, verified |
| Google Gemini | old key retired | new key | ✅ rotated 2026-08-13, live-verified (`finish_reason: STOP`) |
| AlienVault OTX | one shared key | — | ⚠️ can't be separated — see below |

Why it's worth doing for AbuseIPDB and Gemini:

- **Containment.** The production key lives on a third-party PaaS you don't
  control. A leak there is revoked in isolation without breaking local work, and
  vice versa.
- **Attribution.** Separate keys mean separate usage graphs. Anomalous usage
  identifies *which* environment leaked, rather than leaving you guessing.
- **Rotation without downtime.** You can roll one side while the other keeps working.

**AbuseIPDB was rotated regardless of whether it had leaked**, on principle — it sat
unprotected on disk before this project's hardening pass. It never appeared in git,
but "not in git" isn't the same as "never exposed," and rotation is cheap.

### OTX is a structural exception, not an oversight

AlienVault OTX issues **exactly one API key per account** — there's no way to
generate a second, project-scoped key the way AbuseIPDB and Gemini allow. The
existing key is already shared with other, unrelated projects on this account.

Given that, **the decision made here is to keep it dev-only and never deploy it to
the hosting platform.** Putting a cross-project credential into a third-party
platform's env store would widen its blast radius past this deployment — a
platform-side compromise would then expose whatever else that key protects, not
just this honeypot. This reasoning is independent of which specific platform is
used (Koyeb, then Render after Koyeb's free tier closed to new signups) — it
follows from OTX's one-key-per-account limitation, not from anything
platform-specific.

The app degrades cleanly without it: `_has_api_key()` in
`honeypot/intelligence/async_otx.py` gates every OTX call, tested since Phase 3. In
production, OTX pulse-match enrichment (one of 14 scoring factors, weight 15/100)
simply doesn't populate — nothing crashes, nothing else is affected. See
`docs/RENDER.md`'s environment variable table.

If OTX enrichment in production ever becomes a priority, the only way to get a
project-scoped key is a **separate AlienVault OTX account** dedicated to this
project — not a setting change, an entirely new account.

## 3. Confirm no billing is attached

The point is that a stolen key cannot generate a bill. Verify in each console:

- **AbuseIPDB** — free tier is 1,000 checks/day, no card required. Confirm the
  account has no subscription. Over-quota returns HTTP 429, which the client already
  handles as a graceful failure rather than an overage charge.
- **AlienVault OTX** — free, no card, no paid tier to accidentally enter.
- **Google Gemini** — an **AI Studio** key on the free tier cannot bill you, because
  there is no payment method to charge. The trap is that AI Studio keys belong to a
  Google Cloud project: if that project ever has billing enabled, the same key
  silently starts billing at pay-as-you-go rates. Verify at
  console.cloud.google.com → Billing that the project backing the key shows **no
  billing account**.

Cross-check that the honeypot's own caching is limiting call volume — the enrichment
TTLs in `config.py` (`GEO_CACHE_TTL_SECONDS`, `ABUSEIPDB_CACHE_TTL_SECONDS`,
`OTX_CACHE_TTL_SECONDS`) exist so one noisy attacker can't burn a daily quota.

---

## 4. Pre-commit hook (local)

```bash
git config core.hooksPath .githooks    # once per clone
```

Blocks staged **added lines** matching Gemini/OpenAI/AWS/Slack key shapes, 64- and
80-char hex keys, private key blocks, Postgres URLs with an inline password, and
generic `SECRET`/`TOKEN`/`PASSWORD` assignments. Placeholder forms (`your_key_here`,
`REPLACE_ME`, `<password>`) pass through.

Verified against 14 cases — 8 real key shapes blocked, 6 placeholder/normal-code
cases allowed, including a 40-char git SHA (not mistaken for a key).

**This is a convenience guard, not a boundary.** It is bypassed by `--no-verify`,
and it does nothing at all for a fresh clone where nobody ran the config command.
That is what section 5 is for.

## 5. GitHub push protection (server-side) — **you must enable this**

This one cannot be done from the repo working tree; it is a GitHub repository
setting, so it needs you in the GitHub web UI:

> **Settings → Advanced Security** (older UI: *Code security and analysis*) →
> enable **Secret scanning**, then enable **Push protection**.

Once on, GitHub rejects the push itself when a recognized secret appears in the
diff — server-side, so `--no-verify` is irrelevant and it protects every clone and
contributor automatically.

**Availability depends on repo visibility:** secret scanning and push protection are
free on **public** repositories. On **private** repositories they require the paid
GitHub Secret Protection / Advanced Security add-on. If `Ammy215/Honeypot-system` is
private and you don't want to pay, the pre-commit hook is your only automated layer —
which is a further reason to treat production keys as disposable and rotate on any
doubt.

---

## 6. Database exposure

### The REST API surface is the non-obvious risk

Supabase automatically publishes every table in the `public` schema over PostgREST
at `https://<project>.supabase.co/rest/v1/<table>`, readable with the project's
`anon` key — a key that is *designed* to be public and ships inside browser
frontends. Default grants therefore make `public` tables world-readable over HTTPS
no matter how tightly the Postgres role is scoped.

This database stores **captured plaintext credentials**. Left at defaults, they would
be published.

`database/grants_production.sql` closes this by revoking `anon` and `authenticated`
from the schema entirely, including `ALTER DEFAULT PRIVILEGES` so tables added later
don't silently re-open it. RLS was deliberately not used instead: RLS with no
policies would also block the honeypot's own role.

**Verify after applying** — this must return zero rows:

```sql
SELECT grantee, table_name, privilege_type
FROM information_schema.role_table_grants
WHERE grantee IN ('anon','authenticated') AND table_schema = 'public';
```

And from outside, with the project's anon key — expect a permission error, not data:

```bash
curl "https://<project>.supabase.co/rest/v1/login_attempts?select=*" \
     -H "apikey: <anon-key>"
```

### The Postgres port is reachable, and cannot be closed on the free tier

Be clear-eyed about this: Supabase's Postgres endpoint is a public hostname on the
internet. **Network Restrictions (IP allowlisting) is a paid feature** — on the free
tier there is no way to make the database unreachable at the network layer.

So the controls that actually apply are:

1. **A strong, unique password** on `honeyshield_app` — generated, not reused, and
   never the DB owner's password.
2. **TLS required** — `DB_SSL_MODE=require` (`config.py`), passed explicitly to
   `asyncpg.create_pool`. asyncpg defaults to `prefer`, which silently accepts an
   unencrypted connection; captured credentials would otherwise cross the internet
   in cleartext.
3. **Least privilege** — `SELECT/INSERT/UPDATE` only, no `DELETE`/`TRUNCATE`/`DROP`/
   `ALTER`/`CREATE`, and **no access to `admin_users`** at all, so a compromised
   honeypot cannot read dashboard password hashes or create itself an admin account.
4. **The DB owner credential never leaves your machine.** Only the least-privilege
   credential goes to the PaaS.

### Captured credentials are third-party personal data

Credential-stuffing bots replay credentials from real breaches, so this database
accumulates **real people's real passwords**. They are kept plaintext deliberately —
that is what makes the dataset useful for analysis, and it matches standard honeypot
research practice — which makes the controls above a privacy obligation, not only a
security one.

Practical consequences:

- Never screenshot, export, or paste raw `login_attempts` rows into an issue, a
  write-up, or a portfolio piece. Aggregate (top usernames, attempt counts) rather
  than dumping rows.
- Never point a public dashboard at this table.
- The hosting provider processes this data under its DPA; if you deploy to an EU
  region this sits more squarely inside GDPR than a US region does.

---

## 7. If a key does leak

1. **Revoke first, investigate second.** Regenerate in the provider console before
   working out how it happened.
2. **Rotate the paired credential too** if the leak vector could have exposed the
   whole `.env` (a committed file, a shared log, a screenshot).
3. **Purging git history is not rotation.** Rewriting history does not un-publish
   anything already fetched, cloned, or indexed. Rotate; rewrite only afterwards, and
   only if it's worth the effort.
4. **Check for usage you didn't cause** — provider dashboards show per-key request
   counts, which is the quickest way to tell exposure from exploitation.
