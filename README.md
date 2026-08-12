# 🍯 HoneyShield Intelligence Platform

A multi-protocol honeypot and threat-intelligence platform. It exposes convincing
fake SSH, FTP, HTTP and Telnet services, captures what attackers do to them,
enriches every source IP against live threat feeds, correlates activity into
alerts and campaigns, and presents the result through an AI-assisted SOC
dashboard.

Built on asyncio and raw SQL — no web framework, no ORM.

> **Deployment status:** only the **HTTP honeypot** currently runs in production.
> SSH, FTP and Telnet are fully built and tested but need raw TCP socket access,
> which free PaaS tiers don't provide. See [Future Work](#future-work--deferred)
> for the reasoning and what unblocks them.

---

## Architecture

```
                    ┌──────────────────────────────────────┐
   attacker  ─────► │  honeypot services (asyncio)         │
                    │  SSH 2222 · FTP 2121                 │
                    │  HTTP 8080 · Telnet 2323             │
                    └──────────────┬───────────────────────┘
                                   │ every connection / credential
                                   ▼
                    ┌──────────────────────────────────────┐
                    │  database  (SQLite dev / Postgres prod)│
                    └──────────────┬───────────────────────┘
                                   │
              ┌────────────────────┼────────────────────┐
              ▼                    ▼                    ▼
     ┌─────────────────┐  ┌────────────────┐  ┌──────────────────┐
     │  enrichment     │  │  detection     │  │  AI analyst      │
     │  ip-api.com     │  │  brute force   │  │  Google Gemini   │
     │  AbuseIPDB      │  │  cred stuffing │  │  (direct SDK)    │
     │  AlienVault OTX │  │  multi-service │  └──────────────────┘
     │  threat scoring │  │  campaigns     │
     └─────────────────┘  └────────────────┘
                                   │
                                   ▼
                    ┌──────────────────────────────────────┐
                    │  Streamlit dashboard (127.0.0.1 only)│
                    └──────────────────────────────────────┘
```

Enrichment runs as fire-and-forget background tasks so a slow threat-feed lookup
can never delay or fail the connection handler that triggered it.

## Technology stack

| Layer | Choice |
|---|---|
| Language | Python 3.13, `asyncio` — raw sockets, no web framework |
| Database | SQLite (stdlib `sqlite3`, dev) / PostgreSQL (`asyncpg`, prod) — hand-written SQL, no ORM |
| Dashboard | Streamlit + Plotly + Pandas |
| AI analyst | **Google Gemini** via `google-genai`, called directly — no LangChain |
| Admin auth | **argon2** (`argon2-cffi`) |
| Threat intel | AbuseIPDB, AlienVault OTX, ip-api.com (no key needed) |

> `bcrypt` and `openai` remain in `requirements.txt` for the legacy v1 modules
> (`auth/auth_manager.py`, `honeypot/ai/analyst.py`) only. The v2 async core and
> dashboard use argon2 and Gemini.

## Honeypot services

| Service | Port | Behaviour |
|---|---|---|
| SSH | 2222 | Fake OpenSSH banner, captures username/password pairs |
| FTP | 2121 | Fake ProFTPD banner, `USER`/`PASS` capture |
| HTTP | 8080 | Fake admin, WordPress and phpMyAdmin login pages; captures POSTed credentials; logs path reconnaissance |
| Telnet | 2323 | Fake Ubuntu login prompt — the protocol IoT/Mirai-family botnets target |

Non-standard ports avoid needing root. SMTP (2525) and RDP (3389) are defined in
`config.py` but **intentionally disabled** — a deliberate scope decision, not a bug.

Attacker input is treated as inert text everywhere: stored via parameterized
queries, never interpreted, never executed, never rendered as HTML.

## Detection

| Detector | Rule |
|---|---|
| Brute force | Per-service thresholds: SSH 10/5min · FTP 10/5min · **Telnet 5/5min** · HTTP 10/10min |
| Credential stuffing | 5+ distinct usernames from one IP within 10 minutes |
| Multi-service | Same IP hitting 2+ services within 5 minutes |
| Campaigns | 3+ distinct IPs sharing an ASN within a 24-hour window |

Telnet's threshold is lower and HTTP's window longer because Telnet bots are
noisier and faster, while web form-fill bots are slower.

### Threat scoring

14 weighted factors produce a 0–100 score, capped at 100:

- **Volume** — connections (5/10/20 by tier), login attempts (5/15/30 by tier)
- **Behaviour** — 5+ distinct usernames (10), multi-service targeting (15)
- **Reputation** — AbuseIPDB confidence (10/15/20/25 by band), OTX pulse match (15)
- **Infrastructure** — datacenter/hosting ISP (5)

| Verdict | Score |
|---|---|
| LOW | 0–14 |
| MEDIUM | 15–34 |
| HIGH | 35–59 |
| CRITICAL | 60–100 |

Enrichment results are cached with per-source TTLs (geolocation 24h, AbuseIPDB 1h,
OTX 6h) so repeat traffic from one IP can't burn a daily API quota.

## Dashboard

Seven pages, behind a single admin login:

| Page | Contents |
|---|---|
| 🔴 Live Feed | Connections and login attempts as they arrive |
| 🌍 Attacker Intel | Per-IP profiles, geolocation map, enrichment, threat score |
| 📈 Analytics | Service breakdown, verdict distribution, activity timeline |
| 🚨 Alerts | Generated alerts with evidence; acknowledge workflow |
| 🔍 Threat Hunting | IOC/pattern search across credentials, IPs and payloads |
| 🎪 Campaigns | ASN-grouped coordinated activity |
| 🤖 AI Analysis | Gemini-generated threat reports from real captured data |

### Admin authentication

- **argon2** password hashing — plaintext passwords are never stored or logged
- Single admin account; **10 failed attempts → 15-minute lockout**, and a correct
  password still fails while the lockout is active
- On first run an `admin` account is created and its one-time password is
  **printed to the console once**. It is never written to disk — save it immediately
- Bound to **127.0.0.1 only** via `.streamlit/config.toml`

Every field rendering attacker-controlled data goes through `st.dataframe`, which
never interprets HTML or markdown in cell contents. `unsafe_allow_html` is not used
anywhere in the dashboard.

---

## Installation

```bash
git clone https://github.com/Ammy215/Honeypot-system.git
cd Honeypot-system

python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

pip install -r requirements.txt

cp .env.example .env             # then fill in your keys — see docs/GET_API_KEYS_GUIDE.md
git config core.hooksPath .githooks   # enable the secret-blocking pre-commit hook
```

With `DATABASE_URL` unset, the app uses a local SQLite database and creates the
schema automatically on first run. No database setup is needed for local development.

## Running

### Honeypot

```bash
python main.py
```

Starts every service in `ENABLED_SERVICES` (all four by default). **Ctrl+C** stops
it cleanly — listeners close and the database connection is released.

```bash
# Try it
nc localhost 2222                     # SSH
nc localhost 2121                     # FTP — try USER admin / PASS admin
nc localhost 2323                     # Telnet
curl http://localhost:8080/admin      # HTTP
curl -X POST -d "username=admin&password=letmein" http://localhost:8080/admin
```

To run a subset — which is what production does:

```bash
ENABLED_SERVICES=HTTP python main.py
```

### Dashboard

```bash
streamlit run dashboard/app.py
```

Visit `http://localhost:8501`. **Ctrl+C** to stop.

### Tests

```bash
python tests/test_option_a_fixes.py    # 37 tests: proxy IP resolution, $PORT, service gating, DB TLS
python tests/test_complete_system.py   # static environment/config health check
```

Standalone scripts, not pytest — run each directly. A pytest suite is a tracked
follow-up.

### Inspect the database

```bash
sqlite3 data/honeyshield_dev.db "SELECT * FROM connections ORDER BY connected_at DESC LIMIT 10;"
```

See [docs/VIEW_DATABASE_GUIDE.md](docs/VIEW_DATABASE_GUIDE.md).

---

## Project structure

```
.
├── honeypot/
│   ├── core/               # async base service, client IP resolution
│   ├── services/           # SSH / FTP / HTTP / Telnet honeypots
│   ├── detectors/          # brute force, credential stuffing, correlation, campaigns
│   ├── intelligence/       # geolocation, AbuseIPDB, OTX, enrichment, threat scoring
│   ├── alerting/           # alert generation
│   └── ai/                 # Gemini analyst
├── database/               # schemas (Postgres + SQLite), async DB layer, prod grants
├── dashboard/              # Streamlit app, login, 7 pages
├── auth/                   # argon2 admin auth, lockout state
├── security/               # encrypted API key vault, audit logging
├── deploy/                 # systemd units, deploy.sh, Cloudflare Tunnel guide (full VPS deployment)
├── scripts/                # operational one-off scripts
├── tests/                  # standalone test scripts
├── docs/                   # deployment, secrets, API keys, DB inspection, architecture
├── .githooks/pre-commit    # blocks commits containing key-shaped strings
├── config.py               # all runtime configuration
└── main.py                 # honeypot entry point
```

## Database schema

SQLite locally (`data/honeyshield_dev.db`), PostgreSQL in production. Schemas in
[database/schema_postgres.sql](database/schema_postgres.sql) and
[database/schema_sqlite_dev.sql](database/schema_sqlite_dev.sql).

| Table | Purpose |
|---|---|
| `attackers` | Per-IP profile: geolocation, ASN/ISP, reputation scores, threat score, verdict, enrichment cache timestamps |
| `connections` | Every connection, with service, port and the raw proxy forwarding header |
| `login_attempts` | Every credential pair, stored as literal text |
| `attacker_commands` | Commands typed post-"login" — stored, never executed |
| `alerts` | Generated alerts with JSON evidence and acknowledgement state |
| `ai_reports` | Stored Gemini-generated analyses |
| `service_stats` | Per-service activity counters |
| `ioc_matches` | IOC list matches |
| `admin_users` | Dashboard accounts: argon2 hash, failed-attempt count, lockout expiry |

## Configuration

All settings live in `config.py`, populated from `.env`. Full list in
[.env.example](.env.example).

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | PostgreSQL connection string. Empty → local SQLite |
| `SQLITE_PATH` | Local dev database path |
| `DB_SSL_MODE` | `require` (default) or `verify-full`. asyncpg would otherwise accept an unencrypted connection |
| `SKIP_SCHEMA_INIT` | `true` in production — the least-privilege DB role can't run `CREATE TABLE` |
| `ENABLED_SERVICES` | Which listeners start. Production: `HTTP` |
| `PORT` | Injected by the host platform; overrides the HTTP port |
| `TRUST_PROXY_HEADERS` | `true` behind a load balancer, `false` on direct exposure |
| `TRUSTED_CLIENT_IP_HEADER` | Platform-set single-value client IP header, if offered |
| `FORWARDED_IP_HEADER` | List-valued fallback (default `x-forwarded-for`) |
| `TRUSTED_PROXY_HOPS` | Proxy hops you control (1 = bare PaaS, 2 = Cloudflare in front) |
| `ABUSEIPDB_API_KEY` | IP reputation (free tier) |
| `OTX_API_KEY` | AlienVault OTX pulses (free) |
| `GEMINI_API_KEY` / `GEMINI_MODEL` | AI analyst (default `gemini-flash-latest`) |
| `API_KEY_ENCRYPTION_SECRET` | Encrypts the v1 API key vault |

Getting keys: [docs/GET_API_KEYS_GUIDE.md](docs/GET_API_KEYS_GUIDE.md).

---

## Deployment

Production runs the HTTP honeypot on a free PaaS tier, with PostgreSQL on Supabase
and the dashboard **kept local** — it is never exposed publicly at all.

Behind a load balancer the socket peer address is the balancer, not the attacker,
so the real client IP is resolved from the forwarding header by
[honeypot/core/client_ip.py](honeypot/core/client_ip.py). Because proxies *append*
to `X-Forwarded-For`, an attacker-supplied value gets pushed leftward — so the
trusted entry is counted from the **right**, never the left. The raw header is
stored alongside the resolved address, since a spoofed `X-Forwarded-For` is itself
useful intel.

`TRUST_PROXY_HEADERS` must stay `false` for direct exposure, where no trusted proxy
exists and the header is entirely attacker-controlled.

- **[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)** — full four-service VPS deployment
  (systemd, ufw, Cloudflare Tunnel). Pre-staged; usable as-is once hosting exists.
- **[docs/SECRETS.md](docs/SECRETS.md)** — key handling, database exposure, rotation.
- **[database/grants_production.sql](database/grants_production.sql)** — least-privilege
  production database role.

## Security notes

⚠️ This is a honeypot. The fake services are *meant* to be attacked. Everything
else should be treated as sensitive.

- **The dashboard is a real admin panel.** Keep it on `127.0.0.1`; reach it over an
  SSH tunnel or Cloudflare Access, never a public port.
- **The production database role is least-privilege** — `SELECT`/`INSERT`/`UPDATE`
  only, no `DELETE`/`DROP`/`ALTER`, and no access to `admin_users`, so a compromised
  honeypot can't destroy the dataset or read dashboard password hashes.
- **Captured credentials are stored in plaintext**, deliberately — that's what makes
  the dataset useful. Credential-stuffing bots replay real breach data, so this is
  real third-party personal data: don't screenshot raw `login_attempts` rows, don't
  export them, aggregate instead. See [docs/SECRETS.md](docs/SECRETS.md).
- **Secrets never enter git.** `.env`, `security/.master_key`, `security/api_keys.enc`
  and `auth/*.json` are gitignored; `.githooks/pre-commit` blocks key-shaped strings;
  GitHub push protection is the server-side backstop.
- Review `logs/audit.log` and `logs/honeypot.log` regularly.

---

## Future Work / Deferred

The current deployment is a **deliberately constrained one, not the final
architecture.** This section records what was built but isn't yet deployed, so the
gap is a documented decision rather than an unexplained inconsistency.

### Current deployment: HTTP only

Only the **HTTP honeypot (port 8080)** is deployed, to a free no-card PaaS tier. Free
PaaS tiers route HTTP/HTTPS only — they don't provide raw TCP socket access — so the
SSH, FTP, and Telnet services can't run there.

**All four services remain in the codebase, fully built and tested.** Only the hosting
is missing. Everything else runs against real live traffic: credential capture,
brute-force and credential-stuffing detection, geolocation, AbuseIPDB and OTX
enrichment, threat scoring, campaign detection, alerting, the AI analyst, and the
dashboard.

### Deferred: full 4-service deployment

| Deferred item | Why it's blocked | What unblocks it |
|---|---|---|
| SSH (2222), FTP (2121), Telnet (2323) | Need raw TCP sockets on a routable public IP | Any VPS, or a spare dedicated device |
| `multi_service` detection | Needs 2+ live services to correlate across | Same as above — activates automatically |
| `multi_service_targeting` score weight (15) | Same | Same |

- **SSH is the highest-value missing service** — the most-attacked protocol on the
  public internet, and the richest source of credential data by a wide margin.
- **Telnet** matters for a different reason: it's where IoT and Mirai-family botnets
  concentrate, so it captures a distinct attacker population rather than more of the
  same traffic.
- **Multi-service detection and its scoring weight are implemented and tested**, not
  stubbed or disabled. Nothing needs to be written or re-enabled — both begin firing
  automatically the moment a second service is reachable.

### Expected traffic volume

A PaaS hostname is not IP-addressable. Mass scanners sweep IPv4 ranges and connect to
*addresses*, but a PaaS app sits behind a shared edge that routes by Host/SNI, so
IP-based scans never reach it. Real traffic arrives instead from Certificate
Transparency log harvesters (the TLS cert is published within minutes of deploy) and
from hostname-based path scanning for `/wp-admin`, `/.env`, `/phpmyadmin` — which is
precisely what the HTTP decoys are built to catch.

Expect **dozens of hits per 48 hours, not thousands.** A sparse database during the
validation window is the expected result, not a broken pipeline.

### Deployment scaffolding is already written

The [`deploy/`](deploy/) directory — systemd unit files, `deploy.sh`, and
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) — is written for the **full four-service
deployment** and stays in the repo unchanged. It isn't dead code; it becomes usable
as-is the moment VPS or dedicated hardware exists.

### Also deferred (unrelated to hosting)

- **Dashboard rewrite** — replacing Streamlit with **React 18 + Vite + Tailwind +
  shadcn/ui**.
- **Cyber-range attack/defend rooms module.**

## License

MIT — see [LICENSE](LICENSE).

## Disclaimer

For educational and authorized security-research use only. Use responsibly and
ethically; the authors are not responsible for misuse.
