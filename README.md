# 🍯 HoneyShield Intelligence Platform

A multi-protocol honeypot and threat-intelligence platform: it attracts, captures, analyzes, and visualizes attacker behavior across SSH, FTP, HTTP, and Telnet — built from raw Python sockets and SQLite, with an AI-assisted analyst and a Streamlit SOC dashboard on top.

> Educational security tool for a single operator. See [Security Notes](#security-notes) before deploying anywhere network-reachable.

## Technology Stack

- **Core Language**: Python 3.13+ (raw TCP socket programming, no web framework)
- **Database**: SQLite, hand-written SQL (no ORM), optional pooled/WAL "production" mode
- **Dashboard**: Streamlit + Plotly
- **Data Analysis**: Pandas
- **Threat Intelligence**: AbuseIPDB, ip-api.com (free, no key)
- **AI Analysis**: OpenAI (`gpt-4o-mini` by default), called directly via the `openai` SDK
- **Security**: `bcrypt` password hashing, `cryptography.Fernet`-encrypted API key vault

## Features

- **Honeypot services**: SSH (2222), FTP (2121), HTTP (8080), Telnet (2323) with realistic fake banners. SMTP/RDP are defined but intentionally left disabled.
- **Detection**: brute-force detection (9 rules), multi-service correlation, attack-campaign detection (4 types)
- **Threat intelligence**: geolocation, AbuseIPDB reputation, IOC list matching, weighted threat scoring (18 factors, 0–100)
- **Dashboard**: Live Feed, Attacker Intel (map), Analytics, Alerts, Threat Hunting, Campaigns, AI Analysis — behind role-based login
- **AI Analyst**: GPT-generated attacker analysis, threat reports, and executive summaries
- **Auth**: admin/analyst/viewer roles, bcrypt-hashed passwords, session lockout after repeated failed logins

See [CHANGELOG.md](CHANGELOG.md) for how these were built up in phases.

## Installation

```bash
git clone https://github.com/Ammy215/Honeypot-system.git
cd Honeypot-system

python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

pip install -r requirements.txt

cp .env.example .env             # then fill in your API keys — see docs/GET_API_KEYS_GUIDE.md
```

The database initializes automatically on first run.

## Usage

### Start the honeypot

```bash
python main.py
```

Listens on: SSH `2222`, FTP `2121`, HTTP `8080`, Telnet `2323`.

```bash
# Try it out
nc localhost 2222                     # SSH honeypot
nc localhost 2121                     # FTP honeypot — try USER admin / PASS admin
curl http://localhost:8080/admin      # HTTP honeypot
nc localhost 2323                     # Telnet honeypot
```

### Start the dashboard

```bash
streamlit run dashboard/app.py
```

Visit `http://localhost:8501`. On first run, a default `admin` account is created and its one-time password is **printed to the console only** — it is never written to disk, so save it immediately and change it after logging in.

### Inspect the database directly

```bash
sqlite3 data/honeypot.db "SELECT * FROM connections ORDER BY timestamp DESC LIMIT 10;"
```

See [docs/VIEW_DATABASE_GUIDE.md](docs/VIEW_DATABASE_GUIDE.md) for more.

## Project Structure

```
.
├── honeypot/               # Core honeypot services
│   ├── core/               # Base service class + server orchestrator
│   ├── services/           # SSH / FTP / HTTP / Telnet honeypots
│   ├── detectors/          # Brute-force, correlation, campaign detection
│   ├── intelligence/       # Geolocation, AbuseIPDB, threat scoring, IOC
│   ├── alerting/           # Alert generation
│   └── ai/                 # AI-powered analysis and report generation
├── database/                # Schema, migrations, connection managers
├── dashboard/                # Streamlit app + pages
├── auth/                     # RBAC, bcrypt hashing, sessions
├── security/                  # Encrypted API key vault, audit logging
├── scripts/                   # Operational scripts (setup, security/system checks)
├── tests/                      # Integration-style smoke tests
├── docs/                        # Deployment, API keys, DB inspection, architecture guides
├── config.py                     # Central configuration
└── main.py                       # Honeypot entry point
```

## Database Schema

SQLite, file at `data/honeypot.db`:

| Table | Purpose |
|---|---|
| `attackers` | Per-IP profile: enrichment, threat score, verdict |
| `connections` | Every TCP connection attempt |
| `login_attempts` | Every credential attempt |
| `attacker_commands` | Commands typed by attackers post-"login" |
| `alerts` | Generated security alerts |
| `ai_reports` | Stored AI-generated analyses |
| `service_stats` | Per-service activity counters |
| `ioc_matches` | IOC list matches |

## Configuration

All settings live in `config.py`, populated from `.env` (see `.env.example`). Key flags:

| Variable | Purpose |
|---|---|
| `ABUSEIPDB_API_KEY` | IP reputation lookups (free tier available) |
| `OPENAI_API_KEY` / `OPENAI_MODEL` | AI Analyst |
| `API_KEY_ENCRYPTION_SECRET` | Encrypts the API key vault — required outside local dev |
| `ENABLE_AUTHENTICATION`, `ENABLE_RATE_LIMITING`, `ENABLE_AUDIT_LOGGING` | Security toggles |
| `USE_PRODUCTION_DB`, `DB_POOL_SIZE` | Connection pooling / WAL mode |

Get API keys: see [docs/GET_API_KEYS_GUIDE.md](docs/GET_API_KEYS_GUIDE.md).

## Security Notes

⚠️ This is a honeypot — it's designed to attract attacks against its fake services, but the **dashboard is a real, authenticated admin panel** and should be treated like one:

- Run the honeypot listeners in an isolated network segment; don't expose the *dashboard* port directly to the internet without a reverse proxy + HTTPS
- Non-standard honeypot ports (2222, 2121, etc.) avoid needing root
- The API key vault's encryption key (`API_KEY_ENCRYPTION_SECRET`) and `.env` must never be committed — both are gitignored
- Dashboard login locks an account for 15 minutes after 5 failed attempts
- Review `logs/audit.log` and `logs/honeypot.log` regularly

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for a fuller deployment checklist.

## License

MIT — see [LICENSE](LICENSE).

## Disclaimer

For educational and authorized security-research use only. Use responsibly and ethically; the authors are not responsible for misuse.
