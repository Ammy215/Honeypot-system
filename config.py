import os
from dotenv import load_dotenv
load_dotenv()

# ── Honeypot Services ──────────────────────────────────
HONEYPOT_HOST = "0.0.0.0"

SERVICES = {
    "SSH":    {"port": 2222,  "enabled": True},   # Use 2222 not 22 (avoid root requirement)
    "FTP":    {"port": 2121,  "enabled": True},   # Use 2121 not 21
    "HTTP":   {"port": 8080,  "enabled": True},
    "Telnet": {"port": 2323,  "enabled": True},   # Use 2323 not 23
    "SMTP":   {"port": 2525,  "enabled": False},  # Enable in phase 2
    "RDP":    {"port": 3389,  "enabled": False},  # Enable in phase 2
}

# ── Deployment / hosting (Option A: HTTP-only on a free PaaS) ──
# PaaS platforms inject the port to bind as $PORT and route only that one
# port. Falls back to the local-dev port above when $PORT isn't set.
HTTP_PORT = int(os.getenv("PORT") or SERVICES["HTTP"]["port"])

# Which services main.py starts. Free PaaS tiers route HTTP only (no raw TCP),
# so production sets ENABLED_SERVICES=HTTP; local dev defaults to all four.
# SSH/FTP/Telnet are gated here, never removed — see README "Future Work".
ENABLED_SERVICES = [
    name.strip().upper()
    for name in os.getenv("ENABLED_SERVICES", "SSH,FTP,TELNET,HTTP").split(",")
    if name.strip()
]

# ── Reverse-proxy / load-balancer client IP resolution ────
# Behind a PaaS load balancer the socket peer address is the balancer, not the
# attacker — every attacker would record as the same IP, making geolocation,
# reputation, scoring and campaign detection meaningless. Enable in production.
# MUST stay off for direct exposure: with no trusted proxy in front, these
# headers are entirely attacker-controlled and trusting them lets an attacker
# forge their own source IP.
TRUST_PROXY_HEADERS = os.getenv("TRUST_PROXY_HEADERS", "false").lower() == "true"

# A single-value header the platform sets itself (e.g. CF-Connecting-IP).
# Preferred when the platform offers one: unlike X-Forwarded-For it is not a
# list, so attacker-supplied entries can't pollute it. Empty = not available.
TRUSTED_CLIENT_IP_HEADER = os.getenv("TRUSTED_CLIENT_IP_HEADER", "").strip().lower()

# Fallback list-valued header. Proxies *append*, so an attacker who sends their
# own value gets it pushed leftward — the trustworthy entry is counted from the
# right, never the left. See honeypot/core/client_ip.py.
FORWARDED_IP_HEADER = os.getenv("FORWARDED_IP_HEADER", "x-forwarded-for").strip().lower()

# How many proxy hops we actually control. Each appends exactly one entry, so
# the real client sits this many positions from the right-hand end.
# 1 = bare PaaS load balancer. 2 = Cloudflare in front of the PaaS.
TRUSTED_PROXY_HOPS = int(os.getenv("TRUSTED_PROXY_HOPS", "1"))

# Drop connections that arrive without a forwarding header when we're behind a
# proxy. Platform health checks probe the instance directly rather than through
# the load balancer, so they carry no forwarding header — without this they get
# recorded as attacker connections every few seconds and bury the real signal
# (which, on a PaaS hostname, is only dozens of hits per day).
#
# Opt-in and default off: if the load balancer ever stopped sending the header,
# this would silently discard real traffic. Enable it in production only after
# confirming real requests do arrive with the header. Ignored entirely when
# TRUST_PROXY_HEADERS is false.
IGNORE_UNFORWARDED_CONNECTIONS = (
    os.getenv("IGNORE_UNFORWARDED_CONNECTIONS", "false").lower() == "true"
)

# ── Database (v1, legacy dashboard/auth — unchanged) ─────
DATABASE_PATH = "data/honeypot.db"

# ── Database (v2 async core, HONEYSHIELD_PROJECT.md §5) ──
# Postgres in prod when set; falls back to local SQLite for dev when empty.
DATABASE_URL = os.getenv("DATABASE_URL", "")
SQLITE_PATH = os.getenv("SQLITE_PATH", "./data/honeyshield_dev.db")

# ── Logging ─────────────────────────────────────────────
LOG_DIR = "logs/"
LOG_LEVEL = "INFO"
LOG_FORMAT = "%(asctime)s | %(levelname)s | %(name)s | %(message)s"

# ── Threat Intelligence APIs ─────────────────────────────
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")  # re-introduced in v2 phase 3 — actually used this time
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")  # AI analyst (phase 6) — swapped from OpenAI to Gemini
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-flash-latest")  # gemini-2.5-flash 404s for new keys; -latest tracks Google's current recommended flash model

# ── Geolocation ──────────────────────────────────────────
GEOIP_API_URL = "http://ip-api.com/json"   # Free, no key needed
GEOIP_RATE_LIMIT = 45                       # Requests per minute

# ── Enrichment cache TTLs (v2 phase 3) ────────────────────
# Bounds re-checks to what each API's rate limit can sustain; values match
# the caching strategy already used elsewhere (Project 4 in CLAUDE_CONTEXT.md).
GEO_CACHE_TTL_SECONDS = 24 * 60 * 60        # 24h — geolocation rarely changes
ABUSEIPDB_CACHE_TTL_SECONDS = 60 * 60       # 1h  — free tier easily sustains hourly re-checks
OTX_CACHE_TTL_SECONDS = 6 * 60 * 60         # 6h  — pulse data updates slowly

# ── Detection Thresholds ──────────────────────────────────
BRUTE_FORCE_THRESHOLD = 10         # Login attempts per 5 minutes
RAPID_FIRE_THRESHOLD = 3           # Attempts per second
MULTI_SERVICE_THRESHOLD = 2        # Services before flagging
MULTI_SERVICE_WINDOW_SECONDS = 300 # Window for "same IP hit 2+ services" (v2 phase 5)
CREDENTIAL_STUFFING_THRESHOLD = 5  # Unique usernames per 10 minutes

# ── Campaign Detection (v2 phase 5) ───────────────────────
CAMPAIGN_MIN_ATTACKERS = 3            # Distinct IPs sharing an ASN before it's a "campaign"
CAMPAIGN_WINDOW_SECONDS = 24 * 60 * 60  # 24h — matches v1's campaign_detector.py precedent

# ── Dashboard ────────────────────────────────────────────
DASHBOARD_REFRESH_SECONDS = 15
DASHBOARD_PORT = 8501

# ── Connection Limits ────────────────────────────────────
MAX_CONNECTIONS_PER_IP = 100      # Block after this many
MAX_TOTAL_CONNECTIONS = 500       # Global ceiling (async core, spec §6.5)
CONNECTION_TIMEOUT_SECONDS = 30
MAX_LOGIN_ATTEMPTS_PER_SESSION = 10

# ── Security ─────────────────────────────────────────────
ENABLE_AUTHENTICATION = os.getenv("ENABLE_AUTHENTICATION", "true").lower() == "true"
SESSION_TIMEOUT_HOURS = int(os.getenv("SESSION_TIMEOUT_HOURS", "8"))
ENABLE_AUDIT_LOGGING = os.getenv("ENABLE_AUDIT_LOGGING", "true").lower() == "true"
ENABLE_RATE_LIMITING = os.getenv("ENABLE_RATE_LIMITING", "true").lower() == "true"
DASHBOARD_RATE_LIMIT = int(os.getenv("DASHBOARD_RATE_LIMIT", "100"))  # Requests per minute

# ── Production Database ──────────────────────────────────
USE_PRODUCTION_DB = os.getenv("USE_PRODUCTION_DB", "true").lower() == "true"
DB_POOL_SIZE = int(os.getenv("DB_POOL_SIZE", "5"))

# TLS for the Postgres connection. asyncpg negotiates but does not *require*
# TLS by default, so this is set explicitly. "require" encrypts without
# verifying the server cert; "verify-full" also checks the chain + hostname
# and is the stronger setting when a CA bundle is available.
DB_SSL_MODE = os.getenv("DB_SSL_MODE", "require")

# The production DB user is least-privilege (SELECT/INSERT/UPDATE only) and
# cannot run CREATE TABLE. Apply database/schema_postgres.sql once as the DB
# owner, then set this so startup skips init_schema().
SKIP_SCHEMA_INIT = os.getenv("SKIP_SCHEMA_INIT", "false").lower() == "true"

# ── IOC ──────────────────────────────────────────────────
IOC_FILE_PATH = "ioc/known_bad_ips.txt"
IOC_CHECK_ENABLED = True

# ── Fake Service Banners ──────────────────────────────────
BANNERS = {
    "SSH":    "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4",
    "FTP":    "220 ProFTPD 1.3.5e Server (ProFTPD Default Installation) [127.0.0.1]",
    "SMTP":   "220 mail.example.com ESMTP Postfix (Ubuntu)",
    "Telnet": "\r\nUbuntu 20.04.6 LTS\r\nlocalhost login: ",
}
